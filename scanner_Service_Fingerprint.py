"""Cross-platform TCP service and version fingerprinting.

This module consumes open TCP ports produced by ``scanner_Port_Scanner`` and
performs lightweight, application-aware identification. It intentionally keeps
fingerprinting separate from port discovery so the scanner pipeline remains:

    host discovery -> port discovery -> service fingerprinting -> CVE matching

The implementation uses only Python's standard networking libraries for the
fingerprinting stage and therefore works on Linux, Windows, and macOS.

Only scan systems and networks you are authorized to assess.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import ssl
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import Event
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from scanner_Host_Discovery import Device, print_devices
from scanner_Port_Scanner import (
    PortResult,
    discover_hosts,
    parse_ports,
    scan_open_ports,
    smart_scan_open_ports,
)


MAX_RESPONSE_BYTES = 8192
DEFAULT_FINGERPRINT_TIMEOUT = 1.0
DEFAULT_FINGERPRINT_WORKERS = 32
MAX_FINGERPRINT_WORKERS = 128
SIGNATURE_PATH = Path(__file__).with_name("service_signatures.json")

# Ports that commonly carry TLS directly. This is guidance for selecting the
# first probe only; the observed response is what determines the final result.
DIRECT_TLS_PORTS = {
    443,
    465,
    636,
    853,
    989,
    990,
    992,
    993,
    995,
    2376,
    5986,
    8443,
    8883,
    9443,
}

WEB_PORTS = {
    80,
    81,
    443,
    3000,
    3001,
    4000,
    4200,
    5000,
    5001,
    7001,
    7002,
    8000,
    8001,
    8002,
    8008,
    8080,
    8081,
    8082,
    8083,
    8084,
    8085,
    8086,
    8088,
    8090,
    8091,
    8180,
    8181,
    8280,
    8443,
    8880,
    8888,
    9000,
    9001,
    9002,
    9090,
    9091,
    9200,
    9443,
    10000,
}

SSH_HINTS = {"ssh"}
FTP_HINTS = {"ftp", "ftps", "ftp-data"}
SMTP_HINTS = {"smtp", "submission", "smtps"}
HTTP_HINTS = {"http", "https", "http-alt", "https-alt"}


@dataclass(frozen=True)
class ServiceFingerprint:
    ip: str
    mac: Optional[str]
    port: int
    protocol: str
    service: str
    product: Optional[str]
    version: Optional[str]
    banner: Optional[str]
    cpe: Optional[str]
    confidence: float
    detection_method: str
    fingerprinted_at: str


@dataclass(frozen=True)
class Signature:
    service: str
    product: str
    pattern: re.Pattern[str]
    confidence: float


@dataclass(frozen=True)
class ProbeObservation:
    service: str
    banner: str
    detection_method: str
    protocol_confidence: float


FingerprintProgressCallback = Callable[[ServiceFingerprint], None]


def _clean_text(data: bytes) -> str:
    """Decode a network response while keeping output printable and bounded."""
    if not data:
        return ""

    text = data[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
    text = text.replace("\x00", "")
    return "".join(ch for ch in text if ch in "\r\n\t" or ch.isprintable()).strip()


def _recv_available(sock: socket.socket, max_bytes: int = MAX_RESPONSE_BYTES) -> bytes:
    """Read until timeout/EOF or the configured response limit is reached."""
    chunks: List[bytes] = []
    remaining = max_bytes

    while remaining > 0:
        try:
            chunk = sock.recv(min(2048, remaining))
        except socket.timeout:
            break

        if not chunk:
            break

        chunks.append(chunk)
        remaining -= len(chunk)

        # Most identification banners fit within the first packet. Keep reading
        # only when a full chunk was returned so protocol probes remain quick.
        if len(chunk) < 2048:
            break

    return b"".join(chunks)


def _open_tcp(ip: str, port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection((ip, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def _tls_wrap(sock: socket.socket, ip: str) -> ssl.SSLSocket:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(sock, server_hostname=ip)


def load_signatures(path: Path = SIGNATURE_PATH) -> List[Signature]:
    """Load the small local signature set used by the first implementation."""
    with path.open("r", encoding="utf-8") as handle:
        raw_signatures = json.load(handle)

    signatures: List[Signature] = []
    for entry in raw_signatures:
        signatures.append(
            Signature(
                service=str(entry["service"]),
                product=str(entry["product"]),
                pattern=re.compile(str(entry["pattern"]), re.IGNORECASE | re.MULTILINE),
                confidence=float(entry.get("confidence", 0.9)),
            )
        )
    return signatures


try:
    SERVICE_SIGNATURES = load_signatures()
except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, re.error):
    # Fingerprinting should still work at the protocol level even if the local
    # signature file was accidentally removed or edited incorrectly.
    SERVICE_SIGNATURES = []


def match_signature(text: str, service: Optional[str] = None) -> Optional[Tuple[str, Optional[str], float]]:
    """Return ``(product, version, confidence)`` for the best matching signature."""
    if not text:
        return None

    candidates = SERVICE_SIGNATURES
    if service and service != "unknown":
        filtered = [signature for signature in candidates if signature.service == service]
        if filtered:
            candidates = filtered

    best: Optional[Tuple[str, Optional[str], float]] = None

    for signature in candidates:
        match = signature.pattern.search(text)
        if not match:
            continue

        version = match.groupdict().get("version")
        current = (signature.product, version, signature.confidence)
        if best is None or current[2] > best[2]:
            best = current

    return best


def probe_passive_banner(ip: str, port: int, timeout: float) -> Optional[ProbeObservation]:
    """Connect and read any banner a service sends without receiving a request."""
    try:
        with _open_tcp(ip, port, timeout) as sock:
            banner = _clean_text(_recv_available(sock))
    except (OSError, ssl.SSLError):
        return None

    if not banner:
        return None

    service = "unknown"
    upper = banner.upper()
    if banner.startswith("SSH-"):
        service = "ssh"
    elif banner.startswith("220") and "SMTP" in upper:
        service = "smtp"
    elif banner.startswith("220") and ("FTP" in upper or "FILEZILLA" in upper):
        service = "ftp"

    return ProbeObservation(
        service=service,
        banner=banner,
        detection_method="passive_banner",
        protocol_confidence=0.70 if service == "unknown" else 0.88,
    )


def probe_unknown_service(ip: str, port: int, timeout: float) -> Optional[ProbeObservation]:
    """Use one connection to check for a passive banner, then try HTTP.

    Reusing the connection avoids consuming a one-shot or rate-limited service
    just to learn that it does not send a greeting banner.
    """
    try:
        with _open_tcp(ip, port, timeout) as sock:
            original_timeout = timeout
            sock.settimeout(min(timeout, 0.20))
            try:
                initial = sock.recv(2048)
            except socket.timeout:
                initial = b""

            if initial:
                banner = _clean_text(initial)
                service = "unknown"
                upper = banner.upper()
                if banner.startswith("SSH-"):
                    service = "ssh"
                elif banner.startswith("220") and "SMTP" in upper:
                    service = "smtp"
                elif banner.startswith("220") and ("FTP" in upper or "FILEZILLA" in upper):
                    service = "ftp"

                return ProbeObservation(
                    service=service,
                    banner=banner,
                    detection_method="passive_banner",
                    protocol_confidence=0.70 if service == "unknown" else 0.88,
                )

            sock.settimeout(original_timeout)
            sock.sendall(_http_request(ip))
            response = _clean_text(_recv_available(sock))
            first_line = response.splitlines()[0] if response.splitlines() else ""
            if first_line.upper().startswith("HTTP/"):
                return ProbeObservation(
                    service="http",
                    banner=response,
                    detection_method="http_headers",
                    protocol_confidence=0.95,
                )
    except (OSError, ssl.SSLError):
        return None

    return None


def probe_ssh(ip: str, port: int, timeout: float) -> Optional[ProbeObservation]:
    """Read an SSH protocol identification string."""
    try:
        with _open_tcp(ip, port, timeout) as sock:
            banner = _clean_text(_recv_available(sock))
    except OSError:
        return None

    if not banner.startswith("SSH-"):
        return None

    return ProbeObservation(
        service="ssh",
        banner=banner.splitlines()[0],
        detection_method="ssh_banner",
        protocol_confidence=0.96,
    )


def _http_request(ip: str) -> bytes:
    host = ipaddress.ip_address(ip).compressed
    return (
        f"HEAD / HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        "User-Agent: CPSC491-Vulnerability-Scanner/0.1\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


def probe_http(
    ip: str,
    port: int,
    timeout: float,
    use_tls: bool = False,
) -> Optional[ProbeObservation]:
    """Send a lightweight HTTP HEAD request and collect response headers."""
    sock: Optional[socket.socket] = None
    wrapped: Optional[ssl.SSLSocket] = None

    try:
        sock = _open_tcp(ip, port, timeout)
        active: socket.socket

        if use_tls:
            wrapped = _tls_wrap(sock, ip)
            wrapped.settimeout(timeout)
            active = wrapped
        else:
            active = sock

        active.sendall(_http_request(ip))
        response = _clean_text(_recv_available(active))
    except (OSError, ssl.SSLError):
        return None
    finally:
        try:
            if wrapped is not None:
                wrapped.close()
            elif sock is not None:
                sock.close()
        except OSError:
            pass

    if not response:
        return None

    first_line = response.splitlines()[0] if response.splitlines() else ""
    if not first_line.upper().startswith("HTTP/"):
        return None

    return ProbeObservation(
        service="https" if use_tls else "http",
        banner=response,
        detection_method="https_headers" if use_tls else "http_headers",
        protocol_confidence=0.95,
    )


def probe_ftp(ip: str, port: int, timeout: float) -> Optional[ProbeObservation]:
    """Read an FTP greeting banner."""
    observation = probe_passive_banner(ip, port, timeout)
    if observation is None or not observation.banner.startswith("220"):
        return None

    upper = observation.banner.upper()
    if "SMTP" in upper:
        return None

    return ProbeObservation(
        service="ftp",
        banner=observation.banner,
        detection_method="ftp_banner",
        protocol_confidence=0.90,
    )


def probe_smtp(ip: str, port: int, timeout: float) -> Optional[ProbeObservation]:
    """Read an SMTP greeting and issue EHLO to obtain server capabilities."""
    try:
        with _open_tcp(ip, port, timeout) as sock:
            greeting = _recv_available(sock)
            if not greeting.startswith(b"220"):
                return None

            try:
                sock.sendall(b"EHLO vulnerability-scanner.local\r\n")
                capabilities = _recv_available(sock)
            except OSError:
                capabilities = b""
    except OSError:
        return None

    combined = _clean_text(greeting + capabilities)
    if not combined:
        return None

    return ProbeObservation(
        service="smtp",
        banner=combined,
        detection_method="smtp_banner_ehlo",
        protocol_confidence=0.92,
    )


def _hint_family(port_result: PortResult) -> str:
    hint = (port_result.service_hint or "unknown").strip().lower()

    if hint in SSH_HINTS or port_result.port in {22, 2222}:
        return "ssh"
    if hint in FTP_HINTS or port_result.port in {21, 990}:
        return "ftp"
    if hint in SMTP_HINTS or port_result.port in {25, 465, 587, 2525}:
        return "smtp"
    if hint in HTTP_HINTS or port_result.port in WEB_PORTS:
        return "http"
    return "unknown"


def _run_probe_plan(port_result: PortResult, timeout: float) -> Optional[ProbeObservation]:
    """Run a small ordered probe set based on hints, then fall back safely."""
    family = _hint_family(port_result)
    ip = port_result.ip
    port = port_result.port

    if family == "ssh":
        observation = probe_ssh(ip, port, timeout)
        if observation:
            return observation

    elif family == "ftp":
        observation = probe_ftp(ip, port, timeout)
        if observation:
            return observation

    elif family == "smtp":
        # Implicit TLS SMTP requires a TLS-aware SMTP probe. For the initial
        # implementation, preserve the port hint rather than misidentifying it.
        if port != 465:
            observation = probe_smtp(ip, port, timeout)
            if observation:
                return observation

    elif family == "http":
        if port in DIRECT_TLS_PORTS or "https" in (port_result.service_hint or "").lower():
            observation = probe_http(ip, port, timeout, use_tls=True)
            if observation:
                return observation

        observation = probe_http(ip, port, timeout, use_tls=False)
        if observation:
            return observation

    # On an unusual port, use one connection to wait briefly for a greeting
    # banner and then speak HTTP if the server stays silent.
    observation = probe_unknown_service(ip, port, timeout)
    if observation:
        return observation

    # Finally, try TLS+HTTP on direct-TLS ports that were not already handled.
    if port in DIRECT_TLS_PORTS:
        return probe_http(ip, port, timeout, use_tls=True)

    return None


def fingerprint_port(
    port_result: PortResult,
    timeout: float = DEFAULT_FINGERPRINT_TIMEOUT,
) -> ServiceFingerprint:
    """Identify the service/product/version behind one known-open TCP port."""
    if timeout <= 0:
        raise ValueError("fingerprint timeout must be greater than 0")

    observation = _run_probe_plan(port_result, timeout)
    hint = (port_result.service_hint or "unknown").lower()

    if observation is None:
        return ServiceFingerprint(
            ip=port_result.ip,
            mac=port_result.mac,
            port=port_result.port,
            protocol=port_result.protocol,
            service=hint,
            product=None,
            version=None,
            banner=None,
            cpe=None,
            confidence=0.25 if hint != "unknown" else 0.10,
            detection_method="port_hint" if hint != "unknown" else "unidentified",
            fingerprinted_at=datetime.now().isoformat(timespec="seconds"),
        )

    service = observation.service
    match = match_signature(observation.banner, service=service)

    product: Optional[str] = None
    version: Optional[str] = None
    confidence = observation.protocol_confidence

    if match is not None:
        product, version, signature_confidence = match
        confidence = max(confidence, signature_confidence)

    # A passive banner can identify a product even when protocol inference was
    # initially unknown. Re-run against all signatures before falling back.
    if product is None:
        broad_match = match_signature(observation.banner)
        if broad_match is not None:
            product, version, signature_confidence = broad_match
            confidence = max(confidence, signature_confidence)

            for signature in SERVICE_SIGNATURES:
                if signature.product == product:
                    service = signature.service
                    break

    if service == "unknown" and hint != "unknown":
        service = hint
        confidence = max(confidence, 0.40)

    return ServiceFingerprint(
        ip=port_result.ip,
        mac=port_result.mac,
        port=port_result.port,
        protocol=port_result.protocol,
        service=service,
        product=product,
        version=version,
        banner=observation.banner,
        cpe=None,  # Reserved for the later CPE/NVD normalization stage.
        confidence=round(min(confidence, 1.0), 2),
        detection_method=observation.detection_method,
        fingerprinted_at=datetime.now().isoformat(timespec="seconds"),
    )


def fingerprint_services(
    port_results: Sequence[PortResult],
    timeout: float = DEFAULT_FINGERPRINT_TIMEOUT,
    workers: int = DEFAULT_FINGERPRINT_WORKERS,
    progress_callback: Optional[FingerprintProgressCallback] = None,
    cancel_event: Optional[Event] = None,
) -> List[ServiceFingerprint]:
    """Fingerprint open ports with bounded concurrency and cooperative cancel."""
    if timeout <= 0:
        raise ValueError("fingerprint timeout must be greater than 0")
    if workers < 1:
        raise ValueError("fingerprint workers must be at least 1")
    if workers > MAX_FINGERPRINT_WORKERS:
        raise ValueError(f"fingerprint workers may not exceed {MAX_FINGERPRINT_WORKERS}")
    if not port_results:
        return []
    if cancel_event is not None and cancel_event.is_set():
        return []

    fingerprints: List[ServiceFingerprint] = []
    result_iter = iter(port_results)
    queue_limit = max(workers * 4, workers)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending: Dict[object, PortResult] = {}

        def submit_next() -> bool:
            if cancel_event is not None and cancel_event.is_set():
                return False
            try:
                result = next(result_iter)
            except StopIteration:
                return False

            future = executor.submit(fingerprint_port, result, timeout)
            pending[future] = result
            return True

        for _ in range(queue_limit):
            if not submit_next():
                break

        while pending:
            completed, _ = wait(set(pending), return_when=FIRST_COMPLETED)

            for future in completed:
                pending.pop(future, None)
                if future.cancelled():
                    continue
                fingerprint = future.result()
                fingerprints.append(fingerprint)
                if progress_callback is not None:
                    progress_callback(fingerprint)

            if cancel_event is not None and cancel_event.is_set():
                for future in list(pending):
                    future.cancel()
                break

            for _ in range(len(completed)):
                if not submit_next():
                    break

    return sorted(
        fingerprints,
        key=lambda result: (ipaddress.ip_address(result.ip), result.port),
    )

def print_fingerprints(results: Sequence[ServiceFingerprint]) -> None:
    print()
    print(
        f"{'IP ADDRESS':<18} "
        f"{'PORT':<8} "
        f"{'SERVICE':<10} "
        f"{'PRODUCT':<24} "
        f"{'VERSION':<16} "
        f"{'CONF':<6} "
        f"{'METHOD'}"
    )
    print("-" * 112)

    if not results:
        print("No open services were available to fingerprint.")
        return

    for result in results:
        product = result.product or "unknown"
        version = result.version or "unknown"
        print(
            f"{result.ip:<18} "
            f"{str(result.port) + '/' + result.protocol:<8} "
            f"{result.service:<10} "
            f"{product:<24.24} "
            f"{version:<16.16} "
            f"{result.confidence:<6.2f} "
            f"{result.detection_method}"
        )


def _scan_ports_for_cli(
    devices: Sequence[Device],
    port_spec: Optional[str],
    timeout: float,
    workers: int,
) -> List[PortResult]:
    normalized = (port_spec or "smart").strip().lower()
    if normalized == "smart":
        return smart_scan_open_ports(devices, timeout=timeout, workers=workers)

    ports = parse_ports(port_spec)
    return scan_open_ports(devices, ports, timeout=timeout, workers=workers)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Discover authorized local IPv4 hosts, find open TCP ports, and "
            "perform lightweight service/version fingerprinting."
        )
    )
    parser.add_argument(
        "--network",
        help="Authorized IPv4 CIDR to discover, e.g. 192.168.1.0/24",
    )
    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Use only the OS neighbor table for host discovery",
    )
    parser.add_argument(
        "--ports",
        default=None,
        help=(
            "TCP ports or mode: smart (default), common, all, 22,80,443, "
            "or ranges such as 8000-8100"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.35,
        help="TCP connect timeout used by port discovery (default: 0.35)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Port-scan worker count (default: 100)",
    )
    parser.add_argument(
        "--fingerprint-timeout",
        type=float,
        default=DEFAULT_FINGERPRINT_TIMEOUT,
        help="Per-probe fingerprint timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--fingerprint-workers",
        type=int,
        default=DEFAULT_FINGERPRINT_WORKERS,
        help="Concurrent fingerprint worker count (default: 32)",
    )
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        devices, interface, local_ip, gateway, discovery_network = discover_hosts(
            requested_network=args.network,
            passive_only=args.passive_only,
        )
    except Exception as exc:
        parser.error(f"Host discovery failed: {exc}")

    print(f"[*] Interface : {interface}")
    print(f"[*] Local IP  : {local_ip}")
    print(f"[*] Gateway   : {gateway}")
    print(f"[*] Network   : {discovery_network}")
    print_devices(devices)

    if not devices:
        print("[!] No hosts were discovered; skipping service fingerprinting.")
        return

    try:
        port_results = _scan_ports_for_cli(
            devices,
            args.ports,
            timeout=args.timeout,
            workers=args.workers,
        )
        print(
            f"[*] Fingerprint : {len(port_results)} open TCP port(s), "
            f"{args.fingerprint_workers} worker(s)"
        )
        fingerprints = fingerprint_services(
            port_results,
            timeout=args.fingerprint_timeout,
            workers=args.fingerprint_workers,
        )
    except (ValueError, argparse.ArgumentTypeError) as exc:
        parser.error(str(exc))

    print_fingerprints(fingerprints)


if __name__ == "__main__":
    main()
