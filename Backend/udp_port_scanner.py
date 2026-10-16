"""UDP port scanning and protocol probing module."""

import errno
import ipaddress
import socket
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime
from threading import Event
from typing import Callable
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from scanner_Host_Discovery import Device

COMMON_UDP_PORTS = (53, 67, 68, 69, 123, 137, 138, 161, 500, 514, 520, 5353)

UDP_PROBES: Dict[int, bytes] = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09localhost\x00\x00\x01\x00\x01",
    123: b"\x1b" + 47 * b"\x00",
    161: (
        b"\x30\x29\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x1c"
        b"\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30"
        b"\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
    ),
    137: (
        b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00"
        b"\x00\x21\x00\x01"
    ),
}


@dataclass(frozen=True)
class UDPPortResult:
    ip: str
    mac: Optional[str]
    port: int
    protocol: str
    state: str
    service_hint: str
    scanned_at: str
    state_reason: Optional[str] = None
    evidence_method: Optional[str] = None


def service_hint_udp(port: int) -> str:
    """Return the operating system well-known UDP service name."""
    try:
        return socket.getservbyport(port, "udp")
    except OSError:
        return "unknown"


def probe_udp_port(
    device: Device, port: int, timeout: float = 1.0,
) -> UDPPortResult:
    """Classify one UDP probe using a connected datagram socket.

    Connecting the datagram socket filters responses by remote IP and port.
    An attributable OS-level connection refusal indicates a closed port where
    supported. Other socket errors remain unknown rather than being guessed.
    """
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    state, reason = "unknown", "socket_error"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((device.ip, port))
            sock.send(UDP_PROBES.get(port, b"\x00"))
            response = sock.recv(2048)
            if response:
                state, reason = "open", "udp_application_response"
            else:
                reason = "empty_udp_response"
    except (socket.timeout, TimeoutError):
        state, reason = "open|filtered", "udp_timeout"
    except OSError as exc:
        # ICMP port-unreachable is exposed differently by socket APIs.
        # Windows WSAECONNRESET (10054) often represents that UDP ICMP error.
        if exc.errno in {errno.ECONNREFUSED, errno.ECONNRESET, 10061, 10054}:
            state, reason = "closed", "icmp_port_unreachable"

    return UDPPortResult(
        ip=device.ip,
        mac=device.mac,
        port=port,
        protocol="udp",
        state=state,
        service_hint=service_hint_udp(port),
        scanned_at=datetime.now().isoformat(timespec="seconds"),
        state_reason=reason,
        evidence_method="udp_application_probe",
    )


def scan_udp_port(
    device: Device, port: int, timeout: float = 1.0,
) -> Optional[UDPPortResult]:
    """Backward-compatible open-only UDP probe."""
    outcome = probe_udp_port(device, port, timeout)
    return outcome if outcome.state == "open" else None


UDPProgressCallback = Callable[[Device, int, Optional[UDPPortResult]], None]


def scan_udp_ports(
    devices: Sequence[Device],
    ports: Sequence[int],
    timeout: float = 1.0,
    workers: int = 30,
    progress_callback: Optional[UDPProgressCallback] = None,
    cancel_event: Optional[Event] = None,
    include_non_open: bool = False,
) -> List[UDPPortResult]:
    """UDP scan with bounded concurrency and progress/cancellation support."""
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    if not 1 <= workers <= 512:
        raise ValueError("workers must be between 1 and 512")
    if not devices or not ports or (cancel_event and cancel_event.is_set()):
        return []

    targets = ((device, port) for device in devices for port in ports)
    target_iter = iter(targets)
    results: List[UDPPortResult] = []
    probe = probe_udp_port if include_non_open else scan_udp_port

    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = {}

        def submit_next() -> bool:
            if cancel_event is not None and cancel_event.is_set():
                return False
            try:
                device, port = next(target_iter)
            except StopIteration:
                return False
            pending[executor.submit(probe, device, port, timeout)] = (device, port)
            return True

        for _ in range(workers * 4):
            if not submit_next():
                break

        while pending:
            completed, _ = wait(set(pending), return_when=FIRST_COMPLETED)
            for future in completed:
                device, port = pending.pop(future)
                if future.cancelled():
                    continue
                outcome = future.result()
                if outcome is not None:
                    results.append(outcome)
                if progress_callback is not None:
                    progress_callback(device, port, outcome)

            if cancel_event is not None and cancel_event.is_set():
                for future in pending:
                    future.cancel()
                break
            for _ in range(len(completed)):
                if not submit_next():
                    break

    return sorted(results, key=lambda r: (ipaddress.ip_address(r.ip), r.port))
