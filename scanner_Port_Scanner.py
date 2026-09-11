import argparse
import ipaddress
import socket
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional, Sequence, Tuple

from scanner_Host_Discovery import (
    Device,
    discover_devices,
    print_devices,
)


# Fixed common-port profile. These are only service hints; actual
# service/version identification belongs in the fingerprinting module.
COMMON_TCP_PORTS = (
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    111,   # rpcbind
    135,   # MS RPC
    139,   # NetBIOS
    143,   # IMAP
    389,   # LDAP
    443,   # HTTPS
    445,   # SMB
    465,   # SMTPS
    587,   # SMTP submission
    636,   # LDAPS
    993,   # IMAPS
    995,   # POP3S
    1433,  # Microsoft SQL Server
    1521,  # Oracle
    2049,  # NFS
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8000,  # Alternate HTTP / development server
    8008,  # Alternate HTTP
    8080,  # Alternate HTTP
    8081,  # Alternate HTTP
    8443,  # Alternate HTTPS
    8888,  # Alternate HTTP / notebook servers
    9000,  # Common application/admin port
    9090,  # Common application/admin port
    9200,  # Elasticsearch
    9300,  # Elasticsearch transport
)

# Smart mode begins with a broader high-probability set. It is intentionally
# much smaller than 1-65535, but includes ports frequently exposed by local
# infrastructure, development tools, remote administration, databases, and
# web applications.
SMART_BASE_PORTS = tuple(sorted(set(COMMON_TCP_PORTS + (
    20, 26, 37, 42, 49, 67, 68, 69, 79, 81, 88, 102, 113, 119, 123,
    161, 162, 179, 199, 264, 427, 444, 500, 512, 513, 514, 515, 548,
    554, 623, 631, 873, 902, 1080, 1099, 1194, 1883, 2222, 2375, 2376,
    3000, 3128, 3268, 3269, 5000, 5001, 5357, 5601, 5672, 5985, 5986,
    6443, 7001, 7002, 8009, 8088, 8181, 8300, 8500, 8883, 9042, 9092,
    9443, 10000, 11211, 15672, 27017, 27018, 28017, 32400, 50000,
))))

# If a service family is found, smart mode checks additional ports commonly
# associated with that family. This is discovery guidance, not a claim that
# those ports run a particular service.
RELATED_PORT_GROUPS = (
    (
        {80, 81, 443, 8000, 8008, 8080, 8081, 8088, 8181, 8443, 8888, 9000, 9090, 9443},
        {3000, 3001, 4000, 4200, 5000, 5001, 7001, 7002, 8001, 8002, 8009,
         8082, 8083, 8084, 8085, 8086, 8090, 8091, 8180, 8280, 8880, 9001,
         9002, 9091, 9443, 10000},
    ),
    (
        {22, 23, 3389, 5900},
        {2200, 2222, 5901, 5902, 5985, 5986},
    ),
    (
        {135, 139, 445, 3389},
        {593, 2179, 5985, 5986, 47001},
    ),
    (
        {25, 110, 143, 465, 587, 993, 995},
        {4190, 2525, 8025},
    ),
    (
        {1433, 1521, 3306, 5432, 6379, 9042, 9200, 9300, 11211, 27017},
        {1434, 1522, 33060, 5433, 6380, 9160, 27018, 27019, 28017},
    ),
    (
        {2375, 2376, 6443},
        {10250, 10255, 30000},
    ),
)

SMART_FALLBACK_PORTS = tuple(range(1, 1025))


@dataclass(frozen=True)
class PortResult:
    ip: str
    mac: str
    port: int
    protocol: str
    state: str
    service_hint: str
    scanned_at: str


def parse_ports(spec: Optional[str]) -> List[int]:
    """
    Convert a CLI port specification into a sorted list of TCP ports.

    Supported forms:
      None / smart    -> smart-mode base profile
      all             -> full TCP range (1-65535)
      common          -> predefined common-port profile
      22
      22,80,443
      1-1024
      22,80,443,8000-8100
    """
    if spec is None:
        return list(SMART_BASE_PORTS)

    normalized = spec.strip().lower()

    if normalized == "smart":
        return list(SMART_BASE_PORTS)

    if normalized == "all":
        return list(range(1, 65536))

    if normalized == "common":
        return list(COMMON_TCP_PORTS)

    ports = set()

    for token in spec.split(","):
        token = token.strip()

        if not token:
            continue

        if "-" in token:
            start_text, end_text = token.split("-", 1)

            try:
                start = int(start_text)
                end = int(end_text)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(
                    f"Invalid port range: {token}"
                ) from exc

            if start > end:
                raise argparse.ArgumentTypeError(
                    f"Port range start must be <= end: {token}"
                )

            if start < 1 or end > 65535:
                raise argparse.ArgumentTypeError(
                    f"Ports must be between 1 and 65535: {token}"
                )

            ports.update(range(start, end + 1))

        else:
            try:
                port = int(token)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(
                    f"Invalid port: {token}"
                ) from exc

            if port < 1 or port > 65535:
                raise argparse.ArgumentTypeError(
                    f"Port must be between 1 and 65535: {port}"
                )

            ports.add(port)

    if not ports:
        raise argparse.ArgumentTypeError("At least one TCP port is required.")

    return sorted(ports)


def service_hint(port: int) -> str:
    """
    Return the operating system's well-known TCP service name for a port.

    This is not fingerprinting. A process listening on port 80 is not
    guaranteed to be HTTP, so later scanner stages should verify the service.
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_tcp_port(
    device: Device,
    port: int,
    timeout: float,
) -> Optional[PortResult]:
    """
    Perform a TCP connect scan against one discovered host/port pair.

    Returns a PortResult only when the TCP connection succeeds. Closed,
    filtered, and unreachable endpoints are omitted from the open-port list.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((device.ip, port))

        if result != 0:
            return None

        return PortResult(
            ip=device.ip,
            mac=device.mac,
            port=port,
            protocol="tcp",
            state="open",
            service_hint=service_hint(port),
            scanned_at=datetime.now().isoformat(timespec="seconds"),
        )

    except (OSError, ValueError):
        return None

    finally:
        sock.close()


def _targets(
    devices: Sequence[Device],
    ports: Sequence[int],
) -> Iterable[Tuple[Device, int]]:
    for device in devices:
        for port in ports:
            yield device, port


def _scan_targets(
    targets: Iterable[Tuple[Device, int]],
    timeout: float,
    workers: int,
) -> List[PortResult]:
    """Scan an arbitrary stream of host/port targets with bounded concurrency."""
    if timeout <= 0:
        raise ValueError("timeout must be greater than 0")

    if workers < 1:
        raise ValueError("workers must be at least 1")

    if workers > 512:
        raise ValueError("workers may not exceed 512")

    open_ports: List[PortResult] = []
    target_iter = iter(targets)
    queue_limit = max(workers * 4, workers)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = set()

        def submit_next() -> bool:
            try:
                device, port = next(target_iter)
            except StopIteration:
                return False

            pending.add(
                executor.submit(scan_tcp_port, device, port, timeout)
            )
            return True

        for _ in range(queue_limit):
            if not submit_next():
                break

        while pending:
            completed, pending = wait(
                pending,
                return_when=FIRST_COMPLETED,
            )

            for future in completed:
                result = future.result()

                if result is not None:
                    open_ports.append(result)

            for _ in range(len(completed)):
                if not submit_next():
                    break

    return sorted(
        open_ports,
        key=lambda result: (
            ipaddress.ip_address(result.ip),
            result.port,
        ),
    )


def scan_open_ports(
    devices: Sequence[Device],
    ports: Sequence[int],
    timeout: float = 0.35,
    workers: int = 100,
) -> List[PortResult]:
    """Scan the same requested TCP port set across all discovered devices."""
    if not devices or not ports:
        return []

    return _scan_targets(
        _targets(devices, ports),
        timeout=timeout,
        workers=workers,
    )


def related_ports_for(open_ports: Sequence[int]) -> List[int]:
    """Choose additional TCP ports based on service families already exposed."""
    discovered = set(open_ports)
    related = set()

    for triggers, candidates in RELATED_PORT_GROUPS:
        if discovered.intersection(triggers):
            related.update(candidates)

    related.difference_update(discovered)
    related.difference_update(SMART_BASE_PORTS)
    return sorted(related)


def smart_scan_open_ports(
    devices: Sequence[Device],
    timeout: float = 0.35,
    workers: int = 100,
) -> List[PortResult]:
    """
    Adaptively discover likely open TCP services without scanning all 65,535 ports.

    Stage 1 scans a broad high-probability set on every host.
    Stage 2 is per-host:
      * if Stage 1 found services, scan related service-family ports;
      * if Stage 1 found nothing, fall back to the privileged range 1-1024.

    This is intentionally faster than a full scan and therefore cannot
    guarantee discovery of an arbitrary service on an unusual high port.
    Use ``--ports all`` when exhaustive coverage is required.
    """
    if not devices:
        return []

    print(
        f"[*] Smart scan : stage 1 checks {len(SMART_BASE_PORTS)} "
        f"high-probability TCP ports per host"
    )

    stage_one = scan_open_ports(
        devices=devices,
        ports=SMART_BASE_PORTS,
        timeout=timeout,
        workers=workers,
    )

    open_by_ip = {}
    for result in stage_one:
        open_by_ip.setdefault(result.ip, set()).add(result.port)

    stage_two_targets = []
    stage_two_counts = {}

    for device in devices:
        discovered = sorted(open_by_ip.get(device.ip, set()))

        if discovered:
            candidate_ports = related_ports_for(discovered)
            reason = "related"
        else:
            candidate_ports = sorted(
                set(SMART_FALLBACK_PORTS).difference(SMART_BASE_PORTS)
            )
            reason = "fallback"

        stage_two_counts[device.ip] = (reason, len(candidate_ports))
        stage_two_targets.extend((device, port) for port in candidate_ports)

    related_hosts = sum(
        1 for reason, count in stage_two_counts.values()
        if reason == "related" and count
    )
    fallback_hosts = sum(
        1 for reason, count in stage_two_counts.values()
        if reason == "fallback" and count
    )

    if stage_two_targets:
        print(
            f"[*] Smart scan : stage 2 expands {related_hosts} host(s) by "
            f"service family and checks 1-1024 on {fallback_hosts} host(s) "
            f"with no stage-1 hits"
        )
        stage_two = _scan_targets(
            stage_two_targets,
            timeout=timeout,
            workers=workers,
        )
    else:
        stage_two = []

    deduplicated = {}
    for result in stage_one + stage_two:
        deduplicated[(result.ip, result.port, result.protocol)] = result

    return sorted(
        deduplicated.values(),
        key=lambda result: (
            ipaddress.ip_address(result.ip),
            result.port,
        ),
    )


def discover_hosts(
    requested_network: Optional[str] = None,
    passive_only: bool = False,
) -> Tuple[List[Device], object, str, str, str]:
    """
    Reuse the shared host-discovery pipeline before TCP port scanning.

    Returns:
        devices, interface, local_ip, gateway, discovery_network

    ``include_local=True`` is intentional: ARP discovery generally does not
    return the scanning host itself, but local listeners should still be
    visible to the TCP scan.
    """
    devices, context, discovery_network = discover_devices(
        requested_network=requested_network,
        passive_only=passive_only,
        include_local=True,
    )

    return (
        devices,
        context.interface,
        context.local_ip,
        context.gateway,
        discovery_network,
    )

def print_port_results(
    devices: Sequence[Device],
    results: Sequence[PortResult],
) -> None:
    print()
    print(
        f"{'IP ADDRESS':<18} "
        f"{'PORT':<8} "
        f"{'PROTO':<7} "
        f"{'STATE':<8} "
        f"{'SERVICE HINT'}"
    )
    print("-" * 72)

    if not results:
        print("No open TCP ports found in the requested port set.")
    else:
        for result in results:
            print(
                f"{result.ip:<18} "
                f"{result.port:<8} "
                f"{result.protocol:<7} "
                f"{result.state:<8} "
                f"{result.service_hint}"
            )

    print()
    print(f"Scanned {len(devices)} discovered host(s).")
    print(f"Found {len(results)} open TCP port(s).")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Discover hosts on an authorized local IPv4 network and scan "
            "selected TCP ports on those discovered hosts."
        )
    )

    parser.add_argument(
        "--network",
        help="Authorized IPv4 CIDR to discover, e.g. 192.168.1.0/24",
    )

    parser.add_argument(
        "--passive-only",
        action="store_true",
        help=(
            "Use only hosts already present in the OS neighbor table; "
            "do not send ARP discovery requests."
        ),
    )

    parser.add_argument(
        "--ports",
        default=None,
        help=(
            "TCP scan mode or explicit ports. If omitted, uses smart adaptive "
            "discovery. Use 'smart' explicitly for the same behavior, 'common' "
            "for the fixed common-port profile, 'all' for 1-65535, or values "
            "such as 22,80,443,8000-8100."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.35,
        help="TCP connection timeout in seconds per port (default: 0.35)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Maximum concurrent TCP connection attempts (default: 100)",
    )

    args = parser.parse_args()

    normalized_port_spec = (args.ports or "smart").strip().lower()
    smart_mode = normalized_port_spec == "smart"

    try:
        ports = None if smart_mode else parse_ports(args.ports)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

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
        print("[!] No hosts were discovered; skipping port scan.")
        return

    try:
        if smart_mode:
            print(
                f"[*] TCP scan  : smart adaptive discovery across "
                f"{len(devices)} host(s)"
            )
            results = smart_scan_open_ports(
                devices=devices,
                timeout=args.timeout,
                workers=args.workers,
            )
        else:
            print(
                f"[*] TCP scan  : {len(ports)} port(s) across "
                f"{len(devices)} host(s)"
            )
            results = scan_open_ports(
                devices=devices,
                ports=ports,
                timeout=args.timeout,
                workers=args.workers,
            )
    except ValueError as exc:
        parser.error(str(exc))

    print_port_results(devices, results)


if __name__ == "__main__":
    main()
