"""UDP port scanning and protocol probing module."""

import ipaddress
import socket
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple

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
    mac: str
    port: int
    protocol: str
    state: str
    service_hint: str
    scanned_at: str


def service_hint_udp(port: int) -> str:
    """Return the operating system well-known UDP service name."""
    try:
        return socket.getservbyport(port, "udp")
    except OSError:
        return "unknown"


def scan_udp_port(
    device: Device,
    port: int,
    timeout: float = 1.0,
) -> Optional[UDPPortResult]:
    """Probe a UDP port; return result only when an active response arrives."""
    probe = UDP_PROBES.get(port, b"\x00")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(probe, (device.ip, port))
            response, _ = sock.recvfrom(2048)

            if response:
                return UDPPortResult(
                    ip=device.ip,
                    mac=device.mac,
                    port=port,
                    protocol="udp",
                    state="open",
                    service_hint=service_hint_udp(port),
                    scanned_at=datetime.now().isoformat(timespec="seconds"),
                )
        except (socket.timeout, OSError):
            return None

    return None


def scan_udp_ports(
    devices: Sequence[Device],
    ports: Sequence[int],
    timeout: float = 1.0,
    workers: int = 30,
) -> List[UDPPortResult]:
    """Scan UDP ports across discovered devices with controlled worker limits."""
    if not devices or not ports:
        return []

    targets: List[Tuple[Device, int]] = [
        (device, port) for device in devices for port in ports
    ]

    open_ports: List[UDPPortResult] = []
    target_iter = iter(targets)
    queue_limit = max(workers * 2, workers)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = set()

        def submit_next() -> bool:
            try:
                device, port = next(target_iter)
            except StopIteration:
                return False
            pending.add(executor.submit(scan_udp_port, device, port, timeout))
            return True

        for _ in range(queue_limit):
            if not submit_next():
                break

        while pending:
            completed, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in completed:
                result = future.result()
                if result is not None:
                    open_ports.append(result)

            for _ in range(len(completed)):
                if not submit_next():
                    break

    return sorted(
        open_ports,
        key=lambda r: (ipaddress.ip_address(r.ip), r.port),
    )