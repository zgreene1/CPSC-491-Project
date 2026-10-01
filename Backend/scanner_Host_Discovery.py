import argparse
import ipaddress
import logging
import platform
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, List, Optional, Sequence, Tuple

from scapy.all import ARP, Ether, conf, srp


MAX_ARP_ADDRESSES = 1024
FALLBACK_PREFIX = 24
LOGGER = logging.getLogger(__name__)


@dataclass
class Device:
    ip: str
    mac: Optional[str]
    source: str
    last_seen: str


@dataclass(frozen=True)
class NetworkContext:
    """Cross-platform IPv4 context used by scanner discovery modules."""

    interface: Any
    local_ip: str
    gateway: str
    network: str


def normalize_mac(mac: str) -> str:
    """Normalize MAC addresses to lowercase colon-separated form."""
    return mac.strip().lower().replace("-", ":")


def _interface_matches(left: Any, right: Any) -> bool:
    """Compare Scapy interface objects/names without assuming an OS type."""
    return left == right or str(left) == str(right)


def _as_ipv4(value: Any) -> ipaddress.IPv4Address:
    """Convert Scapy route-table IPv4 values (string or integer) safely."""
    if isinstance(value, int):
        return ipaddress.IPv4Address(value)
    return ipaddress.IPv4Address(str(value))


def _route_network(route: Sequence[Any]) -> ipaddress.IPv4Network:
    """Convert one Scapy IPv4 route tuple to an IPv4Network."""
    network_value = _as_ipv4(route[0])
    netmask_value = _as_ipv4(route[1])
    return ipaddress.IPv4Network(
        f"{network_value}/{netmask_value}",
        strict=False,
    )


def _is_direct_gateway(value: Any) -> bool:
    """Return True when a Scapy route represents a directly connected route."""
    try:
        return _as_ipv4(value) == ipaddress.IPv4Address("0.0.0.0")
    except (ipaddress.AddressValueError, ValueError):
        return str(value) in {"0", "0.0.0.0"}


def get_active_interface() -> Tuple[Any, str, str]:
    """
    Ask Scapy which interface it would use for a normal IPv4 route.

    Scapy populates its routing table using OS-specific backends on Linux,
    Windows, and BSD-derived systems such as macOS. Keeping this lookup in
    Scapy avoids parsing platform-specific route command output.
    """
    interface, local_ip, gateway = conf.route.route("8.8.8.8")

    local_ip = str(local_ip)
    gateway = str(gateway)

    try:
        ipaddress.IPv4Address(local_ip)
    except ipaddress.AddressValueError as exc:
        raise RuntimeError(
            f"Could not determine a usable local IPv4 address: {local_ip!r}"
        ) from exc

    return interface, local_ip, gateway


def get_interface_network(
    interface: Any,
    local_ip: Optional[str] = None,
) -> str:
    """
    Determine the directly connected IPv4 network from Scapy's route table.

    Scapy obtains its route table through OS-specific providers, so this path
    works across Linux, Windows, and macOS without parsing ``ip``, ``ifconfig``,
    or ``ipconfig`` output.
    """
    if local_ip is None:
        active_interface, local_ip, _ = get_active_interface()
        if not _interface_matches(interface, active_interface):
            # Search the requested interface's route entries, but do not use
            # the active interface's IP to select its subnet.
            local_ip = None

    local_address = (
        ipaddress.IPv4Address(local_ip) if local_ip is not None else None
    )

    candidates = []

    for route in conf.route.routes:
        if len(route) < 5:
            continue

        route_interface = route[3]
        if not _interface_matches(route_interface, interface):
            continue

        try:
            network = _route_network(route)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            continue

        route_output_ip = str(route[4])

        if local_address is not None:
            if local_address not in network:
                continue
            if route_output_ip not in {str(local_address), "0.0.0.0", "0"}:
                continue

        gateway = route[2] if len(route) > 2 else "0.0.0.0"
        metric = route[5] if len(route) > 5 else 0

        try:
            metric_value = int(metric)
        except (TypeError, ValueError):
            metric_value = 0

        # Prefer directly connected routes, then a real subnet over /0 or /32,
        # then the most specific subnet, then the lower route metric.
        rank = (
            1 if _is_direct_gateway(gateway) else 0,
            1 if 0 < network.prefixlen < 32 else 0,
            network.prefixlen,
            -metric_value,
        )
        candidates.append((rank, network))

    if not candidates:
        if local_address is None:
            raise RuntimeError(
                f"Could not determine an IPv4 network for interface {interface!s}"
            )

        # Route tables can be incomplete on VPN/tunnel configurations. Use a
        # conservative local /24 instead of an OS-specific command parser.
        return str(
            ipaddress.ip_network(
                f"{local_address}/{FALLBACK_PREFIX}",
                strict=False,
            )
        )

    _, selected_network = max(candidates, key=lambda item: item[0])
    return str(selected_network)


def get_network_context() -> NetworkContext:
    """Return active interface, local IPv4, gateway, and connected subnet."""
    interface, local_ip, gateway = get_active_interface()
    network = get_interface_network(interface, local_ip)
    return NetworkContext(
        interface=interface,
        local_ip=local_ip,
        gateway=gateway,
        network=network,
    )


def _run_first_available(commands: Iterable[Sequence[str]]) -> str:
    """Run the first available neighbor-table command that succeeds."""
    last_error: Optional[Exception] = None

    for command in commands:
        try:
            return subprocess.check_output(
                list(command),
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except (FileNotFoundError, subprocess.CalledProcessError, OSError) as exc:
            last_error = exc

    if last_error is not None:
        raise last_error

    raise RuntimeError("No neighbor-table command was configured")


def get_neighbor_table() -> List[Device]:
    """
    Read the OS ARP/IPv4 neighbor table.

    Linux prefers ``ip neigh`` and falls back to ``arp -an`` when available.
    macOS uses ``arp -an``. Windows uses ``arp -a``. Neighbor-cache access is
    intentionally isolated because command formats differ between platforms.

    Failure is non-fatal: active ARP discovery can still continue.
    """
    devices: List[Device] = []
    system = platform.system()

    try:
        if system == "Linux":
            try:
                output = _run_first_available((["ip", "neigh"],))
                pattern = re.compile(
                    r"(\d+\.\d+\.\d+\.\d+).*?lladdr\s+([0-9a-fA-F:]{17})"
                )
            except (FileNotFoundError, subprocess.CalledProcessError, OSError):
                output = _run_first_available((["arp", "-an"],))
                pattern = re.compile(
                    r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})"
                )

        elif system == "Darwin":
            output = _run_first_available((["arp", "-an"],))
            pattern = re.compile(
                r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})"
            )

        elif system == "Windows":
            output = _run_first_available((["arp", "-a"],))
            pattern = re.compile(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})"
            )

        else:
            LOGGER.warning("Unsupported OS neighbor-table lookup: %s", system)
            return []

        now = datetime.now().isoformat(timespec="seconds")

        for ip, mac in pattern.findall(output):
            try:
                ipaddress.IPv4Address(ip)
            except ipaddress.AddressValueError:
                continue

            devices.append(
                Device(
                    ip=ip,
                    mac=normalize_mac(mac),
                    source="neighbor_table",
                    last_seen=now,
                )
            )

    except (FileNotFoundError, subprocess.CalledProcessError, OSError) as exc:
        LOGGER.warning("Could not read neighbor table: %s", exc)

    return devices


def _validated_scan_network(network: str) -> ipaddress.IPv4Network:
    """Parse and enforce the bounded IPv4 ARP-scan policy."""
    parsed = ipaddress.ip_network(network, strict=False)

    if parsed.version != 4:
        raise ValueError("Only IPv4 ARP discovery is supported.")

    if parsed.num_addresses > MAX_ARP_ADDRESSES:
        raise ValueError(
            f"Refusing to ARP-scan {parsed.num_addresses} addresses. "
            f"Choose an authorized subnet with at most {MAX_ARP_ADDRESSES} addresses."
        )

    return parsed


def choose_scan_network(
    local_ip: str,
    requested_network: Optional[str] = None,
    detected_network: Optional[str] = None,
) -> str:
    """
    Select a bounded IPv4 network for ARP discovery.

    An explicit ``--network`` is honored after validation. Otherwise, the
    detected interface subnet is used when it is valid, contains the local IP,
    and is no larger than the configured safety bound. Larger or unusable
    detected networks fall back to the local /24.
    """
    if requested_network:
        return str(_validated_scan_network(requested_network))

    if detected_network:
        try:
            detected = ipaddress.ip_network(detected_network, strict=False)
            local_address = ipaddress.IPv4Address(local_ip)
            if (
                detected.version == 4
                and local_address in detected
                and detected.num_addresses <= MAX_ARP_ADDRESSES
            ):
                return str(detected)
        except (ValueError, ipaddress.AddressValueError):
            pass

    fallback = ipaddress.ip_network(
        f"{local_ip}/{FALLBACK_PREFIX}",
        strict=False,
    )
    return str(fallback)


def filter_devices_to_network(
    devices: Sequence[Device],
    network: str,
) -> List[Device]:
    """Keep neighbor-table entries that belong to the selected scan network."""
    parsed_network = ipaddress.ip_network(network, strict=False)
    filtered: List[Device] = []

    for device in devices:
        try:
            address = ipaddress.ip_address(device.ip)
        except ValueError:
            continue

        if address.version == 4 and address in parsed_network:
            filtered.append(device)

    return filtered


def arp_scan(network: str, interface: Any) -> List[Device]:
    """Perform a bounded ARP request sweep against an authorized IPv4 network."""
    parsed_network = _validated_scan_network(network)
    scan_network = str(parsed_network)

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=scan_network)

    answered, _ = srp(
        packet,
        iface=interface,
        timeout=2,
        retry=0,
        verbose=False,
    )

    devices: List[Device] = []
    now = datetime.now().isoformat(timespec="seconds")

    for _, response in answered:
        devices.append(
            Device(
                ip=response.psrc,
                mac=normalize_mac(response.hwsrc),
                source="arp_scan",
                last_seen=now,
            )
        )

    return devices


def _merge_sources(left: str, right: str) -> str:
    """Combine source labels into a deterministic ``+``-separated value."""
    sources = set(left.split("+"))
    sources.update(right.split("+"))
    return "+".join(sorted(source for source in sources if source))


def merge_devices(*device_lists: Sequence[Device]) -> List[Device]:
    """
    Normalize and merge duplicate device observations, primarily by MAC.

    Source labels are combined so downstream modules can distinguish passive
    neighbor-table evidence from active ARP responses.
    """
    merged = {}

    for device_list in device_lists:
        for device in device_list:
            normalized_mac = normalize_mac(device.mac) if device.mac else None
            # ARP/neighbor observations normally have a MAC address.  Fall back
            # to IPv4 identity for local/manual-style observations where a MAC
            # is legitimately unknown.
            key = (
                f"mac:{normalized_mac}"
                if normalized_mac
                else f"ip:{device.ip}"
            )

            if key in merged:
                existing = merged[key]
                existing.ip = device.ip
                existing.last_seen = device.last_seen
                existing.source = _merge_sources(existing.source, device.source)
            else:
                # Copy the observation so callers' Device objects are not
                # unexpectedly mutated by normalization/merging.
                merged[key] = Device(
                    ip=device.ip,
                    mac=normalized_mac,
                    source=device.source,
                    last_seen=device.last_seen,
                )

    return list(merged.values())


def ensure_local_device(
    devices: List[Device],
    local_ip: str,
) -> List[Device]:
    """Ensure the scanner host itself can be included in later TCP scanning."""
    if not any(device.ip == local_ip for device in devices):
        devices.append(
            Device(
                ip=local_ip,
                mac=None,
                source="local_interface",
                last_seen=datetime.now().isoformat(timespec="seconds"),
            )
        )
    return devices


def discover_devices(
    requested_network: Optional[str] = None,
    passive_only: bool = False,
    include_local: bool = False,
) -> Tuple[List[Device], NetworkContext, str]:
    """
    Run the shared host-discovery pipeline.

    Returns ``(devices, network_context, discovery_network)``. Port scanning and
    future modules should call this function rather than duplicating discovery.

    Neighbor-table lookup and active ARP discovery are best-effort evidence
    sources. If active ARP discovery fails after the network has been validated,
    the function keeps any usable neighbor-table observations instead of losing
    the entire discovery result.
    """
    context = get_network_context()
    discovery_network = choose_scan_network(
        local_ip=context.local_ip,
        requested_network=requested_network,
        detected_network=context.network,
    )

    neighbor_devices = filter_devices_to_network(
        get_neighbor_table(),
        discovery_network,
    )

    if passive_only:
        devices = neighbor_devices
    else:
        try:
            arp_devices = arp_scan(discovery_network, context.interface)
        except Exception as exc:
            # Scapy raises different backend exceptions across operating systems
            # for permission/adapter failures. Preserve passive evidence rather
            # than discarding already discovered hosts.
            LOGGER.warning(
                "Active ARP discovery failed; using neighbor-table results: %s",
                exc,
            )
            arp_devices = []

        devices = merge_devices(neighbor_devices, arp_devices)

    if include_local:
        devices = ensure_local_device(devices, context.local_ip)

    return devices, context, discovery_network


def print_devices(devices: Sequence[Device]) -> None:
    """Print discovery results for the standalone command-line interface."""
    print()
    print(f"{'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'SOURCE'}")
    print("-" * 65)

    for device in sorted(
        devices,
        key=lambda d: ipaddress.ip_address(d.ip),
    ):
        mac = device.mac or "unknown"
        print(
            f"{device.ip:<18} "
            f"{mac:<20} "
            f"{device.source}"
        )

    print()
    print(f"Discovered {len(devices)} device(s).")


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the standalone CLI parser without coupling it to discovery logic."""
    parser = argparse.ArgumentParser(
        description="Cross-platform local IPv4 device discovery"
    )

    parser.add_argument(
        "--network",
        help=(
            "Authorized IPv4 CIDR to scan, e.g. 192.168.1.0/24. "
            f"Maximum {MAX_ARP_ADDRESSES} addresses."
        ),
    )

    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Only inspect the OS neighbor table; do not send ARP requests",
    )

    parser.add_argument(
        "--include-local",
        action="store_true",
        help="Include the scanner host itself in the returned device list",
    )

    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        devices, context, discovery_network = discover_devices(
            requested_network=args.network,
            passive_only=args.passive_only,
            include_local=args.include_local,
        )
    except (RuntimeError, ValueError, OSError) as exc:
        parser.error(f"Host discovery failed: {exc}")

    print(f"[*] Interface : {context.interface}")
    print(f"[*] Local IP  : {context.local_ip}")
    print(f"[*] Gateway   : {context.gateway}")
    print(f"[*] Interface network : {context.network}")
    print(f"[*] Discovery network : {discovery_network}")

    print_devices(devices)


if __name__ == "__main__":
    main()
