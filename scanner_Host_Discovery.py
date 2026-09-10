import argparse
import ipaddress
import platform
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime

from scapy.all import ARP, Ether, conf, srp


@dataclass
class Device:
    ip: str
    mac: str
    source: str
    last_seen: str


def normalize_mac(mac: str) -> str:
    return mac.lower().replace("-", ":")


def get_active_interface():
    """
    Ask Scapy which interface it would use to reach the Internet.
    Returns:
        interface name
        local IPv4 address
        gateway
    """
    interface, local_ip, gateway = conf.route.route("8.8.8.8")

    return interface, local_ip, gateway


def get_neighbor_table():
    """
    Read the OS ARP/neighbor table.

    Supports:
      Linux:   ip neigh
      macOS:   arp -an
      Windows: arp -a
    """

    devices = []
    system = platform.system()

    try:
        if system == "Linux":
            output = subprocess.check_output(
                ["ip", "neigh"],
                text=True,
                stderr=subprocess.DEVNULL
            )

            # Example:
            # 192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            pattern = re.compile(
                r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-fA-F:]{17})"
            )

        elif system == "Darwin":
            output = subprocess.check_output(
                ["arp", "-an"],
                text=True,
                stderr=subprocess.DEVNULL
            )

            # Example:
            # ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0
            pattern = re.compile(
                r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})"
            )

        elif system == "Windows":
            output = subprocess.check_output(
                ["arp", "-a"],
                text=True,
                stderr=subprocess.DEVNULL
            )

            # Example:
            # 192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic
            pattern = re.compile(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})"
            )

        else:
            print(f"[!] Unsupported OS: {system}")
            return []

        now = datetime.now().isoformat(timespec="seconds")

        for ip, mac in pattern.findall(output):
            devices.append(
                Device(
                    ip=ip,
                    mac=normalize_mac(mac),
                    source="neighbor_table",
                    last_seen=now
                )
            )

    except Exception as exc:
        print(f"[!] Could not read neighbor table: {exc}")

    return devices


def arp_scan(network: str, interface: str):
    """
    Perform an ARP request against the supplied IPv4 network.
    """

    print(f"[*] ARP discovery on {network}")

    arp_request = ARP(pdst=network)
    ethernet = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ethernet / arp_request

    answered, _ = srp(
        packet,
        iface=interface,
        timeout=2,
        retry=0,
        verbose=False
    )

    devices = []
    now = datetime.now().isoformat(timespec="seconds")

    for _, response in answered:
        devices.append(
            Device(
                ip=response.psrc,
                mac=normalize_mac(response.hwsrc),
                source="arp_scan",
                last_seen=now
            )
        )

    return devices

def get_interface_network(interface: str) -> str:
    output = subprocess.check_output(
        ["ip", "-4", "addr", "show", "dev", interface],
        text=True
    )

    match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", output)

    if not match:
        raise RuntimeError("Could not determine IPv4 network")

    ip = match.group(1)
    prefix = match.group(2)

    network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)

    return str(network)

def merge_devices(*device_lists):
    """
    Merge devices primarily using MAC address.

    If a device appears in both the OS table and Scapy discovery,
    the source is changed to indicate both.
    """

    merged = {}

    for device_list in device_lists:
        for device in device_list:

            key = device.mac

            if key in merged:
                existing = merged[key]

                existing.ip = device.ip
                existing.last_seen = device.last_seen

                sources = set(existing.source.split("+"))
                sources.add(device.source)

                existing.source = "+".join(sorted(sources))

            else:
                merged[key] = device

    return list(merged.values())


def choose_scan_network(local_ip: str, requested_network=None):
    """
    By default, only scan the /24 containing the local IP.

    This is intentionally conservative because a public network may
    advertise something much larger, such as a /16.
    """

    if requested_network:
        network = ipaddress.ip_network(requested_network, strict=False)

        if network.version != 4:
            raise ValueError("Only IPv4 ARP discovery is supported.")

        if network.num_addresses > 1024:
            raise ValueError(
                f"Refusing to ARP-scan {network.num_addresses} addresses. "
                "Choose a smaller authorized subnet."
            )

        return str(network)

    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)

    return str(network)


def print_devices(devices):
    print()
    print(f"{'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'SOURCE'}")
    print("-" * 65)

    for device in sorted(
        devices,
        key=lambda d: ipaddress.ip_address(d.ip)
    ):
        print(
            f"{device.ip:<18} "
            f"{device.mac:<20} "
            f"{device.source}"
        )

    print()
    print(f"Discovered {len(devices)} device(s).")


def main():
    parser = argparse.ArgumentParser(
        description="Basic local network device discovery"
    )

    parser.add_argument(
        "--network",
        help="Authorized IPv4 CIDR to scan, e.g. 192.168.1.0/24"
    )

    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Only inspect the OS neighbor table; do not send ARP requests"
    )

    args = parser.parse_args()

    interface, local_ip, gateway = get_active_interface()

    print(f"[*] Interface : {interface}")
    print(f"[*] Local IP  : {local_ip}")
    print(f"[*] Gateway   : {gateway}")

    actual_network = get_interface_network(interface)

    print(f"[*] Network   : {actual_network}")

    neighbor_devices = get_neighbor_table()

    if args.passive_only:
        print_devices(neighbor_devices)
        return

    scan_network = args.network if args.network else actual_network

    arp_devices = arp_scan(
        scan_network,
        interface
    )

    devices = merge_devices(
        neighbor_devices,
        arp_devices
    )

    print_devices(devices)

if __name__ == "__main__":
    main()