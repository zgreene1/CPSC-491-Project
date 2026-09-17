"""Target and network validation logic for discovery and scanning."""

import ipaddress
from typing import Optional

MAX_ARP_ADDRESSES = 1024
FALLBACK_PREFIX = 24


def validate_scan_network(
    network: str,
    max_addresses: int = MAX_ARP_ADDRESSES,
) -> ipaddress.IPv4Network:
    """Validate that the target is a supported IPv4 subnet within scan bounds."""
    if max_addresses < 1:
        raise ValueError("max_addresses must be at least 1")

    try:
        parsed = ipaddress.ip_network(network, strict=False)
    except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise ValueError(f"Invalid network CIDR '{network}': {exc}") from exc

    if parsed.version != 4:
        raise ValueError("Only IPv4 ARP discovery is supported.")

    if parsed.num_addresses > max_addresses:
        raise ValueError(
            f"Refusing to ARP-scan {parsed.num_addresses} addresses. "
            f"Choose a subnet with at most {max_addresses} addresses."
        )

    return parsed


def validate_local_target(
    target_network: ipaddress.IPv4Network,
    local_network: str,
) -> ipaddress.IPv4Network:
    """
    Ensure the target subnet is wholly contained within the local L2 network.

    ARP discovery packets cannot cross Layer-3 router boundaries.
    """
    try:
        local = ipaddress.ip_network(local_network, strict=False)
    except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise ValueError(f"Invalid local network '{local_network}': {exc}") from exc

    if local.version != 4:
        raise ValueError("Local network must be IPv4.")

    if not target_network.subnet_of(local):
        raise ValueError(
            f"Target {target_network} is outside the local network {local}."
        )

    return target_network


def choose_scan_network(
    local_ip: str,
    requested_network: Optional[str] = None,
    detected_network: Optional[str] = None,
    max_addresses: int = MAX_ARP_ADDRESSES,
    fallback_prefix: int = FALLBACK_PREFIX,
) -> str:
    """
    Select a bounded IPv4 network for ARP discovery.

    Honors explicit targets after bounds and local-scope validation. Otherwise,
    uses the detected subnet if safe, falling back to a local /24.
    """
    if not 0 <= fallback_prefix <= 32:
        raise ValueError("fallback_prefix must be between 0 and 32")

    if requested_network:
        target = validate_scan_network(requested_network, max_addresses=max_addresses)
        if detected_network:
            validate_local_target(target, detected_network)
        return str(target)

    if detected_network:
        try:
            detected = ipaddress.ip_network(detected_network, strict=False)
            local_address = ipaddress.IPv4Address(local_ip)
            if (
                detected.version == 4
                and local_address in detected
                and detected.num_addresses <= max_addresses
            ):
                return str(detected)
        except (ValueError, ipaddress.AddressValueError):
            pass

    fallback = ipaddress.ip_network(
        f"{local_ip}/{fallback_prefix}",
        strict=False,
    )
    return str(fallback)