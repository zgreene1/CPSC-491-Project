"""Normalize manual and discovered targets into shared HostObservation objects."""

from __future__ import annotations

import ipaddress
import socket
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from scanner_Host_Discovery import MAX_ARP_ADDRESSES
from scanner_contracts import HostObservation, ScannerError


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _merge_sources(left: str, right: str) -> str:
    sources = set(filter(None, left.split("+")))
    sources.update(filter(None, right.split("+")))
    return "+".join(sorted(sources))


def _merge_metadata(
    left: Optional[Dict[str, object]],
    right: Optional[Dict[str, object]],
) -> Optional[Dict[str, object]]:
    if not left and not right:
        return None
    merged: Dict[str, object] = {}
    if left:
        merged.update(left)
    if right:
        for key, value in right.items():
            if key not in merged:
                merged[key] = value
            elif merged[key] != value:
                existing = merged[key]
                if isinstance(existing, list):
                    values = list(existing)
                else:
                    values = [existing]
                if value not in values:
                    values.append(value)
                merged[key] = values
    return merged


def merge_host_observations(hosts: Iterable[HostObservation]) -> List[HostObservation]:
    """Deduplicate hosts by IPv4 address while preserving useful provenance."""
    merged: Dict[str, HostObservation] = {}

    for host in hosts:
        existing = merged.get(host.ip)
        if existing is None:
            merged[host.ip] = HostObservation(
                ip=host.ip,
                hostname=host.hostname,
                mac=host.mac,
                discovery_source=host.discovery_source,
                discovery_status=host.discovery_status,
                last_seen=host.last_seen,
                metadata=dict(host.metadata) if host.metadata else None,
            )
            continue

        source = _merge_sources(existing.discovery_source, host.discovery_source)
        statuses = {existing.discovery_status, host.discovery_status}
        if "discovered" in statuses:
            status = "discovered"
        elif "manual" in statuses:
            status = "manual"
        elif "unreachable" in statuses:
            status = "unreachable"
        else:
            status = existing.discovery_status or host.discovery_status

        last_seen_values = [value for value in (existing.last_seen, host.last_seen) if value]
        last_seen = max(last_seen_values) if last_seen_values else None

        merged[host.ip] = HostObservation(
            ip=host.ip,
            hostname=existing.hostname or host.hostname,
            mac=existing.mac or host.mac,
            discovery_source=source,
            discovery_status=status,
            last_seen=last_seen,
            metadata=_merge_metadata(existing.metadata, host.metadata),
        )

    return sorted(merged.values(), key=lambda item: ipaddress.ip_address(item.ip))


def _manual_host(
    ip: str,
    original_target: str,
    hostname: Optional[str] = None,
) -> HostObservation:
    return HostObservation(
        ip=ip,
        hostname=hostname,
        mac=None,
        discovery_source="manual_target",
        discovery_status="manual",
        last_seen=_now(),
        metadata={"input_target": original_target},
    )


def _expand_manual_target(target: str) -> Tuple[List[HostObservation], List[ScannerError]]:
    target = target.strip()
    if not target:
        return [], [
            ScannerError(
                code="INVALID_TARGET",
                message="Empty scan target was ignored.",
                stage="configuration",
                details={"target": target},
                recoverable=True,
            )
        ]

    # Direct IPv4 target.
    try:
        address = ipaddress.ip_address(target)
        if address.version != 4:
            raise ValueError("Only IPv4 targets are currently supported.")
        return [_manual_host(str(address), target)], []
    except ValueError:
        pass

    # CIDR target. Keep the same bounded-network safety policy used by ARP discovery.
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.version != 4:
                raise ValueError("Only IPv4 target networks are currently supported.")
            if network.num_addresses > MAX_ARP_ADDRESSES:
                raise ValueError(
                    f"Target network contains {network.num_addresses} addresses; "
                    f"maximum supported size is {MAX_ARP_ADDRESSES}."
                )
            return [
                _manual_host(str(address), target)
                for address in network.hosts()
            ], []
        except ValueError as exc:
            return [], [
                ScannerError(
                    code="INVALID_TARGET",
                    message=f"Invalid target network {target!r}: {exc}",
                    stage="configuration",
                    details={"target": target},
                    recoverable=True,
                )
            ]

    # Hostname target. Resolve with the Python socket API for Linux/Windows/macOS parity.
    try:
        resolved = socket.getaddrinfo(
            target,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        return [], [
            ScannerError(
                code="INVALID_TARGET",
                message=f"Could not resolve target hostname {target!r}.",
                stage="configuration",
                details={"target": target, "reason": str(exc)},
                recoverable=True,
            )
        ]

    addresses = sorted({item[4][0] for item in resolved}, key=ipaddress.ip_address)
    if not addresses:
        return [], [
            ScannerError(
                code="INVALID_TARGET",
                message=f"Target hostname {target!r} did not resolve to IPv4.",
                stage="configuration",
                details={"target": target},
                recoverable=True,
            )
        ]

    return [_manual_host(ip, target, hostname=target) for ip in addresses], []


def normalize_targets(
    manual_targets: Sequence[str],
    discovered_hosts: Sequence[HostObservation] = (),
) -> Tuple[List[HostObservation], List[ScannerError]]:
    """Combine discovery output and user targets into one deduplicated host list."""
    hosts: List[HostObservation] = list(discovered_hosts)
    errors: List[ScannerError] = []

    for target in manual_targets:
        normalized, target_errors = _expand_manual_target(str(target))
        hosts.extend(normalized)
        errors.extend(target_errors)

    return merge_host_observations(hosts), errors
