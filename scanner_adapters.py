"""Adapters between scanner-internal objects and shared scanner contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from scanner_Host_Discovery import Device
from scanner_Port_Scanner import PortResult
from scanner_Service_Fingerprint import ServiceFingerprint
from scanner_contracts import HostObservation, PortObservation


def _contract_mac(mac: Optional[str]) -> Optional[str]:
    """Convert internal sentinel/empty MAC values to contract-friendly nulls."""
    if mac is None:
        return None
    normalized = str(mac).strip()
    if not normalized or normalized.lower() in {"local", "unknown", "none"}:
        return None
    return normalized


def device_to_host_observation(device: Device) -> HostObservation:
    """Convert host-discovery output into the shared host contract."""
    source = device.source or "unknown"
    status = "manual" if "manual_target" in source.split("+") else "discovered"
    return HostObservation(
        ip=device.ip,
        hostname=None,
        mac=_contract_mac(device.mac),
        discovery_source=source,
        discovery_status=status,
        last_seen=device.last_seen or None,
        metadata=None,
    )


def host_observation_to_device(host: HostObservation) -> Device:
    """Adapt a normalized host back to the low-level TCP scanner input."""
    return Device(
        ip=host.ip,
        mac=host.mac,
        source=host.discovery_source,
        last_seen=host.last_seen or datetime.now().isoformat(timespec="seconds"),
    )


def port_result_to_port_observation(result: PortResult) -> PortObservation:
    """Convert TCP port-discovery output into the shared port contract."""
    return PortObservation(
        host_ip=result.ip,
        host_mac=_contract_mac(result.mac),
        port=result.port,
        protocol=result.protocol,
        state=result.state,
        service_hint=result.service_hint or None,
        service=None,
        product=None,
        version=None,
        banner=None,
        confidence=None,
        observed_at=result.scanned_at or None,
    )


def apply_service_fingerprint(
    observation: PortObservation,
    fingerprint: ServiceFingerprint,
) -> PortObservation:
    """Return a port observation enriched by one service fingerprint result."""
    if (
        observation.host_ip != fingerprint.ip
        or observation.port != fingerprint.port
        or observation.protocol != fingerprint.protocol
    ):
        raise ValueError("Fingerprint does not match the supplied port observation.")

    return PortObservation(
        host_ip=observation.host_ip,
        host_mac=observation.host_mac,
        port=observation.port,
        protocol=observation.protocol,
        state=observation.state,
        service_hint=observation.service_hint,
        service=fingerprint.service or None,
        product=fingerprint.product,
        version=fingerprint.version,
        banner=fingerprint.banner,
        confidence=fingerprint.confidence,
        observed_at=observation.observed_at,
    )
