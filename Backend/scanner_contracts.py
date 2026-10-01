"""Shared scanner data contracts for the CPSC 491 vulnerability scanner.

These models are the stable boundary between scanner internals and future
backend, frontend, persistence, and CVE-matching work.  They intentionally use
only JSON-compatible Python data types and do not expose sockets, Scapy
objects, subprocess results, or other platform-specific implementation details.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


KNOWN_SCAN_MODES = {"smart", "common", "custom", "all"}
MAX_SCAN_CONCURRENCY = 512


def _port_spec_validation_error(port_spec: str) -> Optional[str]:
    """Validate a TCP port expression without importing scanner internals.

    Keeping this parser in the contract layer lets invalid configuration be
    rejected before the coordinator starts scanner stages and avoids a circular
    dependency on ``scanner_Port_Scanner``.
    """
    normalized = port_spec.strip().lower()
    if not normalized:
        return None

    if normalized in {"smart", "common", "all"}:
        return None

    saw_port = False
    for token in port_spec.split(","):
        token = token.strip()
        if not token:
            continue

        if "-" in token:
            parts = token.split("-", 1)
            if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
                return f"Invalid port range: {token}"
            try:
                start = int(parts[0])
                end = int(parts[1])
            except ValueError:
                return f"Invalid port range: {token}"
            if start > end:
                return f"Port range start must be <= end: {token}"
            if start < 1 or end > 65535:
                return f"Ports must be between 1 and 65535: {token}"
            saw_port = True
        else:
            try:
                port = int(token)
            except ValueError:
                return f"Invalid port: {token}"
            if port < 1 or port > 65535:
                return f"Port must be between 1 and 65535: {port}"
            saw_port = True

    if not saw_port:
        return "At least one TCP port is required."
    return None


def _json_ready(value: Any) -> Any:
    """Recursively convert contract values into JSON-serializable data."""
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {
            field.name: _json_ready(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_ready(item) for item in value]
    return value


class JSONSerializable:
    """Mixin providing plain-data and JSON representations for contracts."""

    def to_dict(self) -> Dict[str, Any]:
        return _json_ready(self)

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), **kwargs)


class ScanLifecycleState(str, Enum):
    CREATED = "CREATED"
    DISCOVERING = "DISCOVERING"
    SCANNING = "SCANNING"
    IDENTIFYING = "IDENTIFYING"
    MATCHING = "MATCHING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass
class ScannerError(JSONSerializable):
    code: str
    message: str
    stage: str
    details: Optional[Dict[str, Any]] = None
    recoverable: bool = False


@dataclass
class ScanConfiguration(JSONSerializable):
    scan_id: Optional[str] = None
    targets: List[str] = field(default_factory=list)
    scan_mode: str = "smart"
    ports: List[int] = field(default_factory=list)
    port_spec: Optional[str] = None
    timeout_seconds: float = 1.0
    discovery_enabled: bool = True
    discovery_network: Optional[str] = None
    include_local_host: bool = True
    concurrency: int = 100
    created_at: Optional[str] = None

    def __post_init__(self) -> None:
        # Avoid mutable defaults while keeping the field declarations concise
        # and straightforward for consumers of the contract.
        self.targets = list(self.targets or [])
        self.ports = list(self.ports or [])

        if self.created_at is None:
            self.created_at = datetime.now().isoformat(timespec="seconds")

    def validation_errors(self) -> List[ScannerError]:
        """Return structured configuration errors without raising exceptions."""
        errors: List[ScannerError] = []
        mode = (
            self.scan_mode.strip().lower()
            if isinstance(self.scan_mode, str)
            else ""
        )
        port_spec_text = (
            self.port_spec.strip()
            if isinstance(self.port_spec, str)
            else ""
        )

        if not self.targets and not self.discovery_enabled:
            errors.append(
                ScannerError(
                    code="INVALID_CONFIGURATION",
                    message=(
                        "At least one manual target is required when host "
                        "discovery is disabled."
                    ),
                    stage="configuration",
                    recoverable=False,
                )
            )

        if mode not in KNOWN_SCAN_MODES:
            errors.append(
                ScannerError(
                    code="INVALID_CONFIGURATION",
                    message=f"Unsupported scan mode: {self.scan_mode!r}.",
                    stage="configuration",
                    details={"supported_modes": sorted(KNOWN_SCAN_MODES)},
                    recoverable=False,
                )
            )

        if self.discovery_network:
            try:
                network = ipaddress.ip_network(str(self.discovery_network), strict=False)
                if network.version != 4:
                    raise ValueError("only IPv4 discovery networks are supported")
            except ValueError as exc:
                errors.append(
                    ScannerError(
                        code="INVALID_CONFIGURATION",
                        message="Discovery network must be a valid IPv4 CIDR.",
                        stage="configuration",
                        details={
                            "discovery_network": self.discovery_network,
                            "reason": str(exc),
                        },
                        recoverable=False,
                    )
                )

        invalid_ports = [
            port
            for port in self.ports
            if not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535
        ]
        if invalid_ports:
            errors.append(
                ScannerError(
                    code="INVALID_CONFIGURATION",
                    message="All TCP ports must be integers between 1 and 65535.",
                    stage="configuration",
                    details={"invalid_ports": invalid_ports},
                    recoverable=False,
                )
            )

        if mode == "custom" and not self.ports and not port_spec_text:
            errors.append(
                ScannerError(
                    code="INVALID_CONFIGURATION",
                    message="Custom scan mode requires ports or a port specification.",
                    stage="configuration",
                    recoverable=False,
                )
            )

        if port_spec_text:
            port_spec_error = _port_spec_validation_error(port_spec_text)
            if port_spec_error is not None:
                errors.append(
                    ScannerError(
                        code="INVALID_CONFIGURATION",
                        message=port_spec_error,
                        stage="configuration",
                        details={"port_spec": self.port_spec},
                        recoverable=False,
                    )
                )

        timeout_valid = (
            isinstance(self.timeout_seconds, (int, float))
            and not isinstance(self.timeout_seconds, bool)
            and self.timeout_seconds > 0
        )
        if not timeout_valid:
            errors.append(
                ScannerError(
                    code="INVALID_CONFIGURATION",
                    message="Scan timeout must be a number greater than zero.",
                    stage="configuration",
                    details={"timeout_seconds": self.timeout_seconds},
                    recoverable=False,
                )
            )

        concurrency_valid = (
            isinstance(self.concurrency, int)
            and not isinstance(self.concurrency, bool)
            and 1 <= self.concurrency <= MAX_SCAN_CONCURRENCY
        )
        if not concurrency_valid:
            errors.append(
                ScannerError(
                    code="INVALID_CONFIGURATION",
                    message=(
                        f"Concurrency must be an integer between 1 and "
                        f"{MAX_SCAN_CONCURRENCY}."
                    ),
                    stage="configuration",
                    details={"concurrency": self.concurrency},
                    recoverable=False,
                )
            )

        return errors


@dataclass
class HostObservation(JSONSerializable):
    ip: str
    discovery_source: str
    discovery_status: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    last_seen: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class PortObservation(JSONSerializable):
    host_ip: str
    port: int
    protocol: str
    state: str
    host_mac: Optional[str] = None
    service_hint: Optional[str] = None
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    confidence: Optional[float] = None
    observed_at: Optional[str] = None


@dataclass
class ScanProgress(JSONSerializable):
    state: ScanLifecycleState
    scan_id: Optional[str] = None
    hosts_discovered: int = 0
    hosts_completed: int = 0
    ports_completed: int = 0
    total_ports: int = 0
    percent_complete: float = 0.0
    current_host: Optional[str] = None
    current_port: Optional[int] = None
    elapsed_seconds: float = 0.0
    cancellation_requested: bool = False


@dataclass
class ScanResult(JSONSerializable):
    configuration: ScanConfiguration
    state: ScanLifecycleState
    hosts: List[HostObservation]
    ports: List[PortObservation]
    progress: ScanProgress
    errors: List[ScannerError]
    scan_id: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

