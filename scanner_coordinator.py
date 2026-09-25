"""Sprint 2 scanner orchestration layer.

The coordinator keeps existing discovery, TCP scanning, and service
fingerprinting modules independent while exposing one contract-based pipeline:

    configuration -> discovery -> normalization -> TCP scan -> identification
                  -> aggregation

The module uses cooperative cancellation and standard-library synchronization,
so the orchestration behavior remains portable across Linux, Windows, and
macOS.
"""

from __future__ import annotations

import argparse
import copy
import time
import uuid
from dataclasses import replace
from datetime import datetime
from threading import Event, Lock
from typing import Dict, List, Optional, Sequence, Set, Tuple

from scanner_Host_Discovery import NetworkContext, discover_devices
from scanner_Port_Scanner import (
    COMMON_TCP_PORTS,
    PortResult,
    parse_ports,
    scan_open_ports,
    smart_scan_open_ports,
)
from scanner_Service_Fingerprint import (
    DEFAULT_FINGERPRINT_TIMEOUT,
    DEFAULT_FINGERPRINT_WORKERS,
    MAX_FINGERPRINT_WORKERS,
    ServiceFingerprint,
    fingerprint_services,
)
from scanner_adapters import (
    apply_service_fingerprint,
    device_to_host_observation,
    host_observation_to_device,
    port_result_to_port_observation,
)
from scanner_contracts import (
    HostObservation,
    PortObservation,
    ScanConfiguration,
    ScanLifecycleState,
    ScanProgress,
    ScanResult,
    ScannerError,
)
from scanner_target_normalizer import normalize_targets


class ScannerCoordinator:
    """Coordinate one scanner pipeline while preserving low-level modules."""

    def __init__(
        self,
        *,
        identify_services: bool = True,
        fingerprint_timeout: float = DEFAULT_FINGERPRINT_TIMEOUT,
        fingerprint_workers: int = DEFAULT_FINGERPRINT_WORKERS,
    ) -> None:
        if fingerprint_timeout <= 0:
            raise ValueError("fingerprint timeout must be greater than 0")
        if fingerprint_workers < 1 or fingerprint_workers > MAX_FINGERPRINT_WORKERS:
            raise ValueError(
                f"fingerprint workers must be between 1 and {MAX_FINGERPRINT_WORKERS}"
            )

        self.identify_services = identify_services
        self.fingerprint_timeout = fingerprint_timeout
        self.fingerprint_workers = fingerprint_workers

        self._cancel_event = Event()
        self._lock = Lock()
        self._progress: Optional[ScanProgress] = None
        self._result: Optional[ScanResult] = None
        self._started_monotonic: Optional[float] = None
        self._host_check_counts: Dict[str, int] = {}
        self._host_expected_checks: Dict[str, int] = {}
        self._completed_hosts: Set[str] = set()

    def cancel(self) -> None:
        """Request cooperative cancellation of the currently active scan."""
        self._cancel_event.set()
        with self._lock:
            if self._progress is not None:
                self._progress.cancellation_requested = True
                self._refresh_elapsed_locked()

    def get_progress(self) -> Optional[ScanProgress]:
        """Return a safe snapshot of current progress for backend/status use."""
        with self._lock:
            if self._progress is None:
                return None
            self._refresh_elapsed_locked()
            return copy.deepcopy(self._progress)

    def get_result(self) -> Optional[ScanResult]:
        """Return a snapshot of the most recently completed/partial result."""
        with self._lock:
            return copy.deepcopy(self._result)

    def _refresh_elapsed_locked(self) -> None:
        if self._progress is None or self._started_monotonic is None:
            return
        self._progress.elapsed_seconds = round(
            max(0.0, time.monotonic() - self._started_monotonic),
            3,
        )

    def _recalculate_percent_locked(self) -> None:
        if self._progress is None:
            return
        if self._progress.total_ports <= 0:
            self._progress.percent_complete = 0.0
            return
        percent = (
            self._progress.ports_completed
            / self._progress.total_ports
            * 100.0
        )
        # ``percent_complete`` represents the whole coordinated scan, not only
        # TCP checks. Reserve 100% for the final COMPLETED result so a scan can
        # still report IDENTIFYING work after every port check has finished.
        upper_bound = (
            100.0
            if self._progress.state == ScanLifecycleState.COMPLETED
            else 99.0
        )
        self._progress.percent_complete = round(
            max(0.0, min(percent, upper_bound)),
            2,
        )

    def _set_state(self, state: ScanLifecycleState) -> None:
        with self._lock:
            if self._progress is not None:
                self._progress.state = state
                self._progress.cancellation_requested = self._cancel_event.is_set()
                self._refresh_elapsed_locked()

    def _set_total_ports(self, total: int) -> None:
        with self._lock:
            if self._progress is None:
                return
            self._progress.total_ports = max(0, int(total))
            self._recalculate_percent_locked()
            self._refresh_elapsed_locked()

    def _on_port_checked(
        self,
        device,
        port: int,
        _result: Optional[PortResult],
    ) -> None:
        """Progress callback invoked by the low-level TCP scanner."""
        with self._lock:
            if self._progress is None:
                return

            self._progress.ports_completed += 1
            self._progress.current_host = device.ip
            self._progress.current_port = port

            count = self._host_check_counts.get(device.ip, 0) + 1
            self._host_check_counts[device.ip] = count
            expected = self._host_expected_checks.get(device.ip)
            if (
                expected is not None
                and expected > 0
                and count >= expected
                and device.ip not in self._completed_hosts
            ):
                self._completed_hosts.add(device.ip)
                self._progress.hosts_completed += 1

            self._recalculate_percent_locked()
            self._refresh_elapsed_locked()

    def _on_fingerprint(self, fingerprint: ServiceFingerprint) -> None:
        """Expose which open service is currently in the identification stage."""
        with self._lock:
            if self._progress is None:
                return
            self._progress.current_host = fingerprint.ip
            self._progress.current_port = fingerprint.port
            self._refresh_elapsed_locked()

    def _context_metadata(
        self,
        context: Optional[NetworkContext],
        discovery_network: Optional[str],
    ) -> Dict[str, object]:
        metadata: Dict[str, object] = {
            "service_identification_enabled": self.identify_services,
        }
        if discovery_network is not None:
            metadata["discovery_network"] = discovery_network
        if context is not None:
            metadata["network_context"] = {
                "interface": str(context.interface),
                "local_ip": context.local_ip,
                "gateway": context.gateway,
                "network": context.network,
            }
        return metadata

    def _build_result(
        self,
        *,
        config: ScanConfiguration,
        state: ScanLifecycleState,
        started_at: str,
        hosts: Sequence[HostObservation],
        ports: Sequence[PortObservation],
        errors: Sequence[ScannerError],
        metadata: Optional[Dict[str, object]],
    ) -> ScanResult:
        completed_at = datetime.now().isoformat(timespec="seconds")
        with self._lock:
            if self._progress is None:
                progress = ScanProgress(
                    scan_id=config.scan_id,
                    state=state,
                    cancellation_requested=self._cancel_event.is_set(),
                )
            else:
                self._progress.state = state
                self._progress.current_host = None
                self._progress.current_port = None
                self._progress.cancellation_requested = self._cancel_event.is_set()
                if state == ScanLifecycleState.COMPLETED:
                    self._progress.hosts_completed = len(hosts)
                    self._progress.percent_complete = 100.0
                self._refresh_elapsed_locked()
                progress = copy.deepcopy(self._progress)

            result = ScanResult(
                scan_id=config.scan_id,
                configuration=config,
                state=state,
                started_at=started_at,
                completed_at=completed_at,
                hosts=list(hosts),
                ports=list(ports),
                progress=progress,
                errors=list(errors),
                metadata=metadata,
            )
            self._result = copy.deepcopy(result)
            return result

    @staticmethod
    def _scan_stage_for_state(state: ScanLifecycleState) -> str:
        return {
            ScanLifecycleState.CREATED: "configuration",
            ScanLifecycleState.DISCOVERING: "discovery",
            ScanLifecycleState.SCANNING: "scanning",
            ScanLifecycleState.IDENTIFYING: "identifying",
            ScanLifecycleState.MATCHING: "matching",
        }.get(state, "aggregation")

    @staticmethod
    def _resolved_fixed_ports(config: ScanConfiguration) -> List[int]:
        """Resolve non-smart modes without changing the low-level parser rules."""
        mode = config.scan_mode

        if mode == "custom":
            if config.ports:
                return sorted(set(config.ports))
            return parse_ports(config.port_spec)

        if config.ports:
            return sorted(set(config.ports))

        if mode == "common":
            return list(COMMON_TCP_PORTS)
        if mode == "all":
            return parse_ports("all")

        raise ValueError(f"Unsupported fixed scan mode: {mode}")

    def run(self, configuration: ScanConfiguration) -> ScanResult:
        """Run one complete/partial scan and return a shared ScanResult."""
        self._cancel_event.clear()
        self._started_monotonic = time.monotonic()
        started_at = datetime.now().isoformat(timespec="seconds")

        config = replace(
            configuration,
            scan_id=configuration.scan_id or f"scan-{uuid.uuid4()}",
            targets=[str(target).strip() for target in configuration.targets],
            scan_mode=(configuration.scan_mode or "").strip().lower(),
            ports=sorted(set(configuration.ports)),
        )

        self._host_check_counts = {}
        self._host_expected_checks = {}
        self._completed_hosts = set()
        errors: List[ScannerError] = []
        hosts: List[HostObservation] = []
        ports: List[PortObservation] = []
        context: Optional[NetworkContext] = None
        discovery_network: Optional[str] = None

        with self._lock:
            self._progress = ScanProgress(
                scan_id=config.scan_id,
                state=ScanLifecycleState.CREATED,
                cancellation_requested=False,
            )
            self._result = None

        validation_errors = config.validation_errors()
        if validation_errors:
            errors.extend(validation_errors)
            return self._build_result(
                config=config,
                state=ScanLifecycleState.FAILED,
                started_at=started_at,
                hosts=hosts,
                ports=ports,
                errors=errors,
                metadata=self._context_metadata(context, discovery_network),
            )

        try:
            discovered_hosts: List[HostObservation] = []

            if config.discovery_enabled:
                self._set_state(ScanLifecycleState.DISCOVERING)
                try:
                    devices, context, discovery_network = discover_devices(
                        requested_network=config.discovery_network,
                        include_local=config.include_local_host,
                    )
                    discovered_hosts = [
                        device_to_host_observation(device)
                        for device in devices
                    ]
                except Exception as exc:
                    recoverable = bool(config.targets)
                    errors.append(
                        ScannerError(
                            code="DISCOVERY_FAILED",
                            message="Host discovery failed.",
                            stage="discovery",
                            details={"reason": str(exc)},
                            recoverable=recoverable,
                        )
                    )
                    if not recoverable:
                        return self._build_result(
                            config=config,
                            state=ScanLifecycleState.FAILED,
                            started_at=started_at,
                            hosts=hosts,
                            ports=ports,
                            errors=errors,
                            metadata=self._context_metadata(context, discovery_network),
                        )

            if self._cancel_event.is_set():
                return self._build_result(
                    config=config,
                    state=ScanLifecycleState.CANCELLED,
                    started_at=started_at,
                    hosts=hosts,
                    ports=ports,
                    errors=errors,
                    metadata=self._context_metadata(context, discovery_network),
                )

            hosts, target_errors = normalize_targets(
                config.targets,
                discovered_hosts=discovered_hosts,
            )

            # A bad target is recoverable when other normalized/discovered
            # hosts remain available. If every supplied manual target is
            # unusable, the scan cannot continue and the target errors become
            # non-recoverable at the coordinator boundary.
            if config.targets and not hosts and target_errors:
                target_errors = [
                    replace(error, recoverable=False)
                    for error in target_errors
                ]
            errors.extend(target_errors)

            with self._lock:
                if self._progress is not None:
                    self._progress.hosts_discovered = len(hosts)
                    self._refresh_elapsed_locked()

            if not hosts and config.targets and target_errors:
                return self._build_result(
                    config=config,
                    state=ScanLifecycleState.FAILED,
                    started_at=started_at,
                    hosts=hosts,
                    ports=ports,
                    errors=errors,
                    metadata=self._context_metadata(context, discovery_network),
                )

            if not hosts:
                return self._build_result(
                    config=config,
                    state=ScanLifecycleState.COMPLETED,
                    started_at=started_at,
                    hosts=hosts,
                    ports=ports,
                    errors=errors,
                    metadata=self._context_metadata(context, discovery_network),
                )

            if self._cancel_event.is_set():
                return self._build_result(
                    config=config,
                    state=ScanLifecycleState.CANCELLED,
                    started_at=started_at,
                    hosts=hosts,
                    ports=ports,
                    errors=errors,
                    metadata=self._context_metadata(context, discovery_network),
                )

            scan_devices = [host_observation_to_device(host) for host in hosts]
            self._set_state(ScanLifecycleState.SCANNING)

            if config.scan_mode == "smart":
                port_results = smart_scan_open_ports(
                    scan_devices,
                    timeout=config.timeout_seconds,
                    workers=config.concurrency,
                    progress_callback=self._on_port_checked,
                    total_callback=self._set_total_ports,
                    cancel_event=self._cancel_event,
                    verbose=False,
                )
            else:
                try:
                    fixed_ports = self._resolved_fixed_ports(config)
                except (ValueError, argparse.ArgumentTypeError) as exc:
                    errors.append(
                        ScannerError(
                            code="INVALID_CONFIGURATION",
                            message=str(exc),
                            stage="configuration",
                            recoverable=False,
                        )
                    )
                    return self._build_result(
                        config=config,
                        state=ScanLifecycleState.FAILED,
                        started_at=started_at,
                        hosts=hosts,
                        ports=ports,
                        errors=errors,
                        metadata=self._context_metadata(context, discovery_network),
                    )

                total = len(scan_devices) * len(fixed_ports)
                self._set_total_ports(total)
                self._host_expected_checks = {
                    device.ip: len(fixed_ports)
                    for device in scan_devices
                }
                port_results = scan_open_ports(
                    scan_devices,
                    fixed_ports,
                    timeout=config.timeout_seconds,
                    workers=config.concurrency,
                    progress_callback=self._on_port_checked,
                    cancel_event=self._cancel_event,
                )

            ports = [
                port_result_to_port_observation(result)
                for result in port_results
            ]

            if config.scan_mode == "smart" and not self._cancel_event.is_set():
                with self._lock:
                    if self._progress is not None:
                        self._progress.hosts_completed = len(hosts)
                        self._refresh_elapsed_locked()

            if self._cancel_event.is_set():
                errors.append(
                    ScannerError(
                        code="CANCELLED",
                        message="Scan cancellation was requested.",
                        stage="scanning",
                        recoverable=False,
                    )
                )
                return self._build_result(
                    config=config,
                    state=ScanLifecycleState.CANCELLED,
                    started_at=started_at,
                    hosts=hosts,
                    ports=ports,
                    errors=errors,
                    metadata=self._context_metadata(context, discovery_network),
                )

            if self.identify_services and port_results:
                self._set_state(ScanLifecycleState.IDENTIFYING)
                try:
                    fingerprints = fingerprint_services(
                        port_results,
                        timeout=self.fingerprint_timeout,
                        workers=self.fingerprint_workers,
                        progress_callback=self._on_fingerprint,
                        cancel_event=self._cancel_event,
                    )
                    fingerprint_map: Dict[
                        Tuple[str, int, str], ServiceFingerprint
                    ] = {
                        (item.ip, item.port, item.protocol): item
                        for item in fingerprints
                    }
                    ports = [
                        apply_service_fingerprint(
                            observation,
                            fingerprint_map[
                                (
                                    observation.host_ip,
                                    observation.port,
                                    observation.protocol,
                                )
                            ],
                        )
                        if (
                            observation.host_ip,
                            observation.port,
                            observation.protocol,
                        ) in fingerprint_map
                        else observation
                        for observation in ports
                    ]
                except Exception as exc:
                    # Port discovery remains useful even if optional service
                    # identification fails, so preserve results and continue.
                    errors.append(
                        ScannerError(
                            code="SCAN_FAILED",
                            message=(
                                "Service identification failed; open-port "
                                "results were preserved."
                            ),
                            stage="identifying",
                            details={"reason": str(exc)},
                            recoverable=True,
                        )
                    )

            if self._cancel_event.is_set():
                errors.append(
                    ScannerError(
                        code="CANCELLED",
                        message="Scan cancellation was requested.",
                        stage="identifying",
                        recoverable=False,
                    )
                )
                return self._build_result(
                    config=config,
                    state=ScanLifecycleState.CANCELLED,
                    started_at=started_at,
                    hosts=hosts,
                    ports=ports,
                    errors=errors,
                    metadata=self._context_metadata(context, discovery_network),
                )

            metadata = self._context_metadata(context, discovery_network)
            metadata["service_identification_enabled"] = self.identify_services
            return self._build_result(
                config=config,
                state=ScanLifecycleState.COMPLETED,
                started_at=started_at,
                hosts=hosts,
                ports=ports,
                errors=errors,
                metadata=metadata,
            )

        except Exception as exc:
            current_state = (
                self.get_progress().state
                if self.get_progress() is not None
                else ScanLifecycleState.CREATED
            )
            errors.append(
                ScannerError(
                    code="INTERNAL_ERROR",
                    message="Unexpected scanner pipeline failure.",
                    stage=self._scan_stage_for_state(current_state),
                    details={"reason": str(exc)},
                    recoverable=False,
                )
            )
            return self._build_result(
                config=config,
                state=ScanLifecycleState.FAILED,
                started_at=started_at,
                hosts=hosts,
                ports=ports,
                errors=errors,
                metadata=self._context_metadata(context, discovery_network),
            )
