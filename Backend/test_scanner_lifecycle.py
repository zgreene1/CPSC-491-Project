"""End-to-end scanner lifecycle tests for the Sprint 2 pipeline.

These tests verify that the scanner modules work together through the
``ScannerCoordinator`` rather than testing each module in isolation.

The suite is intentionally cross-platform and safe:

* no public or external targets are scanned;
* successful network probing uses only a temporary HTTP service on localhost;
* discovery is supplied with a deterministic localhost observation so the
  lifecycle test does not require administrator/root privileges or ARP access;
* cancellation uses a mocked slow TCP probe so it is deterministic on Linux,
  Windows, and macOS.

Run with either:

    python -m unittest -v test_scanner_lifecycle.py

or:

    python -m pytest -q test_scanner_lifecycle.py
"""

from __future__ import annotations

import json
import socket
import threading
import time
import unittest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict
from unittest.mock import patch

import scanner_Host_Discovery as host_discovery
import scanner_Port_Scanner as port_scanner
from scanner_contracts import ScanConfiguration, ScanLifecycleState
from scanner_coordinator import ScannerCoordinator


class _QuietSimpleHTTPRequestHandler(SimpleHTTPRequestHandler):
    """Serve HEAD/GET requests without writing request logs during tests."""

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return


class _LocalHTTPService:
    """Context manager for a real, temporary HTTP service on 127.0.0.1."""

    def __init__(self) -> None:
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> "_LocalHTTPService":
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            _QuietSimpleHTTPRequestHandler,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name="scanner-lifecycle-http-test",
            daemon=True,
        )
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=2.0)

    @property
    def port(self) -> int:
        if self.server is None:
            raise RuntimeError("HTTP test service has not been started")
        return int(self.server.server_address[1])


class ScannerLifecycleIntegrationTests(unittest.TestCase):
    """Verify successful, failed, and cancelled coordinator lifecycles."""

    def test_full_lifecycle_discovery_scan_identification_completion(self) -> None:
        """Exercise the implemented pipeline with a real local TCP/HTTP service.

        Host discovery itself is made deterministic by returning localhost from
        the discovery boundary. Everything after that boundary is real:
        normalization -> Device adapter -> TCP connect scan -> PortResult
        adapter -> service fingerprinting -> PortObservation enrichment ->
        ScanResult aggregation.
        """
        with _LocalHTTPService() as http_service:
            discovered_device = host_discovery.Device(
                ip="127.0.0.1",
                mac=None,
                source="local_interface",
                last_seen="2026-09-24T00:00:00",
            )
            network_context = host_discovery.NetworkContext(
                interface="test-loopback",
                local_ip="127.0.0.1",
                gateway="0.0.0.0",
                network="127.0.0.0/8",
            )

            config = ScanConfiguration(
                targets=[],
                scan_mode="custom",
                ports=[http_service.port],
                timeout_seconds=0.75,
                discovery_enabled=True,
                include_local_host=True,
                concurrency=4,
            )
            coordinator = ScannerCoordinator(
                identify_services=True,
                fingerprint_timeout=0.75,
                fingerprint_workers=2,
            )

            observed_states = []
            original_set_state = coordinator._set_state

            def record_state(state: ScanLifecycleState) -> None:
                # The first transition must start from a real CREATED progress
                # object, proving initialization occurred before DISCOVERING.
                if not observed_states:
                    progress = coordinator.get_progress()
                    self.assertIsNotNone(progress)
                    self.assertEqual(progress.state, ScanLifecycleState.CREATED)
                    observed_states.append(progress.state)

                observed_states.append(state)
                original_set_state(state)

            with (
                patch(
                    "scanner_coordinator.discover_devices",
                    return_value=(
                        [discovered_device],
                        network_context,
                        "127.0.0.1/32",
                    ),
                ),
                patch.object(coordinator, "_set_state", side_effect=record_state),
            ):
                result = coordinator.run(config)

            observed_states.append(result.state)

            # Print the same application-facing ScanResult that backend,
            # persistence, and future frontend code will consume. Keeping the
            # output as formatted JSON also verifies that the complete result
            # remains easy to inspect during local and CI test runs.
            print("\n=== Scanner Lifecycle Result ===")
            print(result.to_json(indent=2))

        self.assertEqual(
            observed_states,
            [
                ScanLifecycleState.CREATED,
                ScanLifecycleState.DISCOVERING,
                ScanLifecycleState.SCANNING,
                ScanLifecycleState.IDENTIFYING,
                ScanLifecycleState.COMPLETED,
            ],
        )

        # Final lifecycle/result contract.
        self.assertEqual(result.state, ScanLifecycleState.COMPLETED)
        self.assertIsNotNone(result.scan_id)
        self.assertTrue(result.scan_id.startswith("scan-"))
        self.assertIsNotNone(result.started_at)
        self.assertIsNotNone(result.completed_at)
        self.assertEqual(result.errors, [])

        # Discovery -> HostObservation normalization.
        self.assertEqual(len(result.hosts), 1)
        self.assertEqual(result.hosts[0].ip, "127.0.0.1")
        self.assertIsNone(result.hosts[0].mac)
        self.assertEqual(result.hosts[0].discovery_source, "local_interface")
        self.assertEqual(result.hosts[0].discovery_status, "discovered")

        # TCP scanner -> PortObservation -> fingerprint enrichment.
        self.assertEqual(len(result.ports), 1)
        port = result.ports[0]
        self.assertEqual(port.host_ip, "127.0.0.1")
        self.assertEqual(port.port, http_service.port)
        self.assertEqual(port.protocol, "tcp")
        self.assertEqual(port.state, "open")
        self.assertEqual(port.service, "http")
        self.assertIsNotNone(port.banner)
        self.assertIsNotNone(port.confidence)

        # Product/version are optional contract fields. The lifecycle test
        # proves that IDENTIFYING recognized HTTP; signature-database-specific
        # product/version matching belongs in focused fingerprint tests.
        if port.product is not None:
            self.assertIsInstance(port.product, str)
            self.assertTrue(port.product)
        if port.version is not None:
            self.assertIsInstance(port.version, str)
            self.assertTrue(port.version)

        # Progress must describe all performed TCP work, not only open ports.
        self.assertEqual(result.progress.state, ScanLifecycleState.COMPLETED)
        self.assertEqual(result.progress.hosts_discovered, 1)
        self.assertEqual(result.progress.hosts_completed, 1)
        self.assertEqual(result.progress.ports_completed, 1)
        self.assertEqual(result.progress.total_ports, 1)
        # 100% is reserved for the final COMPLETED aggregate result.
        self.assertEqual(result.progress.percent_complete, 100.0)
        self.assertIsNone(result.progress.current_host)
        self.assertIsNone(result.progress.current_port)
        self.assertFalse(result.progress.cancellation_requested)

        # Application-facing output must remain JSON serializable.
        payload = json.loads(result.to_json())
        self.assertEqual(payload["state"], "COMPLETED")
        self.assertEqual(payload["hosts"][0]["ip"], "127.0.0.1")
        self.assertEqual(payload["ports"][0]["service"], "http")
        self.assertEqual(
            payload["metadata"]["network_context"]["interface"],
            "test-loopback",
        )

    def test_invalid_configuration_fails_before_scanner_stages(self) -> None:
        """Verify CREATED -> FAILED when configuration cannot start a scan."""
        coordinator = ScannerCoordinator(identify_services=True)
        config = ScanConfiguration(
            targets=[],
            discovery_enabled=False,
        )

        with (
            patch("scanner_coordinator.discover_devices") as discovery_mock,
            patch("scanner_coordinator.scan_open_ports") as scan_mock,
            patch("scanner_coordinator.fingerprint_services") as fingerprint_mock,
        ):
            result = coordinator.run(config)

        self.assertEqual(result.state, ScanLifecycleState.FAILED)
        self.assertEqual(result.progress.state, ScanLifecycleState.FAILED)
        self.assertTrue(result.errors)
        self.assertEqual(result.errors[0].code, "INVALID_CONFIGURATION")
        self.assertEqual(result.errors[0].stage, "configuration")
        self.assertFalse(result.errors[0].recoverable)

        discovery_mock.assert_not_called()
        scan_mock.assert_not_called()
        fingerprint_mock.assert_not_called()
        json.loads(result.to_json())

    def test_cancellation_moves_scanning_to_cancelled_and_preserves_progress(self) -> None:
        """Verify cooperative cancellation across coordinator and port scanner."""
        ports = list(range(20000, 20080))
        coordinator = ScannerCoordinator(identify_services=False)
        config = ScanConfiguration(
            targets=["127.0.0.1"],
            scan_mode="custom",
            ports=ports,
            timeout_seconds=0.25,
            discovery_enabled=False,
            concurrency=2,
        )

        result_holder: Dict[str, object] = {}

        def slow_closed_port(device, port: int, timeout: float):
            # Deterministic delay gives the test enough time to issue cancel()
            # without relying on operating-system TCP timing.
            time.sleep(0.03)
            return None

        def run_scan() -> None:
            result_holder["result"] = coordinator.run(config)

        with patch.object(
            port_scanner,
            "scan_tcp_port",
            side_effect=slow_closed_port,
        ):
            worker = threading.Thread(
                target=run_scan,
                name="scanner-lifecycle-cancellation-test",
                daemon=True,
            )
            worker.start()

            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                progress = coordinator.get_progress()
                if (
                    progress is not None
                    and progress.state == ScanLifecycleState.SCANNING
                    and progress.ports_completed >= 2
                ):
                    break
                time.sleep(0.005)
            else:
                self.fail("scanner did not enter SCANNING state in time")

            coordinator.cancel()
            worker.join(timeout=5.0)

        self.assertFalse(worker.is_alive(), "cancelled scan did not terminate")
        self.assertIn("result", result_holder)
        result = result_holder["result"]

        self.assertEqual(result.state, ScanLifecycleState.CANCELLED)
        self.assertEqual(result.progress.state, ScanLifecycleState.CANCELLED)
        self.assertTrue(result.progress.cancellation_requested)
        self.assertGreater(result.progress.ports_completed, 0)
        self.assertLess(result.progress.ports_completed, result.progress.total_ports)
        self.assertEqual(result.progress.total_ports, len(ports))
        self.assertEqual(result.ports, [])
        self.assertTrue(any(error.code == "CANCELLED" for error in result.errors))
        self.assertTrue(
            any(error.stage == "scanning" for error in result.errors),
            result.errors,
        )
        json.loads(result.to_json())


if __name__ == "__main__":
    unittest.main(verbosity=2)
