"""Sprint 2 contract/coordinator tests.

Run on Linux, Windows, or macOS after project dependencies are installed:
    python -m unittest -v test_scanner_compatibility.py test_scanner_sprint2.py

The tests use localhost or mocks only and never scan external systems.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import unittest
from threading import Event
from unittest.mock import patch

import scanner_Host_Discovery as host_discovery
import scanner_Port_Scanner as port_scanner
from scanner_adapters import device_to_host_observation
from scanner_contracts import (
    HostObservation,
    PortObservation,
    ScanConfiguration,
    ScanLifecycleState,
    ScanProgress,
)
from scanner_coordinator import ScannerCoordinator
from scanner_target_normalizer import normalize_targets


class ContractTests(unittest.TestCase):
    def test_configuration_reports_structured_validation_error(self):
        config = ScanConfiguration(
            targets=[],
            discovery_enabled=False,
        )
        errors = config.validation_errors()
        self.assertTrue(errors)
        self.assertEqual(errors[0].code, "INVALID_CONFIGURATION")
        self.assertEqual(errors[0].stage, "configuration")

    def test_contract_serialization_uses_plain_json_values(self):
        config = ScanConfiguration(
            targets=["127.0.0.1"],
            scan_mode="custom",
            ports=[80],
            discovery_enabled=False,
        )
        payload = json.loads(config.to_json())
        self.assertEqual(payload["scan_mode"], "custom")
        self.assertEqual(payload["ports"], [80])

    def test_local_device_sentinel_becomes_null_mac(self):
        device = host_discovery.Device(
            ip="127.0.0.1",
            mac="local",
            source="local_interface",
            last_seen="2026-01-01T00:00:00",
        )
        observation = device_to_host_observation(device)
        self.assertIsNone(observation.mac)
        self.assertEqual(observation.discovery_status, "discovered")


    def test_optional_contract_fields_have_real_defaults(self):
        host = HostObservation(
            ip="127.0.0.1",
            discovery_source="manual_target",
            discovery_status="manual",
        )
        port = PortObservation(
            host_ip="127.0.0.1",
            port=80,
            protocol="tcp",
            state="open",
        )
        progress = ScanProgress(state=ScanLifecycleState.CREATED)

        self.assertIsNone(host.hostname)
        self.assertIsNone(host.mac)
        self.assertIsNone(port.host_mac)
        self.assertIsNone(port.product)
        self.assertIsNone(progress.scan_id)

    def test_invalid_port_spec_is_rejected_by_configuration_contract(self):
        config = ScanConfiguration(
            targets=["127.0.0.1"],
            scan_mode="custom",
            port_spec="70000",
            discovery_enabled=False,
        )
        errors = config.validation_errors()
        self.assertTrue(errors)
        self.assertTrue(
            any(error.code == "INVALID_CONFIGURATION" for error in errors)
        )
        self.assertTrue(
            any("65535" in error.message for error in errors),
            errors,
        )


class TargetNormalizationTests(unittest.TestCase):
    def test_manual_ipv4_and_cidr_share_one_normalized_path(self):
        hosts, errors = normalize_targets(
            ["192.0.2.1", "192.0.2.0/30"],
        )
        self.assertFalse(errors)
        self.assertEqual(
            [host.ip for host in hosts],
            ["192.0.2.1", "192.0.2.2"],
        )
        self.assertTrue(
            all(host.discovery_source == "manual_target" for host in hosts)
        )


class CoordinatorTests(unittest.TestCase):
    def test_manual_target_scan_returns_contract_result(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        open_port = listener.getsockname()[1]

        def accept_once():
            connection, _ = listener.accept()
            connection.close()
            listener.close()

        threading.Thread(target=accept_once, daemon=True).start()

        config = ScanConfiguration(
            targets=["127.0.0.1"],
            scan_mode="custom",
            ports=[open_port],
            discovery_enabled=False,
            timeout_seconds=0.5,
            concurrency=4,
        )
        result = ScannerCoordinator(identify_services=False).run(config)

        self.assertEqual(result.state, ScanLifecycleState.COMPLETED)
        self.assertEqual(len(result.hosts), 1)
        self.assertEqual(len(result.ports), 1)
        self.assertEqual(result.ports[0].port, open_port)
        self.assertEqual(result.progress.ports_completed, 1)
        self.assertEqual(result.progress.total_ports, 1)
        self.assertEqual(result.progress.percent_complete, 100.0)
        json.loads(result.to_json())

    def test_all_invalid_manual_targets_are_nonrecoverable(self):
        config = ScanConfiguration(
            targets=["definitely-not-a-real-hostname.invalid"],
            scan_mode="custom",
            ports=[80],
            discovery_enabled=False,
        )

        with patch(
            "scanner_target_normalizer.socket.getaddrinfo",
            side_effect=socket.gaierror("test resolution failure"),
        ):
            result = ScannerCoordinator(identify_services=False).run(config)

        self.assertEqual(result.state, ScanLifecycleState.FAILED)
        self.assertTrue(result.errors)
        self.assertTrue(all(not error.recoverable for error in result.errors))
        self.assertTrue(any(error.code == "INVALID_TARGET" for error in result.errors))

    def test_scanning_progress_does_not_reach_100_before_completion(self):
        coordinator = ScannerCoordinator(identify_services=False)
        coordinator._started_monotonic = time.monotonic()
        coordinator._progress = ScanProgress(
            state=ScanLifecycleState.SCANNING,
            total_ports=1,
        )
        device = host_discovery.Device(
            ip="127.0.0.1",
            mac=None,
            source="test",
            last_seen="test",
        )

        coordinator._on_port_checked(device, 80, None)
        progress = coordinator.get_progress()
        self.assertIsNotNone(progress)
        self.assertEqual(progress.percent_complete, 99.0)

    def test_cancellation_stops_new_tcp_work(self):
        devices = [
            host_discovery.Device(
                ip="127.0.0.1",
                mac=None,
                source="test",
                last_seen="test",
            )
        ]
        ports = list(range(10000, 10100))
        cancel_event = Event()
        completed = []

        def fake_scan(device, port, timeout):
            time.sleep(0.01)
            return None

        def on_progress(device, port, result):
            completed.append(port)
            if len(completed) >= 3:
                cancel_event.set()

        with patch.object(port_scanner, "scan_tcp_port", side_effect=fake_scan):
            port_scanner.scan_open_ports(
                devices,
                ports,
                timeout=0.1,
                workers=2,
                progress_callback=on_progress,
                cancel_event=cancel_event,
            )

        self.assertTrue(cancel_event.is_set())
        self.assertLess(len(completed), len(ports))


if __name__ == "__main__":
    unittest.main()
