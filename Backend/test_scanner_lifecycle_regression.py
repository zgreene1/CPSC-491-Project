"""TEST-01: deterministic scanner lifecycle and error-path regression tests.

Run from Backend with:
    python -m pytest -q test_scanner_lifecycle_regression.py

All scan targets are localhost; network probes and discovery are mocked.
This suite is designed to work on Linux, Windows, and macOS without privileges.
"""

from __future__ import annotations

import json
import threading
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import scanner_Port_Scanner as port_scanner
from scanner_Port_Scanner import PortResult
from scanner_contracts import ScanConfiguration, ScanLifecycleState
from scanner_coordinator import ScannerCoordinator


LOCALHOST = "127.0.0.1"


def _config(*, ports=(19081,), discovery=False) -> ScanConfiguration:
    return ScanConfiguration(
        targets=[LOCALHOST] if not discovery else [],
        scan_mode="custom",
        ports=list(ports),
        timeout_seconds=0.25,
        discovery_enabled=discovery,
        concurrency=1,
    )


def _open_port(port: int = 19081) -> PortResult:
    return PortResult(
        ip=LOCALHOST,
        mac=None,
        port=port,
        protocol="tcp",
        state="open",
        service_hint="http",
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )


def _run_in_thread(coordinator, config, result_holder):
    """Capture exceptions raised by test workers, not only successful results."""
    try:
        result_holder["result"] = coordinator.run(config)
    except BaseException as exc:
        result_holder["exception"] = exc


class ScannerLifecycleRegressionTests(unittest.TestCase):
    """TEST-01 scenarios not covered by the original lifecycle suite."""

    def test_discovery_failure_without_fallback_is_terminal(self):
        coordinator = ScannerCoordinator(identify_services=False)
        config = _config(discovery=True)

        with (
            patch("scanner_coordinator.discover_devices", side_effect=OSError("no interface")),
            patch("scanner_coordinator.scan_open_ports") as scan_mock,
        ):
            result = coordinator.run(config)

        self.assertEqual(result.state, ScanLifecycleState.FAILED)
        self.assertEqual(result.progress.state, ScanLifecycleState.FAILED)
        self.assertEqual(result.progress.hosts_discovered, 0)
        self.assertEqual(result.progress.ports_completed, 0)
        self.assertEqual(result.progress.percent_complete, 0.0)
        self.assertEqual(result.ports, [])
        self.assertEqual(result.hosts, [])
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0].code, "DISCOVERY_FAILED")
        self.assertEqual(result.errors[0].stage, "discovery")
        self.assertFalse(result.errors[0].recoverable)
        scan_mock.assert_not_called()
        self.assertEqual(json.loads(result.to_json())["state"], "FAILED")

    def test_discovery_failure_with_manual_target_continues(self):
        coordinator = ScannerCoordinator(identify_services=False)
        config = ScanConfiguration(
            targets=[LOCALHOST],
            scan_mode="custom",
            ports=[19081],
            timeout_seconds=0.25,
            discovery_enabled=True,
            concurrency=1,
        )

        with (
            patch("scanner_coordinator.discover_devices", side_effect=OSError("blocked ARP")),
            patch.object(port_scanner, "scan_tcp_port", return_value=None),
        ):
            result = coordinator.run(config)

        self.assertEqual(result.state, ScanLifecycleState.COMPLETED)
        self.assertEqual(result.progress.state, ScanLifecycleState.COMPLETED)
        self.assertEqual(result.progress.percent_complete, 100.0)
        self.assertEqual(result.progress.hosts_discovered, 1)
        self.assertEqual(result.progress.hosts_completed, 1)
        self.assertEqual(result.progress.total_ports, 1)
        self.assertEqual(result.progress.ports_completed, 1)
        self.assertEqual([host.ip for host in result.hosts], [LOCALHOST])
        self.assertEqual(result.ports, [])
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0].code, "DISCOVERY_FAILED")
        self.assertTrue(result.errors[0].recoverable)

    def test_fingerprint_failure_preserves_open_port_and_completes(self):
        coordinator = ScannerCoordinator(identify_services=True)
        with (
            patch.object(port_scanner, "scan_tcp_port", return_value=_open_port()),
            patch(
                "scanner_coordinator.fingerprint_services",
                side_effect=RuntimeError("fingerprint unavailable"),
            ),
        ):
            result = coordinator.run(_config())

        self.assertEqual(result.state, ScanLifecycleState.COMPLETED)
        self.assertEqual(result.progress.state, ScanLifecycleState.COMPLETED)
        self.assertEqual(result.progress.percent_complete, 100.0)
        self.assertEqual(result.progress.total_ports, 1)
        self.assertEqual(result.progress.ports_completed, 1)
        self.assertEqual(len(result.ports), 1)
        self.assertEqual(result.ports[0].port, 19081)
        self.assertEqual(result.ports[0].state, "open")
        self.assertIsNone(result.ports[0].product)
        self.assertIsNone(result.ports[0].version)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0].code, "SCAN_FAILED")
        self.assertEqual(result.errors[0].stage, "identifying")
        self.assertTrue(result.errors[0].recoverable)
        self.assertEqual(len(json.loads(result.to_json())["ports"]), 1)

    def test_live_progress_is_monotonic_and_terminal_progress_is_clean(self):
        coordinator = ScannerCoordinator(identify_services=False)
        config = _config(ports=(19081, 19082, 19083, 19084))
        snapshots = []
        original = coordinator._on_port_checked

        def record_port_progress(device, port, value):
            original(device, port, value)
            snapshots.append(coordinator.get_progress())

        with (
            patch.object(port_scanner, "scan_tcp_port", return_value=None),
            patch.object(coordinator, "_on_port_checked", side_effect=record_port_progress),
        ):
            result = coordinator.run(config)

        self.assertEqual(result.state, ScanLifecycleState.COMPLETED)
        self.assertEqual(len(snapshots), 4)
        self.assertEqual([snapshot.ports_completed for snapshot in snapshots], [1, 2, 3, 4])
        percentages = [snapshot.percent_complete for snapshot in snapshots]
        self.assertEqual(percentages, sorted(percentages))
        self.assertTrue(all(0 <= value < 100 for value in percentages))
        self.assertTrue(all(snapshot.state == ScanLifecycleState.SCANNING for snapshot in snapshots))
        self.assertTrue(all(snapshot.total_ports == 4 for snapshot in snapshots))
        self.assertTrue(all(snapshot.hosts_completed <= snapshot.hosts_discovered for snapshot in snapshots))
        self.assertEqual(result.progress.percent_complete, 100.0)
        self.assertEqual(result.progress.ports_completed, 4)
        self.assertEqual(result.progress.hosts_completed, 1)
        self.assertIsNone(result.progress.current_port)
        self.assertIsNone(result.progress.current_host)
        self.assertFalse(result.progress.cancellation_requested)
        # Poll again after termination: a finished scan must not keep aging.
        time.sleep(0.025)
        self.assertEqual(coordinator.get_progress().to_dict(), result.progress.to_dict())

    def test_cancellation_during_scanning_preserves_completed_open_port(self):
        coordinator = ScannerCoordinator(identify_services=False)
        config = _config(ports=range(19081, 19121))
        first_open_observed = threading.Event()
        release_other_probes = threading.Event()
        results = {}
        original = coordinator._on_port_checked

        def fake_probe(device, port, timeout):
            if port == 19081:
                return _open_port(port)
            if not release_other_probes.wait(timeout=5.0):
                raise AssertionError("blocked test probe was never released")
            return None

        def notify_open(device, port, observation):
            original(device, port, observation)
            if observation is not None:
                first_open_observed.set()

        with (
            patch.object(port_scanner, "scan_tcp_port", side_effect=fake_probe),
            patch.object(coordinator, "_on_port_checked", side_effect=notify_open),
        ):
            worker = threading.Thread(
                target=_run_in_thread,
                args=(coordinator, config, results),
                daemon=True,
            )
            worker.start()
            try:
                self.assertTrue(first_open_observed.wait(timeout=5.0), "open port was not observed")
                progress = coordinator.get_progress()
                self.assertEqual(progress.state, ScanLifecycleState.SCANNING)
                self.assertGreaterEqual(progress.ports_completed, 1)
                self.assertLess(progress.percent_complete, 100.0)
                coordinator.cancel()
            finally:
                release_other_probes.set()
                worker.join(timeout=6.0)

        self.assertFalse(worker.is_alive(), "cancelled scanner worker did not exit")
        self.assertNotIn("exception", results, results.get("exception"))
        result = results["result"]
        self.assertEqual(result.state, ScanLifecycleState.CANCELLED)
        self.assertEqual(result.progress.state, ScanLifecycleState.CANCELLED)
        self.assertTrue(result.progress.cancellation_requested)
        self.assertGreater(result.progress.ports_completed, 0)
        self.assertLess(result.progress.ports_completed, result.progress.total_ports)
        self.assertLess(result.progress.percent_complete, 100.0)
        self.assertEqual([(item.port, item.state) for item in result.ports], [(19081, "open")])
        self.assertEqual([host.ip for host in result.hosts], [LOCALHOST])
        self.assertTrue(any(error.code == "CANCELLED" and error.stage == "scanning" for error in result.errors))
        self.assertIsNone(result.progress.current_host)
        self.assertIsNone(result.progress.current_port)
        self.assertEqual(len(json.loads(result.to_json())["ports"]), 1)

    def test_cancellation_during_identification_keeps_scanned_ports(self):
        coordinator = ScannerCoordinator(identify_services=True)
        started_identifying = threading.Event()
        resume_identifying = threading.Event()
        results = {}

        def delayed_fingerprint(*args, **kwargs):
            started_identifying.set()
            if not resume_identifying.wait(timeout=5.0):
                raise AssertionError("blocked fingerprint stage was never released")
            return []

        with (
            patch.object(port_scanner, "scan_tcp_port", return_value=_open_port()),
            patch("scanner_coordinator.fingerprint_services", side_effect=delayed_fingerprint),
        ):
            worker = threading.Thread(
                target=_run_in_thread,
                args=(coordinator, _config(), results),
                daemon=True,
            )
            worker.start()
            try:
                self.assertTrue(started_identifying.wait(timeout=5.0))
                progress = coordinator.get_progress()
                self.assertEqual(progress.state, ScanLifecycleState.IDENTIFYING)
                self.assertEqual(progress.ports_completed, 1)
                self.assertLess(progress.percent_complete, 100.0)
                coordinator.cancel()
            finally:
                resume_identifying.set()
                worker.join(timeout=6.0)

        self.assertFalse(worker.is_alive(), "cancelled fingerprint worker did not exit")
        self.assertNotIn("exception", results, results.get("exception"))
        result = results["result"]
        self.assertEqual(result.state, ScanLifecycleState.CANCELLED)
        self.assertTrue(result.progress.cancellation_requested)
        self.assertLess(result.progress.percent_complete, 100.0)
        self.assertEqual([(item.port, item.state) for item in result.ports], [(19081, "open")])
        self.assertTrue(any(error.code == "CANCELLED" and error.stage == "identifying" for error in result.errors))
        self.assertEqual(len(json.loads(result.to_json())["ports"]), 1)

    def test_cancellation_during_discovery_is_terminal_before_scanning(self):
        coordinator = ScannerCoordinator(identify_services=False)
        discovering = threading.Event()
        release_discovery = threading.Event()
        results = {}

        def delayed_discovery(**kwargs):
            discovering.set()
            if not release_discovery.wait(timeout=5.0):
                raise AssertionError("blocked discovery was never released")
            return [], None, None

        with (
            patch("scanner_coordinator.discover_devices", side_effect=delayed_discovery),
            patch("scanner_coordinator.scan_open_ports") as scan_mock,
        ):
            worker = threading.Thread(
                target=_run_in_thread,
                args=(coordinator, _config(discovery=True), results),
                daemon=True,
            )
            worker.start()
            try:
                self.assertTrue(discovering.wait(timeout=5.0))
                self.assertEqual(coordinator.get_progress().state, ScanLifecycleState.DISCOVERING)
                coordinator.cancel()
            finally:
                release_discovery.set()
                worker.join(timeout=6.0)

        self.assertFalse(worker.is_alive())
        self.assertNotIn("exception", results, results.get("exception"))
        result = results["result"]
        self.assertEqual(result.state, ScanLifecycleState.CANCELLED)
        self.assertTrue(result.progress.cancellation_requested)
        self.assertEqual(result.progress.ports_completed, 0)
        self.assertEqual(result.progress.percent_complete, 0.0)
        self.assertEqual(result.ports, [])
        scan_mock.assert_not_called()

    def test_result_snapshots_are_isolated_and_new_runs_reset_terminal_state(self):
        coordinator = ScannerCoordinator(identify_services=False)
        bad_config = ScanConfiguration(targets=[], discovery_enabled=False)
        failed_result = coordinator.run(bad_config)
        self.assertEqual(failed_result.state, ScanLifecycleState.FAILED)
        self.assertTrue(failed_result.errors)

        with patch.object(port_scanner, "scan_tcp_port", return_value=_open_port()):
            completed = coordinator.run(_config())

        self.assertEqual(completed.state, ScanLifecycleState.COMPLETED)
        self.assertEqual(completed.errors, [])
        self.assertEqual(completed.progress.ports_completed, 1)
        self.assertFalse(completed.progress.cancellation_requested)

        result_copy = coordinator.get_result()
        self.assertEqual(result_copy.to_dict(), completed.to_dict())
        result_copy.ports.clear()
        result_copy.progress.ports_completed = 999
        progress_copy = coordinator.get_progress()
        progress_copy.percent_complete = -1

        fresh_result = coordinator.get_result()
        fresh_progress = coordinator.get_progress()
        self.assertEqual(len(fresh_result.ports), 1)
        self.assertEqual(fresh_result.progress.ports_completed, 1)
        self.assertEqual(fresh_progress.percent_complete, 100.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
