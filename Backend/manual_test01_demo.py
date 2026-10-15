"""Operator-run TEST-01 smoke demonstration; scans localhost only.

From the Backend directory:
    python manual_test01_demo.py failure
    python manual_test01_demo.py cancel

The failure case injects a discovery error. The cancellation case performs
one real localhost TCP connection, while slow *other* probes are simulated
so cancellation is repeatable on Linux, Windows, and macOS.
"""

from __future__ import annotations

import argparse
import socket
import threading
from unittest.mock import patch

import scanner_Port_Scanner as port_scanner
from scanner_contracts import ScanConfiguration, ScanLifecycleState
from scanner_coordinator import ScannerCoordinator


def show_result(title, result):
    print(f"\n{title}")
    print(f"State: {result.state.value}")
    print(f"Progress: {result.progress.ports_completed}/{result.progress.total_ports} "
          f"({result.progress.percent_complete}%)")
    print(f"Cancelled: {result.progress.cancellation_requested}")
    print(f"Open ports: {[port.port for port in result.ports]}")
    print(f"Errors: {[(error.code, error.stage) for error in result.errors]}")


def failure_demo() -> None:
    config = ScanConfiguration(
        targets=[],
        discovery_enabled=True,
        scan_mode="custom",
        ports=[80],
    )
    coordinator = ScannerCoordinator(identify_services=False)

    with patch(
        "scanner_coordinator.discover_devices",
        side_effect=OSError("TEST-01 simulated discovery failure"),
    ):
        result = coordinator.run(config)

    show_result("FAILURE PATH (injected discovery error)", result)
    assert result.state == ScanLifecycleState.FAILED
    assert len(result.errors) == 1
    assert result.errors[0].code == "DISCOVERY_FAILED"
    print("PASS: discovery failure correctly produced FAILED and a structured error.")


def cancel_demo() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        open_port = listener.getsockname()[1]
        # At least 40 planned checks ensure cancellation occurs mid-scan.
        planned_ports = [open_port]
        for increment in range(1, 41):
            candidate = ((open_port + increment - 1) % 65535) + 1
            if candidate != open_port:
                planned_ports.append(candidate)

        config = ScanConfiguration(
            targets=["127.0.0.1"],
            discovery_enabled=False,
            scan_mode="custom",
            ports=planned_ports,
            concurrency=1,
            timeout_seconds=0.4,
        )
        coordinator = ScannerCoordinator(identify_services=False)
        original_probe = port_scanner.scan_tcp_port
        original_callback = coordinator._on_port_checked
        open_observed = threading.Event()
        release = threading.Event()
        holder = {}

        def demo_probe(device, port, timeout):
            if port == open_port:
                return original_probe(device, port, timeout)
            if not release.wait(timeout=12.0):
                raise RuntimeError("Simulated probe was not released")
            return None

        def record_checked(device, port, result):
            original_callback(device, port, result)
            if result is not None and port == open_port:
                open_observed.set()

        def scan_worker():
            try:
                holder["result"] = coordinator.run(config)
            except BaseException as exc:
                holder["exception"] = exc

        print(f"Controlled localhost listener: 127.0.0.1:{open_port}")
        print(f"Planned port checks: {len(config.ports)}; other probes simulated.")
        with (
            patch.object(port_scanner, "scan_tcp_port", side_effect=demo_probe),
            patch.object(coordinator, "_on_port_checked", side_effect=record_checked),
        ):
            worker = threading.Thread(target=scan_worker, daemon=True)
            worker.start()
            try:
                if not open_observed.wait(timeout=10.0):
                    raise RuntimeError("Localhost listener not detected before timeout")
                snapshot = coordinator.get_progress()
                print(f"During scan: {snapshot.ports_completed}/{snapshot.total_ports} "
                      f"completed; state={snapshot.state.value}")
                coordinator.cancel()
            finally:
                release.set()
                worker.join(timeout=15.0)

        if worker.is_alive():
            raise RuntimeError("Cancellation did not terminate the worker")
        if "exception" in holder:
            raise holder["exception"]
        result = holder["result"]
        show_result("CANCELLATION PATH (real open localhost port)", result)
        assert result.state == ScanLifecycleState.CANCELLED
        assert result.progress.cancellation_requested
        assert result.progress.ports_completed < result.progress.total_ports
        assert any(port.port == open_port for port in result.ports)
        print("PASS: cancellation kept confirmed partial results and unfinished coverage.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=("failure", "cancel"))
    args = parser.parse_args()
    if args.scenario == "failure":
        failure_demo()
    else:
        cancel_demo()


if __name__ == "__main__":
    main()
