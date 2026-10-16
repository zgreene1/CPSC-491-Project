"""Local-only TCP/UDP classification demonstration; no external network traffic.

Usage (from Backend): python manual_port_states_udp_demo.py [--output path.json]
"""
from __future__ import annotations

import argparse
import json
import socket
import threading
from pathlib import Path

from scanner_contracts import ScanConfiguration
from scanner_coordinator import ScannerCoordinator
from scanner_Host_Discovery import Device
from scanner_Port_Scanner import probe_tcp_port
from udp_port_scanner import probe_udp_port


def demonstrate() -> dict:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_server:
        tcp_server.bind(("127.0.0.1", 0))
        tcp_server.listen(4)
        port = tcp_server.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_server:
            udp_server.bind(("127.0.0.1", port))

            def udp_response() -> None:
                data, sender = udp_server.recvfrom(2048)
                udp_server.sendto(b"PONG", sender)

            responder = threading.Thread(target=udp_response, daemon=True)
            responder.start()
            scan = ScannerCoordinator(identify_services=False).run(ScanConfiguration(
                targets=["127.0.0.1"], scan_mode="custom", ports=[port],
                protocol="both", include_non_open=True,
                discovery_enabled=False, timeout_seconds=0.75, concurrency=2,
            ))
            responder.join(timeout=2)

    device = Device(ip="127.0.0.1", mac=None, source="test", last_seen="test")
    # Reserve then release a temporary TCP port to test a refused connection.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
        reserved.bind(("127.0.0.1", 0))
        closed_tcp_port = reserved.getsockname()[1]
    closed_tcp = probe_tcp_port(device, closed_tcp_port, timeout=0.25)

    # A bound UDP port with no response remains inconclusive rather than closed.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
        silent.bind(("127.0.0.1", 0))
        silent_udp = probe_udp_port(device, silent.getsockname()[1], timeout=0.15)

    observations = scan.to_dict()
    summary = {
        "scan_state": observations["state"],
        "ports_completed": observations["progress"]["ports_completed"],
        "total_ports": observations["progress"]["total_ports"],
        "expected": {"tcp": "open", "udp": "open"},
        "actual": {item["protocol"]: item["state"] for item in observations["ports"]},
        "ports": observations["ports"],
        "closed_tcp": {"state": closed_tcp.state, "reason": closed_tcp.state_reason},
        "silent_udp": {"state": silent_udp.state, "reason": silent_udp.state_reason},
    }
    summary["passed"] = (
        summary["scan_state"] == "COMPLETED"
        and summary["actual"] == summary["expected"]
        and summary["ports_completed"] == summary["total_ports"] == 2
        and closed_tcp.state == "closed"
        and silent_udp.state == "open|filtered"
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="Optional JSON evidence file path")
    args = parser.parse_args()
    result = demonstrate()
    print(json.dumps(result, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
