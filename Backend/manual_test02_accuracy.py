"""TEST-02 manual accuracy demonstration with ten controlled localhost services.

Run from Backend (Linux, Windows, or macOS):
    python manual_test02_accuracy.py --output test02_manual_results.json

The report compares observed port/service/product/version information against
mock-services-lab ground truth and exits nonzero if anything is incorrect.
Inspect the printed comparison table and attach JSON output to Jira TEST-02.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import scanner_Port_Scanner as tcp
import scanner_Service_Fingerprint as fingerprint
from scanner_Host_Discovery import Device
from test02_accuracy_support import LocalFixtureLab, OpaqueHandler


def run_accuracy_check() -> dict:
    target = Device(ip="127.0.0.1", mac="local", source="test02", last_seen="test02")
    rows = []

    with LocalFixtureLab() as lab:
        unknown = lab.add_service(
            "opaque", OpaqueHandler, service="unknown", product="", version=None
        )
        expected_by_port = {item.port: item for item in lab.fixtures}
        ports = sorted(expected_by_port)
        results = tcp.scan_open_ports(
            devices=[target], ports=ports, timeout=1.0, workers=8
        )
        results_by_port = {r.port: r for r in results}
        observed = []
        for port_result in results:
            # Fingerprint the unknown fixture without OS service-name assumptions.
            if port_result.port == unknown.port:
                port_result = replace(port_result, service_hint="unknown")
            observed.append(fingerprint.fingerprint_port(port_result, timeout=1.0))
        identified_by_port = {r.port: r for r in observed}

        for port in ports:
            expected = expected_by_port[port]
            port_result = results_by_port.get(port)
            actual = identified_by_port.get(port)
            expected_product = expected.product or None
            passed = (
                port_result is not None
                and port_result.protocol == "tcp"
                and port_result.state == "open"
                and actual is not None
                and actual.service == expected.service
                and actual.product == expected_product
                and actual.version == expected.version
            )
            rows.append({
                "fixture": expected.name,
                "host": "127.0.0.1",
                "port": port,
                "expected": {"state": "open", "service": expected.service,
                             "product": expected_product, "version": expected.version},
                "actual": {
                    "state": port_result.state if port_result else None,
                    "service": actual.service if actual else None,
                    "product": actual.product if actual else None,
                    "version": actual.version if actual else None,
                    "confidence": actual.confidence if actual else None,
                    "detection_method": actual.detection_method if actual else None,
                },
                "status": "PASS" if passed else "FAIL",
            })

    return {
        "test": "TEST-02 TCP Scanner and Service Fingerprinting Accuracy",
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "target": "127.0.0.1",
        "configuration": "Controlled localhost ephemeral-port TCP scan; mock_services_lab handlers",
        "fixtures_expected": len(rows),
        "fixtures_passed": sum(row["status"] == "PASS" for row in rows),
        "fixtures_failed": sum(row["status"] == "FAIL" for row in rows),
        "observations": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write a JSON evidence file")
    args = parser.parse_args()
    report = run_accuracy_check()
    print("TEST-02 controlled localhost accuracy inventory")
    print(f"{'FIXTURE':<14} {'PORT':>6} {'EXPECTED PRODUCT':<20} {'EXPECTED VERSION':<16} "
          f"{'ACTUAL PRODUCT':<20} {'ACTUAL VERSION':<16} RESULT")
    print("-" * 112)
    for row in report["observations"]:
        exp = row["expected"]
        got = row["actual"]
        print(f"{row['fixture']:<14} {row['port']:>6} {str(exp['product'] or '-'):20.20} "
              f"{str(exp['version'] or '-'):16.16} {str(got['product'] or '-'):20.20} "
              f"{str(got['version'] or '-'):16.16} {row['status']}")
    print(f"\nPass: {report['fixtures_passed']}  Fail: {report['fixtures_failed']}")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Evidence saved: {args.output}")
    return 1 if report["fixtures_failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
