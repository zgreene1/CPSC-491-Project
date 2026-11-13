"""Offline demonstration of curated CVE matching (no network scanning).

Run from Backend on Linux, Windows, or macOS:
    python demo_service_cve.py

The observations below are synthetic service fingerprints and findings are
POTENTIAL version-range matches, not proof of a vulnerable installation.
"""
from __future__ import annotations

from scanner_contracts import PortObservation
from service_vulnerability_matcher import load_catalog, match_observations


SCENARIOS = (
    ("Apache httpd", "2.4.48"),
    ("Apache httpd", "2.4.49"),
    ("Apache httpd", "2.4.50"),
    ("Apache httpd", "2.4.51"),
    ("nginx", "1.20.0"),
    ("nginx", "1.20.1"),
)


def main() -> None:
    records = load_catalog()
    print(f"Offline CVE demo: {len(records)} vetted catalog records (not a full NVD feed).")
    for product, version in SCENARIOS:
        observation = PortObservation(
            host_ip="127.0.0.1", port=8080, protocol="tcp", state="open",
            service="http", product=product, version=version,
            confidence=0.98, fingerprint_method="http_headers",
        )
        findings = match_observations((observation,), records)
        labels = ", ".join(item.vulnerability_id for item in findings) or "no catalog match"
        print(f"{product:12} {version:8} -> {labels}")
    print("NOTE: Version-only matches are POTENTIAL. No real host was scanned.")
    print("No catalog match does not prove the service is secure.")


if __name__ == "__main__":
    main()
