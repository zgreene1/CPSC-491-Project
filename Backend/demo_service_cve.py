"""Offline, read-only CVE matching demonstration (no network scanning)."""
from __future__ import annotations

from pathlib import Path
from scanner_contracts import PortObservation
from service_vulnerability_matcher import load_catalog, match_observations

EXAMPLE_CATALOG = Path(__file__).resolve().parent.parent / "examples" / "example_curated_catalog.json"


def main() -> None:
    records = load_catalog(EXAMPLE_CATALOG)
    examples = [
        PortObservation(
            host_ip="127.0.0.1", port=8080, protocol="tcp", state="open",
            service="http", product="Apache httpd", version=version,
            confidence=0.98, fingerprint_method="http_headers",
        )
        for version in ("2.4.48", "2.4.49", "2.4.50")
    ]
    for observation in examples:
        matches = match_observations([observation], records)
        label = ", ".join(item.vulnerability_id + " (POTENTIAL)" for item in matches) or "no catalog match"
        print(f"Apache HTTP Server {observation.version}: {label}")
    print("Lab observations only. No real host was scanned or confirmed vulnerable.")


if __name__ == "__main__":
    main()
