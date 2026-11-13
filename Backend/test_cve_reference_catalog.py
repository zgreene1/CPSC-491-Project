"""Offline regression against vendor/NVD-reviewed CVE version boundaries.

Run on Linux, Windows, or macOS without network access, Scapy, or Flask:
    python -m unittest -v test_cve_reference_catalog

Only the local curated catalog is tested; no live CVE/NVD API is queried and
no real vulnerable service is deployed.
"""
from __future__ import annotations

import socket
import unittest

from mock_services_lab import (
    CVE_TEST_HANDLERS, CVE_TEST_SERVICES, ThreadingTCPServer,
)
from scanner_contracts import PortObservation
from service_vulnerability_matcher import (
    DEFAULT_CATALOG, load_catalog, match_observations,
)


class CuratedCVERecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.records = load_catalog(DEFAULT_CATALOG)

    def observation(self, product: str, version: str, **overrides) -> PortObservation:
        values = dict(
            host_ip="127.0.0.1", port=18084, protocol="tcp", state="open",
            service="http", product=product, version=version, confidence=0.98,
            fingerprint_method="http_headers",
        )
        values.update(overrides)
        return PortObservation(**values)

    def ids_for(self, product: str, version: str, **kwargs) -> set[str]:
        result = match_observations([self.observation(product, version, **kwargs)], self.records)
        return {finding.vulnerability_id for finding in result}

    def test_production_catalog_contains_reviewed_cves_only(self):
        self.assertEqual(
            {record.vulnerability_id for record in self.records},
            {"CVE-2021-41773", "CVE-2021-42013", "CVE-2021-23017"},
        )
        self.assertTrue(all(record.source_url.startswith("https://") for record in self.records))

    def test_apache_version_boundaries_from_official_advisory(self):
        # https://httpd.apache.org/security/vulnerabilities_24.html
        scenarios = [
            ("2.4.48", set()),
            ("2.4.49", {"CVE-2021-41773", "CVE-2021-42013"}),
            ("2.4.50", {"CVE-2021-42013"}),
            ("2.4.51", set()),
            ("2.4.58", set()),
        ]
        for version, expected in scenarios:
            with self.subTest(version=version):
                self.assertEqual(self.ids_for("Apache httpd", version), expected)

    def test_nginx_version_boundaries_from_official_advisory(self):
        # https://nginx.org/en/security_advisories.html
        # nginx 1.20.1 and mainline 1.21.0 contain the fix.
        for version, expected in [
            ("0.6.17", False),
            ("0.6.18", True),
            ("1.19.10", True),
            ("1.20.0", True),
            ("1.20.1", False),
            ("1.21.0", False),
            ("1.24.0", False),
        ]:
            with self.subTest(version=version):
                expected_ids = {"CVE-2021-23017"} if expected else set()
                self.assertEqual(self.ids_for("nginx", version), expected_ids)

    def test_matching_requires_high_confidence_valid_tcp_fingerprint(self):
        cases = [
            dict(confidence=0.4),
            dict(fingerprint_method="port_hint"),
            dict(fingerprint_method=None),
            dict(state="closed"),
            dict(protocol="udp"),
            dict(version="2.4.49-vendorpatch"),
            dict(version=None),
            dict(product="unrecognized"),
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                self.assertEqual(
                    match_observations(
                        [self.observation(**{**{"product": "Apache httpd", "version": "2.4.49"}, **overrides})],
                        self.records,
                    ),
                    [],
                )

    def test_matches_stay_potential_and_deduplicate(self):
        observation = self.observation("Apache httpd", "2.4.49")
        matches = match_observations([observation, observation], self.records)
        self.assertEqual(len(matches), 2)
        self.assertEqual({m.status for m in matches}, {"potential"})
        self.assertTrue(all(m.fingerprint_confidence == 0.98 for m in matches))
        self.assertTrue(all(m.source_url.startswith("https://") for m in matches))

    def test_different_product_does_not_inherit_apache_matches(self):
        self.assertEqual(self.ids_for("nginx", "2.4.49"), set())
        self.assertEqual(self.ids_for("Microsoft IIS", "2.4.49"), set())


class CVEBannerFixtureTests(unittest.TestCase):
    def test_local_mock_banners_provide_both_affected_and_patched_versions(self):
        # Uses only loopback sockets; these servers merely send synthetic
        # headers and are NOT actually vulnerable product installations.
        for fixture in CVE_TEST_SERVICES:
            with self.subTest(service=fixture.handler_name):
                handler = CVE_TEST_HANDLERS[fixture.handler_name]
                server = ThreadingTCPServer(("127.0.0.1", 0), handler)
                server.timeout = 1.0
                try:
                    with socket.create_connection(server.server_address, timeout=1.0) as client:
                        client.settimeout(1.0)
                        client.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                        server.handle_request()
                        banner = client.recv(4096).decode("ascii")
                    expected_header = (
                        "Apache/" if fixture.handler_name.startswith("apache")
                        else "nginx/"
                    ) + fixture.version
                    self.assertIn(f"Server: {expected_header}", banner)
                finally:
                    server.server_close()


if __name__ == "__main__":
    unittest.main()
