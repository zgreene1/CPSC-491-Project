"""Sprint 6 controlled accuracy and integration regression checks.

All active TCP services bind to ephemeral 127.0.0.1 ports. UDP timeout and
closed-port conditions are deterministic socket mocks; no external targets,
privileged probes, or real vulnerable services are used.

Run from Backend on Linux, Windows, or macOS:
    python -m pytest -v test_scanner_sprint6_accuracy.py
"""
from __future__ import annotations

import socket
import unittest
from dataclasses import replace
from unittest.mock import patch

import scanner_Port_Scanner as tcp
import scanner_Service_Fingerprint as fingerprint
import udp_port_scanner as udp
from scanner_Host_Discovery import Device
from scanner_adapters import apply_service_fingerprint, port_result_to_port_observation
from scanner_contracts import PortObservation, ScanConfiguration
from scanner_coordinator import ScannerCoordinator
from service_vulnerability_matcher import identify_software, load_catalog, match_observations
from test02_accuracy_support import LocalFixtureLab
from mock_services_lab import CVE_TEST_HANDLERS, QuietHandler


LOCAL = Device("127.0.0.1", "local", "sprint6", "test")


class GenericHTTPHandler(QuietHandler):
    """A valid HTTP service whose banner does not identify a known product."""

    def handle(self) -> None:
        self.recv_some()
        self.send(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: FixtureGateway\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n\r\n"
        )


class Sprint6AccuracyMatrixTests(unittest.TestCase):
    def _config(self, ports: list[int], **overrides) -> ScanConfiguration:
        values = dict(
            targets=["127.0.0.1"], scan_mode="custom", ports=ports,
            discovery_enabled=False, timeout_seconds=0.8, concurrency=4,
            match_vulnerabilities=True,
        )
        values.update(overrides)
        return ScanConfiguration(**values)

    def test_acc_01_to_04_affected_and_patched_cve_matrix(self):
        """Two Apache CVEs and one nginx CVE survive the complete scan pipeline."""
        with LocalFixtureLab(()) as lab:
            fixtures = (
                ("ACC-01", "apache_cve", "Apache httpd", "2.4.49",
                 {"CVE-2021-41773", "CVE-2021-42013"}),
                ("ACC-02", "apache_patched", "Apache httpd", "2.4.51", set()),
                ("ACC-03", "nginx_cve", "nginx", "1.20.0", {"CVE-2021-23017"}),
                ("ACC-04", "nginx_patched", "nginx", "1.20.1", set()),
            )
            for case_id, name, product, version, _expected in fixtures:
                lab.add_service(
                    name, CVE_TEST_HANDLERS[name], service="http",
                    product=product, version=version,
                )

            result = ScannerCoordinator(fingerprint_timeout=0.8).run(
                self._config([fixture.port for fixture in lab.fixtures])
            )
            self.assertEqual(result.state.value, "COMPLETED")
            by_port: dict[int, set[str]] = {}
            for finding in result.vulnerabilities:
                by_port.setdefault(finding.port, set()).add(finding.vulnerability_id)
                self.assertEqual(finding.status, "potential")
            for (case_id, _name, _product, _version, expected), fixture in zip(fixtures, lab.fixtures):
                with self.subTest(case=case_id):
                    self.assertEqual(by_port.get(fixture.port, set()), expected)

            # JSON contract keeps both Apache CVEs attached to the same port.
            wire = result.to_dict()
            apache_port = lab.fixtures[0].port
            serialized = {
                item["vulnerability_id"] for item in wire["vulnerabilities"]
                if item["port"] == apache_port
            }
            self.assertEqual(serialized, {"CVE-2021-41773", "CVE-2021-42013"})
            self.assertTrue(wire["configuration"]["match_vulnerabilities"])

    def test_acc_05_unknown_http_is_protocol_only(self):
        with LocalFixtureLab(()) as lab:
            fixture = lab.add_service(
                "generic_http", GenericHTTPHandler, service="http",
                product="", version=None,
            )
            result = tcp.scan_tcp_port(LOCAL, fixture.port, timeout=0.8)
            self.assertIsNotNone(result)
            observed = fingerprint.fingerprint_port(result, timeout=0.8)
            self.assertEqual(observed.service, "http")
            self.assertIsNone(observed.product)
            self.assertIsNone(observed.version)
            self.assertEqual(observed.detection_method, "http_headers")

    def test_acc_06_http_on_unusual_ephemeral_port_is_identified(self):
        with LocalFixtureLab(("apache",)) as lab:
            fixture = lab.fixtures[0]
            self.assertGreater(fixture.port, 1024)
            open_result = tcp.scan_tcp_port(LOCAL, fixture.port, timeout=0.8)
            self.assertIsNotNone(open_result)
            no_hint = replace(open_result, service_hint="unknown")
            observed = fingerprint.fingerprint_port(no_hint, timeout=0.8)
            self.assertEqual(
                (observed.service, observed.product, observed.version),
                ("http", "Apache httpd", "2.4.58"),
            )

    def test_acc_07_closed_tcp_is_not_reported_open(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as closed_socket:
            closed_socket.bind(("127.0.0.1", 0))
            port = int(closed_socket.getsockname()[1])
            results = tcp.scan_open_ports([LOCAL], [port], timeout=0.2, workers=1)
        self.assertEqual(results, [])

    def test_acc_08_misleading_ssh_hint_does_not_override_http(self):
        with LocalFixtureLab(("apache",)) as lab:
            result = tcp.scan_tcp_port(LOCAL, lab.fixtures[0].port, timeout=0.8)
            self.assertIsNotNone(result)
            observed = fingerprint.fingerprint_port(
                replace(result, service_hint="ssh"), timeout=0.8
            )
            self.assertEqual(
                (observed.service, observed.product, observed.version),
                ("http", "Apache httpd", "2.4.58"),
            )

    def test_acc_09_low_confidence_fingerprint_is_suppressed_from_cves(self):
        observation = PortObservation(
            host_ip="127.0.0.1", port=8080, protocol="tcp", state="open",
            service="http", product="Apache httpd", version="2.4.49",
            confidence=0.89, fingerprint_method="http_headers",
        )
        catalog = load_catalog()
        self.assertIsNone(identify_software(observation))
        self.assertEqual(match_observations([observation], catalog), [])

    def test_acc_10_silent_udp_is_inconclusive_and_not_open(self):
        with patch.object(udp.socket, "socket") as constructor:
            constructor.return_value.__enter__.return_value.recv.side_effect = socket.timeout()
            outcome = udp.probe_udp_port(LOCAL, 161, timeout=0.1)
            self.assertEqual((outcome.state, outcome.state_reason),
                             ("open|filtered", "udp_timeout"))
            self.assertIsNone(udp.scan_udp_port(LOCAL, 161, timeout=0.1))

    def test_fingerprint_adapter_preserves_identity_fields_for_json(self):
        base = tcp.PortResult(
            ip="127.0.0.1", mac="local", port=18080, protocol="tcp",
            state="open", service_hint="http", scanned_at="test",
        )
        observation = port_result_to_port_observation(base)
        fp = fingerprint.ServiceFingerprint(
            ip="127.0.0.1", mac="local", port=18080, protocol="tcp",
            service="http", product="Apache httpd", version="2.4.49",
            banner="Server: Apache/2.4.49", cpe=None, confidence=0.98,
            detection_method="http_headers", fingerprinted_at="test",
        )
        payload = apply_service_fingerprint(observation, fp).to_dict()
        self.assertEqual(payload["product"], "Apache httpd")
        self.assertEqual(payload["version"], "2.4.49")
        self.assertEqual(payload["fingerprint_method"], "http_headers")
        self.assertEqual(payload["software_id"], "apache:http_server")

    def test_api_configuration_preserves_explicit_matching_flag(self):
        # Keep this import local: API module initialization creates its normal
        # local SQLite database only when this integration boundary is tested.
        import api_server

        enabled = api_server._build_configuration({"match_vulnerabilities": True})
        disabled = api_server._build_configuration({})
        self.assertTrue(enabled.match_vulnerabilities)
        self.assertFalse(disabled.match_vulnerabilities)


if __name__ == "__main__":
    unittest.main()
