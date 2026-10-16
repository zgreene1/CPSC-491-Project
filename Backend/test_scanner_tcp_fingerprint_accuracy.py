"""TEST-02: TCP scan-mode and service/version detection accuracy regression.

All live sockets bind only to localhost ephemeral ports. No privileged access,
external networks, or environment-dependent fixed ports are required.

Run from Backend on Linux, Windows, or macOS:
    python -m pytest -q test_scanner_tcp_fingerprint_accuracy.py
    python -m unittest -v test_scanner_tcp_fingerprint_accuracy
"""
from __future__ import annotations

import socket
import unittest
from dataclasses import replace
from unittest.mock import patch

import scanner_Port_Scanner as tcp
import scanner_Service_Fingerprint as fingerprint
from scanner_Host_Discovery import Device
from test02_accuracy_support import LocalFixtureLab, OpaqueHandler


LOOPBACK = Device(ip="127.0.0.1", mac="local", source="test02", last_seen="test02")


class TcpScanModeAccuracyTests(unittest.TestCase):
    def test_port_profiles_and_custom_ranges(self):
        common = tcp.parse_ports("common")
        smart = tcp.parse_ports("smart")
        custom = tcp.parse_ports("443,22,22,8000-8002")
        full = tcp.parse_ports("all")

        self.assertEqual(common, list(tcp.COMMON_TCP_PORTS))
        self.assertEqual(smart, list(tcp.SMART_BASE_PORTS))
        self.assertEqual(custom, [22, 443, 8000, 8001, 8002])
        self.assertTrue(set(common).issubset(set(smart)))
        self.assertEqual(len(full), 65535)
        self.assertEqual((full[0], full[-1]), (1, 65535))
        # This verifies selection semantics without opening 65,535 sockets in CI.

    def test_custom_scan_detects_known_listeners_and_omits_closed_port(self):
        with LocalFixtureLab(("ssh", "apache", "nginx")) as lab:
            # A bound-but-not-listening TCP socket reserves a reliably closed
            # port without introducing a race with another local process.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as closed_socket:
                closed_socket.bind(("127.0.0.1", 0))
                closed_port = closed_socket.getsockname()[1]
                expected = {entry.port for entry in lab.fixtures}
                checked = []
                results = tcp.scan_open_ports(
                    devices=[LOOPBACK],
                    ports=[closed_port, *sorted(expected)],
                    timeout=0.8,
                    workers=4,
                    progress_callback=lambda _device, port, outcome: checked.append((port, outcome)),
                )

            self.assertEqual({result.port for result in results}, expected)
            self.assertEqual(len(results), 3)
            self.assertEqual(len(checked), 4)
            self.assertTrue(all(result.protocol == "tcp" and result.state == "open" for result in results))
            self.assertNotIn(closed_port, {result.port for result in results})

    def test_smart_mode_expands_to_related_port_with_real_listeners(self):
        with LocalFixtureLab(("apache", "nginx")) as lab:
            primary, related = (entry.port for entry in lab.fixtures)
            checked = []
            totals = []
            with patch.object(tcp, "SMART_BASE_PORTS", (primary,)), patch.object(
                tcp, "RELATED_PORT_GROUPS", (({primary}, {related}),)
            ):
                results = tcp.smart_scan_open_ports(
                    devices=[LOOPBACK],
                    timeout=0.8,
                    workers=2,
                    verbose=False,
                    progress_callback=lambda _device, port, _outcome: checked.append(port),
                    total_callback=totals.append,
                )
            self.assertEqual({result.port for result in results}, {primary, related})
            self.assertEqual(totals, [1, 2])
            self.assertCountEqual(checked, [primary, related])

    def test_smart_mode_fallback_checks_additional_ports_when_stage_one_empty(self):
        with LocalFixtureLab(("ssh",)) as lab:
            open_port = lab.fixtures[0].port
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as closed_socket:
                closed_socket.bind(("127.0.0.1", 0))
                closed_port = closed_socket.getsockname()[1]
                with patch.object(tcp, "SMART_BASE_PORTS", (closed_port,)), patch.object(
                    tcp, "SMART_FALLBACK_PORTS", (closed_port, open_port)
                ), patch.object(tcp, "RELATED_PORT_GROUPS", ()):
                    results = tcp.smart_scan_open_ports(
                        devices=[LOOPBACK], timeout=0.8, workers=2, verbose=False
                    )
            self.assertEqual([result.port for result in results], [open_port])


class ServiceFingerprintAccuracyTests(unittest.TestCase):
    def test_all_mock_service_signatures_match_expected_product_and_version(self):
        with LocalFixtureLab() as lab:
            self.assertEqual(len(lab.fixtures), 10)
            detected_ports = tcp.scan_open_ports(
                [LOOPBACK], [item.port for item in lab.fixtures], timeout=0.8, workers=10
            )
            self.assertEqual({item.port for item in detected_ports},
                             {item.port for item in lab.fixtures})
            identified = fingerprint.fingerprint_services(
                detected_ports, timeout=0.9, workers=8
            )
            by_port = {item.port: item for item in identified}
            self.assertEqual(len(by_port), len(lab.fixtures))
            for expected in lab.fixtures:
                with self.subTest(fixture=expected.name):
                    actual = by_port[expected.port]
                    self.assertEqual(actual.service, expected.service)
                    self.assertEqual(actual.product, expected.product)
                    self.assertEqual(actual.version, expected.version)
                    self.assertNotEqual(actual.detection_method, "port_hint")
                    self.assertGreaterEqual(actual.confidence, 0.7)

    def test_unrecognized_banner_does_not_invent_product_or_version(self):
        with LocalFixtureLab(()) as lab:
            unknown = lab.add_service(
                "opaque", OpaqueHandler, service="unknown", product="", version=None
            )
            found = tcp.scan_tcp_port(LOOPBACK, unknown.port, timeout=0.8)
            self.assertIsNotNone(found)
            # Do not rely on OS-specific socket.getservbyport() names.
            observation = fingerprint.fingerprint_port(
                replace(found, service_hint="unknown"), timeout=0.8
            )
            self.assertEqual(observation.service, "unknown")
            self.assertIsNone(observation.product)
            self.assertIsNone(observation.version)
            self.assertEqual(observation.detection_method, "passive_banner")

    def test_misleading_port_hint_does_not_override_http_fingerprint(self):
        with LocalFixtureLab(("apache",)) as lab:
            found = tcp.scan_tcp_port(LOOPBACK, lab.fixtures[0].port, timeout=0.8)
            self.assertIsNotNone(found)
            misleading = replace(found, service_hint="ssh")
            actual = fingerprint.fingerprint_port(misleading, timeout=0.8)
            self.assertEqual((actual.service, actual.product, actual.version),
                             ("http", "Apache httpd", "2.4.58"))
            self.assertNotEqual(actual.detection_method, "port_hint")

    def test_closed_unprobed_port_hint_does_not_claim_product_or_version(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as closed_socket:
            closed_socket.bind(("127.0.0.1", 0))
            port = closed_socket.getsockname()[1]
            fake_known_open = tcp.PortResult(
                ip="127.0.0.1", mac=None, port=port, protocol="tcp",
                state="open", service_hint="http", scanned_at="test02"
            )
            result = fingerprint.fingerprint_port(fake_known_open, timeout=0.15)
        self.assertEqual(result.detection_method, "port_hint")
        self.assertEqual(result.service, "http")
        self.assertIsNone(result.product)
        self.assertIsNone(result.version)
        self.assertLess(result.confidence, 0.5)


if __name__ == "__main__":
    unittest.main()
