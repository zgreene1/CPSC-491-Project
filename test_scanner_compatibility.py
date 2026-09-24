"""Privilege-free compatibility tests for scanner host/port/fingerprint modules.

Run on Linux, Windows, or macOS with:
    python -m unittest -v test_scanner_compatibility.py

These tests intentionally do not send ARP packets. Active Layer-2 discovery
should be covered separately by an integration test on an authorized network.
"""

import socket
import threading
import unittest
from unittest.mock import patch

import scanner_Host_Discovery as host_discovery
import scanner_Port_Scanner as port_scanner
import scanner_Service_Fingerprint as service_fingerprint


class FakeRouteTable:
    def __init__(self):
        self.routes = [
            (0, 0, "192.168.50.1", "test0", "192.168.50.25", 100),
            (
                int.from_bytes(bytes((192, 168, 50, 0)), "big"),
                int.from_bytes(bytes((255, 255, 255, 0)), "big"),
                "0.0.0.0",
                "test0",
                "192.168.50.25",
                0,
            ),
        ]

    def route(self, _destination):
        return "test0", "192.168.50.25", "192.168.50.1"


class NetworkContextTests(unittest.TestCase):
    def test_scapy_route_table_selects_connected_subnet(self):
        with patch.object(host_discovery.conf, "route", FakeRouteTable()):
            context = host_discovery.get_network_context()

        self.assertEqual(context.local_ip, "192.168.50.25")
        self.assertEqual(context.gateway, "192.168.50.1")
        self.assertEqual(context.network, "192.168.50.0/24")

    def test_large_detected_network_falls_back_to_local_24(self):
        selected = host_discovery.choose_scan_network(
            "10.0.5.20",
            detected_network="10.0.0.0/16",
        )
        self.assertEqual(selected, "10.0.5.0/24")

    def test_reasonable_detected_network_is_preserved(self):
        selected = host_discovery.choose_scan_network(
            "10.0.5.20",
            detected_network="10.0.4.0/23",
        )
        self.assertEqual(selected, "10.0.4.0/23")

    def test_oversized_requested_network_is_rejected(self):
        with self.assertRaises(ValueError):
            host_discovery.choose_scan_network(
                "10.0.5.20",
                requested_network="10.0.0.0/16",
            )


class NeighborTableParsingTests(unittest.TestCase):
    CASES = (
        (
            "Linux",
            "192.168.50.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n",
        ),
        (
            "Darwin",
            "? (192.168.50.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n",
        ),
        (
            "Windows",
            "  192.168.50.1          aa-bb-cc-dd-ee-ff     dynamic\n",
        ),
    )

    def test_supported_neighbor_formats(self):
        for system_name, command_output in self.CASES:
            with self.subTest(system=system_name):
                with patch.object(
                    host_discovery.platform,
                    "system",
                    return_value=system_name,
                ), patch.object(
                    host_discovery.subprocess,
                    "check_output",
                    return_value=command_output,
                ):
                    devices = host_discovery.get_neighbor_table()

                self.assertEqual(len(devices), 1)
                self.assertEqual(devices[0].ip, "192.168.50.1")
                self.assertEqual(devices[0].mac, "aa:bb:cc:dd:ee:ff")


class TcpScannerTests(unittest.TestCase):
    def test_tcp_connect_scan_detects_local_listener(self):
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

        device = host_discovery.Device(
            ip="127.0.0.1",
            mac="local",
            source="test",
            last_seen="test",
        )
        result = port_scanner.scan_tcp_port(device, open_port, timeout=0.5)

        self.assertIsNotNone(result)
        self.assertEqual(result.port, open_port)
        self.assertEqual(result.protocol, "tcp")
        self.assertEqual(result.state, "open")


# Service fingerprinting tests use local loopback listeners only. They do not
# contact external hosts and remain privilege-free on Linux, Windows, and macOS.
class ServiceFingerprintTests(unittest.TestCase):
    def _port_result(self, port, hint="unknown"):
        return port_scanner.PortResult(
            ip="127.0.0.1",
            mac="local",
            port=port,
            protocol="tcp",
            state="open",
            service_hint=hint,
            scanned_at="test",
        )

    def test_ssh_banner_detects_openssh_version(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve_once():
            connection, _ = listener.accept()
            connection.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
            connection.close()
            listener.close()

        threading.Thread(target=serve_once, daemon=True).start()
        result = service_fingerprint.fingerprint_port(
            self._port_result(port),
            timeout=0.75,
        )

        self.assertEqual(result.service, "ssh")
        self.assertEqual(result.product, "OpenSSH")
        self.assertEqual(result.version, "9.6p1")
        self.assertGreaterEqual(result.confidence, 0.95)

    def test_http_headers_detect_apache_version(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve_once():
            connection, _ = listener.accept()
            connection.settimeout(1.0)
            try:
                connection.recv(4096)
            except socket.timeout:
                pass
            connection.sendall(
                b"HTTP/1.0 200 OK\r\n"
                b"Server: Apache/2.4.58 (Unix)\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            connection.close()
            listener.close()

        threading.Thread(target=serve_once, daemon=True).start()
        result = service_fingerprint.fingerprint_port(
            self._port_result(port),
            timeout=0.75,
        )

        self.assertEqual(result.service, "http")
        self.assertEqual(result.product, "Apache httpd")
        self.assertEqual(result.version, "2.4.58")
        self.assertEqual(result.detection_method, "http_headers")

    def test_hint_fallback_does_not_claim_version(self):
        # A closed local port is sufficient here because fingerprint_port falls
        # back to the supplied service hint when no protocol evidence is found.
        temp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp.bind(("127.0.0.1", 0))
        port = temp.getsockname()[1]
        temp.close()

        result = service_fingerprint.fingerprint_port(
            self._port_result(port, hint="http"),
            timeout=0.1,
        )

        self.assertEqual(result.service, "http")
        self.assertIsNone(result.product)
        self.assertIsNone(result.version)
        self.assertEqual(result.detection_method, "port_hint")
        self.assertLess(result.confidence, 0.5)


if __name__ == "__main__":
    unittest.main()
