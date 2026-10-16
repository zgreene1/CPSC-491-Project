"""Detailed TCP/UDP outcomes and coordinator integration (localhost/mocks only).

No privileged operations, broadcasts, or external network traffic. Designed to
run under pytest/unittest on Linux, Windows, and macOS.
"""
from __future__ import annotations

import errno
import json
import socket
import threading
import unittest
from unittest.mock import patch

import scanner_Port_Scanner as tcp
import udp_port_scanner as udp
from scanner_Host_Discovery import Device
from scanner_contracts import ScanConfiguration, ScanLifecycleState
from scanner_coordinator import ScannerCoordinator

LOCAL = Device(ip="127.0.0.1", mac="local", source="test", last_seen="test")


class DetailedTCPTests(unittest.TestCase):
    def test_open_tcp_and_legacy_api(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            server.listen(4)
            port = server.getsockname()[1]
            outcome = tcp.probe_tcp_port(LOCAL, port, timeout=0.5)
            self.assertEqual((outcome.state, outcome.state_reason), ("open", "tcp_connect_success"))
            self.assertEqual(outcome.evidence_method, "tcp_connect")
            self.assertEqual(tcp.scan_tcp_port(LOCAL, port, timeout=0.5).state, "open")

    def test_refused_tcp_is_closed_and_legacy_api_omits_it(self):
        with patch.object(tcp.socket, "socket") as constructor:
            constructor.return_value.__enter__.return_value.connect_ex.return_value = errno.ECONNREFUSED
            outcome = tcp.probe_tcp_port(LOCAL, 32123, timeout=0.1)
            self.assertEqual(outcome.state, "closed")
            self.assertEqual(outcome.state_reason, "connection_refused")
            self.assertIsNone(tcp.scan_tcp_port(LOCAL, 32123, timeout=0.1))

    def test_timeout_is_unknown_not_filtered_or_closed(self):
        with patch.object(tcp.socket, "socket") as constructor:
            constructor.return_value.__enter__.return_value.connect_ex.return_value = errno.ETIMEDOUT
            outcome = tcp.probe_tcp_port(LOCAL, 32123, timeout=0.1)
            self.assertEqual((outcome.state, outcome.state_reason), ("unknown", "tcp_timeout"))

    def test_unexpected_socket_error_is_unknown(self):
        with patch.object(tcp.socket, "socket") as constructor:
            constructor.return_value.__enter__.return_value.connect_ex.side_effect = OSError(errno.ENETUNREACH, "no route")
            outcome = tcp.probe_tcp_port(LOCAL, 32123, timeout=0.1)
            self.assertEqual((outcome.state, outcome.state_reason), ("unknown", "socket_error"))

    def test_detailed_batch_includes_closed_and_open_only_keeps_open(self):
        with patch.object(tcp, "probe_tcp_port", side_effect=lambda dev, port, timeout: tcp.PortResult(
            ip=dev.ip, mac=dev.mac, port=port, protocol="tcp",
            state="open" if port == 101 else "closed",
            service_hint="unknown", scanned_at="test", state_reason="synthetic",
        )):
            complete = tcp.scan_open_ports([LOCAL], [101, 102], workers=2, include_non_open=True)
            self.assertEqual([(item.port, item.state) for item in complete], [(101, "open"), (102, "closed")])
            # Legacy scan_tcp_port is a separate compatibility interface.
            self.assertEqual(tcp.scan_open_ports([LOCAL], [], workers=2), [])

    def test_smart_related_expansion_ignores_non_open_outcomes(self):
        def fake_stage(devices, ports, **kwargs):
            # Stage 1 contains closed '80' and open '22', and must expand SSH,
            # not HTTP based on closed service hints.
            if 80 in ports:
                return [tcp.PortResult(LOCAL.ip, LOCAL.mac, 80, "tcp", "closed", "http", "t"),
                        tcp.PortResult(LOCAL.ip, LOCAL.mac, 22, "tcp", "open", "ssh", "t")]
            return []
        with patch.object(tcp, "scan_open_ports", side_effect=fake_stage), patch.object(tcp, "_scan_targets", return_value=[]) as stage_two:
            outcomes = tcp.smart_scan_open_ports([LOCAL], include_non_open=True, verbose=False)
            called_targets = list(stage_two.call_args.args[0])
            self.assertIn((LOCAL, 2200), called_targets)
            self.assertNotIn((LOCAL, 3001), called_targets)
            self.assertEqual({item.state for item in outcomes}, {"closed", "open"})


class DetailedUDPTests(unittest.TestCase):
    def test_udp_local_responder_is_open(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            def respond():
                payload, sender = listener.recvfrom(2048)
                listener.sendto(b"PONG", sender)
            thread = threading.Thread(target=respond, daemon=True)
            thread.start()
            outcome = udp.probe_udp_port(LOCAL, port, timeout=0.75)
            thread.join(timeout=2)
            self.assertEqual((outcome.state, outcome.state_reason), ("open", "udp_application_response"))

    def test_udp_timeout_is_inconclusive(self):
        with patch.object(udp.socket, "socket") as constructor:
            constructor.return_value.__enter__.return_value.recv.side_effect = socket.timeout()
            outcome = udp.probe_udp_port(LOCAL, 161, timeout=0.1)
            self.assertEqual((outcome.state, outcome.state_reason), ("open|filtered", "udp_timeout"))
            self.assertIsNone(udp.scan_udp_port(LOCAL, 161, timeout=0.1))
            constructor.return_value.__enter__.return_value.connect.assert_called_with((LOCAL.ip, 161))

    def test_os_reported_udp_refusal_is_closed(self):
        with patch.object(udp.socket, "socket") as constructor:
            constructor.return_value.__enter__.return_value.recv.side_effect = OSError(errno.ECONNREFUSED, "refused")
            outcome = udp.probe_udp_port(LOCAL, 161, timeout=0.1)
            self.assertEqual((outcome.state, outcome.state_reason), ("closed", "icmp_port_unreachable"))

    def test_udp_other_socket_errors_are_unknown(self):
        with patch.object(udp.socket, "socket") as constructor:
            constructor.return_value.__enter__.return_value.recv.side_effect = OSError(errno.ENETUNREACH, "no route")
            outcome = udp.probe_udp_port(LOCAL, 161, timeout=0.1)
            self.assertEqual((outcome.state, outcome.state_reason), ("unknown", "socket_error"))

    def test_empty_datagram_does_not_establish_service(self):
        with patch.object(udp.socket, "socket") as constructor:
            constructor.return_value.__enter__.return_value.recv.return_value = b""
            outcome = udp.probe_udp_port(LOCAL, 161, timeout=0.1)
            self.assertEqual((outcome.state, outcome.state_reason), ("unknown", "empty_udp_response"))

    def test_udp_cancellation_stops_submission(self):
        from threading import Event
        cancelled = Event()
        attempted = []
        def fake_probe(dev, port, timeout):
            attempted.append(port)
            return None
        def progress(dev, port, outcome):
            cancelled.set()
        with patch.object(udp, "scan_udp_port", side_effect=fake_probe):
            udp.scan_udp_ports([LOCAL], list(range(1000, 1020)), workers=1,
                               progress_callback=progress, cancel_event=cancelled)
        self.assertTrue(cancelled.is_set())
        self.assertLess(len(attempted), 20)

    def test_udp_batch_reports_progress_and_outcomes(self):
        outcomes = []
        with patch.object(udp, "probe_udp_port", side_effect=lambda dev, port, timeout: udp.UDPPortResult(
            dev.ip, dev.mac, port, "udp", "open|filtered", "unknown", "test", "udp_timeout", "udp_application_probe"
        )):
            results = udp.scan_udp_ports([LOCAL], [101, 102], workers=1,
                                         progress_callback=lambda dev, port, outcome: outcomes.append(port),
                                         include_non_open=True)
        self.assertEqual([result.port for result in results], [101, 102])
        self.assertEqual(set(outcomes), {101, 102})


class CoordinatorProtocolTests(unittest.TestCase):
    @staticmethod
    def config(port, **kwargs):
        return ScanConfiguration(
            targets=["127.0.0.1"], scan_mode="custom", ports=[port],
            discovery_enabled=False, timeout_seconds=0.6, concurrency=2,
            **kwargs,
        )

    def test_invalid_protocol_is_rejected(self):
        config = self.config(123, protocol="sctp")
        self.assertTrue(any("Protocol" in err.message for err in config.validation_errors()))
        self.assertEqual(ScannerCoordinator(identify_services=False).run(config).state, ScanLifecycleState.FAILED)

    def test_invalid_detailed_flag_is_rejected(self):
        config = self.config(123, include_non_open="yes")
        self.assertTrue(config.validation_errors())

    def test_coordinator_udp_only_real_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            def respond():
                data, sender = listener.recvfrom(2048)
                listener.sendto(b"PONG", sender)
            thread = threading.Thread(target=respond, daemon=True)
            thread.start()
            result = ScannerCoordinator().run(self.config(port, protocol="udp"))
            thread.join(timeout=2)
            self.assertEqual(result.state, ScanLifecycleState.COMPLETED)
            self.assertEqual([(p.protocol, p.state) for p in result.ports], [("udp", "open")])
            self.assertEqual((result.progress.ports_completed, result.progress.total_ports), (1, 1))
            self.assertEqual(result.progress.percent_complete, 100.0)
            json.loads(result.to_json())

    def test_coordinator_both_protocols_preserves_each_result(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            port = listener.getsockname()[1]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_listener:
                udp_listener.bind(("127.0.0.1", port))
                def respond():
                    payload, sender = udp_listener.recvfrom(2048)
                    udp_listener.sendto(b"PONG", sender)
                thread = threading.Thread(target=respond, daemon=True)
                thread.start()
                result = ScannerCoordinator(identify_services=False).run(self.config(port, protocol="both"))
                thread.join(timeout=2)
                self.assertEqual(result.state, ScanLifecycleState.COMPLETED)
                self.assertEqual({(item.protocol, item.state) for item in result.ports},
                                 {("tcp", "open"), ("udp", "open")})
                self.assertEqual((result.progress.ports_completed, result.progress.total_ports), (2, 2))

    def test_coordinator_tcp_detailed_non_open_has_reason(self):
        with patch.object(tcp, "probe_tcp_port", return_value=tcp.PortResult(
            LOCAL.ip, LOCAL.mac, 34567, "tcp", "closed", "unknown", "t", "connection_refused", "tcp_connect"
        )):
            result = ScannerCoordinator(identify_services=False).run(self.config(34567, include_non_open=True))
        self.assertEqual(result.state, ScanLifecycleState.COMPLETED)
        self.assertEqual(len(result.ports), 1)
        self.assertEqual((result.ports[0].state, result.ports[0].state_reason), ("closed", "connection_refused"))
        self.assertEqual(result.progress.ports_completed, 1)

    def test_udp_smart_mode_uses_common_profile(self):
        with patch("scanner_coordinator.scan_udp_ports", return_value=[]) as udp_mock:
            result = ScannerCoordinator(identify_services=False).run(ScanConfiguration(
                targets=["127.0.0.1"], discovery_enabled=False, scan_mode="smart", protocol="udp"
            ))
        self.assertEqual(result.state, ScanLifecycleState.COMPLETED)
        self.assertEqual(list(udp_mock.call_args.args[1]), list(udp.COMMON_UDP_PORTS))
        self.assertEqual(result.progress.total_ports, len(udp.COMMON_UDP_PORTS))


if __name__ == "__main__":
    unittest.main()
