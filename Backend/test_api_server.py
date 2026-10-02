"""Tests for the thin HTTP API wrapping ScannerCoordinator (api_server.py)."""

from __future__ import annotations

import time
import unittest

import api_server


class ApiServerTests(unittest.TestCase):
    def setUp(self) -> None:
        api_server.app.testing = True
        self.client = api_server.app.test_client()
        with api_server._scans_lock:
            api_server._scans.clear()

    def test_start_scan_rejects_invalid_configuration(self) -> None:
        response = self.client.post(
            "/api/scans",
            json={
                "targets": ["127.0.0.1"],
                "scan_mode": "custom",
                "port_spec": "not-a-port",
                "discovery_enabled": False,
            },
        )
        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertTrue(body["errors"])
        self.assertEqual(body["errors"][0]["code"], "INVALID_CONFIGURATION")

    def test_start_scan_requires_a_target_when_discovery_disabled(self) -> None:
        response = self.client.post(
            "/api/scans",
            json={"targets": [], "scan_mode": "custom", "port_spec": "80", "discovery_enabled": False},
        )
        self.assertEqual(response.status_code, 400)

    def test_progress_and_results_are_not_found_for_unknown_scan(self) -> None:
        self.assertEqual(self.client.get("/api/scans/does-not-exist/progress").status_code, 404)
        self.assertEqual(self.client.get("/api/scans/does-not-exist/results").status_code, 404)

    def test_start_scan_runs_end_to_end_against_a_local_port(self) -> None:
        import socketserver
        import threading

        class EchoHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.recv(1024)

        server = socketserver.TCPServer(("127.0.0.1", 0), EchoHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)

        response = self.client.post(
            "/api/scans",
            json={
                "targets": ["127.0.0.1"],
                "scan_mode": "custom",
                "ports": [port],
                "discovery_enabled": False,
                "timeout_seconds": 1.0,
            },
        )
        self.assertEqual(response.status_code, 202)
        scan_id = response.get_json()["scan_id"]

        deadline = time.monotonic() + 5
        result = None
        while time.monotonic() < deadline:
            results_response = self.client.get(f"/api/scans/{scan_id}/results")
            if results_response.status_code == 200:
                result = results_response.get_json()
                break
            time.sleep(0.05)

        self.assertIsNotNone(result, "scan did not complete in time")
        self.assertEqual(result["state"], "COMPLETED")
        open_ports = [p["port"] for p in result["ports"] if p["state"] == "open"]
        self.assertIn(port, open_ports)


if __name__ == "__main__":
    unittest.main()
