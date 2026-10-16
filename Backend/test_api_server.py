"""Tests for the thin HTTP API wrapping ScannerCoordinator (api_server.py)."""

from __future__ import annotations

import socketserver
import threading
import time
import unittest

import api_server


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.recv(1024)


class ApiServerTests(unittest.TestCase):
    def setUp(self) -> None:
        api_server.app.testing = True
        self.client = api_server.app.test_client()
        with api_server._scans_lock:
            api_server._scans.clear()

    def _start_local_listener(self) -> int:
        """Start a throwaway TCP listener on an OS-assigned port and return it."""
        server = socketserver.TCPServer(("127.0.0.1", 0), EchoHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        return port

    def _start_scan_and_wait_for_results(self, port: int) -> dict:
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
        while time.monotonic() < deadline:
            results_response = self.client.get(f"/api/scans/{scan_id}/results")
            if results_response.status_code == 200:
                return results_response.get_json()
            time.sleep(0.05)

        self.fail("scan did not complete in time")

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

    def test_list_scans_is_empty_when_none_have_been_started(self) -> None:
        response = self.client.get("/api/scans")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"scans": []})

    def test_list_scans_includes_a_scan_still_in_progress(self) -> None:
        start_response = self.client.post(
            "/api/scans",
            json={
                "targets": ["127.0.0.1"],
                "scan_mode": "custom",
                "ports": [65000],
                "discovery_enabled": False,
                "timeout_seconds": 2.0,
            },
        )
        scan_id = start_response.get_json()["scan_id"]

        list_response = self.client.get("/api/scans")
        self.assertEqual(list_response.status_code, 200)
        scans = list_response.get_json()["scans"]
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["scan_id"], scan_id)
        self.assertEqual(scans[0]["configuration"]["targets"], ["127.0.0.1"])
        self.assertIn(scans[0]["state"], {"CREATED", "SCANNING", "COMPLETED"})

    def test_two_scans_started_back_to_back_get_different_ids(self) -> None:
        payload = {
            "targets": ["127.0.0.1"],
            "scan_mode": "custom",
            "ports": [65001],
            "discovery_enabled": False,
            "timeout_seconds": 0.5,
        }
        first = self.client.post("/api/scans", json=payload).get_json()["scan_id"]
        second = self.client.post("/api/scans", json=payload).get_json()["scan_id"]
        self.assertNotEqual(first, second)

    def test_start_scan_runs_end_to_end_against_a_local_port(self) -> None:
        port = self._start_local_listener()
        result = self._start_scan_and_wait_for_results(port)

        self.assertEqual(result["state"], "COMPLETED")
        open_ports = [p["port"] for p in result["ports"] if p["state"] == "open"]
        self.assertIn(port, open_ports)

    def test_list_scans_includes_a_completed_scan_with_its_findings(self) -> None:
        port = self._start_local_listener()
        result = self._start_scan_and_wait_for_results(port)
        scan_id = result["scan_id"]

        list_response = self.client.get("/api/scans")
        scans = list_response.get_json()["scans"]
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["scan_id"], scan_id)
        self.assertEqual(scans[0]["state"], "COMPLETED")
        open_ports = [p["port"] for p in scans[0]["ports"] if p["state"] == "open"]
        self.assertIn(port, open_ports)


if __name__ == "__main__":
    unittest.main()
