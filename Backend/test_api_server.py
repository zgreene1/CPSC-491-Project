
"""Tests for the thin HTTP API wrapping ScannerCoordinator (api_server.py)."""

from __future__ import annotations

import os
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
        thread = threading.Thread(
            target=server.serve_forever,
            daemon=True,
        )
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
            results_response = self.client.get(
                f"/api/scans/{scan_id}/results"
            )

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
        self.assertEqual(
            body["errors"][0]["code"],
            "INVALID_CONFIGURATION",
        )

    def test_start_scan_requires_a_target_when_discovery_disabled(self) -> None:
        response = self.client.post(
            "/api/scans",
            json={
                "targets": [],
                "scan_mode": "custom",
                "port_spec": "80",
                "discovery_enabled": False,
            },
        )

        self.assertEqual(response.status_code, 400)

    # ==========================================================
    # Sprint 4 - Adreana Navarro
    # API Validation and Integration Testing
    # October 29, 2026
    # ==========================================================

    def test_start_scan_rejects_invalid_port_range(self) -> None:
        """Verify the API rejects ports outside the valid range."""
        response = self.client.post(
            "/api/scans",
            json={
                "targets": ["127.0.0.1"],
                "scan_mode": "custom",
                "port_spec": "70000",
                "discovery_enabled": False,
            },
        )

        self.assertEqual(response.status_code, 400)

        body = response.get_json()
        self.assertTrue(body["errors"])

    def test_start_scan_rejects_invalid_scan_mode(self) -> None:
        """Verify unsupported scan modes are rejected by the API."""
        response = self.client.post(
            "/api/scans",
            json={
                "targets": ["127.0.0.1"],
                "scan_mode": "invalid-mode",
                "ports": [80],
                "discovery_enabled": False,
            },
        )

        self.assertEqual(response.status_code, 400)

        body = response.get_json()
        self.assertTrue(body["errors"])

    def test_invalid_configuration_does_not_create_scan(self) -> None:
        """Verify rejected scan requests are not added to scan history."""
        response = self.client.post(
            "/api/scans",
            json={
                "targets": ["127.0.0.1"],
                "scan_mode": "custom",
                "port_spec": "invalid",
                "discovery_enabled": False,
            },
        )

        self.assertEqual(response.status_code, 400)

        list_response = self.client.get("/api/scans")

        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(
            list_response.get_json(),
            {"scans": []},
        )

    # ==========================================================
    # Existing API Integration Tests
    # ==========================================================

    def test_progress_and_results_are_not_found_for_unknown_scan(self) -> None:
        self.assertEqual(
            self.client.get(
                "/api/scans/does-not-exist/progress"
            ).status_code,
            404,
        )

        self.assertEqual(
            self.client.get(
                "/api/scans/does-not-exist/results"
            ).status_code,
            404,
        )

    def test_list_scans_is_empty_when_none_have_been_started(self) -> None:
        response = self.client.get("/api/scans")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"scans": []},
        )

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

        self.assertEqual(start_response.status_code, 202)
        scan_id = start_response.get_json()["scan_id"]

        list_response = self.client.get("/api/scans")

        self.assertEqual(list_response.status_code, 200)

        scans = list_response.get_json()["scans"]

        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["scan_id"], scan_id)

        self.assertEqual(
            scans[0]["configuration"]["targets"],
            ["127.0.0.1"],
        )

        self.assertIn(
            scans[0]["state"],
            {"CREATED", "SCANNING", "COMPLETED"},
        )

    def test_two_scans_started_back_to_back_get_different_ids(self) -> None:
        payload = {
            "targets": ["127.0.0.1"],
            "scan_mode": "custom",
            "ports": [65001],
            "discovery_enabled": False,
            "timeout_seconds": 0.5,
        }

        first_response = self.client.post(
            "/api/scans",
            json=payload,
        )

        second_response = self.client.post(
            "/api/scans",
            json=payload,
        )

        self.assertEqual(first_response.status_code, 202)
        self.assertEqual(second_response.status_code, 202)

        first = first_response.get_json()["scan_id"]
        second = second_response.get_json()["scan_id"]

        self.assertNotEqual(first, second)

    def test_start_scan_runs_end_to_end_against_a_local_port(self) -> None:
        port = self._start_local_listener()

        result = self._start_scan_and_wait_for_results(port)

        self.assertEqual(result["state"], "COMPLETED")

        open_ports = [
            p["port"]
            for p in result["ports"]
            if p["state"] == "open"
        ]

        self.assertIn(port, open_ports)

    def test_list_scans_includes_a_completed_scan_with_its_findings(self) -> None:
        port = self._start_local_listener()

        result = self._start_scan_and_wait_for_results(port)
        scan_id = result["scan_id"]

        list_response = self.client.get("/api/scans")

        self.assertEqual(list_response.status_code, 200)

        scans = list_response.get_json()["scans"]

        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["scan_id"], scan_id)
        self.assertEqual(scans[0]["state"], "COMPLETED")

        open_ports = [
            p["port"]
            for p in scans[0]["ports"]
            if p["state"] == "open"
        ]

        self.assertIn(port, open_ports)


class AuthEndpointTests(unittest.TestCase):
    """SOC 2 CC6.1 — the auth endpoints themselves are always real,
    independent of whether REQUIRE_AUTH enforces them on scan endpoints."""

    def setUp(self) -> None:
        api_server.app.testing = True
        self.client = api_server.app.test_client()
        os.environ["AUTH_USERNAME"] = "analyst"
        os.environ["AUTH_PASSWORD"] = "test-password-123"

    def tearDown(self) -> None:
        os.environ.pop("AUTH_USERNAME", None)
        os.environ.pop("AUTH_PASSWORD", None)

    def test_login_with_correct_credentials_succeeds(self) -> None:
        response = self.client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": "test-password-123"},
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["username"], "analyst")
        self.assertTrue(body["token"])

    def test_login_with_wrong_password_is_rejected(self) -> None:
        response = self.client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": "wrong"},
        )

        self.assertEqual(response.status_code, 401)

    def test_login_requires_both_fields(self) -> None:
        response = self.client.post("/api/auth/login", json={"username": "analyst"})

        self.assertEqual(response.status_code, 400)

    def test_me_accepts_a_token_from_a_real_login(self) -> None:
        login_response = self.client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": "test-password-123"},
        )
        token = login_response.get_json()["token"]

        me_response = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})

        self.assertEqual(me_response.status_code, 200)
        self.assertEqual(me_response.get_json()["username"], "analyst")

    def test_me_rejects_a_missing_token(self) -> None:
        response = self.client.get("/api/auth/me")

        self.assertEqual(response.status_code, 401)

    def test_me_rejects_a_tampered_token(self) -> None:
        login_response = self.client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": "test-password-123"},
        )
        token = login_response.get_json()["token"]
        tampered = token[:-1] + ("x" if token[-1] != "x" else "y")

        response = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {tampered}"})

        self.assertEqual(response.status_code, 401)

    def test_logout_invalidates_the_token_for_future_requests(self) -> None:
        login_response = self.client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": "test-password-123"},
        )
        token = login_response.get_json()["token"]
        auth_header = {"Authorization": f"Bearer {token}"}

        self.assertEqual(self.client.get("/api/auth/me", headers=auth_header).status_code, 200)

        logout_response = self.client.post("/api/auth/logout", headers=auth_header)
        self.assertEqual(logout_response.status_code, 200)

        self.assertEqual(self.client.get("/api/auth/me", headers=auth_header).status_code, 401)


class RequireAuthEnforcementTests(unittest.TestCase):
    """SOC 2 CC6.1 — REQUIRE_AUTH is opt-in: unset (today's default) must
    leave every scan endpoint exactly as unauthenticated as before."""

    def setUp(self) -> None:
        api_server.app.testing = True
        self.client = api_server.app.test_client()
        with api_server._scans_lock:
            api_server._scans.clear()
        os.environ["AUTH_USERNAME"] = "analyst"
        os.environ["AUTH_PASSWORD"] = "test-password-123"

    def tearDown(self) -> None:
        os.environ.pop("REQUIRE_AUTH", None)
        os.environ.pop("AUTH_USERNAME", None)
        os.environ.pop("AUTH_PASSWORD", None)

    def _issue_token(self) -> str:
        response = self.client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": "test-password-123"},
        )
        return response.get_json()["token"]

    def test_scan_endpoints_are_unauthenticated_when_require_auth_is_unset(self) -> None:
        os.environ.pop("REQUIRE_AUTH", None)

        self.assertEqual(self.client.get("/api/scans").status_code, 200)

        start_response = self.client.post(
            "/api/scans",
            json={
                "targets": ["127.0.0.1"],
                "scan_mode": "custom",
                "ports": [65002],
                "discovery_enabled": False,
                "timeout_seconds": 0.5,
            },
        )
        self.assertEqual(start_response.status_code, 202)

    def test_scan_endpoints_reject_unauthenticated_requests_when_require_auth_is_enabled(self) -> None:
        os.environ["REQUIRE_AUTH"] = "true"

        self.assertEqual(self.client.get("/api/scans").status_code, 401)

        start_response = self.client.post(
            "/api/scans",
            json={
                "targets": ["127.0.0.1"],
                "scan_mode": "custom",
                "ports": [65003],
                "discovery_enabled": False,
                "timeout_seconds": 0.5,
            },
        )
        self.assertEqual(start_response.status_code, 401)

    def test_scan_endpoints_accept_a_valid_token_when_require_auth_is_enabled(self) -> None:
        token = self._issue_token()
        os.environ["REQUIRE_AUTH"] = "true"

        response = self.client.get(
            "/api/scans",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_scan_endpoints_reject_an_invalid_token_when_require_auth_is_enabled(self) -> None:
        os.environ["REQUIRE_AUTH"] = "true"

        response = self.client.get(
            "/api/scans",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        self.assertEqual(response.status_code, 401)

    def test_auth_endpoints_themselves_stay_unaffected_by_require_auth(self) -> None:
        os.environ["REQUIRE_AUTH"] = "true"

        response = self.client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": "test-password-123"},
        )
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
