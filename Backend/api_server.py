"""Minimal HTTP API wrapping ScannerCoordinator for frontend integration.

This module is intentionally a thin adapter: all real scanning logic stays in
scanner_coordinator.py / scanner_contracts.py. Its only job is to expose that
Python interface over HTTP so the frontend (running in a browser) can start a
scan, poll its progress, fetch its results, list all known scans, and cancel
a scan in progress, speaking the shared JSON contracts documented in
"DOCS Inprogress/S2-01 Shared Scanner Data Contracts.md".

Also exposes /api/auth/login, /api/auth/logout, and /api/auth/me (see
auth.py) — these are always real. Whether the scan endpoints themselves
*require* a valid token is controlled by the REQUIRE_AUTH environment
variable (default off, see require_auth below), so existing unauthenticated
workflows keep working until the team opts in.

Run directly for local development:

    python api_server.py

The server listens on http://127.0.0.1:8000 by default (override with the
PORT environment variable).

Scan state lives only in this process's memory — restarting the server
clears all scan history. That's an accepted limitation for now; there's no
persistence layer yet.
"""

from __future__ import annotations

import functools
import os
import threading
import uuid
from typing import Any, Dict, Optional, TypedDict

from flask import Flask, jsonify, request
from flask_cors import CORS

import auth
from scanner_contracts import ScanConfiguration
from scanner_coordinator import ScannerCoordinator

app = Flask(__name__)

# CORS only affects browser-based cross-origin calls (not curl, pytest, or
# any other non-browser client), so restricting it to known frontend origins
# carries no regression risk for existing API testing/tooling.
_DEFAULT_FRONTEND_ORIGINS = "http://localhost:5173,https://dashing-truffle-eb234e.netlify.app"
_frontend_origins = [
    origin.strip()
    for origin in os.environ.get("FRONTEND_ORIGIN", _DEFAULT_FRONTEND_ORIGINS).split(",")
    if origin.strip()
]
CORS(app, origins=_frontend_origins)


def _require_auth_enabled() -> bool:
    return os.environ.get("REQUIRE_AUTH", "false").strip().lower() in ("1", "true", "yes")


def require_auth(view):
    """No-op unless REQUIRE_AUTH is truthy, so existing unauthenticated
    workflows are unaffected until the team opts in. Checked per-request
    (not once at import time) so it can be toggled in tests and without a
    server restart in local development."""

    @functools.wraps(view)
    def wrapper(*args: Any, **kwargs: Any):
        if not _require_auth_enabled():
            return view(*args, **kwargs)

        token = auth.extract_bearer_token(request.headers.get("Authorization"))
        try:
            auth.verify_token(token)
        except auth.AuthError as exc:
            return jsonify({"error": str(exc)}), 401

        return view(*args, **kwargs)

    return wrapper


class ScanEntry(TypedDict):
    coordinator: ScannerCoordinator
    config: ScanConfiguration


_scans_lock = threading.Lock()
_scans: Dict[str, ScanEntry] = {}


def _build_configuration(payload: Dict[str, Any]) -> ScanConfiguration:
    return ScanConfiguration(
        targets=payload.get("targets") or [],
        scan_mode=payload.get("scan_mode", "smart"),
        ports=payload.get("ports") or [],
        port_spec=payload.get("port_spec"),
        timeout_seconds=payload.get("timeout_seconds", 1.0),
        discovery_enabled=payload.get("discovery_enabled", True),
        discovery_network=payload.get("discovery_network"),
        include_local_host=payload.get("include_local_host", True),
        concurrency=payload.get("concurrency", 100),
        protocol=payload.get("protocol", "tcp"),
        include_non_open=payload.get("include_non_open", False),
        match_vulnerabilities=payload.get("match_vulnerabilities", False),
    )


def _get_entry(scan_id: str) -> Optional[ScanEntry]:
    with _scans_lock:
        return _scans.get(scan_id)


def _serialize_entry(scan_id: str, entry: ScanEntry) -> Dict[str, Any]:
    """Serialize one scan as a ScanResult-shaped payload, even if it hasn't
    finished yet (and so has no real ScanResult from the coordinator)."""
    coordinator = entry["coordinator"]
    config = entry["config"]

    result = coordinator.get_result()
    if result is not None:
        return result.to_dict()

    progress = coordinator.get_progress()
    return {
        "scan_id": scan_id,
        "configuration": config.to_dict(),
        "state": progress.state.value if progress else "CREATED",
        "started_at": config.created_at,
        "completed_at": None,
        "hosts": [],
        "ports": [],
        "progress": progress.to_dict() if progress else None,
        "errors": [],
        "metadata": None,
    }


@app.post("/api/scans")
@require_auth
def start_scan():
    payload = request.get_json(silent=True) or {}
    config = _build_configuration(payload)
    config.scan_id = config.scan_id or f"scan-{uuid.uuid4()}"

    validation_errors = config.validation_errors()
    if validation_errors:
        return jsonify({"errors": [error.to_dict() for error in validation_errors]}), 400

    coordinator = ScannerCoordinator()
    with _scans_lock:
        _scans[config.scan_id] = {"coordinator": coordinator, "config": config}

    thread = threading.Thread(target=coordinator.run, args=(config,), daemon=True)
    thread.start()

    return jsonify({"scan_id": config.scan_id}), 202


@app.get("/api/scans")
@require_auth
def list_scans():
    with _scans_lock:
        entries = list(_scans.items())

    scans = [_serialize_entry(scan_id, entry) for scan_id, entry in entries]
    scans.sort(key=lambda scan: scan.get("started_at") or "", reverse=True)

    return jsonify({"scans": scans})


@app.get("/api/scans/<scan_id>/progress")
@require_auth
def get_progress(scan_id: str):
    entry = _get_entry(scan_id)
    if entry is None:
        return jsonify({"error": "Scan not found."}), 404

    progress = entry["coordinator"].get_progress()
    if progress is None:
        return jsonify({"error": "Scan has not started."}), 404

    return jsonify(progress.to_dict())


@app.get("/api/scans/<scan_id>/results")
@require_auth
def get_results(scan_id: str):
    entry = _get_entry(scan_id)
    if entry is None:
        return jsonify({"error": "Scan not found."}), 404

    result = entry["coordinator"].get_result()
    if result is None:
        return jsonify({"status": "running"}), 202

    return jsonify(result.to_dict())


@app.post("/api/scans/<scan_id>/cancel")
@require_auth
def cancel_scan(scan_id: str):
    entry = _get_entry(scan_id)
    if entry is None:
        return jsonify({"error": "Scan not found."}), 404

    entry["coordinator"].cancel()

    progress = entry["coordinator"].get_progress()
    return jsonify(progress.to_dict() if progress else {"scan_id": scan_id, "cancellation_requested": True})


@app.post("/api/auth/login")
def login():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "")
    password = payload.get("password", "")

    if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    if not auth.verify_credentials(username, password):
        return jsonify({"error": "Invalid username or password."}), 401

    token, expires_at = auth.issue_token(username)
    return jsonify({"token": token, "username": username, "expires_at": expires_at})


@app.post("/api/auth/logout")
def logout():
    token = auth.extract_bearer_token(request.headers.get("Authorization"))
    if token:
        auth.invalidate_token(token)
    return jsonify({"status": "logged_out"})


@app.get("/api/auth/me")
def get_current_user():
    token = auth.extract_bearer_token(request.headers.get("Authorization"))
    try:
        username = auth.verify_token(token)
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), 401

    return jsonify({"username": username})


def main() -> None:
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=port, threaded=True)


if __name__ == "__main__":
    main()
