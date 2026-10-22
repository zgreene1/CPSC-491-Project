"""Minimal HTTP API wrapping ScannerCoordinator for frontend integration.

This module is intentionally a thin adapter: all real scanning logic stays in
scanner_coordinator.py / scanner_contracts.py. Its only job is to expose that
Python interface over HTTP so the frontend (running in a browser) can start a
scan, poll its progress, fetch its results, and list all known scans,
speaking the shared JSON contracts documented in
"DOCS Inprogress/S2-01 Shared Scanner Data Contracts.md".

Run directly for local development:

    python api_server.py

The server listens on http://127.0.0.1:8000 by default (override with the
PORT environment variable).

Scan state lives only in this process's memory — restarting the server
clears all scan history. That's an accepted limitation for now; there's no
persistence layer yet.
"""

from __future__ import annotations

import os
import threading
import uuid
from typing import Any, Dict, Optional, TypedDict

from flask import Flask, jsonify, request
from flask_cors import CORS

from scanner_contracts import ScanConfiguration
from scanner_coordinator import ScannerCoordinator

app = Flask(__name__)
CORS(app)


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
def list_scans():
    with _scans_lock:
        entries = list(_scans.items())

    scans = [_serialize_entry(scan_id, entry) for scan_id, entry in entries]
    scans.sort(key=lambda scan: scan.get("started_at") or "", reverse=True)

    return jsonify({"scans": scans})


@app.get("/api/scans/<scan_id>/progress")
def get_progress(scan_id: str):
    entry = _get_entry(scan_id)
    if entry is None:
        return jsonify({"error": "Scan not found."}), 404

    progress = entry["coordinator"].get_progress()
    if progress is None:
        return jsonify({"error": "Scan has not started."}), 404

    return jsonify(progress.to_dict())


@app.get("/api/scans/<scan_id>/results")
def get_results(scan_id: str):
    entry = _get_entry(scan_id)
    if entry is None:
        return jsonify({"error": "Scan not found."}), 404

    result = entry["coordinator"].get_result()
    if result is None:
        return jsonify({"status": "running"}), 202

    return jsonify(result.to_dict())


def main() -> None:
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=port, threaded=True)


if __name__ == "__main__":
    main()
