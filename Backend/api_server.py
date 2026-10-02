"""Minimal HTTP API wrapping ScannerCoordinator for frontend integration.

This module is intentionally a thin adapter: all real scanning logic stays in
scanner_coordinator.py / scanner_contracts.py. Its only job is to expose that
Python interface over HTTP so the frontend (running in a browser) can start a
scan, poll its progress, and fetch its results, speaking the shared JSON
contracts documented in "DOCS Inprogress/S2-01 Shared Scanner Data Contracts.md".

Run directly for local development:

    python api_server.py

The server listens on http://127.0.0.1:8000 by default (override with the
PORT environment variable).
"""

from __future__ import annotations

import os
import threading
import uuid
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request
from flask_cors import CORS

from scanner_contracts import ScanConfiguration
from scanner_coordinator import ScannerCoordinator

app = Flask(__name__)
CORS(app)

_scans_lock = threading.Lock()
_scans: Dict[str, ScannerCoordinator] = {}


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
    )


def _get_coordinator(scan_id: str) -> Optional[ScannerCoordinator]:
    with _scans_lock:
        return _scans.get(scan_id)


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
        _scans[config.scan_id] = coordinator

    thread = threading.Thread(target=coordinator.run, args=(config,), daemon=True)
    thread.start()

    return jsonify({"scan_id": config.scan_id}), 202


@app.get("/api/scans/<scan_id>/progress")
def get_progress(scan_id: str):
    coordinator = _get_coordinator(scan_id)
    if coordinator is None:
        return jsonify({"error": "Scan not found."}), 404

    progress = coordinator.get_progress()
    if progress is None:
        return jsonify({"error": "Scan has not started."}), 404

    return jsonify(progress.to_dict())


@app.get("/api/scans/<scan_id>/results")
def get_results(scan_id: str):
    coordinator = _get_coordinator(scan_id)
    if coordinator is None:
        return jsonify({"error": "Scan not found."}), 404

    result = coordinator.get_result()
    if result is None:
        return jsonify({"status": "running"}), 202

    return jsonify(result.to_dict())


def main() -> None:
    port = int(os.environ.get("PORT", 8000))
    app.run(host="127.0.0.1", port=port, threaded=True)


if __name__ == "__main__":
    main()
