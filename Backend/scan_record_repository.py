import json
import sqlite3
from contextlib import closing

try:
    from .scan_record_database import Database
    from .scan_record_models import ScanRecord
except ImportError:  # Running api_server.py directly from Backend/
    from scan_record_database import Database
    from scan_record_models import ScanRecord

class DuplicateScanError(Exception):
    """Raised when there is already a version of the database made"""
    pass

class ScanRepository:
    def __init__(self, database: Database):
        self.database = database

    def save(self, scan: ScanRecord) -> str:
        try:
            with closing(self.database.connect()) as connection, connection:
                connection.execute("""
                    INSERT INTO scans (
                        scan_id,
                        target,
                        started_at,
                        completed_at,
                        scan_status,
                        host_count,
                        open_port_count
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scan.scan_id,
                        scan.target,
                        scan.started_at,
                        scan.completed_at,
                        scan.scan_status,
                        scan.host_count,
                        scan.open_port_count
                    ),
                )

                connection.executemany("""
                    INSERT INTO scan_ports (
                        scan_id,
                        ip,
                        mac,
                        port,
                        protocol,
                        scan_state,
                        service_hint,
                        scanned_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    [
                        (
                            scan.scan_id,
                            result.ip,
                            result.mac,
                            result.port,
                            result.protocol,
                            result.scan_state,
                            result.service_hint,
                            result.scanned_at,
                        )
                        for result in scan.ports
                    ]
                )

        except sqlite3.IntegrityError as e:
            if "scans.scan_id" in str(e):
                raise DuplicateScanError(
                    f"Scan {scan.scan_id!r} already exists."
                ) from e
            raise

        return scan.scan_id

    def save_result_payload(self, result: dict) -> str:
        """Persist the complete API result alongside searchable scan totals.

        Keeping the contract JSON means newer result fields (fingerprints,
        vulnerability findings, progress and errors) survive without being
        silently discarded by the older normalized record schema.
        """
        scan_id = result.get("scan_id")
        if not isinstance(scan_id, str) or not scan_id:
            raise ValueError("Scan result must contain a scan_id.")
        configuration = result.get("configuration") or {}
        targets = configuration.get("targets") or []
        ports = result.get("ports") or []
        hosts = result.get("hosts") or []
        state = str(result.get("state") or "UNKNOWN").lower()
        started_at = result.get("started_at") or ""
        completed_at = result.get("completed_at") or started_at
        target = ", ".join(str(item) for item in targets) or ""
        encoded = json.dumps(result, separators=(",", ":"), ensure_ascii=False)

        with closing(self.database.connect()) as connection, connection:
            connection.execute(
                """INSERT INTO scans
                   (scan_id, target, started_at, completed_at, scan_status,
                    host_count, open_port_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, target, started_at, completed_at, state, len(hosts),
                 sum(1 for port in ports if str(port.get("state", "")).lower() == "open")),
            )
            connection.executemany(
                """INSERT INTO scan_ports
                   (scan_id, ip, mac, port, protocol, scan_state, service_hint, scanned_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (scan_id, port.get("host_ip", ""), port.get("host_mac"),
                     port.get("port"), port.get("protocol", "tcp"),
                     port.get("state", "unknown"), port.get("service_hint"),
                     port.get("observed_at") or started_at)
                    for port in ports
                ],
            )
            connection.execute(
                """INSERT INTO scan_results (scan_id, started_at, state, result_json)
                   VALUES (?, ?, ?, ?)""",
                (scan_id, started_at, state, encoded),
            )
        return scan_id

    def get_result_payload(self, scan_id: str) -> dict | None:
        with closing(self.database.connect()) as connection:
            row = connection.execute(
                "SELECT result_json FROM scan_results WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def list_result_payloads(self) -> list[dict]:
        with closing(self.database.connect()) as connection:
            rows = connection.execute(
                "SELECT result_json FROM scan_results ORDER BY started_at DESC, scan_id DESC"
            ).fetchall()
        return [json.loads(row[0]) for row in rows]
