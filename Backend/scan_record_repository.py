import sqlite3

from .scan_record_database import Database
from .scan_record_models import ScanRecord

class DuplicateScanError(Exception):
    """Raised when there is already a version of the database made"""
    pass

class ScanRepository:
    def __init__(self, database: Database):
        self.database = database

    def save(self, scan: ScanRecord) -> str:
        try:
            with self.database.connect() as connection:
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
                        scan.targeted_at,
                        scan.status,
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
                            result.state,
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