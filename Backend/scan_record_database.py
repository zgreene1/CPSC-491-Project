import sqlite3
from contextlib import closing
from pathlib import Path

class Database:
    def __init__(self, path):
        self.path = str(path)

    def connect(self) -> sqlite3.Connection:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        with closing(self.connect()) as connection, connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT NOT NULL PRIMARY KEY,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    scan_status TEXT NOT NULL,
                    host_count INTEGER NOT NULL DEFAULT 0,
                    open_port_count INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS scan_ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    mac TEXT,
                    port INTEGER NOT NULL CHECK (port between 1 and 65535),
                    protocol TEXT NOT NULL,
                    scan_state TEXT NOT NULL,
                    service_hint TEXT,
                    scanned_at TEXT NOT NULL,

                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                    ON DELETE CASCADE,

                    UNIQUE(scan_id, ip, port, protocol)
                );

                CREATE TABLE IF NOT EXISTS scan_results (
                    scan_id TEXT NOT NULL PRIMARY KEY,
                    started_at TEXT,
                    state TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                    ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_scan_results_started_at
                ON scan_results(started_at);
            """)
