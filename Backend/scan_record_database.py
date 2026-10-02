import sqlite3
from pathlib import Path

class Database:
    def __init__(self, path: self | Path):
        self.path = str(path)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript("""
                CREATE TABLE scans (
                    scan_id TEXT NOT NULL PRIMARY KEY,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    scan_status TEXT NOT NULL,
                    host_count INTEGER NOT NULL DEFAULT 0,
                    open_port_count INTEGER NOT NULL DEFAULT 0
                    )

                CREATE TABLE scan_ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    mac TEXT,
                    port INTEGER NOT NULL CHECK (port between 1 and 65535),
                    protocol TEXT NOT NULL,
                    scan_state TEXT NOT NULL,
                    service_hint TEXT,
                    scanned_at TEXT NOT NULL

                    FOREIGN KEY (scan_id) REFERENCES (scan_id)
                    ON DELETE CASCADE

                    UNIQUE(scan_id, ip, port, protocol)
                )""")