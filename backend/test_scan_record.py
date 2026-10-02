import sqlite3

import pytest

from .scan_record_database import Database
from .scan_record_models import ScanRecord, ScanPortRecord
from .scan_record_repository import ScanRepository, DuplicateScanError

# creating fixtures so that the databases and sample record don't have to be initialized
@pytest.fixture
def database(tmp_path):
    db_path = tmp_path / "test_scanner.db"

    database = Database(tmp_path)
    database.initialize()

    return database

@pytest.fixture
def sample_scan():
    return ScanRecord(
        scan_id="test-scan-001",
        target="127.0.0.1",
        started_at="2026-10-01T16:00:00",
        completed_at="2026-10-01T16:00:02",
        scan_status="completed",
        host_count=1,
        open_port_count=2,
        ports=(
            ScanPortRecord(
                ip="127.0.0.1",
                mac="local",
                port=22,
                protocol="tcp",
                scan_state="open",
                service_hint="ssh",
                scanned_at="2026-10-01T16:00:01"
            ),
            ScanPortRecord(
                ip="127.0.0.1",
                mac="local",
                port=80,
                protocol="tcp",
                scan_state="open",
                service_hint="http",
                scanned_at="2026-10-01T16:00:01"
            )
        )
    )

def test_initialize_creates_tables(database):
    """Test if the tables can be created"""
    with database.connect() as connection:
        rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            """
        ).fetchall()

    table_names = {row[0] for row in rows}

    assert "scans" in table_names
    assert "scan_ports" in table_names

def test_save_persists_scan(database, sample_scan):
    """Test if the record is saved in SQL"""
    repository = ScanRepository(database)

    repository.save(sample_scan)

    with database.connect() as connection:
        row = connection.execute(
            """
            SELECT
                scan_id,
                target,
                scan_status,
                host_count,
                open_port_count
            FROM scans
            WHERE scan_id = ?
            """,
            (sample_scan.scan_id,),
        ).fetchone()

    assert row is not None
    assert row[0] == "test_scan_001"
    assert row[1] == "127.0.0.1"
    assert row[2] == "completed"
    assert row[3] == 1
    assert row[4] == 2

def test_save_persists_scan_ports(database, sample_scan):
    """Test that both ports in the sample record are detected"""
    repository = ScanRepository(database)

    repository.save(sample_scan)

    with database.connect() as connection:
        rows = connection.execute(
            """
            SELECT
                ip,
                port,
                protocol,
                scan_state,
                service_hint
            FROM scan_ports
            WHERE scan_id = ?
            ORDER BY port
            """,
            (sample_scan.scan_id,),
        ).fetchall()

    assert len(rows) == 2
    assert rows[0][0] == "test_scan_001"
    assert rows[0][1] == 22
    assert rows[0][2] == "tcp"
    assert rows[0][3] == "open"
    assert rows[0][4] == "ssh"

    assert rows[1][1] == 80
    assert rows[1][4] == "http"

def test_save_allows_no_open_port_scan(database):
    """Test that a scan can be completed with 0 ports open"""
    zero_scan = ScanRecord(
        scan_id="test-scan-empty",
        target="127.0.0.1",
        started_at="2026-10-01T16:00:00",
        completed_at="2026-10-01T16:00:02",
        status="completed",
        host_count=1,
        open_port_count=0,
        ports=(),
    )

    repository = ScanRepository(database)
    
    repository.save(zero_scan)

    with database.connect() as connection:
        row = connection.execute(
            """
            SELECT scan_id
            FROM scans
            WHERE scan_id = ?
            """,
            (zero_scan.scan_id,),
        ).fetchone()

        port_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM scan_ports
            WHERE scan_id = ?
            """,
            (zero_scan.scan_id,),
        ).fetchone()[0]

    assert row is not None
    assert port_count == 0

def test_duplicate_scan_ids_rejected(database, sample_scan):
    repository = ScanRepository(database)

    repository.save(sample_scan)

    with pytest.raises(DuplicateScanError):
        repository.save(sample_scan)