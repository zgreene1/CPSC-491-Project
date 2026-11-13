from contextlib import closing

from .scanner_contracts import (
    ScanConfiguration,
    ScanResult,
    ScanLifecycleState,
    ScanProgress,
    HostObservation,
    PortObservation,
)

from .scan_record_database import Database
from .scan_record_repository import ScanRepository
from .scan_result_persistence_adapter import scan_result_to_record


def test_scanner_result_maps_to_sqlite(tmp_path):

    # Set up isolated test database.
    database = Database(tmp_path / "test_mapping.db")
    database.initialize()

    repository = ScanRepository(database)

    # Construct a genuine scanner configuration.
    configuration = ScanConfiguration(
        scan_id="sprint4-mapping-001",
        targets=["127.0.0.1"],
        scan_mode="custom",
        ports=[22, 443],
        discovery_enabled=False,
    )

    # Construct a genuine host observation.
    host = HostObservation(
        ip="127.0.0.1",
        discovery_source="manual_target",
        discovery_status="manual",
    )

    # Construct genuine port observations.
    open_port = PortObservation(
        host_ip="127.0.0.1",
        port=22,
        protocol="tcp",
        state="open",
        service_hint="ssh",
        observed_at="2026-10-29T17:00:01",
    )

    closed_port = PortObservation(
        host_ip="127.0.0.1",
        port=443,
        protocol="tcp",
        state="closed",
        observed_at="2026-10-29T17:00:02",
    )

    # Construct the shared ScanResult.
    result = ScanResult(
        configuration=configuration,
        state=ScanLifecycleState.COMPLETED,
        hosts=[host],
        ports=[open_port, closed_port],
        progress=ScanProgress(
            state=ScanLifecycleState.COMPLETED,
            scan_id="sprint4-mapping-001",
        ),
        errors=[],
        scan_id="sprint4-mapping-001",
        started_at="2026-10-29T17:00:00",
        completed_at="2026-10-29T17:00:03",
    )

    # Verify that both observations exist in the scanner result.
    assert len(result.ports) == 2
    assert {port.port for port in result.ports} == {22, 443}

    # Convert the scanner result.
    record = scan_result_to_record(result)

    # Verify that conversion preserved both observations.
    assert len(record.ports) == 2
    assert {port.port for port in record.ports} == {22, 443}

    # Persist through the actual repository.
    repository.save(record)

    # Retrieve stored data using SQL.
    with closing(database.connect()) as connection:

        scan_row = connection.execute(
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
            ("sprint4-mapping-001",),
        ).fetchone()

        port_rows = connection.execute(
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
            ("sprint4-mapping-001",),
        ).fetchall()

    # Verify the scan metadata.
    assert scan_row == (
        "sprint4-mapping-001",
        "127.0.0.1",
        "completed",
        1,
        1,
    )

    # Verify both observations were preserved.
    assert port_rows == [
        ("127.0.0.1", 22, "tcp", "open", "ssh"),
        ("127.0.0.1", 443, "tcp", "closed", None),
    ]

    # Verify that SQLite contains both observations.
    assert len(port_rows) == 2