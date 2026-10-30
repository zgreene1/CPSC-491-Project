from .scanner_contracts import ScanResult, ScanLifecycleState
from .scan_record_models import ScanRecord, ScanPortRecord

def scan_result_to_record(result: ScanResult) -> ScanRecord:
    """
    Convert a completed scan result into a ScanRecord.

    Initial scope:
    - One configured target
    - Completed scans
    - Existing database fields
    - No enriched service fingerprint storage
    """

    if result.state != ScanLifecycleState.COMPLETED:
        raise ValueError("Only completed scans are currently supported.")

    if not result.scan_id:
        raise ValueError("ScanResult must contain a Scan ID.")

    if not result.started_at or not result.completed_at:
        raise ValueError("Required timestamps are missing.")

    if len(result.configuration.targets) != 1:
        raise ValueError("Exactly one configured target is required.")

    port_records = []

    for port in result.ports:
        if not port.observed_at:
            raise ValueError("Port observation timestamp is missing.")

        if any(
            value is not None
            for value in (port.service, port.product, port.version)
        ):
            raise ValueError(
                "Enriched service fields are not supported by the current persistence schema.")

        port_record = ScanPortRecord(
            ip=port.host_ip,
            mac=port.host_mac,
            port=port.port,
            protocol=port.protocol,
            scan_state=port.state,
            service_hint=port.service_hint,
            scanned_at=port.observed_at
        )

        port_records.append(port_record)

        return ScanRecord(
            scan_id=result.scan_id,
            target=result.configuration.targets[0],
            started_at=result.started_at,
            completed_at=result.completed_at,
            scan_status=result.state.value.lower(),
            host_count=len(result.hosts),
            open_port_count=sum(
                port.state.lower() == "open"
                for port in result.ports
            ),
            ports=tuple(port_records)
        )