from dataclasses import dataclass, field

@dataclass(frozen=True)
class ScanPortRecord:
    ip: str
    mac: str
    port: int
    protocol: str
    scan_state: str
    service_hint: str
    scanned_at: str

@dataclass(frozen=True)
class ScanRecord:
    scan_id: str
    target: str
    started_at: str
    completed_at: str
    scan_status: str
    host_count: int
    open_port_count: int