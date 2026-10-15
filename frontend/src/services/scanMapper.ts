import type { ScanProgressState, ScanRecord, ScanStatus, Vulnerability } from "../types/scan";

/**
 * Maps the shared backend contracts (see
 * "DOCS Inprogress/S2-01 Shared Scanner Data Contracts.md") onto the
 * frontend's domain types. The backend does not yet perform CVE/vulnerability
 * matching (see Backend/README.md "In Development / Planned"), so every real
 * port observation is surfaced as "unclassified" rather than inventing a
 * severity/CVE/CVSS the backend hasn't actually determined.
 */

interface ApiPortObservation {
  host_ip: string;
  host_mac: string | null;
  port: number;
  protocol: string;
  state: string;
  service_hint: string | null;
  service: string | null;
  product: string | null;
  version: string | null;
  banner: string | null;
  confidence: number | null;
  observed_at: string | null;
}

interface ApiScanProgress {
  scan_id: string | null;
  state: string;
  hosts_discovered: number;
  hosts_completed: number;
  ports_completed: number;
  total_ports: number;
  percent_complete: number;
  current_host: string | null;
  current_port: number | null;
  elapsed_seconds: number;
  cancellation_requested: boolean;
}

interface ApiScanResult {
  scan_id: string | null;
  configuration: { targets: string[] };
  state: string;
  started_at: string | null;
  completed_at: string | null;
  ports: ApiPortObservation[];
  progress: ApiScanProgress;
}

const LIFECYCLE_TO_STATUS: Record<string, ScanStatus> = {
  CREATED: "queued",
  DISCOVERING: "running",
  SCANNING: "running",
  IDENTIFYING: "running",
  MATCHING: "running",
  COMPLETED: "completed",
  FAILED: "failed",
  CANCELLED: "cancelled",
};

export function mapLifecycleState(state: string): ScanStatus {
  return LIFECYCLE_TO_STATUS[state] ?? "queued";
}

export function mapApiProgress(progress: ApiScanProgress): ScanProgressState {
  return {
    scanId: progress.scan_id ?? "",
    status: mapLifecycleState(progress.state),
    percentComplete: progress.percent_complete,
    hostsDiscovered: progress.hosts_discovered,
    hostsCompleted: progress.hosts_completed,
    portsCompleted: progress.ports_completed,
    totalPorts: progress.total_ports,
    currentHost: progress.current_host,
    currentPort: progress.current_port,
    elapsedSeconds: progress.elapsed_seconds,
    cancellationRequested: progress.cancellation_requested,
  };
}

function describeService(port: ApiPortObservation): string {
  if (port.product) {
    return port.version ? `${port.product} ${port.version}` : port.product;
  }
  return port.service ?? port.service_hint ?? "unknown";
}

function mapPortToVulnerability(port: ApiPortObservation): Vulnerability {
  return {
    id: `${port.host_ip}-${port.port}`,
    cve: "Not yet assessed",
    severity: "unclassified",
    host: port.host_ip,
    port: port.port,
    service: describeService(port),
    cvss: 0,
    description: port.banner
      ? `Open port detected. Observed banner: ${port.banner}`
      : "Open port detected. Vulnerability matching is not implemented yet.",
    remediation: "No automated remediation guidance available yet — CVE/vulnerability matching is planned for a later sprint.",
  };
}

export function mapApiResultToScanRecord(result: ApiScanResult): ScanRecord {
  const vulnerabilities = result.ports
    .filter((port) => port.state === "open")
    .map(mapPortToVulnerability);

  const severityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    unclassified: vulnerabilities.length,
  };

  return {
    id: result.scan_id ?? "unknown-scan",
    target: result.configuration.targets.join(", ") || "Unknown target",
    startedAt: result.started_at ?? new Date().toISOString(),
    status: mapLifecycleState(result.state),
    totalFindings: vulnerabilities.length,
    severityCounts,
    config: {
      target: result.configuration.targets[0] ?? "",
      portRange: "",
      scanType: "custom",
      scanDepth: "standard",
    },
    vulnerabilities,
  };
}
