import type { PotentialMatch, ScanProgressState, ScanRecord, ScanStatus, Vulnerability } from "../types/scan";

/**
 * Maps the shared backend contracts (see
 * "DOCS Inprogress/S2-01 Shared Scanner Data Contracts.md") onto the
 * frontend's domain types. The backend's vulnerability matcher is real and
 * wired in (see Backend/service_vulnerability_matcher.py), but it has no
 * concept of severity or CVSS, and its catalog is currently empty — so every
 * real port observation keeps surfacing severity as "unclassified" rather
 * than inventing a level the backend hasn't actually determined. Real
 * catalog matches (once the catalog has entries) show up via the `matches`
 * field on each Vulnerability row.
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

interface ApiVulnerabilityFinding {
  vulnerability_id: string;
  host_ip: string;
  port: number;
  protocol: string;
  software_id: string;
  observed_version: string;
  status: string;
  summary: string;
  source_url: string;
  fingerprint_confidence: number | null;
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

export interface ApiScanResult {
  scan_id: string | null;
  configuration: { targets: string[] };
  state: string;
  started_at: string | null;
  completed_at: string | null;
  ports: ApiPortObservation[];
  progress: ApiScanProgress;
  vulnerabilities?: ApiVulnerabilityFinding[];
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

function mapVulnerabilityFinding(finding: ApiVulnerabilityFinding): PotentialMatch {
  return {
    vulnerabilityId: finding.vulnerability_id,
    status: finding.status,
    summary: finding.summary,
    sourceUrl: finding.source_url,
    confidence: finding.fingerprint_confidence,
  };
}

function portKey(hostIp: string, port: number, protocol: string): string {
  return `${hostIp}|${port}|${protocol}`;
}

function describeMatches(matches: PotentialMatch[]): string {
  if (matches.length === 0) return "";
  const ids = matches.map((match) => match.vulnerabilityId).join(", ");
  return ` Potential catalog match: ${ids}.`;
}

function mapPortToVulnerability(port: ApiPortObservation, matches: PotentialMatch[]): Vulnerability {
  const baseDescription = port.banner
    ? `Open port detected. Observed banner: ${port.banner}`
    : "Open port detected. Vulnerability matching is not implemented yet.";

  return {
    id: `${port.host_ip}-${port.port}`,
    cve: matches[0]?.vulnerabilityId ?? "Not yet assessed",
    severity: "unclassified",
    host: port.host_ip,
    port: port.port,
    service: describeService(port),
    cvss: 0,
    description: `${baseDescription}${describeMatches(matches)}`,
    remediation: matches.length > 0
      ? "A potential version-range match was found against the vulnerability catalog — this is not a confirmed exploit. Review the source reference below and verify before acting."
      : "No automated remediation guidance available yet — the vulnerability catalog has no entries for this service/version.",
    matches,
  };
}

export function mapApiResultToScanRecord(result: ApiScanResult): ScanRecord {
  const matchesByPort = new Map<string, PotentialMatch[]>();
  for (const finding of result.vulnerabilities ?? []) {
    const key = portKey(finding.host_ip, finding.port, finding.protocol);
    const existing = matchesByPort.get(key) ?? [];
    existing.push(mapVulnerabilityFinding(finding));
    matchesByPort.set(key, existing);
  }

  const vulnerabilities = result.ports
    .filter((port) => port.state === "open")
    .map((port) =>
      mapPortToVulnerability(port, matchesByPort.get(portKey(port.host_ip, port.port, port.protocol)) ?? []),
    );

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
    isDemo: false,
    config: {
      target: result.configuration.targets[0] ?? "",
      portRange: "",
      scanType: "custom",
      scanDepth: "standard",
    },
    vulnerabilities,
  };
}
