import type { PotentialMatch, ScanProgressState, ScanRecord, ScanStatus, ScanWarning, Severity, Vulnerability } from "../types/scan";

/**
 * Maps the shared backend contracts (see
 * "DOCS Inprogress/S2-01 Shared Scanner Data Contracts.md") onto the
 * frontend's domain types. The backend's vulnerability matcher is real and
 * wired in (see Backend/service_vulnerability_matcher.py), with a small
 * curated offline catalog (not a full CVE feed). CVSS 3.1 Base score, vector,
 * and severity are included with catalog matches. Version-range matches
 * remain POTENTIAL findings, not confirmed vulnerabilities.
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
  cvss_version?: string | null;
  cvss_score?: number | null;
  severity?: string | null;
  cvss_vector?: string | null;
  cvss_source_url?: string | null;
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

interface ApiScannerError {
  code: string;
  message: string;
  stage: string;
  details?: Record<string, unknown> | null;
  recoverable: boolean;
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
  errors?: ApiScannerError[];
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
    ...(finding.cvss_version ? { cvssVersion: finding.cvss_version } : {}),
    ...(finding.cvss_score != null ? { cvssScore: finding.cvss_score } : {}),
    ...(finding.severity === "none"
      ? { severity: "none" as const }
      : isSeverity(finding.severity)
        ? { severity: finding.severity }
        : {}),
    ...(finding.cvss_vector ? { cvssVector: finding.cvss_vector } : {}),
    ...(finding.cvss_source_url ? { cvssSourceUrl: finding.cvss_source_url } : {}),
  };
}

function isSeverity(value: string | null | undefined): value is Severity {
  return value === "critical" || value === "high" || value === "medium" || value === "low" || value === "info";
}

function mapScanWarning(error: ApiScannerError): ScanWarning {
  return { code: error.code, message: error.message, stage: error.stage };
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
  const primaryMatch = [...matches].sort(
    (left, right) => (right.cvssScore ?? -1) - (left.cvssScore ?? -1),
  )[0];
  const primarySeverity = primaryMatch?.severity;
  const baseDescription = port.banner
    ? `Open port detected. Observed banner: ${port.banner}`
    : "Open port detected. CVE matching uses a limited curated catalog.";

  return {
    // TCP and UDP may both be scanned on the same host/port number.
    // Include protocol so their frontend records remain distinct.
    id: `${port.host_ip}-${port.port}-${port.protocol}`,
    cve: primaryMatch?.vulnerabilityId ?? "Not yet assessed",
    severity:
      primarySeverity && primarySeverity !== "none"
        ? primarySeverity
        : "unclassified",
    host: port.host_ip,
    port: port.port,
    service: describeService(port),
    cvss: primaryMatch?.cvssScore ?? null,
    cvssVersion: primaryMatch?.cvssVersion ?? null,
    cvssVector: primaryMatch?.cvssVector ?? null,
    description: `${baseDescription}${describeMatches(matches)}`,
    remediation: matches.length > 0
      ? "A potential version-range match was found against the vulnerability catalog — this is not a confirmed exploit. Review the source reference below and verify before acting."
      : "No confirmed vulnerability assessment or automated remediation guidance is available for this observation.",
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
    unclassified: 0,
  };
  for (const vulnerability of vulnerabilities) {
    severityCounts[vulnerability.severity] += 1;
  }

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
    // Non-recoverable errors mean the whole scan failed (already reflected by
    // `status`), so only recoverable ones surface as a non-fatal warning —
    // e.g. vulnerability matching was unavailable but port results are intact.
    warnings: (result.errors ?? []).filter((error) => error.recoverable).map(mapScanWarning),
  };
}
