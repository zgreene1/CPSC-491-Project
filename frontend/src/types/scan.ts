export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unclassified";

export type ScanType = "quick" | "full" | "custom";

export type ScanDepth = "light" | "standard" | "deep";

export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface ScanConfig {
  target: string;
  portRange: string;
  scanType: ScanType;
  scanDepth: ScanDepth;
}

/**
 * A real match from the backend's vulnerability catalog against an observed
 * service/version. "Potential" because it's a version-range match, not a
 * confirmed exploit — the backend never claims otherwise (see
 * Backend/service_vulnerability_matcher.py). No severity/CVSS here: the
 * backend doesn't produce that data yet.
 */
export interface PotentialMatch {
  vulnerabilityId: string;
  status: string;
  summary: string;
  sourceUrl: string;
  confidence: number | null;
}

export interface Vulnerability {
  id: string;
  cve: string;
  severity: Severity;
  host: string;
  port: number;
  service: string;
  cvss: number;
  description: string;
  remediation: string;
  /** Real catalog matches for this host/port, if any. Empty for demo data. */
  matches: PotentialMatch[];
}

export interface ScanSummary {
  id: string;
  target: string;
  startedAt: string;
  status: ScanStatus;
  totalFindings: number;
  severityCounts: Record<Severity, number>;
  /** True for the seeded Sprint 1 example scans; false for real backend scans. */
  isDemo: boolean;
}

export interface ScanRecord extends ScanSummary {
  config: ScanConfig;
  vulnerabilities: Vulnerability[];
}

export interface ScanProgressState {
  scanId: string;
  status: ScanStatus;
  percentComplete: number;
  hostsDiscovered: number;
  hostsCompleted: number;
  portsCompleted: number;
  totalPorts: number;
  currentHost: string | null;
  currentPort: number | null;
  elapsedSeconds: number;
  cancellationRequested: boolean;
}
