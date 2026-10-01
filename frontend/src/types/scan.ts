export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ScanType = "quick" | "full" | "custom";

export type ScanDepth = "light" | "standard" | "deep";

export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface ScanConfig {
  target: string;
  portRange: string;
  scanType: ScanType;
  scanDepth: ScanDepth;
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
}

export interface ScanSummary {
  id: string;
  target: string;
  startedAt: string;
  status: ScanStatus;
  totalFindings: number;
  severityCounts: Record<Severity, number>;
}

export interface ScanRecord extends ScanSummary {
  config: ScanConfig;
  vulnerabilities: Vulnerability[];
}

export interface ScanProgressState {
  scanId: string;
  status: ScanStatus;
  percentComplete: number;
  currentTarget: string;
  currentPort: number | null;
  elapsedSeconds: number;
  vulnerabilitiesFound: number;
}
