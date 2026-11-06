import type { ScanRecord, Severity } from "../types/scan";

export type OverallRisk = "High" | "Elevated" | "Low";

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info", "unclassified"];

export function computeAggregateCounts(scans: ScanRecord[]): Record<Severity, number> {
  return severityOrder.reduce<Record<Severity, number>>(
    (acc, severity) => {
      acc[severity] = scans.reduce((sum, scan) => sum + scan.severityCounts[severity], 0);
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0, unclassified: 0 },
  );
}

export function computeOverallRisk(counts: Record<Severity, number>): OverallRisk {
  if (counts.critical > 0) return "High";
  if (counts.high > 0) return "Elevated";
  return "Low";
}

export interface HostRiskRow {
  host: string;
  findings: number;
}

/** Hosts ranked by total finding count across every scan, descending. */
export function computeHostRanking(scans: ScanRecord[]): HostRiskRow[] {
  const countsByHost = new Map<string, number>();
  for (const scan of scans) {
    for (const vuln of scan.vulnerabilities) {
      countsByHost.set(vuln.host, (countsByHost.get(vuln.host) ?? 0) + 1);
    }
  }

  return [...countsByHost.entries()]
    .map(([host, findings]) => ({ host, findings }))
    .sort((a, b) => b.findings - a.findings);
}
