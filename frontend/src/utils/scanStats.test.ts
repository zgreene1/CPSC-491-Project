import { describe, expect, it } from "vitest";
import type { ScanRecord } from "../types/scan";
import { computeAggregateCounts, computeHostRanking, computeOverallRisk } from "./scanStats";

function scan(overrides: Partial<ScanRecord> = {}): ScanRecord {
  return {
    id: "scan-1",
    target: "10.0.0.1",
    startedAt: "2026-01-01T00:00:00Z",
    status: "completed",
    totalFindings: 0,
    severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unclassified: 0 },
    isDemo: false,
    config: { target: "10.0.0.1", portRange: "", scanType: "custom", scanDepth: "standard" },
    vulnerabilities: [],
    ...overrides,
  };
}

describe("computeAggregateCounts", () => {
  it("sums severity counts across every scan", () => {
    const counts = computeAggregateCounts([
      scan({ severityCounts: { critical: 1, high: 2, medium: 0, low: 0, info: 0, unclassified: 0 } }),
      scan({ severityCounts: { critical: 1, high: 0, medium: 3, low: 0, info: 0, unclassified: 0 } }),
    ]);

    expect(counts).toEqual({ critical: 2, high: 2, medium: 3, low: 0, info: 0, unclassified: 0 });
  });

  it("returns all zeros for an empty scan list", () => {
    expect(computeAggregateCounts([])).toEqual({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      unclassified: 0,
    });
  });
});

describe("computeOverallRisk", () => {
  it("is High when any critical findings exist", () => {
    expect(computeOverallRisk({ critical: 1, high: 0, medium: 0, low: 0, info: 0, unclassified: 0 })).toBe("High");
  });

  it("is Elevated when there's high but no critical findings", () => {
    expect(computeOverallRisk({ critical: 0, high: 1, medium: 0, low: 0, info: 0, unclassified: 0 })).toBe(
      "Elevated",
    );
  });

  it("is Low otherwise", () => {
    expect(computeOverallRisk({ critical: 0, high: 0, medium: 5, low: 5, info: 0, unclassified: 0 })).toBe("Low");
  });
});

describe("computeHostRanking", () => {
  it("ranks hosts by finding count, descending", () => {
    const ranking = computeHostRanking([
      scan({
        vulnerabilities: [
          { id: "a", cve: "A", severity: "low", host: "10.0.0.1", port: 80, service: "", cvss: 0, description: "", remediation: "", matches: [] },
          { id: "b", cve: "B", severity: "low", host: "10.0.0.2", port: 80, service: "", cvss: 0, description: "", remediation: "", matches: [] },
        ],
      }),
      scan({
        vulnerabilities: [
          { id: "c", cve: "C", severity: "low", host: "10.0.0.1", port: 443, service: "", cvss: 0, description: "", remediation: "", matches: [] },
        ],
      }),
    ]);

    expect(ranking).toEqual([
      { host: "10.0.0.1", findings: 2 },
      { host: "10.0.0.2", findings: 1 },
    ]);
  });

  it("returns an empty list when there are no findings", () => {
    expect(computeHostRanking([scan()])).toEqual([]);
  });
});
