import { useEffect, useState } from "react";
import { PageContainer } from "../components/layout/PageContainer";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorMessage } from "../components/ui/ErrorMessage";
import { LoadingOverlay } from "../components/ui/LoadingIndicator";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { SourcePill } from "../components/ui/SourcePill";
import * as historyService from "../services/historyService";
import type { ScanRecord, Severity } from "../types/scan";
import { computeAggregateCounts, computeHostRanking, computeOverallRisk } from "../utils/scanStats";

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info", "unclassified"];
const severityLabels: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  unclassified: "Unclassified",
};

function buildRecommendations(scans: ScanRecord[], counts: Record<Severity, number>): string[] {
  const recommendations: string[] = [];
  const totalFindings = scans.reduce((sum, scan) => sum + scan.totalFindings, 0);

  if (totalFindings === 0) {
    return ["No findings recorded yet — run a scan to get your first risk summary."];
  }

  if (counts.critical > 0) {
    recommendations.push(`Remediate ${counts.critical} critical finding${counts.critical === 1 ? "" : "s"} first.`);
  }
  if (counts.high > 0) {
    recommendations.push(`Review ${counts.high} high severity finding${counts.high === 1 ? "" : "s"}.`);
  }

  const realMatchCount = scans
    .filter((scan) => !scan.isDemo)
    .flatMap((scan) => scan.vulnerabilities)
    .reduce((sum, vuln) => sum + vuln.matches.length, 0);
  if (realMatchCount > 0) {
    recommendations.push(
      `Investigate ${realMatchCount} potential vulnerability match${realMatchCount === 1 ? "" : "es"} surfaced by the scanner.`,
    );
  }

  if (recommendations.length === 0) {
    recommendations.push("No critical or high severity findings — maintain your current scanning cadence.");
  }

  return recommendations;
}

export function Reports() {
  const [scans, setScans] = useState<ScanRecord[] | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  function load() {
    setIsLoading(true);
    setError(null);
    historyService
      .getScanHistory()
      .then(setScans)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load report data."))
      .finally(() => setIsLoading(false));
  }

  useEffect(load, []);

  if (isLoading) {
    return (
      <PageContainer title="Reports">
        <LoadingOverlay label="Loading risk summary…" />
      </PageContainer>
    );
  }

  if (error) {
    return (
      <PageContainer title="Reports">
        <ErrorMessage message={error} onRetry={load} />
      </PageContainer>
    );
  }

  if (!scans || scans.length === 0) {
    return (
      <PageContainer title="Reports" description="Risk summary and exportable remediation reports.">
        <Card>
          <CardBody>
            <EmptyState
              title="No scans yet"
              description="Run a scan to see a risk assessment here."
            />
          </CardBody>
        </Card>
      </PageContainer>
    );
  }

  const counts = computeAggregateCounts(scans);
  const overallRisk = computeOverallRisk(counts);
  const totalFindings = scans.reduce((sum, scan) => sum + scan.totalFindings, 0);
  const criticalFindings = scans.flatMap((scan) =>
    scan.vulnerabilities
      .filter((vuln) => vuln.severity === "critical")
      .map((vuln) => ({ scan, vuln })),
  );
  const hostRanking = computeHostRanking(scans).slice(0, 5);
  const recommendations = buildRecommendations(scans, counts);

  return (
    <PageContainer title="Reports" description="Risk summary and exportable remediation reports.">
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <h2 className="font-[Space_Grotesk] text-base font-semibold text-ink-50">Severity Distribution</h2>
          </CardHeader>
          <CardBody className="grid grid-cols-2 gap-4 sm:grid-cols-3">
            {severityOrder.map((severity) => (
              <div key={severity} className="rounded-lg border border-ink-650 bg-ink-800/60 px-4 py-3">
                <p className="text-xs text-ink-400">{severityLabels[severity]}</p>
                <p className="mt-1 font-mono text-2xl text-ink-100">{counts[severity]}</p>
              </div>
            ))}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <h2 className="font-[Space_Grotesk] text-base font-semibold text-ink-50">Overall Risk</h2>
          </CardHeader>
          <CardBody className="flex flex-col items-center gap-3 py-8 text-center">
            <div
              className={`flex h-20 w-20 items-center justify-center rounded-full text-xl font-bold ring-4 ${
                overallRisk === "High"
                  ? "bg-severity-critical/10 text-severity-critical ring-severity-critical/20"
                  : overallRisk === "Elevated"
                    ? "bg-severity-high/10 text-severity-high ring-severity-high/20"
                    : "bg-severity-low/10 text-severity-low ring-severity-low/20"
              }`}
            >
              {overallRisk}
            </div>
            <p className="text-sm text-ink-400">
              Based on {scans.length} scan{scans.length === 1 ? "" : "s"} and {totalFindings} total findings.
            </p>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <h2 className="font-[Space_Grotesk] text-base font-semibold text-ink-50">Critical Findings</h2>
        </CardHeader>
        <CardBody className="space-y-2">
          {criticalFindings.length === 0 ? (
            <p className="py-4 text-center text-sm text-ink-400">No critical severity findings.</p>
          ) : (
            criticalFindings.map(({ scan, vuln }) => (
              <div
                key={`${scan.id}-${vuln.id}`}
                className="flex items-center justify-between gap-4 rounded-lg border border-ink-650 bg-ink-800/60 px-4 py-3"
              >
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={vuln.severity} />
                  <span className="font-mono text-sm text-ink-100">{vuln.cve}</span>
                  <span className="text-sm text-ink-400">{vuln.service}</span>
                  <SourcePill isDemo={scan.isDemo} />
                </div>
                <span className="font-mono text-xs text-ink-500">
                  {vuln.host}:{vuln.port}
                </span>
              </div>
            ))
          )}
        </CardBody>
      </Card>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <h2 className="font-[Space_Grotesk] text-base font-semibold text-ink-50">Highest-Risk Hosts</h2>
          </CardHeader>
          <CardBody className="space-y-2">
            {hostRanking.length === 0 ? (
              <p className="py-4 text-center text-sm text-ink-400">No findings to rank yet.</p>
            ) : (
              hostRanking.map((row) => (
                <div
                  key={row.host}
                  className="flex items-center justify-between gap-4 rounded-lg border border-ink-650 bg-ink-800/60 px-4 py-3"
                >
                  <span className="font-mono text-sm text-ink-100">{row.host}</span>
                  <span className="text-xs text-ink-400">
                    {row.findings} finding{row.findings === 1 ? "" : "s"}
                  </span>
                </div>
              ))
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <h2 className="font-[Space_Grotesk] text-base font-semibold text-ink-50">Recommendations</h2>
          </CardHeader>
          <CardBody>
            <ul className="list-disc space-y-2 pl-5">
              {recommendations.map((recommendation) => (
                <li key={recommendation} className="text-sm text-ink-300">
                  {recommendation}
                </li>
              ))}
            </ul>
          </CardBody>
        </Card>
      </div>
    </PageContainer>
  );
}
