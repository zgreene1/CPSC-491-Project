import { useNavigate } from "react-router-dom";
import { Button } from "../components/ui/Button";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { StatusPill } from "../components/ui/StatusPill";
import { PageContainer } from "../components/layout/PageContainer";
import { latestScan, mockScans } from "../mocks/scans";
import type { Severity } from "../types/scan";

const severityOrder: Severity[] = ["critical", "high", "medium", "low"];

const totalFindings = mockScans.reduce((sum, scan) => sum + scan.totalFindings, 0);
const aggregateCounts = severityOrder.reduce<Record<Severity, number>>(
  (acc, severity) => {
    acc[severity] = mockScans.reduce((sum, scan) => sum + scan.severityCounts[severity], 0);
    return acc;
  },
  { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
);

const overallRisk = aggregateCounts.critical > 0 ? "High" : aggregateCounts.high > 0 ? "Elevated" : "Low";

export function Dashboard() {
  const navigate = useNavigate();
  const criticalAlerts = latestScan.vulnerabilities.filter(
    (v) => v.severity === "critical" || v.severity === "high",
  );

  return (
    <PageContainer title="Dashboard" description="Overview of your scanning activity and current risk posture.">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatCard label="Total Findings" value={totalFindings} accent="signal" />
        <StatCard label="Critical" value={aggregateCounts.critical} accent="critical" />
        <StatCard label="High" value={aggregateCounts.high} accent="high" />
        <StatCard label="Medium" value={aggregateCounts.medium} accent="medium" />
        <StatCard label="Low" value={aggregateCounts.low} accent="low" />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <h2 className="font-[Space_Grotesk] text-base font-semibold text-ink-50">Recent Scans</h2>
            <Button variant="ghost" size="sm" onClick={() => navigate("/history")}>
              View all
            </Button>
          </CardHeader>
          <CardBody className="divide-y divide-ink-750 p-0">
            {mockScans.map((scan) => (
              <button
                key={scan.id}
                onClick={() => navigate(`/scans/${scan.id}/results`)}
                className="flex w-full items-center justify-between gap-4 px-5 py-3.5 text-left transition-colors hover:bg-ink-750/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-400 focus-visible:ring-inset"
              >
                <div>
                  <p className="font-mono text-sm text-ink-100">{scan.target}</p>
                  <p className="text-xs text-ink-500">{new Date(scan.startedAt).toLocaleString()}</p>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-ink-400">{scan.totalFindings} findings</span>
                  <StatusPill status={scan.status} />
                </div>
              </button>
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
              Based on {mockScans.length} scans and {totalFindings} total findings.
            </p>
            <Button variant="secondary" size="sm" onClick={() => navigate("/reports")}>
              View risk summary
            </Button>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <h2 className="font-[Space_Grotesk] text-base font-semibold text-ink-50">Alerts</h2>
          <span className="text-xs text-ink-500">From latest scan · {latestScan.target}</span>
        </CardHeader>
        <CardBody className="space-y-2">
          {criticalAlerts.length === 0 ? (
            <p className="py-4 text-center text-sm text-ink-400">No critical or high severity alerts.</p>
          ) : (
            criticalAlerts.map((vuln) => (
              <div
                key={vuln.id}
                className="flex items-center justify-between gap-4 rounded-lg border border-ink-650 bg-ink-800/60 px-4 py-3"
              >
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={vuln.severity} />
                  <span className="font-mono text-sm text-ink-100">{vuln.cve}</span>
                  <span className="text-sm text-ink-400">{vuln.service}</span>
                </div>
                <span className="font-mono text-xs text-ink-500">
                  {vuln.host}:{vuln.port}
                </span>
              </div>
            ))
          )}
        </CardBody>
      </Card>
    </PageContainer>
  );
}

function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent: "signal" | "critical" | "high" | "medium" | "low";
}) {
  const accentClasses: Record<typeof accent, string> = {
    signal: "text-signal-400",
    critical: "text-severity-critical",
    high: "text-severity-high",
    medium: "text-severity-medium",
    low: "text-severity-low",
  };

  return (
    <Card elevation="elevated" className="px-5 py-4">
      <p className="text-sm text-ink-400">{label}</p>
      <p className={`mt-1 font-[Space_Grotesk] text-3xl font-semibold tracking-[-0.03em] ${accentClasses[accent]}`}>
        {value}
      </p>
    </Card>
  );
}
