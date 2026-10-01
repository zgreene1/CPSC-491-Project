import { PageContainer } from "../components/layout/PageContainer";
import { Button } from "../components/ui/Button";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { mockScans } from "../mocks/scans";

const totalCritical = mockScans.reduce((sum, s) => sum + s.severityCounts.critical, 0);
const totalHigh = mockScans.reduce((sum, s) => sum + s.severityCounts.high, 0);

export function Reports() {
  return (
    <PageContainer title="Reports" description="Risk summary and exportable remediation reports.">
      <Card>
        <CardHeader>
          <h2 className="font-[Space_Grotesk] text-base font-semibold text-ink-50">Risk Summary</h2>
        </CardHeader>
        <CardBody className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="rounded-lg border border-ink-650 bg-ink-800/60 px-4 py-3">
            <p className="text-xs text-ink-400">Critical Findings</p>
            <p className="mt-1 font-mono text-2xl text-severity-critical">{totalCritical}</p>
          </div>
          <div className="rounded-lg border border-ink-650 bg-ink-800/60 px-4 py-3">
            <p className="text-xs text-ink-400">High Findings</p>
            <p className="mt-1 font-mono text-2xl text-severity-high">{totalHigh}</p>
          </div>
          <div className="rounded-lg border border-ink-650 bg-ink-800/60 px-4 py-3">
            <p className="text-xs text-ink-400">Scans Analyzed</p>
            <p className="mt-1 font-mono text-2xl text-ink-100">{mockScans.length}</p>
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <h2 className="font-[Space_Grotesk] text-base font-semibold text-ink-50">Export</h2>
        </CardHeader>
        <CardBody className="flex flex-col items-start gap-3">
          <p className="text-sm text-ink-400">
            Full remediation tracking and PDF/CSV export land in a later sprint. This page is wired into
            navigation now so the workflow is demonstrable end-to-end.
          </p>
          <Button variant="secondary" disabled>
            Export report (coming soon)
          </Button>
        </CardBody>
      </Card>
    </PageContainer>
  );
}
