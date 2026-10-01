import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { PageContainer } from "../components/layout/PageContainer";
import { Card, CardBody } from "../components/ui/Card";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorMessage } from "../components/ui/ErrorMessage";
import { LoadingOverlay } from "../components/ui/LoadingIndicator";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { Table, type Column, type SortDirection } from "../components/ui/Table";
import * as resultsService from "../services/resultsService";
import type { ScanRecord, Severity, Vulnerability } from "../types/scan";

const severityRank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const severityFilters: Array<Severity | "all"> = ["all", "critical", "high", "medium", "low", "info"];

export function ScanResults() {
  const { scanId } = useParams<{ scanId: string }>();
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [sortKey, setSortKey] = useState<string>("severity");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [selected, setSelected] = useState<Vulnerability | null>(null);

  useEffect(() => {
    let cancelled = false;
    if (!scanId) return;
    setIsLoading(true);
    setError(null);
    resultsService
      .getScanResults(scanId)
      .then((result) => {
        if (cancelled) return;
        if (!result) {
          setError("This scan could not be found.");
        } else {
          setScan(result);
        }
      })
      .catch(() => {
        if (!cancelled) setError("Failed to load scan results. The backend may be unavailable.");
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  const filteredSorted = useMemo(() => {
    if (!scan) return [];
    const filtered =
      severityFilter === "all"
        ? scan.vulnerabilities
        : scan.vulnerabilities.filter((v) => v.severity === severityFilter);

    const sorted = [...filtered].sort((a, b) => {
      let comparison = 0;
      switch (sortKey) {
        case "severity":
          comparison = severityRank[a.severity] - severityRank[b.severity];
          break;
        case "cvss":
          comparison = a.cvss - b.cvss;
          break;
        case "host":
          comparison = a.host.localeCompare(b.host);
          break;
        case "port":
          comparison = a.port - b.port;
          break;
        default:
          comparison = 0;
      }
      return sortDirection === "asc" ? comparison : -comparison;
    });
    return sorted;
  }, [scan, severityFilter, sortKey, sortDirection]);

  function handleSort(key: string) {
    if (key === sortKey) {
      setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDirection("desc");
    }
  }

  if (isLoading) {
    return (
      <PageContainer title="Scan Results">
        <LoadingOverlay label="Loading scan results…" />
      </PageContainer>
    );
  }

  if (error) {
    return (
      <PageContainer title="Scan Results">
        <ErrorMessage message={error} />
      </PageContainer>
    );
  }

  if (!scan) return null;

  const columns: Column<Vulnerability>[] = [
    { key: "severity", header: "Severity", sortable: true, render: (v) => <SeverityBadge severity={v.severity} /> },
    { key: "cve", header: "CVE", render: (v) => <span className="font-mono text-sm">{v.cve}</span> },
    { key: "host", header: "Host", sortable: true, render: (v) => <span className="font-mono text-sm">{v.host}</span> },
    { key: "port", header: "Port", sortable: true, align: "right", render: (v) => <span className="font-mono text-sm">{v.port}</span> },
    { key: "service", header: "Service", render: (v) => v.service },
    { key: "cvss", header: "CVSS", sortable: true, align: "right", render: (v) => <span className="font-mono text-sm">{v.cvss.toFixed(1)}</span> },
  ];

  return (
    <PageContainer
      title="Scan Results"
      description={`${scan.target} · started ${new Date(scan.startedAt).toLocaleString()}`}
    >
      <div className="flex flex-wrap gap-2">
        {severityFilters.map((sev) => (
          <button
            key={sev}
            onClick={() => setSeverityFilter(sev)}
            className={`rounded-full px-3 py-1.5 text-sm font-medium capitalize transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-400 ${
              severityFilter === sev
                ? "bg-signal-500/15 text-signal-300 ring-1 ring-inset ring-signal-500/30"
                : "bg-ink-800 text-ink-300 hover:bg-ink-750 hover:text-ink-100"
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className={selected ? "lg:col-span-2" : "lg:col-span-3"}>
          <Table
            columns={columns}
            rows={filteredSorted}
            rowKey={(row) => row.id}
            sortKey={sortKey}
            sortDirection={sortDirection}
            onSort={handleSort}
            onRowClick={setSelected}
            emptyState={
              <EmptyState
                title="No known vulnerabilities were detected"
                description={
                  severityFilter === "all"
                    ? "Scan completed with no findings matching the current view."
                    : `No ${severityFilter} severity findings for this scan.`
                }
              />
            }
          />
        </Card>

        {selected && (
          <Card elevation="floating">
            <CardBody className="space-y-4">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="font-mono text-sm text-ink-400">{selected.cve}</p>
                  <SeverityBadge severity={selected.severity} />
                </div>
                <button
                  onClick={() => setSelected(null)}
                  className="rounded-md p-1 text-ink-400 transition-colors hover:bg-ink-750 hover:text-ink-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-400"
                  aria-label="Close detail panel"
                >
                  ✕
                </button>
              </div>

              <div>
                <p className="text-xs font-medium uppercase tracking-wide text-ink-500">CVSS Score</p>
                <p className="font-mono text-2xl font-semibold text-ink-50">{selected.cvss.toFixed(1)}</p>
              </div>

              <div>
                <p className="text-xs font-medium uppercase tracking-wide text-ink-500">Affected Service</p>
                <p className="mt-1 text-sm text-ink-200">
                  {selected.host}:{selected.port} · {selected.service}
                </p>
              </div>

              <div>
                <p className="text-xs font-medium uppercase tracking-wide text-ink-500">Description</p>
                <p className="mt-1 text-sm text-ink-300">{selected.description}</p>
              </div>

              <div>
                <p className="text-xs font-medium uppercase tracking-wide text-ink-500">Recommended Remediation</p>
                <p className="mt-1 text-sm text-ink-300">{selected.remediation}</p>
              </div>
            </CardBody>
          </Card>
        )}
      </div>
    </PageContainer>
  );
}
