import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { PageContainer } from "../components/layout/PageContainer";
import { Button } from "../components/ui/Button";
import { Card, CardBody } from "../components/ui/Card";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorMessage } from "../components/ui/ErrorMessage";
import { LoadingOverlay } from "../components/ui/LoadingIndicator";
import { Pagination } from "../components/ui/Pagination";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { Table, type Column, type SortDirection } from "../components/ui/Table";
import { VulnerabilityDetailPanel } from "../components/ui/VulnerabilityDetailPanel";
import * as resultsService from "../services/resultsService";
import { ScanApiError } from "../services/scanService";
import type { ScanRecord, Severity, Vulnerability } from "../types/scan";

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unclassified: 0,
};
const severityFilters: Array<Severity | "all"> = [
  "all",
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "unclassified",
];
const PAGE_SIZE = 25;

export function ScanResults() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isInProgress, setIsInProgress] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [sortKey, setSortKey] = useState<string>("severity");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [selected, setSelected] = useState<Vulnerability | null>(null);
  const [page, setPage] = useState(1);
  const [retryKey, setRetryKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    if (!scanId) return;
    setIsLoading(true);
    setError(null);
    setIsInProgress(false);
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
      .catch((err) => {
        if (cancelled) return;
        if (err instanceof ScanApiError && err.kind === "in_progress") {
          setIsInProgress(true);
          return;
        }
        setError(
          err instanceof Error ? err.message : "Failed to load scan results. The backend may be unavailable.",
        );
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, retryKey]);

  const filteredSorted = useMemo(() => {
    if (!scan) return [];
    const bySeverity =
      severityFilter === "all"
        ? scan.vulnerabilities
        : scan.vulnerabilities.filter((v) => v.severity === severityFilter);

    const query = searchQuery.trim().toLowerCase();
    const filtered = query
      ? bySeverity.filter(
          (v) =>
            v.cve.toLowerCase().includes(query) ||
            v.host.toLowerCase().includes(query) ||
            v.service.toLowerCase().includes(query),
        )
      : bySeverity;

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
  }, [scan, severityFilter, searchQuery, sortKey, sortDirection]);

  // A filter/search/sort change can leave `page` pointing past the end of
  // the new, smaller result set — reset to the first page whenever the
  // underlying filtered list changes instead of showing an empty page.
  useEffect(() => {
    setPage(1);
  }, [severityFilter, searchQuery, sortKey, sortDirection, scan?.id]);

  const pagedRows = useMemo(
    () => filteredSorted.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE),
    [filteredSorted, page],
  );

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

  if (isInProgress) {
    return (
      <PageContainer title="Scan Results">
        <Card>
          <CardBody>
            <EmptyState
              title="This scan is still running"
              description="Results will be available here once the scan completes."
              action={
                <Button size="sm" onClick={() => navigate(`/scans/${scanId}/progress`)}>
                  View scan progress
                </Button>
              }
            />
          </CardBody>
        </Card>
      </PageContainer>
    );
  }

  if (error) {
    return (
      <PageContainer title="Scan Results">
        <ErrorMessage message={error} onRetry={() => setRetryKey((key) => key + 1)} />
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
      {scan.warnings.length > 0 && (
        <div
          role="status"
          className="flex items-start gap-3 rounded-xl border border-severity-medium/30 bg-severity-medium/10 px-4 py-3.5"
        >
          <span className="mt-0.5 text-severity-medium" aria-hidden="true">
            <svg width="18" height="18" viewBox="0 0 20 20" fill="none">
              <path
                d="M10 2 1 18h18L10 2Zm0 5v5m0 3h.01"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </span>
          <div className="flex-1">
            <p className="text-sm font-semibold text-ink-100">Scan completed with a warning</p>
            {scan.warnings.map((warning) => (
              <p key={warning.code} className="text-sm text-ink-300">
                {warning.message}
              </p>
            ))}
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3">
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

        <label className="relative ml-auto">
          <span className="sr-only">Search by CVE, host, or service</span>
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-500"
            aria-hidden="true"
          >
            <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.8" />
            <path d="m20 20-3.5-3.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
          </svg>
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search CVE, host, or service"
            className="h-9 w-64 rounded-lg border border-ink-600 bg-ink-850 pl-9 pr-3 text-sm text-ink-100 placeholder:text-ink-400 transition-[box-shadow,border-color] duration-150 hover:border-ink-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-signal-400 focus-visible:ring-offset-2 focus-visible:ring-offset-ink-950"
          />
        </label>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className={selected ? "lg:col-span-2" : "lg:col-span-3"}>
          <Table
            columns={columns}
            rows={pagedRows}
            rowKey={(row) => row.id}
            sortKey={sortKey}
            sortDirection={sortDirection}
            onSort={handleSort}
            onRowClick={setSelected}
            emptyState={
              <EmptyState
                title="No known vulnerabilities were detected"
                description={
                  searchQuery.trim()
                    ? `No findings match "${searchQuery.trim()}".`
                    : severityFilter === "all"
                      ? "Scan completed with no findings matching the current view."
                      : `No ${severityFilter} severity findings for this scan.`
                }
              />
            }
          />
          {filteredSorted.length > PAGE_SIZE && (
            <Pagination
              page={page}
              pageSize={PAGE_SIZE}
              totalItems={filteredSorted.length}
              onPageChange={setPage}
              itemLabel="findings"
            />
          )}
        </Card>

        {selected && (
          <VulnerabilityDetailPanel scanId={scan.id} vulnerability={selected} onClose={() => setSelected(null)} />
        )}
      </div>
    </PageContainer>
  );
}
