import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { PageContainer } from "../components/layout/PageContainer";
import { Card } from "../components/ui/Card";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorMessage } from "../components/ui/ErrorMessage";
import { LoadingOverlay } from "../components/ui/LoadingIndicator";
import { StatusPill } from "../components/ui/StatusPill";
import { Table, type Column } from "../components/ui/Table";
import * as historyService from "../services/historyService";
import type { ScanSummary } from "../types/scan";

export function ScanHistory() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  function load() {
    setIsLoading(true);
    setError(null);
    historyService
      .getScanHistory()
      .then(setScans)
      .catch(() => setError("Failed to load scan history. The backend may be unavailable."))
      .finally(() => setIsLoading(false));
  }

  useEffect(load, []);

  if (isLoading) {
    return (
      <PageContainer title="Scan History">
        <LoadingOverlay label="Loading scan history…" />
      </PageContainer>
    );
  }

  if (error) {
    return (
      <PageContainer title="Scan History">
        <ErrorMessage message={error} onRetry={load} />
      </PageContainer>
    );
  }

  const columns: Column<ScanSummary>[] = [
    { key: "startedAt", header: "Date / Time", render: (s) => new Date(s.startedAt).toLocaleString() },
    { key: "target", header: "Target", render: (s) => <span className="font-mono text-sm">{s.target}</span> },
    { key: "status", header: "Status", render: (s) => <StatusPill status={s.status} /> },
    { key: "totalFindings", header: "Findings", align: "right", render: (s) => s.totalFindings },
  ];

  return (
    <PageContainer title="Scan History" description="Review and reopen previous scans.">
      <Card>
        <Table
          columns={columns}
          rows={scans ?? []}
          rowKey={(row) => row.id}
          onRowClick={(scan) => navigate(`/scans/${scan.id}/results`)}
          emptyState={
            <EmptyState
              title="No previous scans have been performed"
              description="Scans you run will show up here with their date, target, and result summary."
            />
          }
        />
      </Card>
    </PageContainer>
  );
}
