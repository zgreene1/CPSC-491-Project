import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { PageContainer } from "../components/layout/PageContainer";
import { Button } from "../components/ui/Button";
import { Card, CardBody } from "../components/ui/Card";
import { ErrorMessage } from "../components/ui/ErrorMessage";
import { LoadingOverlay } from "../components/ui/LoadingIndicator";
import * as scanService from "../services/scanService";
import type { ScanProgressState } from "../types/scan";

const POLL_INTERVAL_MS = 750;
const TERMINAL_STATUSES = new Set(["completed", "failed", "cancelled"]);

function formatElapsed(seconds: number): string {
  const m = Math.floor(seconds / 60)
    .toString()
    .padStart(2, "0");
  const s = Math.floor(seconds % 60)
    .toString()
    .padStart(2, "0");
  return `${m}:${s}`;
}

export function ScanProgress() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [progress, setProgress] = useState<ScanProgressState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!scanId) return;

    let cancelled = false;

    async function poll() {
      try {
        const next = await scanService.getScanProgress(scanId!);
        if (cancelled) return;
        setProgress(next);
        setError(null);
        if (TERMINAL_STATUSES.has(next.status) && pollRef.current) {
          clearInterval(pollRef.current);
        }
      } catch (err) {
        if (cancelled) return;
        setError(
          err instanceof scanService.ScanApiError
            ? err.message
            : "Failed to load scan progress.",
        );
        if (pollRef.current) clearInterval(pollRef.current);
      }
    }

    poll();
    pollRef.current = setInterval(poll, POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [scanId]);

  if (error) {
    return (
      <PageContainer title="Scan Progress" description={`Monitoring scan ${scanId}`}>
        <ErrorMessage title="Backend unavailable" message={error} />
      </PageContainer>
    );
  }

  if (!progress) {
    return (
      <PageContainer title="Scan Progress" description={`Monitoring scan ${scanId}`}>
        <LoadingOverlay label="Connecting to scan service…" />
      </PageContainer>
    );
  }

  const isComplete = progress.status === "completed";
  const isTerminal = TERMINAL_STATUSES.has(progress.status);

  return (
    <PageContainer title="Scan Progress" description={`Monitoring scan ${scanId}`}>
      <Card className="max-w-2xl">
        <CardBody className="space-y-6">
          <div className="flex items-center justify-between">
            <StatusBadge status={progress.status} />
            <span className="font-mono text-sm text-ink-400">
              {formatElapsed(progress.elapsedSeconds)} elapsed
            </span>
          </div>

          <div>
            <div className="mb-2 flex items-center justify-between text-sm">
              <span className="text-ink-300">Progress</span>
              <span className="font-mono text-ink-100">{Math.round(progress.percentComplete)}%</span>
            </div>
            <div className="h-2.5 w-full overflow-hidden rounded-full bg-ink-750">
              <div
                className="h-full rounded-full bg-signal-500 transition-[width] duration-500 ease-[cubic-bezier(0.34,1.56,0.64,1)]"
                style={{ width: `${progress.percentComplete}%` }}
                role="progressbar"
                aria-valuenow={Math.round(progress.percentComplete)}
                aria-valuemin={0}
                aria-valuemax={100}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Metric label="Current Host" value={progress.currentHost ?? "—"} />
            <Metric label="Current Port" value={progress.currentPort ? `${progress.currentPort}` : "—"} />
            <Metric
              label="Hosts Scanned"
              value={`${progress.hostsCompleted}/${progress.hostsDiscovered || "?"}`}
            />
            <Metric
              label="Ports Checked"
              value={`${progress.portsCompleted}/${progress.totalPorts || "?"}`}
              accent
            />
          </div>

          <div className="flex gap-3 pt-2">
            <Button onClick={() => navigate(`/scans/${scanId}/results`)} disabled={!isComplete}>
              View Results
            </Button>
            <Button variant="ghost" onClick={() => navigate("/dashboard")}>
              Back to dashboard
            </Button>
          </div>

          {isTerminal && !isComplete && (
            <p className="text-sm text-ink-400">
              This scan did not complete successfully (status: {progress.status}).
            </p>
          )}
        </CardBody>
      </Card>
    </PageContainer>
  );
}

function StatusBadge({ status }: { status: string }) {
  if (status === "completed") {
    return (
      <span className="inline-flex items-center gap-2 rounded-full bg-signal-500/10 px-3 py-1 text-sm font-medium text-signal-400 ring-1 ring-inset ring-signal-500/25">
        <span className="h-1.5 w-1.5 rounded-full bg-signal-400" />
        Completed
      </span>
    );
  }
  if (status === "failed" || status === "cancelled") {
    return (
      <span className="inline-flex items-center gap-2 rounded-full bg-severity-critical/10 px-3 py-1 text-sm font-medium text-severity-critical ring-1 ring-inset ring-severity-critical/25 capitalize">
        <span className="h-1.5 w-1.5 rounded-full bg-severity-critical" />
        {status}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-2 rounded-full bg-severity-low/10 px-3 py-1 text-sm font-medium text-severity-low ring-1 ring-inset ring-severity-low/25 capitalize">
      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-severity-low" />
      {status}
    </span>
  );
}

function Metric({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className="rounded-lg border border-ink-650 bg-ink-800/60 px-4 py-3">
      <p className="text-xs text-ink-400">{label}</p>
      <p className={`mt-1 font-mono text-lg ${accent ? "text-signal-400" : "text-ink-100"}`}>{value}</p>
    </div>
  );
}
