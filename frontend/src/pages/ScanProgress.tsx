import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { PageContainer } from "../components/layout/PageContainer";
import { Button } from "../components/ui/Button";
import { Card, CardBody } from "../components/ui/Card";

const mockTargets = [
  { port: 22, service: "ssh" },
  { port: 80, service: "http" },
  { port: 443, service: "https" },
  { port: 3306, service: "mysql" },
  { port: 8080, service: "http-proxy" },
  { port: 8443, service: "https-alt" },
];

function formatElapsed(seconds: number): string {
  const m = Math.floor(seconds / 60)
    .toString()
    .padStart(2, "0");
  const s = (seconds % 60).toString().padStart(2, "0");
  return `${m}:${s}`;
}

export function ScanProgress() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [percent, setPercent] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const [vulnsFound, setVulnsFound] = useState(0);
  const [status, setStatus] = useState<"running" | "completed">("running");
  const tickRef = useRef(0);

  useEffect(() => {
    if (status !== "running") return;
    const interval = setInterval(() => {
      tickRef.current += 1;
      setElapsed((prev) => prev + 1);
      setPercent((prev) => {
        const next = Math.min(100, prev + 100 / 8);
        if (next >= 100) {
          setStatus("completed");
        }
        return next;
      });
      if (tickRef.current % 2 === 0 && tickRef.current <= 6) {
        setVulnsFound((prev) => prev + 1);
      }
    }, 700);
    return () => clearInterval(interval);
  }, [status]);

  const currentTarget = mockTargets[Math.min(mockTargets.length - 1, Math.floor((percent / 100) * mockTargets.length))];

  return (
    <PageContainer title="Scan Progress" description={`Monitoring scan ${scanId}`}>
      <Card className="max-w-2xl">
        <CardBody className="space-y-6">
          <div className="flex items-center justify-between">
            <StatusBadge status={status} />
            <span className="font-mono text-sm text-ink-400">{formatElapsed(elapsed)} elapsed</span>
          </div>

          <div>
            <div className="mb-2 flex items-center justify-between text-sm">
              <span className="text-ink-300">Progress</span>
              <span className="font-mono text-ink-100">{Math.round(percent)}%</span>
            </div>
            <div className="h-2.5 w-full overflow-hidden rounded-full bg-ink-750">
              <div
                className="h-full rounded-full bg-signal-500 transition-[width] duration-500 ease-[cubic-bezier(0.34,1.56,0.64,1)]"
                style={{ width: `${percent}%` }}
                role="progressbar"
                aria-valuenow={Math.round(percent)}
                aria-valuemin={0}
                aria-valuemax={100}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
            <Metric label="Current Port" value={status === "completed" ? "—" : `${currentTarget.port}`} />
            <Metric label="Service" value={status === "completed" ? "—" : currentTarget.service} />
            <Metric label="Vulnerabilities Found" value={`${vulnsFound}`} accent />
          </div>

          <div className="flex gap-3 pt-2">
            <Button
              onClick={() => navigate(`/scans/${scanId}/results`)}
              disabled={status !== "completed"}
            >
              View Results
            </Button>
            <Button variant="ghost" onClick={() => navigate("/dashboard")}>
              Back to dashboard
            </Button>
          </div>
        </CardBody>
      </Card>
    </PageContainer>
  );
}

function StatusBadge({ status }: { status: "running" | "completed" }) {
  return status === "running" ? (
    <span className="inline-flex items-center gap-2 rounded-full bg-severity-low/10 px-3 py-1 text-sm font-medium text-severity-low ring-1 ring-inset ring-severity-low/25">
      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-severity-low" />
      Running
    </span>
  ) : (
    <span className="inline-flex items-center gap-2 rounded-full bg-signal-500/10 px-3 py-1 text-sm font-medium text-signal-400 ring-1 ring-inset ring-signal-500/25">
      <span className="h-1.5 w-1.5 rounded-full bg-signal-400" />
      Completed
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
