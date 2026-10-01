import type { ScanStatus } from "../../types/scan";

const styles: Record<ScanStatus, string> = {
  completed: "bg-signal-500/10 text-signal-400 ring-signal-500/25",
  running: "bg-severity-low/10 text-severity-low ring-severity-low/25",
  failed: "bg-severity-critical/10 text-severity-critical ring-severity-critical/25",
  queued: "bg-ink-700 text-ink-300 ring-ink-600",
  cancelled: "bg-ink-700 text-ink-300 ring-ink-600",
};

export function StatusPill({ status }: { status: ScanStatus }) {
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset ${styles[status]}`}>
      {status}
    </span>
  );
}
