import type { Severity } from "../../types/scan";

const config: Record<Severity, { label: string; dot: string; text: string; bg: string; ring: string }> = {
  critical: {
    label: "Critical",
    dot: "bg-severity-critical",
    text: "text-severity-critical",
    bg: "bg-severity-critical/10",
    ring: "ring-severity-critical/30",
  },
  high: {
    label: "High",
    dot: "bg-severity-high",
    text: "text-severity-high",
    bg: "bg-severity-high/10",
    ring: "ring-severity-high/30",
  },
  medium: {
    label: "Medium",
    dot: "bg-severity-medium",
    text: "text-severity-medium",
    bg: "bg-severity-medium/10",
    ring: "ring-severity-medium/30",
  },
  low: {
    label: "Low",
    dot: "bg-severity-low",
    text: "text-severity-low",
    bg: "bg-severity-low/10",
    ring: "ring-severity-low/30",
  },
  info: {
    label: "Info",
    dot: "bg-severity-info",
    text: "text-severity-info",
    bg: "bg-severity-info/10",
    ring: "ring-severity-info/30",
  },
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const { label, dot, text, bg, ring } = config[severity];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ${bg} ${text} ${ring}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${dot}`} aria-hidden="true" />
      {label}
    </span>
  );
}
