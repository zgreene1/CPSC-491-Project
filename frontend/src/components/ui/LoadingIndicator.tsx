interface LoadingIndicatorProps {
  label?: string;
  size?: "sm" | "md" | "lg";
}

const sizes = {
  sm: "h-4 w-4 border-2",
  md: "h-6 w-6 border-2",
  lg: "h-10 w-10 border-[3px]",
};

export function LoadingIndicator({ label = "Loading…", size = "md" }: LoadingIndicatorProps) {
  return (
    <div role="status" className="flex items-center gap-3 text-ink-300">
      <span
        className={`animate-spin rounded-full border-signal-500/30 border-t-signal-400 ${sizes[size]}`}
        aria-hidden="true"
      />
      <span className="text-sm">{label}</span>
    </div>
  );
}

export function LoadingOverlay({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex flex-1 items-center justify-center py-16">
      <LoadingIndicator label={label} size="lg" />
    </div>
  );
}
