/**
 * Labels a scan as "Live" (real backend data) or "Demo" (the seeded Sprint 1
 * example scans), so Dashboard/History never present fabricated data as real.
 */
export function SourcePill({ isDemo }: { isDemo: boolean }) {
  return isDemo ? (
    <span className="rounded-full bg-ink-700 px-2 py-0.5 text-xs font-medium text-ink-300 ring-1 ring-inset ring-ink-600">
      Demo
    </span>
  ) : (
    <span className="rounded-full bg-signal-500/10 px-2 py-0.5 text-xs font-medium text-signal-400 ring-1 ring-inset ring-signal-500/25">
      Live
    </span>
  );
}
