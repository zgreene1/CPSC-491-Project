import type { ReactNode } from "react";

interface WarningBannerProps {
  children: ReactNode;
  className?: string;
}

/**
 * Shared amber/severity-medium banner for a non-fatal, backend-reported
 * condition (a recoverable scan error, a stale session) — distinct from
 * ErrorMessage, which is for a fatal condition with a Retry action.
 */
export function WarningBanner({ children, className = "" }: WarningBannerProps) {
  return (
    <div
      role="status"
      className={`flex items-start gap-3 rounded-xl border border-severity-medium/30 bg-severity-medium/10 px-4 py-3.5 ${className}`}
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
      <div className="flex-1">{children}</div>
    </div>
  );
}
