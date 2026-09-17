import type { ReactNode } from "react";
import { Button } from "./Button";

interface ErrorMessageProps {
  title?: string;
  message: string;
  onRetry?: () => void;
  icon?: ReactNode;
}

export function ErrorMessage({ title = "Something went wrong", message, onRetry, icon }: ErrorMessageProps) {
  return (
    <div
      role="alert"
      className="flex items-start gap-3 rounded-xl border border-severity-critical/30 bg-severity-critical/10 px-4 py-3.5"
    >
      <span className="mt-0.5 text-severity-critical" aria-hidden="true">
        {icon ?? (
          <svg width="18" height="18" viewBox="0 0 20 20" fill="none">
            <path
              d="M10 2 1 18h18L10 2Zm0 5v5m0 3h.01"
              stroke="currentColor"
              strokeWidth="1.6"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        )}
      </span>
      <div className="flex-1">
        <p className="text-sm font-semibold text-ink-100">{title}</p>
        <p className="text-sm text-ink-300">{message}</p>
      </div>
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}
