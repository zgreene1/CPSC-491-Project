import type { ReactNode } from "react";

interface EmptyStateProps {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
}

export function EmptyState({ title, description, icon, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-4 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-ink-750 text-ink-400" aria-hidden="true">
        {icon ?? (
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
            <path
              d="M4 6h16M4 12h16M4 18h10"
              stroke="currentColor"
              strokeWidth="1.6"
              strokeLinecap="round"
            />
          </svg>
        )}
      </div>
      <div>
        <p className="text-sm font-semibold text-ink-100">{title}</p>
        {description && <p className="mt-1 text-sm text-ink-400">{description}</p>}
      </div>
      {action}
    </div>
  );
}
