import { Button } from "./Button";

interface PaginationProps {
  page: number;
  pageSize: number;
  totalItems: number;
  onPageChange: (page: number) => void;
  itemLabel?: string;
}

/**
 * A large finding set (hundreds of open ports on a /16 scan, say) rendered
 * as one unbounded table is slow to scroll and hard to scan. This keeps
 * each page small and shows exactly how much was filtered out of view.
 */
export function Pagination({ page, pageSize, totalItems, onPageChange, itemLabel = "items" }: PaginationProps) {
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const start = totalItems === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, totalItems);

  return (
    <div className="flex items-center justify-between gap-4 border-t border-ink-750 px-5 py-3.5">
      <p className="text-sm text-ink-400">
        Showing {start}–{end} of {totalItems} {itemLabel}
      </p>
      <div className="flex items-center gap-2">
        <Button
          variant="ghost"
          size="sm"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
          aria-label="Previous page"
        >
          Previous
        </Button>
        <span className="font-mono text-sm text-ink-400">
          {page} / {totalPages}
        </span>
        <Button
          variant="ghost"
          size="sm"
          disabled={page >= totalPages}
          onClick={() => onPageChange(page + 1)}
          aria-label="Next page"
        >
          Next
        </Button>
      </div>
    </div>
  );
}
