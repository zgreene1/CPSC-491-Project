import type { ReactNode } from "react";

export interface Column<T> {
  key: string;
  header: string;
  sortable?: boolean;
  align?: "left" | "right";
  render: (row: T) => ReactNode;
}

export type SortDirection = "asc" | "desc";

interface TableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  sortKey?: string;
  sortDirection?: SortDirection;
  onSort?: (key: string) => void;
  onRowClick?: (row: T) => void;
  emptyState?: ReactNode;
}

export function Table<T>({
  columns,
  rows,
  rowKey,
  sortKey,
  sortDirection = "asc",
  onSort,
  onRowClick,
  emptyState,
}: TableProps<T>) {
  if (rows.length === 0 && emptyState) {
    return <div className="px-5 py-12">{emptyState}</div>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">
        <thead>
          <tr className="border-b border-ink-650">
            {columns.map((column) => {
              const isActive = column.key === sortKey;
              return (
                <th
                  key={column.key}
                  scope="col"
                  className={`px-5 py-3 font-medium text-ink-400 ${
                    column.align === "right" ? "text-right" : "text-left"
                  }`}
                >
                  {column.sortable ? (
                    <button
                      type="button"
                      onClick={() => onSort?.(column.key)}
                      className="inline-flex items-center gap-1 rounded transition-colors hover:text-ink-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal-400"
                      aria-label={`Sort by ${column.header}`}
                    >
                      {column.header}
                      <span
                        className={`text-[10px] transition-transform ${isActive ? "text-signal-400" : "text-ink-500"}`}
                      >
                        {isActive && sortDirection === "desc" ? "▼" : "▲"}
                      </span>
                    </button>
                  ) : (
                    column.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={rowKey(row)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              className={`border-b border-ink-750 last:border-0 ${
                onRowClick
                  ? "cursor-pointer transition-colors hover:bg-ink-800/60 focus-visible:outline-none"
                  : ""
              }`}
              tabIndex={onRowClick ? 0 : undefined}
              onKeyDown={
                onRowClick
                  ? (event) => {
                      if (event.key === "Enter") onRowClick(row);
                    }
                  : undefined
              }
            >
              {columns.map((column) => (
                <td
                  key={column.key}
                  className={`px-5 py-3.5 text-ink-200 ${column.align === "right" ? "text-right" : "text-left"}`}
                >
                  {column.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
