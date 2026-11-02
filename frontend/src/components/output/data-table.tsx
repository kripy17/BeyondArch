import { type ReactNode, useState, useMemo } from "react";
import { ArrowUp, ArrowDown, ArrowUpDown } from "lucide-react";
import { Empty } from "./empty";

export type Column<T> = {
  key: string;
  label: string;
  align?: "left" | "right" | "center";
  sortable?: boolean;
  sortValue?: (row: T) => string | number;
  width?: string;
  render: (row: T, idx: number) => ReactNode;
};

export function DataTable<T extends Record<string, unknown>>({
  columns,
  rows,
  className = "",
  emptyMessage = "No data",
  emptyHint,
  isRowSelected,
  renderExpanded,
  onRowClick,
}: {
  columns: Column<T>[];
  rows: T[];
  className?: string;
  emptyMessage?: string;
  emptyHint?: string;
  isRowSelected?: (row: T, idx: number) => boolean;
  renderExpanded?: (row: T, idx: number) => ReactNode;
  onRowClick?: (row: T, idx: number) => void;
}) {
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const sorted = useMemo(() => {
    if (!sortKey) return rows;
    const col = columns.find((c) => c.key === sortKey);
    if (!col) return rows;
    return [...rows].sort((a, b) => {
      const aVal = col.sortValue ? col.sortValue(a) : (a[sortKey] as string | number);
      const bVal = col.sortValue ? col.sortValue(b) : (b[sortKey] as string | number);
      if (aVal < bVal) return sortDir === "asc" ? -1 : 1;
      if (aVal > bVal) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
  }, [rows, sortKey, sortDir, columns]);

  const toggleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  if (rows.length === 0) {
    return <Empty title={emptyMessage} hint={emptyHint} />;
  }

  return (
    <div className={`overflow-auto rounded-md border border-subtle shadow-sm ${className}`}>
      <table className="w-full border-collapse">
        <thead>
          <tr className="border-b-2 border-b-primary/20 bg-surface-1/95 backdrop-blur-sm">
            {columns.map((col) => (
              <th
                key={col.key}
                className={`sticky top-0 z-10 h-[42px] whitespace-nowrap border-0 border-b-2 border-b-primary/20 bg-surface-1/95 px-3 text-mono ba-text-xs font-semibold uppercase tracking-wider text-muted-foreground backdrop-blur-sm ${
                  col.sortable ? "cursor-pointer select-none hover:text-fg-dim" : ""
                } ${col.align === "right" ? "text-right" : col.align === "center" ? "text-center" : "text-left"}`}
                style={col.width ? { width: col.width, minWidth: col.width } : undefined}
                onClick={() => col.sortable && toggleSort(col.key)}
              >
                <span className="inline-flex items-center gap-1">
                  {col.label}
                  {col.sortable && (
                    sortKey === col.key
                      ? sortDir === "asc" ? <ArrowUp className="h-3 w-3 text-primary" /> : <ArrowDown className="h-3 w-3 text-primary" />
                      : <ArrowUpDown className="h-3 w-3 text-fg-dim" />
                  )}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row, i) => {
            const selected = isRowSelected ? isRowSelected(row, i) : false;
            return (
              <FragmentRow
                key={(row.id as string) ?? i}
                row={row}
                i={i}
                selected={selected}
                onRowClick={onRowClick}
                renderExpanded={renderExpanded}
                colCount={columns.length}
              >
                {columns.map((col) => (
                  <td
                    key={col.key}
                    className={`h-12 border-0 px-3 text-mono ba-text-xs ${
                      col.align === "right" ? "text-right tabular-nums" : col.align === "center" ? "text-center" : "text-left"
                    } group-first/trow:border-l-2 group-first/trow:border-l-transparent ${
                      selected
                        ? "border-l-2 border-l-primary bg-primary/[0.06]"
                        : "group-hover/trow:border-l-primary/40"
                    }`}
                  >
                    {col.render(row, i)}
                  </td>
                ))}
              </FragmentRow>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function FragmentRow<T extends Record<string, unknown>>({
  row,
  i,
  selected,
  onRowClick,
  renderExpanded,
  colCount,
  children,
}: {
  row: T;
  i: number;
  selected: boolean;
  onRowClick?: (row: T, idx: number) => void;
  renderExpanded?: (row: T, idx: number) => ReactNode;
  colCount: number;
  children: ReactNode;
}) {
  const expanded = renderExpanded ? renderExpanded(row, i) : null;
  return (
    <>
      <tr
        onClick={onRowClick ? () => onRowClick(row, i) : undefined}
        className={`group/trow border-b border-divider-soft transition-colors duration-150 ${
          onRowClick ? "cursor-pointer" : ""
        } ${selected ? "bg-primary/[0.06]" : i % 2 === 1 ? "bg-surface-1/40" : "bg-transparent"} ${
          onRowClick ? "hover:bg-surface-2/60" : ""
        }`}
      >
        {children}
      </tr>
      {expanded != null && (
        <tr className="border-b border-divider-soft bg-surface-1">
          <td colSpan={colCount} className="border-0 px-3 py-3">
            {expanded}
          </td>
        </tr>
      )}
    </>
  );
}
