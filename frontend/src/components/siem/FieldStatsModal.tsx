import { useState, useMemo } from "react";
import { X, Copy, Plus, Minus, Search, BarChart3, Layers, Filter } from "lucide-react";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import type { SiemEvent } from "@/data/siem";

interface FieldStatsModalProps {
  field: string;
  events: SiemEvent[];
  onClose: () => void;
  onAddChip: (field: string, value: string) => void;
  onAppendQuery?: (subquery: string) => void;
}

export function FieldStatsModal({
  field,
  events,
  onClose,
  onAddChip,
  onAppendQuery,
}: FieldStatsModalProps) {
  const [searchTerm, setSearchTerm] = useState("");

  const stats = useMemo(() => {
    const total = events.length;
    const valueCounts = new Map<string, number>();
    let populated = 0;

    for (const e of events) {
      const val = e[field as keyof SiemEvent];
      if (val !== undefined && val !== null && val !== "" && val !== "—" && val !== "-") {
        const sVal = String(val);
        populated++;
        valueCounts.set(sVal, (valueCounts.get(sVal) || 0) + 1);
      }
    }

    const sorted = Array.from(valueCounts.entries())
      .map(([value, count]) => ({
        value,
        count,
        pct: populated > 0 ? Math.round((count / populated) * 1000) / 10 : 0,
      }))
      .sort((a, b) => b.count - a.count);

    return {
      total,
      populated,
      coveragePct: total > 0 ? Math.round((populated / total) * 1000) / 10 : 0,
      distinctCount: valueCounts.size,
      topValues: sorted,
    };
  }, [field, events]);

  const filteredValues = useMemo(() => {
    if (!searchTerm.trim()) return stats.topValues;
    const lower = searchTerm.toLowerCase();
    return stats.topValues.filter((v) => v.value.toLowerCase().includes(lower));
  }, [stats.topValues, searchTerm]);

  const handleCopy = (text: string) => {
    copyText(text);
    toast.success("Copied to clipboard");
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-xs"
      onClick={onClose}
    >
      <div
        className="flex max-h-[85vh] w-full max-w-2xl flex-col rounded-lg border border-subtle bg-surface-0 p-5 shadow-2xl elevation-floating"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="flex items-start justify-between border-b border-border/60 pb-3">
          <div className="flex items-center gap-2">
            <div className="rounded-md bg-primary/10 p-2 text-primary">
              <BarChart3 className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-mono ba-text-base font-bold text-foreground">
                  Field Statistics: <span className="text-primary">{field}</span>
                </h3>
                <span className="rounded border border-subtle bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-fg-dim">
                  CIM Standard
                </span>
              </div>
              <p className="mt-0.5 text-mono ba-text-xs text-muted-foreground">
                Distribution and cardinality profile across {stats.total} total event(s)
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 text-muted-foreground transition-colors hover:bg-surface-2 hover:text-foreground"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Telemetry Metrics Strip */}
        <div className="my-3 grid grid-cols-3 gap-2">
          <div className="rounded-md border border-subtle bg-surface-1 p-2.5 text-center">
            <span className="text-mono ba-text-3xs uppercase tracking-wider text-muted-foreground">
              Distinct Values (Cardinality)
            </span>
            <div className="mt-1 font-mono ba-text-lg font-bold text-foreground">
              {stats.distinctCount}
            </div>
          </div>
          <div className="rounded-md border border-subtle bg-surface-1 p-2.5 text-center">
            <span className="text-mono ba-text-3xs uppercase tracking-wider text-muted-foreground">
              Coverage Rate
            </span>
            <div className="mt-1 font-mono ba-text-lg font-bold text-primary">
              {stats.coveragePct}%
            </div>
          </div>
          <div className="rounded-md border border-subtle bg-surface-1 p-2.5 text-center">
            <span className="text-mono ba-text-3xs uppercase tracking-wider text-muted-foreground">
              Populated Events
            </span>
            <div className="mt-1 font-mono ba-text-lg font-bold text-foreground">
              {stats.populated} / {stats.total}
            </div>
          </div>
        </div>

        {/* Search & Action Bar */}
        <div className="mb-3 flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-fg-dim" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder={`Filter ${stats.distinctCount} values...`}
              className="h-8 w-full rounded border border-divider-strong bg-surface-1 pl-8 pr-2 font-mono ba-text-2xs text-foreground outline-none placeholder:text-fg-dim/60 focus:border-primary/50"
            />
          </div>
          {onAppendQuery && (
            <button
              onClick={() => {
                onAppendQuery(` | stats count by ${field}`);
                toast.success(`Appended stats count by ${field} to query`);
                onClose();
              }}
              className="inline-flex h-8 items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 font-mono ba-text-2xs text-primary transition-colors hover:bg-primary/20"
              title="Append Splunk stats aggregation command"
            >
              <Layers className="h-3.5 w-3.5" />
              <span>| stats count by {field}</span>
            </button>
          )}
        </div>

        {/* Values Table */}
        <div className="flex-1 overflow-y-auto rounded border border-subtle bg-surface-1">
          {filteredValues.length === 0 ? (
            <div className="p-8 text-center text-mono ba-text-xs text-muted-foreground">
              No values match the search term.
            </div>
          ) : (
            <table className="w-full text-left font-mono ba-text-2xs">
              <thead className="sticky top-0 border-b border-border/70 bg-surface-2 text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 font-medium">Value</th>
                  <th className="w-20 px-3 py-2 text-right font-medium">Count</th>
                  <th className="w-36 px-3 py-2 font-medium">Distribution</th>
                  <th className="w-24 px-3 py-2 text-center font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/40">
                {filteredValues.map((row) => (
                  <tr key={row.value} className="hover:bg-surface-2/60 transition-colors">
                    <td className="max-w-[240px] truncate px-3 py-2 font-mono text-foreground" title={row.value}>
                      {row.value}
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-foreground">
                      {row.count}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-2">
                        <div className="h-2 flex-1 overflow-hidden rounded-full bg-surface-0">
                          <div
                            className="h-full bg-primary transition-all duration-300"
                            style={{ width: `${Math.min(row.pct, 100)}%` }}
                          />
                        </div>
                        <span className="w-10 text-right tabular-nums text-fg-dim">
                          {row.pct}%
                        </span>
                      </div>
                    </td>
                    <td className="px-3 py-2 text-center">
                      <div className="inline-flex items-center gap-1">
                        <button
                          onClick={() => {
                            onAddChip(field, row.value);
                            toast.success(`Filtered for ${field} = "${row.value}"`);
                            onClose();
                          }}
                          className="rounded border border-subtle p-1 text-fg-dim hover:border-primary/50 hover:bg-primary/10 hover:text-primary transition-colors"
                          title={`Include filter: ${field}=${row.value}`}
                        >
                          <Plus className="h-3 w-3" />
                        </button>
                        {onAppendQuery && (
                          <button
                            onClick={() => {
                              onAppendQuery(` NOT ${field}:"${row.value}"`);
                              toast.success(`Excluded ${row.value} from search`);
                              onClose();
                            }}
                            className="rounded border border-subtle p-1 text-fg-dim hover:border-destructive/50 hover:bg-destructive/10 hover:text-destructive transition-colors"
                            title={`Exclude filter: NOT ${field}:"${row.value}"`}
                          >
                            <Minus className="h-3 w-3" />
                          </button>
                        )}
                        <button
                          onClick={() => handleCopy(row.value)}
                          className="rounded border border-subtle p-1 text-fg-dim hover:bg-surface-2 hover:text-foreground transition-colors"
                          title="Copy value"
                        >
                          <Copy className="h-3 w-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Modal Footer */}
        <div className="mt-3 flex items-center justify-between pt-2">
          <span className="text-mono ba-text-3xs text-fg-dim">
            Showing {filteredValues.length} of {stats.distinctCount} unique value(s)
          </span>
          <button
            onClick={onClose}
            className="rounded border border-subtle bg-surface-1 px-3 py-1 text-mono ba-text-2xs text-muted-foreground hover:bg-surface-2 hover:text-foreground transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
