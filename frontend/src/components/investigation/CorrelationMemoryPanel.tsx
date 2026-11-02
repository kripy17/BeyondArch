import { useState } from "react";
import { Check, GitCompare, X } from "lucide-react";
import {
  loadCorrelationMemory,
  setCorrelationStatus,
  type CorrelationRecord,
  type CorrelationStatus,
} from "@/lib/correlation/memory";

const DIMENSION_LABEL: Record<CorrelationRecord["dimension"], string> = {
  "same-value-previous": "seen in prior case",
  "existing-detection": "covered by existing detection",
  "entity-overlap": "overlaps known entity",
};

const VISIBLE = 6;

export function CorrelationMemoryPanel() {
  const [records, setRecords] = useState<CorrelationRecord[]>(() => loadCorrelationMemory());
  const [expanded, setExpanded] = useState(false);

  const visible = expanded ? records : records.slice(0, VISIBLE);

  const triage = (id: string, status: CorrelationStatus) => {
    setCorrelationStatus(id, status);
    setRecords(loadCorrelationMemory());
  };

  return (
    <div className="rounded-lg border border-border bg-surface-1 p-3">
      <div className="mb-2 flex items-center gap-1.5 text-mono ba-text-2xs text-muted-foreground">
        <GitCompare className="h-3 w-3 text-info" />
        Correlation memory
        <span className="ml-auto text-muted-foreground/60">workspace-wide · {records.length} match{records.length === 1 ? "" : "es"}</span>
      </div>
      {records.length === 0 ? (
        <p className="text-mono ba-text-3xs text-muted-foreground/70">
          No correlation matches yet. Analyses and alert ingest remember matches against prior cases, detections, and known entities.
        </p>
      ) : (
        <ul className="space-y-1.5">
          {visible.map((r) => (
            <li key={r.id} className="rounded-md border border-border/70 bg-card/60 p-2">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-mono text-mono ba-text-3xs text-foreground">{r.value}</span>
                <span
                  className={
                    "shrink-0 rounded px-1 py-0.5 text-mono ba-text-3xs " +
                    (r.status === "new" ? "bg-warning/10 text-warning" : r.status === "confirmed" ? "bg-success/10 text-success" : "bg-muted/40 text-muted-foreground")
                  }
                >
                  {r.status}
                </span>
              </div>
              <div className="mt-1 text-mono ba-text-3xs text-muted-foreground">
                {DIMENSION_LABEL[r.dimension]} · {r.label} · {Math.round(r.confidence * 100)}% · seen {r.seen}×
              </div>
              <div className="mt-1 text-mono ba-text-3xs text-muted-foreground/60">
                {r.matches.map((m) => m.label).join(", ")} · sources: {r.sources.join(", ")}
              </div>
              <div className="mt-1.5 flex items-center gap-1.5">
                <button
                  onClick={() => triage(r.id, "confirmed")}
                  disabled={r.status === "confirmed"}
                  aria-label={`Confirm correlation match ${r.value}`}
                  className="inline-flex items-center gap-1 rounded border border-success/30 bg-success/10 px-1.5 py-0.5 text-mono ba-text-3xs text-success transition-colors duration-150 hover:bg-success/20 disabled:cursor-default disabled:opacity-40"
                >
                  <Check className="h-2.5 w-2.5" /> confirm
                </button>
                <button
                  onClick={() => triage(r.id, "dismissed")}
                  disabled={r.status === "dismissed"}
                  aria-label={`Dismiss correlation match ${r.value}`}
                  className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground transition-colors duration-150 hover:text-foreground disabled:cursor-default disabled:opacity-40"
                >
                  <X className="h-2.5 w-2.5" /> dismiss
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
      {records.length > VISIBLE && (
        <button
          onClick={() => setExpanded((e) => !e)}
          className="mt-2 text-mono ba-text-3xs text-primary transition-colors duration-150 hover:text-primary/80"
        >
          {expanded ? "show fewer" : `show all ${records.length} matches`}
        </button>
      )}
      <p className="mt-2 text-mono ba-text-3xs text-muted-foreground/60">
        Matches never re-rank raw analysis — they are remembered for analyst review only.
      </p>
    </div>
  );
}