import { useState } from "react";
import { GitBranch } from "lucide-react";
import type { Finding, IOC } from "@/types/security";
import type { Edge, NodeRef } from "@/lib/provenance";
import { Chip } from "@/components/soc";
import { ProvenanceTrace } from "./ProvenanceTrace";

const SEVERITY_TONE: Record<string, "destructive" | "warning" | "success" | "info" | "default"> = {
  critical: "destructive", high: "warning", medium: "warning", low: "success", info: "info",
};

export function FindingCard({
  finding,
  relatedIocs,
  onFilterSource,
  filterActive,
  trace,
  resolveNodeLabel,
}: {
  finding: Finding;
  relatedIocs?: IOC[];
  onFilterSource?: (source: string) => void;
  filterActive?: boolean;
  trace?: { back: Edge[]; forward: Edge[] } | null;
  resolveNodeLabel?: (ref: NodeRef) => string;
}) {
  const [traceOpen, setTraceOpen] = useState(false);
  const tone = SEVERITY_TONE[finding.severity] || "default";
  const borderColor = tone === "destructive" ? "border-l-destructive/40" : tone === "warning" ? "border-l-warning/40" : tone === "success" ? "border-l-success/40" : tone === "info" ? "border-l-info/40" : "border-l-border/40";
  const iocs = relatedIocs ?? [];
  const edges = trace ? [...trace.back, ...trace.forward] : [];
  const hasTrace = edges.length > 0;

  return (
    <div className={`rounded-md border border-subtle bg-surface-1 border-l-2 ${borderColor} shadow-sm transition-all duration-200 hover:bg-surface-2 hover:shadow-md`}>
      <div className="px-4 py-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2 min-w-0">
            <Chip tone={tone}>{finding.severity}</Chip>
            <span className="font-mono ba-text-sm font-medium text-foreground truncate">{finding.title}</span>
          </div>
          <div className="flex shrink-0 items-center gap-1">
            {finding.source && onFilterSource && (
              <button
                onClick={() => onFilterSource(finding.source!)}
                className={"rounded px-1.5 py-0.5 font-mono ba-text-2xs transition-colors duration-150 " + (filterActive ? "border border-primary/30 bg-primary/10 text-primary" : "text-muted-foreground hover:text-primary hover:bg-surface-2")}
              >
                {finding.source}
              </button>
            )}
            {hasTrace && (
              <button
                onClick={() => setTraceOpen(v => !v)}
                title="Why is this finding here?"
                className={"rounded px-1.5 py-0.5 transition-colors duration-150 " + (traceOpen ? "text-primary" : "text-muted-foreground hover:text-primary")}
              >
                <GitBranch className="h-3 w-3" />
              </button>
            )}
          </div>
        </div>
        {finding.detail && (
          <div className="mt-1.5 whitespace-pre-wrap font-mono ba-text-xs text-fg-dim">{finding.detail}</div>
        )}
        {iocs.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-2 font-mono ba-text-2xs text-fg-dim">
            {iocs.slice(0, 3).map((ioc) => (
              <span
                key={`${ioc.type}-${ioc.value}`}
                className="inline-flex items-center gap-1 rounded border border-destructive/20 bg-destructive/5 px-1.5 py-0.5 text-destructive/70"
              >
                {ioc.type}:{ioc.value.length > 30 ? ioc.value.slice(0, 30) + "\u2026" : ioc.value}
              </span>
            ))}
            {iocs.length > 3 && (
              <span className="text-muted-foreground">+{iocs.length - 3} more</span>
            )}
          </div>
        )}
        {traceOpen && hasTrace && (
          <div className="mt-2">
            <ProvenanceTrace edges={edges} resolveNodeLabel={resolveNodeLabel} />
          </div>
        )}
      </div>
    </div>
  );
}
