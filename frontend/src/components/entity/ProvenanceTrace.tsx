import type { Edge, NodeRef } from "@/lib/provenance";

/**
 * Shared reader: renders a causal chain of stored provenance edges.
 * The trace is presentation-only — edges are resolved by the caller.
 * Renders nothing when no edges exist.
 */
export function ProvenanceTrace({
  edges,
  resolveNodeLabel,
}: {
  edges: Edge[];
  resolveNodeLabel?: (ref: NodeRef) => string;
}) {
  if (edges.length === 0) return null;

  const label = (ref: NodeRef) => (resolveNodeLabel ? resolveNodeLabel(ref) : ref.id);

  return (
    <div className="rounded border border-subtle bg-surface-0 px-3 py-2">
      <div className="mb-1 text-mono ba-text-2xs text-muted-foreground">provenance</div>
      {edges.map((e) => (
        <div key={e.id} className="flex items-baseline gap-2 py-0.5 text-mono ba-text-2xs">
          <span className="shrink-0 text-fg-dim">{e.relation}</span>
          <span className="shrink-0 text-muted-foreground">[{e.from.kind}] {label(e.from)}</span>
          <span className="shrink-0 text-fg-dim">→</span>
          <span className="truncate text-foreground">[{e.to.kind}] {label(e.to)}</span>
          {e.source && <span className="ml-auto shrink-0 text-muted-foreground">· {e.source}</span>}
        </div>
      ))}
    </div>
  );
}
