import { ChevronRight } from "lucide-react";
import { Chip } from "@/components/soc";
import { ALL_ENTITIES } from "@/data/intel";
import type { Relationship } from "@/data/intel";

const RELATIONSHIP_COLOR: Record<string, "default" | "primary" | "warning" | "info" | "success" | "accent" | "destructive"> = {
  "uses-tool": "primary",
  "associated-with": "warning",
  "linked-to": "info",
  implements: "primary",
  "resolves-to": "info",
  "originates-from": "warning",
  targets: "destructive",
  "related-to": "accent",
} as const;

export function RelationshipCard({
  relationship,
  onNavigate,
}: {
  relationship: Relationship;
  onNavigate?: (targetId: string) => void;
}) {
  const target = ALL_ENTITIES.find((e) => e.id === relationship.targetId);
  const tone = RELATIONSHIP_COLOR[relationship.relationshipType] ?? "default";

  return (
    <button
      onClick={() => onNavigate?.(relationship.targetId)}
      disabled={!onNavigate}
      className="flex w-full flex-col gap-1 rounded-md border border-subtle bg-surface-1 px-3 py-2 text-left transition-colors duration-150 hover:border-primary/30 hover:bg-surface-2 disabled:cursor-default disabled:opacity-70"
    >
      <div className="flex w-full min-w-0 items-center gap-2">
        <ChevronRight className="h-3 w-3 shrink-0 text-fg-dim" />
        <Chip tone={tone}>
          {relationship.relationshipType.replace(/-/g, " ")}
        </Chip>
        {target ? (
          <span className="min-w-0 flex-1 truncate font-mono ba-text-xs text-foreground">{target.title}</span>
        ) : (
          <span className="min-w-0 flex-1 truncate font-mono ba-text-xs text-fg-dim">{relationship.targetId}</span>
        )}
        <Chip tone={relationship.confidence === "high" ? "success" : relationship.confidence === "medium" ? "warning" : "default"}>
          {relationship.confidence}
        </Chip>
      </div>
      <div className="flex w-full min-w-0 items-center gap-2 pl-1 text-mono ba-text-2xs text-muted-foreground/80">
        <span className="min-w-0 truncate" title={relationship.source}>Source: {relationship.source || "internal"}</span>
        <span className="shrink-0 text-muted-foreground/40">·</span>
        <span className="min-w-0 truncate" title={relationship.reason}>Reason: {relationship.reason || "—"}</span>
      </div>
    </button>
  );
}

export function RelationshipList({
  relationships,
  onNavigate,
}: {
  relationships: Relationship[];
  onNavigate?: (targetId: string) => void;
}) {
  if (relationships.length === 0) return null;

  return (
    <div className="space-y-1.5">
      {relationships.map((r, i) => (
        <RelationshipCard key={`${r.targetId}-${r.relationshipType}-${i}`} relationship={r} onNavigate={onNavigate} />
      ))}
    </div>
  );
}
