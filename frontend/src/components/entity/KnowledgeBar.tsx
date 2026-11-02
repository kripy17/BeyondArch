import { useNavigate } from "@tanstack/react-router";
import { Eye, GitBranch, Siren, BookOpen } from "lucide-react";
import type { IntelEntity } from "@/data/intel";

export function KnowledgeBar({
  entity,
  relationshipCount,
  activeCase,
  observables = 0,
  mitre = 0,
}: {
  entity: IntelEntity;
  relationshipCount: number;
  activeCase: { id: string; title: string } | null;
  observables?: number;
  mitre?: number;
}) {
  const navigate = useNavigate();

  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      <StatCard icon={Eye} label="Observables" count={observables || entity.observables.length} />
      <StatCard icon={GitBranch} label="Relationships" count={relationshipCount} />
      <StatCard icon={BookOpen} label="MITRE" count={mitre} />
      <StatCard
        icon={Siren}
        label="Case"
        count={activeCase ? 1 : 0}
        active={!!activeCase}
        onClick={activeCase ? () => navigate({ to: "/case" }) : undefined}
        meta={activeCase?.title}
      />
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  count,
  active,
  onClick,
  meta,
}: {
  icon: typeof Eye;
  label: string;
  count: number;
  active?: boolean;
  onClick?: () => void;
  meta?: string;
}) {
  return (
    <button
      onClick={onClick}
      disabled={!onClick}
      className={"group rounded-md border p-3 text-left transition-colors duration-150 disabled:cursor-default " + (active ? "border-primary/40 bg-primary/10 hover:bg-primary/15" : "border-subtle bg-surface-1 hover:border-primary/30 hover:bg-surface-2 disabled:opacity-70")}
    >
      <div className="flex items-center gap-2">
        <Icon className="h-3.5 w-3.5 text-fg-dim transition-colors duration-150 group-hover:text-primary" />
        <span className="font-mono ba-text-3xs text-fg-dim">{label}</span>
      </div>
      <div className="mt-1 font-mono text-lg font-bold tabular-nums text-foreground">{count}</div>
      {meta && (
        <div className="mt-0.5 truncate font-mono ba-text-2xs text-fg-dim">{meta}</div>
      )}
    </button>
  );
}
