import { type LucideIcon } from "lucide-react";
import { Panel } from "@/components/soc";

export function SendToRow({
  targets,
}: {
  targets: { label: string; to: string; icon?: LucideIcon; onClick?: () => void }[];
}) {
  return (
    <Panel title="Case Handoff" bodyClassName="p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-mono ba-text-2xs text-muted-foreground">
          send artifact to:
        </span>
        {targets.map((t) => {
          const Icon = t.icon;
          return (
            <a
              key={t.to}
              href={t.to}
              onClick={t.onClick}
              className="group/st inline-flex items-center gap-1.5 rounded border border-border bg-card/70 px-2 py-1 text-mono ba-text-2xs text-fg-dim transition-all duration-150 hover:-translate-y-[1px] hover:border-primary/60 hover:bg-primary/5 hover:text-primary"
            >
              {Icon && <Icon className="h-3 w-3 transition-transform group-hover/st:scale-110" />}
              {t.label}
              <span aria-hidden className="text-fg-dim transition-transform group-hover/st:translate-x-0.5 group-hover/st:text-primary">→</span>
            </a>
          );
        })}

      </div>
    </Panel>
  );
}
