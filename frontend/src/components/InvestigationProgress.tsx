import { useMemo } from "react";
import { Check, Circle, FileText, Shield, Share2, Siren, BookOpen, FileOutput, Send, ArrowRight } from "lucide-react";
import { getChecklist, getProgress, markFindingsReviewed, markHandoffReady } from "@/data/case-checklist";
import type { Case } from "@/data/case";
import type { ChecklistItem, ChecklistItemId } from "@/data/case-checklist";
import { cn } from "@/lib/utils";

const ITEM_ICONS: Record<string, typeof Check> = {
  intake: Shield,
  analysis: FileText,
  "findings-reviewed": Check,
  "iocs-investigated": Siren,
  "intel-enriched": Share2,
  "notes-written": BookOpen,
  "report-generated": FileOutput,
  "ready-handoff": Send,
};

type ProgressActions = {
  goToTab?: (tab: string) => void;
  goToRoute?: (path: string) => void;
};

type Action = { label: string; onClick: () => void };

const NEXT_ACTIONS: Partial<Record<ChecklistItemId, (a: ProgressActions) => Action | null>> = {
  "findings-reviewed": (a) => a.goToTab ? { label: "Review Findings", onClick: () => a.goToTab!("findings") } : null,
  "iocs-investigated": (a) => a.goToTab ? { label: "View IOCs", onClick: () => a.goToTab!("findings") } : null,
  "intel-enriched": (a) => a.goToRoute ? { label: "Open Intel Hub", onClick: () => a.goToRoute!("/intel") } : null,
  "notes-written": (a) => a.goToTab ? { label: "Write Notes", onClick: () => a.goToTab!("notebook") } : null,
  "report-generated": (a) => a.goToTab ? { label: "Generate Report", onClick: () => a.goToTab!("reports") } : null,
  "ready-handoff": () => ({ label: "Mark Ready", onClick: () => {} }),
};

export function InvestigationProgress({ case: c, onUpdate, ...actions }: { case: Case; onUpdate?: () => void } & ProgressActions) {
  const items = useMemo(() => getChecklist(c), [c]);
  const progress = useMemo(() => getProgress(items), [items]);
  const nextAction = useMemo(() => {
    const first = items.find((i) => !i.done);
    if (!first) return null;
    const builder = NEXT_ACTIONS[first.id];
    return builder ? builder(actions) : null;
  }, [items, actions]);

  if (c.state === "closed") {
    return (
      <div className="rounded-lg border border-border bg-surface-1 p-3">
        <div className="flex items-center gap-2 text-mono ba-text-2xs text-muted-foreground">
          <Check className="h-3 w-3 text-success" />
          Case Closed
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-surface-1 p-3">
      <div className="mb-2 flex items-center justify-between">
        <span className="text-mono ba-text-2xs text-muted-foreground">Investigation Progress</span>
        <span className="text-mono ba-text-2xs font-bold text-fg-dim">{progress}%</span>
      </div>

      {progress > 0 && progress < 100 && (
        <div className="mb-3 h-1.5 overflow-hidden rounded-full bg-muted">
          <div
            className="h-full rounded-full bg-primary transition-all duration-500"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      {nextAction && (
        <button
          onClick={nextAction.onClick}
          className="mb-3 flex w-full items-center gap-2 rounded-md border border-primary/30 bg-primary/[0.06] px-3 py-2 text-left transition-colors duration-150 hover:bg-primary/[0.1]"
        >
          <ArrowRight className="h-3 w-3 shrink-0 text-primary" />
          <div className="min-w-0 flex-1">
            <div className="text-mono ba-text-3xs text-muted-foreground">Next Action</div>
            <div className="text-mono ba-text-xs font-semibold text-foreground">{nextAction.label}</div>
          </div>
        </button>
      )}

      <ul className="space-y-1">
        {items.map((item) => (
          <ChecklistRow key={item.id} item={item} caseId={c.id} onUpdate={onUpdate} actions={actions} />
        ))}
      </ul>
    </div>
  );
}

function ChecklistRow({ item, caseId, onUpdate, actions }: { item: ChecklistItem; caseId: string; onUpdate?: () => void; actions: ProgressActions }) {
  const Icon = ITEM_ICONS[item.id] ?? Circle;
  const action = useMemo(() => {
    if (item.done) return null;
    const builder = NEXT_ACTIONS[item.id];
    return builder ? builder(actions) : null;
  }, [item, actions]);

  if (item.id === "findings-reviewed" && !item.done) {
    return (
      <li>
        <div className="flex items-center gap-2 rounded px-2 py-1">
          <span className="grid h-4 w-4 shrink-0 place-items-center rounded border border-warning bg-warning/20 text-warning">
            <Icon className="h-2.5 w-2.5" />
          </span>
          <span className="flex-1 text-mono ba-text-2xs text-foreground">{item.label}</span>
          {item.detail && <span className="text-mono ba-text-3xs text-warning">{item.detail}</span>}
        </div>
        <div className="flex gap-1 pl-8">
          <button
            onClick={() => { markFindingsReviewed(caseId); onUpdate?.(); }}
            className="rounded border border-success/30 bg-success/[0.08] px-2 py-0.5 text-mono ba-text-3xs text-success hover:bg-success/[0.15]"
          >
            Mark Reviewed
          </button>
          {action && (
            <button
              onClick={action.onClick}
              className="rounded border border-border bg-surface-2 px-2 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-foreground"
            >
              {action.label} →
            </button>
          )}
        </div>
      </li>
    );
  }

  if (item.id === "ready-handoff" && !item.done) {
    return (
      <li>
        <div className="flex items-center gap-2 rounded px-2 py-1">
          <span className="grid h-4 w-4 shrink-0 place-items-center rounded border border-border bg-surface-2 text-muted-foreground">
            <Icon className="h-2.5 w-2.5" />
          </span>
          <span className="flex-1 text-mono ba-text-2xs text-foreground">{item.label}</span>
        </div>
        <div className="flex gap-1 pl-8">
          <button
            onClick={() => { markHandoffReady(caseId, true); onUpdate?.(); }}
            className="rounded border border-primary/30 bg-primary/[0.08] px-2 py-0.5 text-mono ba-text-3xs text-primary hover:bg-primary/[0.15]"
          >
            Mark Ready
          </button>
        </div>
      </li>
    );
  }

  return (
    <li className="flex items-center gap-2 px-2 py-1">
      <span
        className={cn(
          "grid h-4 w-4 shrink-0 place-items-center rounded",
          item.done
            ? "border border-success/40 bg-success/20 text-success"
            : "border border-border/60 bg-surface-2 text-muted-foreground",
        )}
      >
        {item.done ? <Check className="h-2.5 w-2.5" /> : <Circle className="h-2 w-2" />}
      </span>
      <div className="flex flex-1 items-center gap-2 min-w-0">
        <span className={cn("text-mono ba-text-2xs", item.done ? "text-foreground/60" : "text-foreground")}>
          {item.label}
        </span>
        {item.detail && (
          <span className={cn("text-mono ba-text-3xs", item.done ? "text-success" : "text-warning")}>
            {item.detail}
          </span>
        )}
      </div>
      {action && (
        <button
          onClick={action.onClick}
          className="shrink-0 rounded border border-border bg-surface-2 px-2 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-foreground"
        >
          {action.label} →
        </button>
      )}
    </li>
  );
}
