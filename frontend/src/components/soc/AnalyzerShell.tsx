import { useEffect, type ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { useOutputFilter, OutputFilterBar, OutputFilter } from "@/components/soc/OutputFilter";
import { WorkflowActions, type WorkflowAction } from "@/components/soc/WorkflowActions";
import { Zap, Eraser, CornerDownLeft, Search } from "lucide-react";

export type AnalyzerState = "idle" | "ready" | "parsing" | "error" | "empty" | "analyzing" | "loaded";

const STATE_TONE: Record<string, string> = {
  idle: "border-border text-muted-foreground",
  ready: "border-success/50 bg-success/10 text-success",
  parsing: "border-primary/50 bg-primary/10 text-primary animate-pulse",
  error: "border-destructive/50 bg-destructive/10 text-destructive",
  empty: "border-border text-muted-foreground",
  analyzing: "border-primary/50 bg-primary/10 text-primary animate-pulse",
  loaded: "border-success/50 bg-success/10 text-success",
};

export type SendToTarget = { label: string; to: string; icon: LucideIcon; onClick?: () => void };

export function AnalyzerShell({
  icon: Icon,
  title,
  purpose,
  state = "idle",
  intake,
  resultBanner,
  resumeBanner,
  exportMd,
  exportJson,
  onCreateInvestigation,
  sendToTargets,
  extraActions,
  runLabel = "analyse",
  onRun,
  onClear,
  canRun = false,
  meta,
  children,
}: {
  icon: LucideIcon;
  title: string;
  purpose: string;
  state?: AnalyzerState;
  intake: ReactNode;
  resultBanner?: ReactNode;
  resumeBanner?: ReactNode;
  exportMd?: () => void;
  exportJson?: () => void;
  onCreateInvestigation?: () => void;
  sendToTargets?: SendToTarget[];
  extraActions?: WorkflowAction[];
  runLabel?: string;
  onRun?: () => void;
  onClear?: () => void;
  canRun?: boolean;
  meta?: ReactNode;
  children?: ReactNode;
}) {
  const { filterText, setFilterText, showFilter, toggleFilter } = useOutputFilter();

  const hasContent = !!resultBanner || !!children;

  const workflowActions: WorkflowAction[] = [
    ...(sendToTargets?.map(
      (t): WorkflowAction => ({ kind: "pivot", to: t.to, label: t.label, icon: t.icon, onClick: t.onClick })
    ) ?? []),
    ...(onCreateInvestigation ? [{ kind: "investigation" as const, onClick: onCreateInvestigation }] : []),
    ...(exportMd ? [{ kind: "export-md" as const, onClick: exportMd }] : []),
    ...(exportJson ? [{ kind: "export-json" as const, onClick: exportJson }] : []),
    ...(extraActions ?? []),
  ];

  return (
    <div className="ba-fade-in space-y-4">
      <header className="flex flex-wrap items-center gap-3 border-b border-divider-strong pb-3">
        <div className="flex min-w-0 items-center gap-3">
          <span className="relative grid h-9 w-9 shrink-0 place-items-center rounded-md border border-primary/40 bg-primary/10 text-primary shadow-[0_0_0_3px_color-mix(in_oklab,var(--primary)_8%,transparent)]">
            <Icon className="h-4 w-4" />
            <span className="pointer-events-none absolute -right-0.5 -top-0.5 h-1.5 w-1.5 rounded-full bg-primary/80 shadow-[0_0_6px_var(--primary)]" />
          </span>
          <div className="min-w-0">
            <h2 className="truncate text-mono ba-text-lg font-semibold tracking-tight text-foreground">{title}</h2>
            <p className="truncate ba-text-2xs text-muted-foreground">{purpose}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={toggleFilter}
            className={"inline-flex items-center gap-1 rounded border px-2 py-1 text-mono ba-text-2xs transition-colors duration-150" + (showFilter ? "border-primary/50 bg-primary/10 text-primary" : "border-divider-strong text-muted-foreground hover:border-primary/40 hover:text-primary")}
            title="Toggle output filter"
          >
            <Search className="h-3 w-3" />
            filter
          </button>
          {meta}
          <span className={"inline-flex items-center gap-1 rounded border px-2 py-0.5 text-mono ba-text-2xs" + STATE_TONE[state]}>
            <span className={"h-1.5 w-1.5 rounded-full " + (state === "ready" ? "bg-success" : state === "parsing" || state === "analyzing" ? "bg-primary" : state === "error" ? "bg-destructive" : "bg-muted-foreground/60")} />
            {state}
          </span>
        </div>
      </header>

      {resumeBanner}

      <section className="rounded-lg border border-divider-strong bg-card/35 p-4 shadow-[0_18px_70px_-55px_var(--primary)]">
        <div className="space-y-3">{intake}</div>
      </section>

      <div className="flex flex-wrap items-center gap-2 rounded-md border border-divider-strong bg-card/70 px-3 py-2 backdrop-blur sticky top-[calc(var(--ba-topbar-h)+0.5rem)] z-10 elevation-flat">
        <span className="text-mono ba-text-2xs text-muted-foreground">run</span>
        <button
          type="button"
          onClick={onRun}
          disabled={!canRun}
          className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20 disabled:cursor-not-allowed disabled:border-border disabled:bg-transparent disabled:text-muted-foreground"
        >
          <Zap className="h-3 w-3" />
          {runLabel}
        </button>
        <button
          type="button"
          onClick={onClear}
          className="inline-flex items-center gap-1.5 rounded border border-border px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:border-destructive/50 hover:text-destructive"
        >
          <Eraser className="h-3 w-3" /> clear
        </button>
        <span className="ml-auto text-mono ba-text-2xs text-muted-foreground">auto-runs on paste</span>
      </div>

      {showFilter && (
        <OutputFilterBar
          filterText={filterText}
          onChange={setFilterText}
          onClear={() => setFilterText("")}
          onClose={toggleFilter}
        />
      )}

      <div className="mx-auto h-4 w-px bg-gradient-to-b from-primary/50 via-border/70 to-transparent" aria-hidden />

      {hasContent && (
        <section className="min-w-0 space-y-4">
          <OutputFilter query={filterText.toLowerCase()}>
            {resultBanner}
            {children}
            {workflowActions.length > 0 && <WorkflowActions actions={workflowActions} />}
          </OutputFilter>
        </section>
      )}
    </div>
  );
}
