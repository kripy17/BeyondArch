import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMemo, useState, useEffect, useCallback } from "react";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Panel, Chip, SendToRow } from "@/components/soc";
import { VerdictBanner, MetricGrid } from "@/components/output";
import { useLocker, guessType } from "@/lib/locker";
import { pushTimelineEvent } from "@/lib/timeline";
import { loadCases, saveCases, setActiveCaseId } from "@/data/case";
import {
  SOP_RUNBOOKS,
  SOP_PHASE_CONFIG,
  calculateSopCatalogMetrics,
  instantiateCaseFromSop,
  exportSopRunbookMarkdown,
  type SopRunbook,
  type SopPhase,
  type SopStep,
} from "@/lib/sop-guide";
import { toast } from "sonner";
import {
  BookOpen,
  ArrowRight,
  Database,
  ShieldAlert,
  Search,
  CheckCircle2,
  Circle,
  AlertTriangle,
  ShieldOff,
  Mail,
  FileWarning,
  Activity,
  KeyRound,
  Filter,
  ShieldCheck,
  Globe2,
  User,
  Package,
  Lock,
  Radio,
  Hash,
  Download,
  FolderPlus,
  Siren,
  Cloud,
  CheckSquare,
  Clock,
  Layers,
  ExternalLink,
} from "lucide-react";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/guide")({ component: GuidePage });

const ICON_MAP: Record<string, typeof Mail> = {
  Siren,
  Radio,
  KeyRound,
  Cloud,
  Mail,
  Globe2,
  FileWarning,
  Package,
  ShieldAlert,
  Lock,
  User,
  Activity,
};

const SEV_COLOR: Record<"P1" | "P2" | "P3", "destructive" | "warning" | "default"> = {
  P1: "destructive",
  P2: "warning",
  P3: "default",
};

const CATEGORIES = ["ALL", "Malware", "Network", "Identity", "Cloud", "Email", "Web", "Development", "Insider"] as const;

export function GuidePage() {
  const navigate = useNavigate();
  useEffect(() => {
    navigate({ to: "/investigation", replace: true });
  }, [navigate]);
  const locker = useLocker();
  const [activeId, setActiveId] = useState<string>(SOP_RUNBOOKS[0].id);
  const [query, setQuery] = useState("");
  const [selectedSev, setSelectedSev] = useState<"ALL" | "P1" | "P2" | "P3">("ALL");
  const [selectedCategory, setSelectedCategory] = useState<typeof CATEGORIES[number]>("ALL");
  const [phaseFilter, setPhaseFilter] = useState<"ALL" | SopPhase>("ALL");

  // Local storage persistence for step completion
  const [doneSteps, setDoneSteps] = useState<Record<string, string[]>>(() => {
    try {
      const raw = localStorage.getItem("ba.sop.done.v2");
      if (!raw) return {};
      return JSON.parse(raw);
    } catch {
      return {};
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem("ba.sop.done.v2", JSON.stringify(doneSteps));
    } catch {
      // Storage unavailable
    }
  }, [doneSteps]);

  const catalogMetrics = useMemo(() => calculateSopCatalogMetrics(SOP_RUNBOOKS), []);

  const filteredRunbooks = useMemo(() => {
    const q = query.trim().toLowerCase();
    return SOP_RUNBOOKS.filter((r) => {
      if (selectedSev !== "ALL" && r.severity !== selectedSev) return false;
      if (selectedCategory !== "ALL" && r.category !== selectedCategory) return false;
      if (!q) return true;

      const titleMatch = r.title.toLowerCase().includes(q);
      const summaryMatch = r.summary.toLowerCase().includes(q);
      const categoryMatch = r.category.toLowerCase().includes(q);
      const mitreMatch = r.attack.some((t) => t.toLowerCase().includes(q));
      const stepMatch = r.steps.some((s) => s.text.toLowerCase().includes(q) || s.guidance?.toLowerCase().includes(q));

      return titleMatch || summaryMatch || categoryMatch || mitreMatch || stepMatch;
    });
  }, [query, selectedSev, selectedCategory]);

  const activeRunbook = useMemo(() => {
    return SOP_RUNBOOKS.find((r) => r.id === activeId) ?? SOP_RUNBOOKS[0];
  }, [activeId]);

  const activeDoneSet = useMemo(() => {
    return new Set<string>(doneSteps[activeRunbook.id] ?? []);
  }, [doneSteps, activeRunbook.id]);

  const visibleSteps = useMemo(() => {
    if (phaseFilter === "ALL") return activeRunbook.steps;
    return activeRunbook.steps.filter((s) => s.phase === phaseFilter);
  }, [activeRunbook, phaseFilter]);

  const activeProgress = useMemo(() => {
    if (activeRunbook.steps.length === 0) return 0;
    const count = activeRunbook.steps.filter((s) => activeDoneSet.has(s.id)).length;
    return Math.round((count / activeRunbook.steps.length) * 100);
  }, [activeRunbook, activeDoneSet]);

  const toggleStep = useCallback((stepId: string) => {
    setDoneSteps((prev) => {
      const current = new Set(prev[activeRunbook.id] ?? []);
      if (current.has(stepId)) {
        current.delete(stepId);
      } else {
        current.add(stepId);
      }
      return {
        ...prev,
        [activeRunbook.id]: Array.from(current),
      };
    });
  }, [activeRunbook.id]);

  const handleClear = useCallback(() => {
    setQuery("");
    setSelectedSev("ALL");
    setSelectedCategory("ALL");
    setPhaseFilter("ALL");
    toast.info("Cleared filters");
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") handleClear();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [handleClear]);

  // Extract IOCs to locker
  const handleExtractIocs = () => {
    const text = [
      activeRunbook.title,
      activeRunbook.summary,
      activeRunbook.objective,
      ...activeRunbook.steps.map((s) => `${s.text} ${s.guidance ?? ""}`),
      ...activeRunbook.alwaysRules,
      ...activeRunbook.neverRules,
    ].join(" ");

    const ipRx = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const domainRx = /\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b/g;
    const hashRx = /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi;

    const ips = [...new Set(text.match(ipRx) ?? [])];
    const rawDomains = [...new Set(text.match(domainRx) ?? [])];
    const hashes = [...new Set(text.match(hashRx) ?? [])];

    const domains = rawDomains.filter((d) => !ips.includes(d) && guessType(d) === "domain");

    ips.forEach((v) => locker.add({ value: v, type: "ipv4", source: `/guide#${activeRunbook.id}` }));
    domains.forEach((v) => locker.add({ value: v, type: "domain", source: `/guide#${activeRunbook.id}` }));
    hashes.forEach((v) => locker.add({ value: v, type: "sha256", source: `/guide#${activeRunbook.id}` }));

    const total = ips.length + domains.length + hashes.length;
    pushTimelineEvent({
      source: "guide",
      verb: "extracted",
      detail: `Extracted ${ips.length} IPs, ${domains.length} domains, ${hashes.length} hashes from SOP ${activeRunbook.shortName}`,
      result: `${total} IOCs`,
    });
    toast.success(`Extracted ${total} IOCs from SOP to locker`);
  };

  // Export Markdown checklist
  const handleExportMarkdown = () => {
    const md = exportSopRunbookMarkdown(activeRunbook, activeDoneSet);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sop-${activeRunbook.id}-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Exported ${activeRunbook.shortName} SOP to Markdown`);
  };

  // 1-Click Deploy to Case Desk
  const handleDeployToCase = () => {
    const existingCases = loadCases();
    const newCase = instantiateCaseFromSop(activeRunbook);
    const updated = [newCase, ...existingCases];
    saveCases(updated);
    setActiveCaseId(newCase.id);

    pushTimelineEvent({
      source: "guide",
      verb: "deployed_case",
      detail: `Staged incident case for ${activeRunbook.title}`,
      result: newCase.id,
    });

    toast.success(`Deployed Incident Case: "${newCase.title}"`);
    navigate({ to: "/case" });
  };

  const ActiveIcon = ICON_MAP[activeRunbook.iconName] ?? BookOpen;

  return (
    <ErrorBoundary name="GuidePage">
      <PageShell
        eyebrow="knowledge / sop-guide"
        title="Analyst SOP Field Guide & IR Runbook Manual"
        description="Standard Operating Procedures aligned with NIST SP 800-61r2 & SANS IR lifecycle. Interactive step checklists, response SLAs, 1-click incident deployment to Case Desk, and direct tool pivots."
        crumbs={[{ label: "Knowledge" }, { label: "SOP Guide" }]}
        actions={
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              onClick={handleDeployToCase}
              className="inline-flex items-center gap-1.5 rounded-md border border-primary/40 bg-primary/15 px-2.5 py-1 text-mono ba-text-xs font-medium text-primary hover:bg-primary/25 transition-colors"
              title="Create an incident case pre-populated with this SOP checklist"
            >
              <FolderPlus className="h-3.5 w-3.5 text-primary" />
              <span>Deploy to Case Desk</span>
            </button>
            <button
              onClick={handleExportMarkdown}
              className="inline-flex items-center gap-1 rounded border border-border bg-surface-1 px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground transition-colors"
            >
              <Download className="h-3 w-3" /> .md
            </button>
            <button
              onClick={handleExtractIocs}
              className="inline-flex items-center gap-1 rounded border border-border bg-surface-1 px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground transition-colors"
              title="Extract IPs, domains, and hashes from this SOP to the IOC Locker"
            >
              <Hash className="h-3 w-3 text-primary" /> IOCs
            </button>
          </div>
        }
      >
        {/* Verdict Banner */}
        <VerdictBanner
          verdict={`${catalogMetrics.totalRunbooks} Standardized Incident Response SOPs`}
          tone="success"
          icon={ShieldCheck}
          details={[
            `${catalogMetrics.p1Count} P1 Critical · ${catalogMetrics.p2Count} P2 High · ${catalogMetrics.p3Count} P3 Medium`,
            `SLA Target: ~${catalogMetrics.avgMtrMinutes}m MTTR · ${catalogMetrics.uniqueMitreTechniques} MITRE ATT&CK Techniques Mapped`,
          ]}
        />

        {/* 4-KPI Knowledge Ribbon */}
        <MetricGrid
          columns={4}
          metrics={[
            { label: "Catalog Runbooks", value: catalogMetrics.totalRunbooks, tone: "primary", icon: BookOpen },
            { label: "P1 Critical SOPs", value: catalogMetrics.p1Count, tone: "destructive", icon: Siren },
            { label: "Target Mean SLA", value: `~${catalogMetrics.avgMtrMinutes}m`, tone: "warning", icon: Clock },
            { label: "MITRE Techniques", value: catalogMetrics.uniqueMitreTechniques, tone: "default", icon: ShieldAlert },
          ]}
        />

        <SectionBar
          id="SOP_EXPLORER"
          label="SOP Catalog & Operational Runbook Workspace"
          meta={`${filteredRunbooks.length} of ${catalogMetrics.totalRunbooks} visible`}
        />

        {/* Filter and Search Bar */}
        <div className="space-y-2">
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
            <div className="flex flex-1 items-center gap-2 rounded border border-border bg-surface-0 px-3 py-1.5">
              <Search className="h-4 w-4 text-muted-foreground shrink-0" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                aria-label="Search runbooks"
                placeholder="Search runbooks by title, MITRE ID (e.g. T1486), summary, or keyword…"
                className="w-full bg-transparent text-mono ba-text-sm outline-none placeholder:text-muted-foreground"
              />
              {query && (
                <button
                  onClick={() => setQuery("")}
                  className="text-mono ba-text-3xs text-muted-foreground hover:text-foreground"
                >
                  Clear
                </button>
              )}
            </div>

            <div className="flex items-center gap-1.5 shrink-0">
              <div className="flex items-center gap-1 rounded border border-border bg-surface-1 p-1">
                <span className="text-mono ba-text-3xs text-muted-foreground px-1">SEV:</span>
                {(["ALL", "P1", "P2", "P3"] as const).map((s) => (
                  <button
                    key={s}
                    onClick={() => setSelectedSev(s)}
                    className={cn(
                      "rounded px-2 py-0.5 text-mono ba-text-2xs transition-colors",
                      selectedSev === s
                        ? "bg-primary/20 text-primary font-medium"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Category Chips Bar */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-mono ba-text-3xs text-muted-foreground mr-1 flex items-center gap-1">
              <Filter className="h-3 w-3" /> Category:
            </span>
            {CATEGORIES.map((cat) => {
              const count =
                cat === "ALL"
                  ? catalogMetrics.totalRunbooks
                  : catalogMetrics.categoryBreakdown[cat] ?? 0;
              return (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={cn(
                    "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-mono ba-text-2xs transition-colors",
                    selectedCategory === cat
                      ? "border-primary bg-primary/15 text-primary font-medium"
                      : "border-border/60 bg-surface-1 text-muted-foreground hover:border-border hover:text-foreground"
                  )}
                >
                  <span>{cat}</span>
                  <span className="opacity-60 text-mono ba-text-3xs">({count})</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Responsive Dual Pane: Left Catalog Rail + Right Runbook Stage */}
        <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,21rem)_minmax(0,1fr)] gap-4">
          {/* Left: Runbook Navigation Drawer */}
          <div className="space-y-2">
            <Panel bodyClassName="p-1.5 max-h-[720px] overflow-y-auto">
              <ul className="space-y-1">
                {filteredRunbooks.map((runbook) => {
                  const Icon = ICON_MAP[runbook.iconName] ?? BookOpen;
                  const isActive = runbook.id === activeRunbook.id;
                  const completed = doneSteps[runbook.id]?.length ?? 0;
                  const percent = Math.round((completed / runbook.steps.length) * 100);

                  return (
                    <li key={runbook.id}>
                      <button
                        onClick={() => {
                          setActiveId(runbook.id);
                          setPhaseFilter("ALL");
                        }}
                        className={cn(
                          "group flex w-full flex-col gap-1.5 rounded-md border p-2.5 text-left transition-colors",
                          isActive
                            ? "border-primary/50 bg-primary/10 shadow-sm"
                            : "border-transparent bg-surface-1/40 hover:border-border hover:bg-surface-2"
                        )}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-1.5 min-w-0">
                            <Icon
                              className={cn(
                                "h-4 w-4 shrink-0",
                                isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
                              )}
                            />
                            <span className="truncate text-mono ba-text-xs font-medium text-foreground">
                              {runbook.shortName}
                            </span>
                          </div>
                          <Chip tone={SEV_COLOR[runbook.severity]}>{runbook.severity}</Chip>
                        </div>

                        <p className="line-clamp-2 text-mono ba-text-3xs text-muted-foreground leading-relaxed">
                          {runbook.summary}
                        </p>

                        <div className="flex items-center justify-between text-mono ba-text-3xs text-muted-foreground pt-1 border-t border-border/40">
                          <span className="flex items-center gap-1">
                            <span>{runbook.category}</span>
                            <span>·</span>
                            <span>~{runbook.eta}</span>
                          </span>
                          <span className="font-medium text-primary/80">
                            {completed}/{runbook.steps.length} ({percent}%)
                          </span>
                        </div>

                        {/* Miniature Progress Bar */}
                        <div className="h-1 w-full overflow-hidden rounded-full bg-border/40">
                          <div
                            className={cn("h-full transition-all", percent === 100 ? "bg-success" : "bg-primary")}
                            style={{ width: `${percent}%` }}
                          />
                        </div>
                      </button>
                    </li>
                  );
                })}

                {filteredRunbooks.length === 0 && (
                  <li className="px-3 py-8 text-center text-mono ba-text-xs text-muted-foreground">
                    No incident runbooks match your search filter.
                  </li>
                )}
              </ul>
            </Panel>
          </div>

          {/* Right: Active Runbook Inspection & Interactive Step Runner */}
          <div className="space-y-4">
            {/* Header Card */}
            <Panel
              title={activeRunbook.title}
              icon={ActiveIcon}
              meta={`${activeRunbook.category} · Target SLA: ~${activeRunbook.eta}`}
              actions={
                <div className="flex items-center gap-2">
                  <Chip tone={SEV_COLOR[activeRunbook.severity]}>{activeRunbook.severity}</Chip>
                  <button
                    onClick={handleDeployToCase}
                    className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-mono ba-text-2xs text-primary hover:bg-primary/20 transition-colors"
                  >
                    <FolderPlus className="h-3 w-3" /> Deploy
                  </button>
                </div>
              }
            >
              <div className="space-y-3">
                <p className="text-fg-dim ba-text-sm leading-relaxed">{activeRunbook.summary}</p>

                <div className="rounded border border-border/60 bg-surface-1/70 p-3 space-y-2">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-mono ba-text-xs">
                    <span className="text-muted-foreground">
                      <strong className="text-foreground">Objective:</strong> {activeRunbook.objective}
                    </span>
                  </div>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-mono ba-text-2xs text-muted-foreground border-t border-border/40 pt-2">
                    <span>
                      <strong className="text-destructive">Escalation Trigger:</strong>{" "}
                      {activeRunbook.escalationTrigger}
                    </span>
                  </div>
                </div>

                {/* KPI Benchmarks Strip */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <div className="rounded border border-border/50 bg-surface-0 px-2.5 py-1.5">
                    <div className="text-mono ba-text-3xs text-muted-foreground">Typical Dwell Time</div>
                    <div className="text-mono ba-text-xs font-semibold text-foreground">
                      {activeRunbook.kpis.typicalDwellTime}
                    </div>
                  </div>
                  <div className="rounded border border-border/50 bg-surface-0 px-2.5 py-1.5">
                    <div className="text-mono ba-text-3xs text-muted-foreground">Target Containment SLA</div>
                    <div className="text-mono ba-text-xs font-semibold text-warning">
                      {activeRunbook.kpis.containmentSla}
                    </div>
                  </div>
                  <div className="rounded border border-border/50 bg-surface-0 px-2.5 py-1.5">
                    <div className="text-mono ba-text-3xs text-muted-foreground">FP Likelihood</div>
                    <div className="text-mono ba-text-xs font-semibold text-muted-foreground">
                      {activeRunbook.kpis.falsePositiveRate}
                    </div>
                  </div>
                </div>

                {/* MITRE ATT&CK Badges */}
                {activeRunbook.attack.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-mono ba-text-3xs text-muted-foreground">MITRE ATT&CK:</span>
                    {activeRunbook.attack.map((techniqueId) => (
                      <Link
                        key={techniqueId}
                        to="/mitre"
                        className="inline-flex items-center gap-1 rounded border border-primary/30 bg-primary/10 px-2 py-0.5 text-mono ba-text-2xs text-primary hover:bg-primary/20 transition-colors"
                        title="View technique coverage in MITRE Navigator"
                      >
                        <span>{techniqueId}</span>
                        <ExternalLink className="h-2.5 w-2.5" />
                      </Link>
                    ))}
                  </div>
                )}
              </div>
            </Panel>

            {/* NIST SP 800-61 Lifecycle Phase Filter & Progress Bar */}
            <Panel>
              <div className="space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <CheckSquare className="h-4 w-4 text-primary" />
                    <span className="text-mono ba-text-xs font-semibold text-foreground">
                      NIST SP 800-61 Lifecycle Execution
                    </span>
                  </div>
                  <div className="text-mono ba-text-2xs text-muted-foreground">
                    {activeDoneSet.size} of {activeRunbook.steps.length} steps completed ({activeProgress}%)
                  </div>
                </div>

                {/* Step Progress Bar */}
                <div className="h-2 w-full overflow-hidden rounded-full bg-border/40">
                  <div
                    className={cn(
                      "h-full transition-all duration-300",
                      activeProgress === 100 ? "bg-success" : "bg-primary"
                    )}
                    style={{ width: `${activeProgress}%` }}
                  />
                </div>

                {/* Phase Selection Tabs */}
                <div className="flex flex-wrap items-center gap-1 pt-1 border-t border-border/40">
                  <button
                    onClick={() => setPhaseFilter("ALL")}
                    className={cn(
                      "rounded px-2.5 py-1 text-mono ba-text-2xs transition-colors",
                      phaseFilter === "ALL"
                        ? "bg-primary/20 text-primary font-medium"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    All Steps ({activeRunbook.steps.length})
                  </button>

                  {(
                    [
                      "preparation",
                      "detection",
                      "containment",
                      "eradication",
                      "recovery",
                      "post_incident",
                    ] as const
                  ).map((phase) => {
                    const cfg = SOP_PHASE_CONFIG[phase];
                    const phaseCount = activeRunbook.steps.filter((s) => s.phase === phase).length;
                    if (phaseCount === 0) return null;
                    const phaseDone = activeRunbook.steps.filter(
                      (s) => s.phase === phase && activeDoneSet.has(s.id)
                    ).length;

                    return (
                      <button
                        key={phase}
                        onClick={() => setPhaseFilter(phase)}
                        className={cn(
                          "rounded px-2.5 py-1 text-mono ba-text-2xs transition-colors",
                          phaseFilter === phase
                            ? "bg-primary/20 text-primary font-medium"
                            : "text-muted-foreground hover:text-foreground"
                        )}
                      >
                        <span>{cfg.label.split(". ")[1]}</span>
                        <span className="opacity-60 ml-1">
                          ({phaseDone}/{phaseCount})
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            </Panel>

            {/* Step-by-Step Interactive Checklist */}
            <div className="space-y-2">
              {visibleSteps.map((step, idx) => {
                const isDone = activeDoneSet.has(step.id);
                const phaseConfig = SOP_PHASE_CONFIG[step.phase];

                return (
                  <div
                    key={step.id}
                    className={cn(
                      "group rounded-md border p-3 transition-colors",
                      isDone
                        ? "border-success/40 bg-success/5 text-muted-foreground"
                        : "border-border bg-surface-1 hover:border-primary/40"
                    )}
                  >
                    <div className="flex items-start gap-3">
                      <button
                        onClick={() => toggleStep(step.id)}
                        aria-label={`Toggle step ${step.id}`}
                        className="mt-0.5 shrink-0 focus:outline-none"
                      >
                        {isDone ? (
                          <CheckCircle2 className="h-4 w-4 text-success" />
                        ) : (
                          <Circle className="h-4 w-4 text-muted-foreground group-hover:text-primary transition-colors" />
                        )}
                      </button>

                      <div className="flex-1 min-w-0 space-y-1.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={cn(
                              "text-mono ba-text-3xs font-semibold uppercase px-1.5 py-0.5 rounded border",
                              step.criticality === "mandatory"
                                ? "border-destructive/40 bg-destructive/10 text-destructive"
                                : step.criticality === "recommended"
                                ? "border-warning/40 bg-warning/10 text-warning"
                                : "border-border bg-surface-2 text-muted-foreground"
                            )}
                          >
                            {step.criticality}
                          </span>

                          <Chip tone={phaseConfig.tone}>{phaseConfig.label}</Chip>

                          {step.pivot && (
                            <Link
                              to={step.pivot.to}
                              className="ml-auto inline-flex items-center gap-1 rounded border border-primary/30 bg-primary/10 px-2 py-0.5 text-mono ba-text-2xs text-primary hover:bg-primary/20 transition-colors"
                            >
                              <span>{step.pivot.label}</span>
                              <ArrowRight className="h-3 w-3" />
                            </Link>
                          )}
                        </div>

                        <p
                          className={cn(
                            "ba-text-sm leading-snug",
                            isDone ? "line-through text-muted-foreground" : "text-foreground"
                          )}
                        >
                          {step.text}
                        </p>

                        {step.guidance && (
                          <div className="rounded border border-border/40 bg-surface-0/60 p-2 text-mono ba-text-2xs text-fg-dim">
                            <span className="font-semibold text-primary/90">Guidance: </span>
                            {step.guidance}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* SANS IR Operational Guardrails: Always vs Never Panels */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <Panel title="Mandatory Protocols (Always)" icon={CheckCircle2}>
                <ul className="space-y-2 text-mono ba-text-2xs text-fg-dim">
                  {activeRunbook.alwaysRules.map((rule, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" />
                      <span>{rule}</span>
                    </li>
                  ))}
                </ul>
              </Panel>

              <Panel title="Prohibited Actions (Never)" icon={ShieldOff}>
                <ul className="space-y-2 text-mono ba-text-2xs text-fg-dim">
                  {activeRunbook.neverRules.map((rule, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive" />
                      <span>{rule}</span>
                    </li>
                  ))}
                </ul>
              </Panel>
            </div>
          </div>
        </div>

        {/* Bottom SOC Workflow Pivots */}
        <SendToRow
          targets={[
            { label: "Incident Case Desk", to: "/investigation", icon: Database },
            { label: "MITRE ATT&CK Matrix", to: "/mitre", icon: ArrowRight },
            { label: "Mini SIEM Query Lab", to: "/siem", icon: ShieldAlert },
            { label: "Threat Hunting Arsenal", to: "/snippets", icon: BookOpen },
          ]}
        />
      </PageShell>
    </ErrorBoundary>
  );
}
