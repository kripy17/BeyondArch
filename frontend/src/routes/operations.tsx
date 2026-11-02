import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, useMemo, useEffect } from "react";
import { PageShell } from "@/components/PageShell";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import {
  Play,
  CheckCircle2,
  Clock,
  Terminal,
  Shield,
  Search,
  Filter,
  Layers,
  Wand2,
  Wrench,
  Code2,
  Bookmark,
  ShieldAlert,
  Siren,
  Cloud,
  Cpu,
  Mail,
  Zap,
  ChevronDown,
  ChevronRight,
  RotateCcw,
  ExternalLink,
  Check,
  History,
  Activity,
  ArrowRight,
} from "lucide-react";
import {
  SOAR_PLAYBOOKS,
  loadPlaybookRuns,
  savePlaybookRuns,
  calculatePlaybookTelemetry,
  type Playbook,
  type PlaybookRunRecord,
  type PlaybookCategory,
} from "@/lib/playbooks";
import { PlaybookRunnerModal } from "@/components/operations/PlaybookRunnerModal";
import { useActiveCase } from "@/data/case";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/operations")({
  component: OperationsHub,
});

const CATEGORY_ICONS: Record<PlaybookCategory, typeof Mail> = {
  email: Mail,
  endpoint: Siren,
  network: Shield,
  cloud: Cloud,
  forensics: Cpu,
};

function OperationsHub() {
  const navigate = useNavigate();
  const { activeCase } = useActiveCase();

  const [runs, setRuns] = useState<PlaybookRunRecord[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null);
  const [runnerOpen, setRunnerOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<"all" | PlaybookCategory>("all");
  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);

  const reloadRuns = () => {
    setRuns(loadPlaybookRuns());
  };

  useEffect(() => {
    reloadRuns();
    window.addEventListener("ba:soar-runs-changed", reloadRuns);
    window.addEventListener("storage", reloadRuns);
    return () => {
      window.removeEventListener("ba:soar-runs-changed", reloadRuns);
      window.removeEventListener("storage", reloadRuns);
    };
  }, []);

  const telemetry = useMemo(() => calculatePlaybookTelemetry(runs), [runs]);

  const filteredPlaybooks = useMemo(() => {
    return SOAR_PLAYBOOKS.filter((pb) => {
      if (categoryFilter !== "all" && pb.category !== categoryFilter) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const inTitle = pb.title.toLowerCase().includes(q);
        const inDesc = pb.description.toLowerCase().includes(q);
        const inTactics = pb.mitreTactics.some((t) => t.toLowerCase().includes(q));
        if (!inTitle && !inDesc && !inTactics) return false;
      }
      return true;
    });
  }, [categoryFilter, searchQuery]);

  const handleLaunchPlaybook = (playbook: Playbook) => {
    setSelectedPlaybook(playbook);
    setRunnerOpen(true);
  };

  const handleClearHistory = () => {
    if (!confirm("Clear playbook execution history log?")) return;
    savePlaybookRuns([]);
    setRuns([]);
    toast.success("Cleared SOAR execution history");
  };

  return (
    <ErrorBoundary name="Operations">
      <PageShell
        eyebrow="OPERATIONS // SOAR PLAYBOOK EXECUTION & TOOL WORKSTATION"
        title="Security Operations & Automation Deck"
        description="Automated response orchestration, endpoint containment actions, forensic extraction workflows, and analyst utilities."
        crumbs={[{ label: "Operations" }, { label: "SOAR Playbook Deck" }]}
      >
        <div className="space-y-6">
          {/* Header Action Strip */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-xl border border-border/70 bg-card/60 p-4 backdrop-blur-sm">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-primary/30 bg-primary/10 text-primary">
                <Zap className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-foreground">SOAR Execution Engine</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500 border border-emerald-500/30 font-medium">
                    ACTIVE ORCHESTRATION
                  </span>
                </div>
                <div className="text-xs text-muted-foreground">
                  {telemetry.totalPlaybooks} certified runbooks ready for dispatch across email, endpoint, cloud, and network vectors
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {activeCase ? (
                <div className="flex items-center gap-2 rounded-lg border border-primary/40 bg-primary/10 px-3 py-1.5 text-xs text-primary font-medium">
                  <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                  <span>Targeting Case: {activeCase.title.slice(0, 24)}...</span>
                </div>
              ) : (
                <button
                  onClick={() => navigate({ to: "/investigation" })}
                  className="rounded-lg border border-border bg-card px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
                >
                  Select Active Case
                </button>
              )}
            </div>
          </div>

          {/* 4-KPI Telemetry Ribbon */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Cataloged Playbooks</span>
                <Layers className="h-4 w-4 text-primary" />
              </div>
              <div className="text-2xl font-bold tracking-tight text-foreground font-mono">
                {telemetry.totalPlaybooks}
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">Standardized SOAR workflows</div>
            </div>

            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Automated Actions</span>
                <Zap className="h-4 w-4 text-emerald-500" />
              </div>
              <div className="text-2xl font-bold tracking-tight text-emerald-500 font-mono">
                {telemetry.totalAutomatedActions}
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">API containment hooks</div>
            </div>

            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Executions Completed</span>
                <Terminal className="h-4 w-4 text-primary" />
              </div>
              <div className="text-2xl font-bold tracking-tight text-foreground font-mono">
                {telemetry.completedRuns}
                <span className="text-xs font-normal text-muted-foreground ml-1.5">/ {telemetry.totalRuns} total</span>
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">Logged in audit telemetry</div>
            </div>

            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Success Rate</span>
                <CheckCircle2 className="h-4 w-4 text-emerald-500" />
              </div>
              <div className="text-2xl font-bold tracking-tight text-foreground font-mono">
                {telemetry.successRate}%
              </div>
              <div className="mt-1 text-[11px] text-emerald-500 font-medium">Orchestration pipeline stability</div>
            </div>
          </div>

          {/* Filter and Search Bar */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search playbooks by title, MITRE tactic, or keyword..."
                className="w-full rounded-lg border border-border bg-card pl-9 pr-4 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>

            {/* Category Filter Chips */}
            <div className="flex flex-wrap items-center rounded-lg border border-border bg-muted/40 p-1 text-xs">
              {(["all", "email", "endpoint", "network", "cloud", "forensics"] as const).map((cat) => (
                <button
                  key={cat}
                  onClick={() => setCategoryFilter(cat)}
                  className={cn(
                    "px-3 py-1.5 rounded-md font-medium capitalize transition-all",
                    categoryFilter === cat
                      ? "bg-card text-foreground shadow-sm border border-border"
                      : "text-muted-foreground hover:text-foreground"
                  )}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

          {/* Playbook Catalog Grid */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Playbook Catalog ({filteredPlaybooks.length})
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredPlaybooks.map((pb) => {
                const Icon = CATEGORY_ICONS[pb.category] || Shield;

                return (
                  <div
                    key={pb.id}
                    className="flex flex-col justify-between rounded-xl border border-border/70 bg-card p-5 hover:border-primary/50 transition-all group"
                  >
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <div className="p-1.5 rounded-md bg-muted/80 text-foreground border border-border/60">
                            <Icon className="h-4 w-4 text-primary" />
                          </div>
                          <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                            {pb.category}
                          </span>
                        </div>
                        <span
                          className={cn(
                            "text-[10px] font-mono uppercase px-2 py-0.5 rounded font-semibold",
                            pb.severity === "critical"
                              ? "bg-destructive/20 text-destructive border border-destructive/30"
                              : "bg-warning/20 text-warning border border-warning/30"
                          )}
                        >
                          {pb.severity}
                        </span>
                      </div>

                      <div>
                        <h3 className="text-base font-semibold text-foreground group-hover:text-primary transition-colors leading-snug">
                          {pb.title}
                        </h3>
                        <p className="text-xs text-muted-foreground mt-1.5 line-clamp-2">
                          {pb.description}
                        </p>
                      </div>

                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {pb.mitreTactics.map((tactic) => (
                          <span
                            key={tactic}
                            className="text-[10px] font-mono px-2 py-0.5 rounded bg-muted text-muted-foreground border border-border/60"
                          >
                            {tactic}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="pt-4 mt-4 border-t border-border/60 flex items-center justify-between">
                      <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono">
                        <Clock className="h-3 w-3" />
                        <span>{pb.estimatedRuntime}</span>
                        <span>·</span>
                        <span>{pb.steps.length} steps</span>
                      </div>

                      <button
                        type="button"
                        onClick={() => handleLaunchPlaybook(pb)}
                        className="inline-flex items-center gap-1.5 rounded-lg bg-primary/10 px-3 py-1.5 text-xs font-semibold text-primary hover:bg-primary/20 border border-primary/30 transition-colors"
                      >
                        <Play className="h-3 w-3 fill-current" />
                        <span>Launch</span>
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Execution History & Audit Log Section */}
          <div className="rounded-xl border border-border/70 bg-card overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border/60 bg-muted/20">
              <div className="flex items-center gap-2.5">
                <History className="h-4 w-4 text-primary" />
                <span className="text-xs font-semibold uppercase tracking-wider text-foreground">
                  SOAR Execution History & Audit Log ({runs.length})
                </span>
              </div>

              {runs.length > 0 && (
                <button
                  type="button"
                  onClick={handleClearHistory}
                  className="text-xs text-muted-foreground hover:text-destructive transition-colors"
                >
                  Clear Log
                </button>
              )}
            </div>

            <div className="divide-y divide-border/60">
              {runs.length === 0 ? (
                <div className="p-8 text-center text-muted-foreground text-xs">
                  No playbook execution logs recorded yet. Launch any playbook above to generate live execution audit receipts.
                </div>
              ) : (
                runs.map((run) => {
                  const isExpanded = expandedRunId === run.id;
                  let startedFormatted = "—";
                  try {
                    startedFormatted = new Date(run.startedAt).toLocaleDateString(undefined, {
                      month: "short",
                      day: "numeric",
                      hour: "2-digit",
                      minute: "2-digit",
                    });
                  } catch {
                    // ignore
                  }

                  return (
                    <div key={run.id} className="p-4 transition-colors hover:bg-muted/10">
                      <div
                        className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer"
                        onClick={() => setExpandedRunId(isExpanded ? null : run.id)}
                      >
                        <div className="flex items-center gap-3">
                          <button
                            type="button"
                            className="text-muted-foreground hover:text-foreground"
                          >
                            {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                          </button>

                          <div>
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-semibold text-foreground">
                                {run.playbookTitle}
                              </span>
                              <span
                                className={cn(
                                  "text-[10px] font-mono uppercase px-2 py-0.2 rounded font-semibold",
                                  run.status === "completed"
                                    ? "bg-emerald-500/20 text-emerald-500 border border-emerald-500/30"
                                    : "bg-destructive/20 text-destructive border border-destructive/30"
                                )}
                              >
                                {run.status}
                              </span>
                            </div>

                            <div className="flex items-center gap-2 text-xs text-muted-foreground mt-0.5">
                              <span className="font-mono text-muted-foreground/80">{run.id}</span>
                              <span>·</span>
                              <span>{startedFormatted}</span>
                              <span>·</span>
                              <span>{run.analyst}</span>
                              <span>·</span>
                              <span>{run.stepsCompleted}/{run.totalSteps} steps</span>
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-2 text-xs">
                          {run.caseId && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                navigate({ to: "/case" });
                              }}
                              className="inline-flex items-center gap-1 text-primary hover:underline"
                            >
                              <span>View in Case</span>
                              <ArrowRight className="h-3 w-3" />
                            </button>
                          )}
                        </div>
                      </div>

                      {/* Expandable Execution Logs */}
                      {isExpanded && (
                        <div className="mt-4 pt-3 border-t border-border/50 space-y-3 font-mono text-xs">
                          <div>
                            <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">
                              Execution Parameters
                            </div>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 p-2 rounded bg-muted/30 border border-border/40">
                              {Object.entries(run.inputs).map(([k, v]) => (
                                <div key={k} className="text-muted-foreground truncate">
                                  <span className="text-foreground/80 font-medium">{k}:</span> {v}
                                </div>
                              ))}
                            </div>
                          </div>

                          <div>
                            <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">
                              Audit Receipts & Step Output
                            </div>
                            <div className="p-3 rounded-lg bg-black/80 text-emerald-400 space-y-1">
                              {run.logs.map((log, i) => (
                                <div key={i} className="leading-relaxed">
                                  {log}
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Forensic & Analyst Utilities Launchstation */}
          <div className="space-y-3">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              SOC Forensic Utilities Launchstation
            </span>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              {[
                {
                  to: "/parser",
                  icon: Wand2,
                  title: "Universal Parser",
                  desc: "Defang & extract IOCs from raw logs, emails, and alerts.",
                  badge: "IOC Engine",
                },
                {
                  to: "/chef",
                  icon: Wrench,
                  title: "CyberChef Workbench",
                  desc: "Multi-layer decoding, Base64 deobfuscation, and data transforms.",
                  badge: "Transform",
                },
                {
                  to: "/diff",
                  icon: Code2,
                  title: "Artifact Diff",
                  desc: "Structural and lexical comparison of suspect files and scripts.",
                  badge: "Comparison",
                },
                {
                  to: "/regex-playground",
                  icon: Search,
                  title: "Regex Lab",
                  desc: "Test SIEM and detection patterns against raw logs.",
                  badge: "Detection",
                },
                {
                  to: "/snippets",
                  icon: Bookmark,
                  title: "Playbook Snippets",
                  desc: "Standardized Sigma rules, KQL queries, and triage checklists.",
                  badge: "Knowledge",
                },
                {
                  to: "/activity",
                  icon: Activity,
                  title: "Global Activity Feed",
                  desc: "Comprehensive historical timeline of all analyst tool executions.",
                  badge: "Telemetry",
                },
              ].map((tool) => {
                const Icon = tool.icon;
                return (
                  <button
                    key={tool.to}
                    type="button"
                    onClick={() => navigate({ to: tool.to as any })}
                    className="flex flex-col justify-between p-4 rounded-xl border border-border/70 bg-card hover:border-primary/50 text-left transition-all group"
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <div className="p-2 rounded-lg bg-primary/10 text-primary border border-primary/20 group-hover:scale-105 transition-transform">
                          <Icon className="h-4 w-4" />
                        </div>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-muted text-muted-foreground border border-border">
                          {tool.badge}
                        </span>
                      </div>
                      <div className="font-semibold text-foreground text-sm group-hover:text-primary transition-colors">
                        {tool.title}
                      </div>
                      <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                        {tool.desc}
                      </p>
                    </div>

                    <div className="mt-3 pt-2 border-t border-border/40 flex items-center justify-between text-xs text-primary font-medium">
                      <span>Launch Utility</span>
                      <ArrowRight className="h-3 w-3 group-hover:translate-x-0.5 transition-transform" />
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Playbook Runner Modal */}
        <PlaybookRunnerModal
          playbook={selectedPlaybook}
          open={runnerOpen}
          onClose={() => setRunnerOpen(false)}
          onRunCompleted={() => reloadRuns()}
        />
      </PageShell>
    </ErrorBoundary>
  );
}
