import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, useMemo, useEffect } from "react";
import { PageShell } from "@/components/PageShell";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import {
  FolderPlus,
  ArrowRight,
  Search,
  Filter,
  Download,
  ShieldAlert,
  Clock,
  Database,
  Tag,
  Layers,
  CheckCircle2,
  AlertTriangle,
  FileSpreadsheet,
  FileCode,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Trash2,
  RefreshCw,
  Archive,
  Network,
} from "lucide-react";
import { type Case, loadCases, saveCases, setActiveCaseId, useActiveCase } from "@/data/case";
import {
  calculateQueueMetrics,
  findCrossCaseObservables,
  computeCaseSeverity,
  computeContainmentStage,
  filterCaseQueue,
  exportCaseQueueCsv,
  exportCaseQueueJson,
  type QueueFilters,
  type CrossCaseObservable,
} from "@/lib/case-desk";
import { NewCaseModal } from "@/components/investigation/NewCaseModal";
import { CrossCaseAttackGraph } from "@/components/investigation/CrossCaseAttackGraph";
import { downloadTextFile } from "@/lib/download";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/investigation")({
  component: InvestigationDashboard,
});

function InvestigationDashboard() {
  const navigate = useNavigate();
  const { activeCase, setActiveId } = useActiveCase();
  const [cases, setCases] = useState<Case[]>([]);
  const [newCaseModalOpen, setNewCaseModalOpen] = useState(false);
  const [selectedCaseIds, setSelectedCaseIds] = useState<Set<string>>(new Set());
  const [showCorrelations, setShowCorrelations] = useState(true);
  const [viewMode, setViewMode] = useState<"queue" | "graph">("queue");

  // Filter state
  const [filters, setFilters] = useState<QueueFilters>({
    search: "",
    status: "all",
    severity: "all",
    tag: "",
  });

  // Load cases on mount and storage events
  const reloadCases = () => {
    const list = loadCases();
    setCases(list.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1)));
  };

  useEffect(() => {
    reloadCases();
    window.addEventListener("storage", reloadCases);
    return () => window.removeEventListener("storage", reloadCases);
  }, []);

  // Compute metrics and cross-case observables
  const metrics = useMemo(() => calculateQueueMetrics(cases), [cases]);
  const crossObservables = useMemo(() => findCrossCaseObservables(cases), [cases]);
  const filteredCases = useMemo(() => filterCaseQueue(cases, filters), [cases, filters]);

  // Unique tags for quick filter chips
  const allTags = useMemo(() => {
    const tagSet = new Set<string>();
    for (const c of cases) {
      for (const t of c.tags) {
        tagSet.add(t.toLowerCase());
      }
    }
    return Array.from(tagSet).slice(0, 8);
  }, [cases]);

  // Bulk actions
  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedCaseIds(new Set(filteredCases.map((c) => c.id)));
    } else {
      setSelectedCaseIds(new Set());
    }
  };

  const handleToggleSelect = (id: string) => {
    const next = new Set(selectedCaseIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelectedCaseIds(next);
  };

  const handleBulkClose = () => {
    if (selectedCaseIds.size === 0) return;
    const updated = cases.map((c) => (selectedCaseIds.has(c.id) ? { ...c, state: "closed" as const } : c));
    saveCases(updated);
    setCases(updated);
    setSelectedCaseIds(new Set());
    toast.success(`Closed ${selectedCaseIds.size} incident cases`);
  };

  const handleBulkReopen = () => {
    if (selectedCaseIds.size === 0) return;
    const updated = cases.map((c) => (selectedCaseIds.has(c.id) ? { ...c, state: "active" as const } : c));
    saveCases(updated);
    setCases(updated);
    setSelectedCaseIds(new Set());
    toast.success(`Reopened ${selectedCaseIds.size} incident cases`);
  };

  const handleBulkDelete = () => {
    if (selectedCaseIds.size === 0) return;
    if (!confirm(`Are you sure you want to delete ${selectedCaseIds.size} selected cases?`)) return;
    const updated = cases.filter((c) => !selectedCaseIds.has(c.id));
    saveCases(updated);
    setCases(updated);
    setSelectedCaseIds(new Set());
    toast.success(`Deleted ${selectedCaseIds.size} cases`);
  };

  const handleExportCsv = () => {
    const targetCases = selectedCaseIds.size > 0 ? cases.filter((c) => selectedCaseIds.has(c.id)) : filteredCases;
    const csv = exportCaseQueueCsv(targetCases);
    downloadTextFile(`soc-cases-queue-${new Date().toISOString().slice(0, 10)}.csv`, csv, "text/csv");
    toast.success("Exported incident cases to CSV");
  };

  const handleExportJson = () => {
    const targetCases = selectedCaseIds.size > 0 ? cases.filter((c) => selectedCaseIds.has(c.id)) : filteredCases;
    const jsonStr = exportCaseQueueJson(targetCases);
    downloadTextFile(`soc-cases-queue-${new Date().toISOString().slice(0, 10)}.json`, jsonStr, "application/json");
    toast.success("Exported incident cases to JSON");
  };

  const handleOpenCase = (c: Case) => {
    setActiveCaseId(c.id);
    navigate({ to: "/case" });
  };

  const handleToggleCaseStatus = (c: Case, e: React.MouseEvent) => {
    e.stopPropagation();
    const nextState = c.state === "active" ? "closed" : "active";
    const updated = cases.map((item) => (item.id === c.id ? { ...item, state: nextState as "active" | "closed" } : item));
    saveCases(updated);
    setCases(updated);
    toast.success(`Marked case ${c.title} as ${nextState}`);
  };

  const handleDeleteCase = (c: Case, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(`Delete case "${c.title}"?`)) return;
    const updated = cases.filter((item) => item.id !== c.id);
    saveCases(updated);
    setCases(updated);
    if (activeCase?.id === c.id) {
      setActiveCaseId(updated[0]?.id ?? null);
    }
    toast.success(`Deleted case "${c.title}"`);
  };

  return (
    <ErrorBoundary name="Investigation">
      <PageShell
        eyebrow="INVESTIGATION // INCIDENT OPERATIONS COMMAND CENTER"
        title="Case Desk & Incident Queue"
        description="Enterprise triage queue, MTTC analytics, cross-case campaign observables, and response orchestration."
        crumbs={[{ label: "Investigation" }, { label: "Case Desk" }]}
      >
        <div className="space-y-6">
          {/* Header Action Strip */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-xl border border-border/70 bg-card/60 p-4 backdrop-blur-sm">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-primary/30 bg-primary/10 text-primary">
                <Layers className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-foreground">Incident Desk Operations</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/30 font-medium">
                    DEFENSE STATION
                  </span>
                </div>
                <div className="text-xs text-muted-foreground">
                  {metrics.activeCases} active incidents requiring analyst review and containment
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() => setNewCaseModalOpen(true)}
                className="inline-flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2 text-xs font-semibold text-primary-foreground shadow-sm hover:bg-primary/90 transition-colors"
              >
                <FolderPlus className="h-4 w-4" />
                <span>Initiate Incident</span>
              </button>

              <button
                onClick={handleExportCsv}
                className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-card px-3 py-2 text-xs font-medium text-foreground hover:bg-muted transition-colors"
                title="Export queue as CSV"
              >
                <FileSpreadsheet className="h-3.5 w-3.5 text-muted-foreground" />
                <span>CSV</span>
              </button>

              <button
                onClick={handleExportJson}
                className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-card px-3 py-2 text-xs font-medium text-foreground hover:bg-muted transition-colors"
                title="Export queue as JSON"
              >
                <FileCode className="h-3.5 w-3.5 text-muted-foreground" />
                <span>JSON</span>
              </button>

              {activeCase && (
                <button
                  onClick={() => navigate({ to: "/case" })}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-primary/40 bg-primary/10 px-3 py-2 text-xs font-semibold text-primary hover:bg-primary/20 transition-colors"
                  title="Pivot directly to active case workbench"
                >
                  <span>Open Active Dossier</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* 5-KPI Incident Operations Ribbon */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Active Incidents</span>
                <Layers className="h-4 w-4 text-primary" />
              </div>
              <div className="text-2xl font-bold tracking-tight text-foreground font-mono">
                {metrics.activeCases}
                <span className="text-xs font-normal text-muted-foreground ml-1.5">/ {metrics.totalCases}</span>
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">
                {metrics.closedCases} resolved & archived
              </div>
            </div>

            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Critical / P1</span>
                <ShieldAlert className="h-4 w-4 text-destructive" />
              </div>
              <div className="text-2xl font-bold tracking-tight text-destructive font-mono">
                {metrics.criticalCases}
                <span className="text-xs font-normal text-warning ml-1.5 font-sans">
                  +{metrics.highCases} High
                </span>
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">Immediate escalation priority</div>
            </div>

            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Avg MTTC / Duration</span>
                <Clock className="h-4 w-4 text-warning" />
              </div>
              <div className="text-2xl font-bold tracking-tight text-foreground font-mono">
                {metrics.avgMttcMinutes}
                <span className="text-xs font-normal text-muted-foreground ml-1">min</span>
              </div>
              <div className="mt-1 text-[11px] text-emerald-500 flex items-center gap-1 font-medium">
                <CheckCircle2 className="h-3 w-3" />
                Within 240m SLA target
              </div>
            </div>

            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Cross-Case Links</span>
                <Network className="h-4 w-4 text-primary" />
              </div>
              <div className="text-2xl font-bold tracking-tight text-foreground font-mono">
                {metrics.totalCorrelatedIocs}
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">
                Multi-case campaign observables
              </div>
            </div>

            <div className="col-span-2 md:col-span-1 rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Evidence Custody</span>
                <Database className="h-4 w-4 text-muted-foreground" />
              </div>
              <div className="text-2xl font-bold tracking-tight text-foreground font-mono">
                {metrics.totalEvidenceCount}
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">Verified IOCs & artifacts</div>
            </div>
          </div>

          {/* View Mode Switcher: Incident Queue vs Attack Graph & Correlations */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/70 pb-3" id="investigation-view-switcher">
            <div className="inline-flex items-center rounded-lg border border-border bg-muted/40 p-1 text-xs">
              <button
                type="button"
                onClick={() => setViewMode("queue")}
                className={cn(
                  "inline-flex items-center gap-2 px-3.5 py-1.5 rounded-md font-medium transition-all",
                  viewMode === "queue"
                    ? "bg-card text-foreground shadow-sm border border-border"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                <Layers className="h-3.5 w-3.5" />
                <span>Incident Queue ({filteredCases.length})</span>
              </button>

              <button
                type="button"
                onClick={() => setViewMode("graph")}
                className={cn(
                  "inline-flex items-center gap-2 px-3.5 py-1.5 rounded-md font-medium transition-all",
                  viewMode === "graph"
                    ? "bg-card text-foreground shadow-sm border border-border"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                <Network className="h-3.5 w-3.5 text-primary" />
                <span>Attack Graph & Correlations</span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-primary/20 text-primary border border-primary/30">
                  {crossObservables.length}
                </span>
              </button>
            </div>

            <div className="text-xs text-muted-foreground">
              {viewMode === "queue"
                ? "Unified SOC incident registry, triage status & bulk operations"
                : "Cross-case indicator graph and adversary campaign convergence"}
            </div>
          </div>

          {viewMode === "graph" ? (
            <CrossCaseAttackGraph
              cases={cases}
              activeCaseId={activeCase?.id ?? null}
              onSelectCase={(id) => {
                setActiveCaseId(id);
                navigate({ to: "/case" });
              }}
            />
          ) : (
            <>
              {/* Cross-Case Correlated Observables Drawer / Panel */}
              {crossObservables.length > 0 && (
                <div className="rounded-xl border border-border/70 bg-card overflow-hidden">
                  <button
                    type="button"
                    onClick={() => setShowCorrelations(!showCorrelations)}
                    className="w-full flex items-center justify-between px-5 py-3.5 bg-muted/20 hover:bg-muted/30 transition-colors text-left"
                  >
                <div className="flex items-center gap-2.5">
                  <Network className="h-4 w-4 text-primary" />
                  <span className="text-xs font-semibold uppercase tracking-wider text-foreground">
                    Cross-Case Correlated Observables ({crossObservables.length})
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20 font-medium">
                    CAMPAIGN INTELLIGENCE
                  </span>
                </div>
                <div className="flex items-center gap-2 text-muted-foreground">
                  <span className="text-xs">
                    {showCorrelations ? "Collapse" : "Expand Matrix"}
                  </span>
                  {showCorrelations ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                </div>
              </button>

              {showCorrelations && (
                <div className="p-4 border-t border-border/60 bg-muted/10">
                  <p className="text-xs text-muted-foreground mb-3">
                    The following indicators appear across multiple independent incident cases, indicating coordinated adversary infrastructure or shared campaign vectors.
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
                    {crossObservables.map((obs) => (
                      <div
                        key={obs.key}
                        className="flex flex-col justify-between p-3 rounded-lg border border-border/60 bg-card hover:border-primary/50 transition-colors"
                      >
                        <div>
                          <div className="flex items-center justify-between mb-1.5">
                            <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-semibold">
                              {obs.type}
                            </span>
                            <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/30">
                              Seen in {obs.count} Cases
                            </span>
                          </div>
                          <div className="font-mono text-xs font-medium text-foreground truncate select-all" title={obs.value}>
                            {obs.value}
                          </div>
                        </div>

                        <div className="mt-2 pt-2 border-t border-border/40 flex items-center justify-between text-[11px] text-muted-foreground">
                          <span className="truncate max-w-[160px]" title={obs.caseTitles.join(", ")}>
                            {obs.caseTitles[0]} {obs.caseTitles.length > 1 && `+${obs.caseTitles.length - 1} more`}
                          </span>
                          <button
                            type="button"
                            onClick={() => setFilters({ ...filters, search: obs.value })}
                            className="text-primary hover:underline text-[11px] font-medium"
                          >
                            Filter Queue
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Filter & Search Bar */}
          <div className="space-y-3">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              {/* Search input */}
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <input
                  type="text"
                  value={filters.search}
                  onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                  placeholder="Filter by title, tags, indicators, or entry content..."
                  className="w-full rounded-lg border border-border bg-card pl-9 pr-4 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>

              {/* Status Tabs */}
              <div className="flex items-center rounded-lg border border-border bg-muted/40 p-1 text-xs">
                {(["all", "active", "closed"] as const).map((st) => (
                  <button
                    key={st}
                    onClick={() => setFilters({ ...filters, status: st })}
                    className={cn(
                      "px-3 py-1.5 rounded-md font-medium capitalize transition-all",
                      filters.status === st
                        ? "bg-card text-foreground shadow-sm border border-border"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                  >
                    {st === "all" ? `All (${cases.length})` : st === "active" ? `Active (${metrics.activeCases})` : `Closed (${metrics.closedCases})`}
                  </button>
                ))}
              </div>

              {/* Severity Filter Dropdown */}
              <div className="flex items-center gap-2">
                <select
                  value={filters.severity}
                  onChange={(e) => setFilters({ ...filters, severity: e.target.value as QueueFilters["severity"] })}
                  className="rounded-lg border border-border bg-card px-3 py-2 text-xs font-medium text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value="all">All Severities</option>
                  <option value="critical">Critical (P1)</option>
                  <option value="high">High (P2)</option>
                  <option value="medium">Medium (P3)</option>
                  <option value="low">Low (P4)</option>
                  <option value="info">Info / Triage</option>
                </select>

                {(filters.search || filters.status !== "all" || filters.severity !== "all" || filters.tag) && (
                  <button
                    onClick={() => setFilters({ search: "", status: "all", severity: "all", tag: "" })}
                    className="rounded-lg border border-border px-2.5 py-2 text-xs text-muted-foreground hover:text-foreground hover:bg-muted"
                    title="Reset all filters"
                  >
                    Reset
                  </button>
                )}
              </div>
            </div>

            {/* Quick Tag Chips */}
            {allTags.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                <span className="text-[11px] font-medium text-muted-foreground flex items-center gap-1 mr-1">
                  <Tag className="h-3 w-3" /> Quick Filter:
                </span>
                {allTags.map((tag) => {
                  const isSelected = filters.tag.toLowerCase() === tag;
                  return (
                    <button
                      key={tag}
                      onClick={() => setFilters({ ...filters, tag: isSelected ? "" : tag })}
                      className={cn(
                        "inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono transition-all",
                        isSelected
                          ? "bg-primary text-primary-foreground font-semibold"
                          : "bg-muted/70 hover:bg-muted text-foreground/80 border border-border/60"
                      )}
                    >
                      {tag}
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Bulk Action Toolbar */}
          {selectedCaseIds.size > 0 && (
            <div className="flex items-center justify-between rounded-lg border border-primary/40 bg-primary/10 px-4 py-2.5 text-xs">
              <div className="flex items-center gap-2 text-foreground font-medium">
                <span className="font-semibold text-primary">{selectedCaseIds.size}</span>
                incident cases selected
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleBulkClose}
                  className="rounded px-2.5 py-1 bg-card border border-border hover:bg-muted font-medium transition-colors"
                >
                  Mark Closed
                </button>
                <button
                  onClick={handleBulkReopen}
                  className="rounded px-2.5 py-1 bg-card border border-border hover:bg-muted font-medium transition-colors"
                >
                  Mark Active
                </button>
                <button
                  onClick={handleExportCsv}
                  className="rounded px-2.5 py-1 bg-card border border-border hover:bg-muted font-medium transition-colors"
                >
                  Export CSV
                </button>
                <button
                  onClick={handleBulkDelete}
                  className="rounded px-2.5 py-1 bg-destructive/15 text-destructive border border-destructive/30 hover:bg-destructive/25 font-medium transition-colors"
                >
                  Delete
                </button>
              </div>
            </div>
          )}

          {/* Main Case Backlog Queue */}
          <div className="rounded-xl border border-border/70 bg-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-border bg-muted/40 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="py-3 px-4 w-8">
                      <input
                        type="checkbox"
                        checked={filteredCases.length > 0 && selectedCaseIds.size === filteredCases.length}
                        onChange={(e) => handleSelectAll(e.target.checked)}
                        className="rounded border-border text-primary focus:ring-primary h-3.5 w-3.5"
                      />
                    </th>
                    <th className="py-3 px-4 min-w-[240px]">Incident Dossier</th>
                    <th className="py-3 px-4 min-w-[100px]">Severity</th>
                    <th className="py-3 px-4 min-w-[120px]">Containment Stage</th>
                    <th className="py-3 px-4 min-w-[140px]">Telemetry</th>
                    <th className="py-3 px-4 min-w-[160px]">Tags</th>
                    <th className="py-3 px-4 text-right min-w-[160px]">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {filteredCases.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-muted-foreground">
                        <div className="flex flex-col items-center justify-center gap-2">
                          <Layers className="h-8 w-8 text-muted-foreground/50" />
                          <div className="text-sm font-medium text-foreground">No incident cases found</div>
                          <p className="text-xs max-w-sm">
                            No cases match the current filter criteria or search query. You can initiate a new incident dossier from the header.
                          </p>
                          <button
                            onClick={() => setNewCaseModalOpen(true)}
                            className="mt-2 inline-flex items-center gap-1.5 rounded-lg bg-primary px-3 py-1.5 text-xs font-semibold text-primary-foreground hover:bg-primary/90 transition-colors"
                          >
                            <FolderPlus className="h-3.5 w-3.5" />
                            Initiate Incident
                          </button>
                        </div>
                      </td>
                    </tr>
                  ) : (
                    filteredCases.map((c) => {
                      const sev = computeCaseSeverity(c);
                      const stage = computeContainmentStage(c);
                      const isSelected = selectedCaseIds.has(c.id);
                      const isActiveCase = activeCase?.id === c.id;

                      let createdDateFormatted = "—";
                      try {
                        createdDateFormatted = new Date(c.createdAt).toLocaleDateString(undefined, {
                          month: "short",
                          day: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                        });
                      } catch {
                        // ignore
                      }

                      return (
                        <tr
                          key={c.id}
                          onClick={() => handleOpenCase(c)}
                          className={cn(
                            "cursor-pointer transition-colors group",
                            isSelected ? "bg-primary/5" : "hover:bg-muted/30",
                            isActiveCase && "ring-1 ring-inset ring-primary/40 bg-primary/[0.02]"
                          )}
                        >
                          <td className="py-3 px-4" onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => handleToggleSelect(c.id)}
                              className="rounded border-border text-primary focus:ring-primary h-3.5 w-3.5"
                            />
                          </td>

                          <td className="py-3 px-4">
                            <div className="flex flex-col min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-foreground text-sm group-hover:text-primary transition-colors truncate">
                                  {c.title}
                                </span>
                                {isActiveCase && (
                                  <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 rounded bg-primary/20 text-primary border border-primary/30 font-semibold shrink-0">
                                    CURRENT ACTIVE
                                  </span>
                                )}
                              </div>
                              <div className="flex items-center gap-2 text-[11px] text-muted-foreground mt-0.5">
                                <span className="font-mono text-muted-foreground/80">{c.id}</span>
                                <span>·</span>
                                <span>Opened {createdDateFormatted}</span>
                              </div>
                            </div>
                          </td>

                          <td className="py-3 px-4">
                            <span
                              className={cn(
                                "inline-flex items-center text-[10px] font-mono uppercase px-2 py-0.5 rounded font-semibold",
                                sev === "critical"
                                  ? "bg-destructive/20 text-destructive border border-destructive/30"
                                  : sev === "high"
                                    ? "bg-warning/20 text-warning border border-warning/30"
                                    : sev === "medium"
                                      ? "bg-primary/20 text-primary border border-primary/30"
                                      : "bg-muted text-muted-foreground border border-border"
                              )}
                            >
                              {sev}
                            </span>
                          </td>

                          <td className="py-3 px-4">
                            <span
                              className={cn(
                                "inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-full border",
                                stage === "Closed"
                                  ? "bg-muted text-muted-foreground border-border"
                                  : stage === "Recovery"
                                    ? "bg-emerald-500/10 text-emerald-500 border-emerald-500/30"
                                    : stage === "Containment" || stage === "Eradication"
                                      ? "bg-warning/10 text-warning border-warning/30"
                                      : "bg-primary/10 text-primary border-primary/30"
                              )}
                            >
                              {stage}
                            </span>
                          </td>

                          <td className="py-3 px-4">
                            <div className="flex items-center gap-2 text-[11px] text-muted-foreground font-mono">
                              <span title="Dossier entries">{c.entries.length} ent</span>
                              <span>·</span>
                              <span title="IOCs">{c.iocs?.length ?? 0} ioc</span>
                              <span>·</span>
                              <span title="Findings">{c.findings?.length ?? 0} fnd</span>
                            </div>
                          </td>

                          <td className="py-3 px-4">
                            <div className="flex flex-wrap gap-1 max-w-[200px]">
                              {c.tags.slice(0, 3).map((tag) => (
                                <span
                                  key={tag}
                                  className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted/60 text-muted-foreground border border-border/50 truncate max-w-[90px]"
                                >
                                  {tag}
                                </span>
                              ))}
                              {c.tags.length > 3 && (
                                <span className="text-[10px] text-muted-foreground/70">
                                  +{c.tags.length - 3}
                                </span>
                              )}
                            </div>
                          </td>

                          <td className="py-3 px-4 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleOpenCase(c);
                                }}
                                className="inline-flex items-center gap-1 rounded px-2.5 py-1 bg-primary/10 text-primary hover:bg-primary/20 border border-primary/30 transition-colors font-medium text-[11px]"
                                title="Open in Case Workbench"
                              >
                                <span>Pivot</span>
                                <ArrowRight className="h-3 w-3" />
                              </button>

                              <button
                                type="button"
                                onClick={(e) => handleToggleCaseStatus(c, e)}
                                className="rounded p-1 text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
                                title={c.state === "active" ? "Close incident" : "Reopen incident"}
                              >
                                {c.state === "active" ? (
                                  <Archive className="h-3.5 w-3.5" />
                                ) : (
                                  <RefreshCw className="h-3.5 w-3.5" />
                                )}
                              </button>

                              <button
                                type="button"
                                onClick={(e) => handleDeleteCase(c, e)}
                                className="rounded p-1 text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors"
                                title="Delete case"
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
          </>
          )}
        </div>

        {/* New Case Creation Modal */}
        <NewCaseModal
          open={newCaseModalOpen}
          onClose={() => setNewCaseModalOpen(false)}
          onCaseCreated={() => reloadCases()}
        />
      </PageShell>
    </ErrorBoundary>
  );
}
