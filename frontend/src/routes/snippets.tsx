import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, useMemo, useEffect } from "react";
import { PageShell } from "@/components/PageShell";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import {
  Bookmark,
  Search,
  Plus,
  Copy,
  Check,
  Download,
  Upload,
  Database,
  Terminal,
  ExternalLink,
  Shield,
  Layers,
  Zap,
  Tag,
  Clock,
  ArrowRight,
  Send,
  Wand2,
  ListChecks,
  X,
  Crosshair,
} from "lucide-react";
import {
  HUNTING_PRESETS,
  loadHuntingSnippets,
  saveCustomSnippets,
  interpolateQuery,
  calculateArsenalTelemetry,
  createCustomSnippet,
  type HuntingSnippet,
  type SnippetCategory,
} from "@/lib/hunting-arsenal";
import { useActiveCase } from "@/data/case";
import { getUnifiedIOCs } from "@/components/investigation/legacy-adapter";
import { copyText } from "@/lib/copy";
import { downloadTextFile } from "@/lib/download";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/snippets")({
  component: HuntingArsenalPage,
});

const CATEGORY_LABELS: Record<SnippetCategory | "all", string> = {
  all: "All Arsenal",
  splunk: "Splunk SPL",
  sentinel: "Sentinel KQL",
  elastic: "Elastic EQL",
  suricata: "Suricata IDS",
  checklists: "DFIR Checklists",
};

const CATEGORY_COLORS: Record<SnippetCategory, string> = {
  splunk: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  sentinel: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  elastic: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  suricata: "bg-red-500/10 text-red-400 border-red-500/30",
  checklists: "bg-purple-500/10 text-purple-400 border-purple-500/30",
};

function HuntingArsenalPage() {
  const navigate = useNavigate();
  const { activeCase, addEntry } = useActiveCase();

  // State
  const [snippets, setSnippets] = useState<HuntingSnippet[]>([]);
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<SnippetCategory | "all">("all");
  const [copiedSnippetId, setCopiedSnippetId] = useState<string | null>(null);

  // Variables for Live Interpolation
  const [variables, setVariables] = useState<Record<string, string>>({
    TARGET_IP: "185.220.101.45",
    TARGET_HOST: "SRV-FIN-PRD02",
    USERNAME: "svc-backup",
    TIMEFRAME: "24h",
  });

  // Modal State
  const [authorModalOpen, setAuthorModalOpen] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newCategory, setNewCategory] = useState<SnippetCategory>("splunk");
  const [newDesc, setNewDesc] = useState("");
  const [newTemplate, setNewTemplate] = useState("");
  const [newTags, setNewTags] = useState("");

  const reloadSnippets = () => {
    setSnippets(loadHuntingSnippets());
  };

  useEffect(() => {
    reloadSnippets();
    window.addEventListener("ba:snippets-changed", reloadSnippets);
    window.addEventListener("storage", reloadSnippets);
    return () => {
      window.removeEventListener("ba:snippets-changed", reloadSnippets);
      window.removeEventListener("storage", reloadSnippets);
    };
  }, []);

  const telemetry = useMemo(() => calculateArsenalTelemetry(snippets), [snippets]);

  // Filter snippets
  const filteredSnippets = useMemo(() => {
    return snippets.filter((s) => {
      if (selectedCategory !== "all" && s.category !== selectedCategory) return false;
      if (search) {
        const q = search.toLowerCase();
        const inTitle = s.title.toLowerCase().includes(q);
        const inDesc = s.description.toLowerCase().includes(q);
        const inTemplate = s.queryTemplate.toLowerCase().includes(q);
        const inTags = s.tags.some((t) => t.toLowerCase().includes(q));
        const inMitre = s.mitreTechnique?.toLowerCase().includes(q);
        if (!inTitle && !inDesc && !inTemplate && !inTags && !inMitre) return false;
      }
      return true;
    });
  }, [snippets, selectedCategory, search]);

  const handleVariableChange = (key: string, val: string) => {
    setVariables((prev) => ({ ...prev, [key]: val }));
  };

  const handlePullCaseIndicators = () => {
    if (!activeCase) {
      toast.error("No active case selected.");
      return;
    }
    const iocs = getUnifiedIOCs(activeCase);
    const ipIoc = iocs.find((i) => i.type === "ipv4")?.value;
    const domainIoc = iocs.find((i) => i.type === "domain")?.value;

    setVariables((prev) => ({
      ...prev,
      TARGET_IP: ipIoc || prev.TARGET_IP,
      DOMAIN: domainIoc || prev.DOMAIN || "evil-c2.org",
    }));

    toast.success(`Pulled lead observables from case: ${activeCase.title}`);
  };

  const handleCopyQuery = async (snippet: HuntingSnippet) => {
    const interpolated = interpolateQuery(snippet.queryTemplate, variables);
    const ok = await copyText(interpolated);
    if (ok) {
      setCopiedSnippetId(snippet.id);
      setTimeout(() => setCopiedSnippetId(null), 2000);
      toast.success(`Copied interpolated query: ${snippet.title}`);
    }
  };

  const handleRunInSiem = (snippet: HuntingSnippet) => {
    const interpolated = interpolateQuery(snippet.queryTemplate, variables);
    try {
      localStorage.setItem("ba.siem.keyword", interpolated);
    } catch {
      // ignore
    }
    navigate({ to: "/siem" });
    toast.success("Navigating to SIEM with query loaded");
  };

  const handleExtractInParser = (snippet: HuntingSnippet) => {
    const interpolated = interpolateQuery(snippet.queryTemplate, variables);
    try {
      localStorage.setItem("beyondlabs.pendingArtifact", JSON.stringify({
        type: "raw_log",
        content: interpolated,
        target: "/parser",
        source: `Hunting Arsenal (${snippet.title})`,
        created_at: new Date().toISOString(),
      }));
    } catch {
      // ignore
    }
    navigate({ to: "/parser" });
    toast.success("Sent snippet to Universal Parser");
  };

  const handleFileToCase = (snippet: HuntingSnippet) => {
    if (!activeCase) {
      toast.error("No active case. Please initiate or select an incident case first.");
      return;
    }

    const interpolated = interpolateQuery(snippet.queryTemplate, variables);
    const md = [
      `### Threat Hunting Investigation Artifact: ${snippet.title}`,
      `- **Category:** ${snippet.category.toUpperCase()}`,
      ...(snippet.mitreTechnique ? [`- **MITRE Technique:** ${snippet.mitreTechnique}`] : []),
      `- **Description:** ${snippet.description}`,
      "",
      "```text",
      interpolated,
      "```",
    ].join("\n");

    addEntry(md, "action", "Threat Hunting Arsenal");
    toast.success(`Filed hunting artifact to active case: ${activeCase.title}`);
  };

  const handleCreateCustomSnippet = () => {
    if (!newTitle.trim() || !newTemplate.trim()) {
      toast.error("Title and query template are required.");
      return;
    }

    const parsedTags = newTags
      .split(",")
      .map((t) => t.trim().toLowerCase())
      .filter(Boolean);

    const created = createCustomSnippet({
      title: newTitle.trim(),
      category: newCategory,
      description: newDesc.trim() || "Analyst custom threat hunting query",
      queryTemplate: newTemplate.trim(),
      tags: parsedTags,
    });

    const updated = [...snippets, created];
    saveCustomSnippets(updated);
    setSnippets(updated);
    setAuthorModalOpen(false);

    setNewTitle("");
    setNewDesc("");
    setNewTemplate("");
    setNewTags("");

    toast.success(`Created custom hunting query: ${created.title}`);
  };

  const handleExportBundle = () => {
    const customOnly = snippets.filter((s) => s.isCustom);
    const jsonStr = JSON.stringify(customOnly, null, 2);
    downloadTextFile(`custom-hunting-snippets-${new Date().toISOString().slice(0, 10)}.json`, jsonStr, "application/json");
    toast.success("Exported custom snippets bundle");
  };

  return (
    <ErrorBoundary name="Snippets">
      <PageShell
        eyebrow="OPERATIONS // THREAT HUNTING SNIPPETS & QUERY ARSENAL"
        title="Threat Hunting Query Arsenal & Playbooks"
        description="Production-tested hunting queries across Splunk, Sentinel, Elastic, and Suricata with live parameter interpolation."
        crumbs={[{ label: "Operations" }, { label: "Snippets" }]}
      >
        <div className="space-y-6">
          {/* Header Action Strip */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-xl border border-border/70 bg-card/60 p-4 backdrop-blur-sm">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-primary/30 bg-primary/10 text-primary">
                <Bookmark className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-foreground">Threat Hunting Arsenal</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/30 font-medium">
                    28+ CHEATSHEETS
                  </span>
                </div>
                <div className="text-xs text-muted-foreground">
                  Ready-to-execute queries for Kerberoasting, AitM session hijacking, process hollowing, and living-off-the-land techniques
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setAuthorModalOpen(true)}
                className="inline-flex items-center gap-1.5 rounded-lg bg-primary px-3.5 py-2 text-xs font-semibold text-primary-foreground shadow-sm hover:bg-primary/90 transition-colors"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>Author Query</span>
              </button>

              <button
                type="button"
                onClick={handlePullCaseIndicators}
                className="inline-flex items-center gap-1.5 rounded-lg border border-primary/40 bg-primary/10 px-3 py-2 text-xs font-semibold text-primary hover:bg-primary/20 transition-colors"
                title="Pull observables from active case"
              >
                <Crosshair className="h-3.5 w-3.5" />
                <span>Pull Case IOCs</span>
              </button>

              <button
                type="button"
                onClick={handleExportBundle}
                className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-card px-3 py-2 text-xs font-medium text-foreground hover:bg-muted transition-colors"
                title="Export custom queries as JSON"
              >
                <Download className="h-3.5 w-3.5 text-muted-foreground" />
                <span>Export</span>
              </button>
            </div>
          </div>

          {/* 4-KPI Arsenal Telemetry Ribbon */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Total Arsenal</span>
                <Bookmark className="h-4 w-4 text-primary" />
              </div>
              <div className="text-2xl font-bold tracking-tight text-foreground font-mono">
                {telemetry.total}
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">Production-tested detection queries</div>
            </div>

            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Splunk SPL</span>
                <Terminal className="h-4 w-4 text-amber-500" />
              </div>
              <div className="text-2xl font-bold tracking-tight text-amber-500 font-mono">
                {telemetry.splunkCount}
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">AD & network hunting queries</div>
            </div>

            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">Sentinel KQL</span>
                <Shield className="h-4 w-4 text-blue-500" />
              </div>
              <div className="text-2xl font-bold tracking-tight text-blue-500 font-mono">
                {telemetry.sentinelCount}
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">Cloud & identity correlations</div>
            </div>

            <div className="rounded-xl border border-border/70 bg-card p-3.5">
              <div className="flex items-center justify-between text-muted-foreground mb-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider">EQL / IDS / Runbooks</span>
                <ListChecks className="h-4 w-4 text-emerald-500" />
              </div>
              <div className="text-2xl font-bold tracking-tight text-emerald-500 font-mono">
                {telemetry.elasticCount + telemetry.suricataCount + telemetry.checklistsCount}
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">Endpoint & emergency response</div>
            </div>
          </div>

          {/* Interactive Variable Interpolation Dock */}
          <div className="rounded-xl border border-border/70 bg-card p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Zap className="h-4 w-4 text-primary" />
                <span className="text-xs font-semibold uppercase tracking-wider text-foreground">
                  Active Parameter Interpolation Dock
                </span>
              </div>
              <span className="text-[11px] text-muted-foreground font-mono">
                Variables substitute in real-time across all queries
              </span>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div>
                <label className="block text-[11px] font-mono text-muted-foreground mb-1">
                  {"{{TARGET_IP}}"}
                </label>
                <input
                  type="text"
                  value={variables.TARGET_IP || ""}
                  onChange={(e) => handleVariableChange("TARGET_IP", e.target.value)}
                  placeholder="e.g. 185.220.101.45"
                  className="w-full rounded-lg border border-border bg-background px-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-muted-foreground mb-1">
                  {"{{TARGET_HOST}}"}
                </label>
                <input
                  type="text"
                  value={variables.TARGET_HOST || ""}
                  onChange={(e) => handleVariableChange("TARGET_HOST", e.target.value)}
                  placeholder="e.g. SRV-FIN-PRD02"
                  className="w-full rounded-lg border border-border bg-background px-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-muted-foreground mb-1">
                  {"{{USERNAME}}"}
                </label>
                <input
                  type="text"
                  value={variables.USERNAME || ""}
                  onChange={(e) => handleVariableChange("USERNAME", e.target.value)}
                  placeholder="e.g. svc-backup"
                  className="w-full rounded-lg border border-border bg-background px-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-muted-foreground mb-1">
                  {"{{TIMEFRAME}}"}
                </label>
                <input
                  type="text"
                  value={variables.TIMEFRAME || ""}
                  onChange={(e) => handleVariableChange("TIMEFRAME", e.target.value)}
                  placeholder="e.g. 24h, 7d"
                  className="w-full rounded-lg border border-border bg-background px-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                />
              </div>
            </div>
          </div>

          {/* Filter Bar */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search queries by attack name, MITRE technique, or keyword..."
                className="w-full rounded-lg border border-border bg-card pl-9 pr-4 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>

            {/* Category Filter Chips */}
            <div className="flex flex-wrap items-center rounded-lg border border-border bg-muted/40 p-1 text-xs">
              {(["all", "splunk", "sentinel", "elastic", "suricata", "checklists"] as const).map((cat) => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={cn(
                    "px-3 py-1.5 rounded-md font-medium transition-all",
                    selectedCategory === cat
                      ? "bg-card text-foreground shadow-sm border border-border font-semibold"
                      : "text-muted-foreground hover:text-foreground"
                  )}
                >
                  {CATEGORY_LABELS[cat]}
                </button>
              ))}
            </div>
          </div>

          {/* Snippets Cards Grid */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Query Arsenal ({filteredSnippets.length})
              </span>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {filteredSnippets.map((snippet) => {
                const interpolated = interpolateQuery(snippet.queryTemplate, variables);
                const isCopied = copiedSnippetId === snippet.id;

                return (
                  <div
                    key={snippet.id}
                    className="flex flex-col justify-between rounded-xl border border-border/70 bg-card p-5 hover:border-primary/50 transition-all space-y-3.5 group"
                  >
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span
                            className={cn(
                              "text-[10px] font-mono uppercase px-2 py-0.5 rounded font-semibold border",
                              CATEGORY_COLORS[snippet.category]
                            )}
                          >
                            {snippet.category}
                          </span>
                          {snippet.mitreTechnique && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-muted text-muted-foreground border border-border">
                              {snippet.mitreTechnique}
                            </span>
                          )}
                          {snippet.isCustom && (
                            <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 rounded bg-primary/20 text-primary border border-primary/30">
                              CUSTOM
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() => handleCopyQuery(snippet)}
                            className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
                            title="Copy interpolated query"
                          >
                            {isCopied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
                            <span>{isCopied ? "Copied" : "Copy"}</span>
                          </button>
                        </div>
                      </div>

                      <div>
                        <h3 className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors">
                          {snippet.title}
                        </h3>
                        <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                          {snippet.description}
                        </p>
                      </div>

                      <pre className="p-3 rounded-lg bg-black/90 text-emerald-400 font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed select-all max-h-48">
                        {interpolated}
                      </pre>
                    </div>

                    <div className="pt-3 border-t border-border/60 flex items-center justify-between">
                      <div className="flex flex-wrap gap-1 max-w-[200px]">
                        {snippet.tags.slice(0, 3).map((tag) => (
                          <span
                            key={tag}
                            className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-muted/60 text-muted-foreground border border-border/40"
                          >
                            #{tag}
                          </span>
                        ))}
                      </div>

                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => handleRunInSiem(snippet)}
                          className="inline-flex items-center gap-1 rounded px-2.5 py-1 text-xs font-semibold bg-primary/10 text-primary hover:bg-primary/20 border border-primary/30 transition-colors"
                          title="Open query in SIEM Hunter"
                        >
                          <span>Run in SIEM</span>
                          <ArrowRight className="h-3 w-3" />
                        </button>

                        <button
                          type="button"
                          onClick={() => handleExtractInParser(snippet)}
                          className="rounded p-1 text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
                          title="Extract in Parser"
                        >
                          <Wand2 className="h-3.5 w-3.5" />
                        </button>

                        <button
                          type="button"
                          onClick={() => handleFileToCase(snippet)}
                          className="rounded p-1 text-muted-foreground hover:text-primary hover:bg-primary/10 transition-colors"
                          title="File to Case"
                        >
                          <Send className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Custom Snippet Authoring Modal */}
        {authorModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-in fade-in duration-150">
            <div
              className="flex flex-col w-full max-w-2xl max-h-[90vh] rounded-xl border border-border bg-card shadow-2xl overflow-hidden"
              role="dialog"
              aria-modal="true"
              aria-labelledby="author-modal-title"
            >
              <div className="flex items-center justify-between border-b border-border px-6 py-4 bg-muted/30">
                <div className="flex items-center gap-2.5">
                  <Bookmark className="h-5 w-5 text-primary" />
                  <h2 id="author-modal-title" className="text-base font-semibold text-foreground">
                    Author Custom Threat Hunting Query
                  </h2>
                </div>
                <button
                  onClick={() => setAuthorModalOpen(false)}
                  className="rounded p-1 text-muted-foreground hover:text-foreground"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-6 space-y-4">
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                    Query Title <span className="text-destructive">*</span>
                  </label>
                  <input
                    type="text"
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                    placeholder="e.g. Active Directory DCSync Audit"
                    className="w-full rounded-lg border border-border bg-background px-3.5 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                      Category
                    </label>
                    <select
                      value={newCategory}
                      onChange={(e) => setNewCategory(e.target.value as SnippetCategory)}
                      className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                    >
                      <option value="splunk">Splunk SPL</option>
                      <option value="sentinel">Sentinel KQL</option>
                      <option value="elastic">Elastic EQL</option>
                      <option value="suricata">Suricata IDS</option>
                      <option value="checklists">DFIR Checklist</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                      Tags (comma separated)
                    </label>
                    <input
                      type="text"
                      value={newTags}
                      onChange={(e) => setNewTags(e.target.value)}
                      placeholder="ad, dcsync, credentials"
                      className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                    Description / Purpose
                  </label>
                  <input
                    type="text"
                    value={newDesc}
                    onChange={(e) => setNewDesc(e.target.value)}
                    placeholder="Explain what this query hunts for and expected false positive scenarios..."
                    className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                    Query Template (Supports {"{{TARGET_IP}}"}, {"{{USERNAME}}"}, etc.)
                  </label>
                  <textarea
                    rows={6}
                    value={newTemplate}
                    onChange={(e) => setNewTemplate(e.target.value)}
                    placeholder={`index=security sourcetype="WinEventLog:Security" EventCode=4662 AccessMask="0x100"\n| where src_ip=="{{TARGET_IP}}"`}
                    className="w-full rounded-lg border border-border bg-background p-3 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>

              <div className="flex items-center justify-between border-t border-border px-6 py-4 bg-muted/20">
                <button
                  type="button"
                  onClick={() => setAuthorModalOpen(false)}
                  className="rounded-lg border border-border px-4 py-2 text-xs font-medium text-muted-foreground hover:bg-muted hover:text-foreground"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleCreateCustomSnippet}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground shadow hover:bg-primary/90"
                >
                  <Plus className="h-3.5 w-3.5" />
                  <span>Save to Arsenal</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </PageShell>
    </ErrorBoundary>
  );
}
