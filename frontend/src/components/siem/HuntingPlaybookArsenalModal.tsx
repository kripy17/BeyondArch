import { useState, useMemo, useEffect } from "react";
import { useNavigate } from "@tanstack/react-router";
import {
  BookMarked,
  Crosshair,
  Search,
  Copy,
  Check,
  Plus,
  Play,
  ArrowRight,
  X,
  ShieldCheck,
  CheckCircle2,
  Terminal,
  Activity,
  Layers,
  FileCode,
  SlidersHorizontal,
  Info,
} from "lucide-react";
import { Chip } from "@/components/soc";
import { notify } from "@/lib/notify";
import { copyText } from "@/lib/copy";
import {
  HUNTING_PRESETS,
  loadHuntingSnippets,
  saveCustomSnippets,
  createCustomSnippet,
  interpolateQuery,
  calculateArsenalTelemetry,
  type HuntingSnippet,
  type SnippetCategory,
} from "@/lib/hunting-arsenal";
import {
  tuneQueryToSigma,
  promoteRuleToDetectionLab,
  type TunedSigmaRule,
} from "@/lib/detection/sigma-tuning-engine";

interface HuntingPlaybookArsenalModalProps {
  open: boolean;
  onClose: () => void;
  onLoadQuery: (query: string) => void;
  initialTechnique?: string | null;
}

const CATEGORY_LABELS: Record<SnippetCategory | "all", { label: string; color: string }> = {
  all: { label: "All Playbooks", color: "text-foreground" },
  splunk: { label: "Splunk SPL", color: "text-orange-400" },
  sentinel: { label: "Sentinel KQL", color: "text-sky-400" },
  elastic: { label: "Elastic EQL", color: "text-emerald-400" },
  suricata: { label: "Suricata IDS", color: "text-rose-400" },
  checklists: { label: "DFIR Runbooks", color: "text-purple-400" },
};

export function HuntingPlaybookArsenalModal({
  open,
  onClose,
  onLoadQuery,
  initialTechnique,
}: HuntingPlaybookArsenalModalProps) {
  const navigate = useNavigate();
  const [snippets, setSnippets] = useState<HuntingSnippet[]>(() => loadHuntingSnippets());
  const [selectedCategory, setSelectedCategory] = useState<SnippetCategory | "all">("all");
  const [searchQuery, setSearchQuery] = useState(initialTechnique || "");
  const [selectedSnippetId, setSelectedSnippetId] = useState<string>(() => {
    return HUNTING_PRESETS[0]?.id || "";
  });

  // Parameter variables state
  const [paramValues, setParamValues] = useState<Record<string, string>>({
    TARGET_IP: "10.0.4.15",
    TARGET_HOST: "WS-014",
    HOSTNAME: "WS-014",
    USERNAME: "krish",
    TIMEFRAME: "24h",
  });

  const [copiedQuery, setCopiedQuery] = useState(false);
  const [copiedYaml, setCopiedYaml] = useState(false);
  const [isCreatingCustom, setIsCreatingCustom] = useState(false);

  // New Custom Snippet Form State
  const [newTitle, setNewTitle] = useState("");
  const [newCategory, setNewCategory] = useState<SnippetCategory>("splunk");
  const [newTechnique, setNewTechnique] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newTemplate, setNewTemplate] = useState("");
  const [newTags, setNewTags] = useState("");

  // Sync initial technique when modal opens
  useEffect(() => {
    if (initialTechnique) {
      setSearchQuery(initialTechnique);
      const match = snippets.find(
        (s) =>
          s.mitreTechnique?.toLowerCase() === initialTechnique.toLowerCase() ||
          s.tags.some((t) => t.toLowerCase() === initialTechnique.toLowerCase())
      );
      if (match) setSelectedSnippetId(match.id);
    }
  }, [initialTechnique, snippets]);

  const telemetry = useMemo(() => calculateArsenalTelemetry(snippets), [snippets]);

  // Filter snippets based on category & search query
  const filteredSnippets = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    return snippets.filter((s) => {
      const matchCategory = selectedCategory === "all" || s.category === selectedCategory;
      if (!matchCategory) return false;
      if (!q) return true;
      return (
        s.title.toLowerCase().includes(q) ||
        s.description.toLowerCase().includes(q) ||
        s.queryTemplate.toLowerCase().includes(q) ||
        (s.mitreTechnique && s.mitreTechnique.toLowerCase().includes(q)) ||
        s.tags.some((t) => t.toLowerCase().includes(q))
      );
    });
  }, [snippets, selectedCategory, searchQuery]);

  // Active Snippet
  const activeSnippet = useMemo(() => {
    return snippets.find((s) => s.id === selectedSnippetId) || filteredSnippets[0] || snippets[0];
  }, [snippets, selectedSnippetId, filteredSnippets]);

  // Live Interpolated Query
  const interpolatedQuery = useMemo(() => {
    if (!activeSnippet) return "";
    return interpolateQuery(activeSnippet.queryTemplate, paramValues);
  }, [activeSnippet, paramValues]);

  // Auto-Tuning State for Active Snippet
  const [tunedRule, setTunedRule] = useState<TunedSigmaRule | null>(null);

  // Auto-tune when active snippet changes
  useEffect(() => {
    if (activeSnippet && activeSnippet.category !== "checklists") {
      const tuned = tuneQueryToSigma(activeSnippet.queryTemplate, {
        ruleTitle: `Detection: ${activeSnippet.title}`,
        targetTechnique: activeSnippet.mitreTechnique,
      });
      setTunedRule(tuned);
    } else {
      setTunedRule(null);
    }
  }, [activeSnippet]);

  const handleCopyQuery = async () => {
    if (!interpolatedQuery) return;
    try {
      await copyText(interpolatedQuery);
      setCopiedQuery(true);
      notify.success("Hunting query copied to clipboard");
      setTimeout(() => setCopiedQuery(false), 2000);
    } catch {
      notify.error("Failed to copy query");
    }
  };

  const handleCopyYaml = async () => {
    if (!tunedRule?.yaml) return;
    try {
      await copyText(tunedRule.yaml);
      setCopiedYaml(true);
      notify.success("Tuned Sigma YAML copied to clipboard");
      setTimeout(() => setCopiedYaml(false), 2000);
    } catch {
      notify.error("Failed to copy YAML");
    }
  };

  const handleLoadIntoSiem = () => {
    if (!interpolatedQuery) return;
    onLoadQuery(interpolatedQuery);
    notify.success(`Loaded "${activeSnippet.title}" into SIEM search bar`);
    onClose();
  };

  const handlePromoteToDetection = () => {
    if (!tunedRule) return;
    const saved = promoteRuleToDetectionLab(tunedRule);
    notify.success(`Promoted "${saved.name}" to Detection Sandbox (Draft)`);
    onClose();
    navigate({ to: "/detection" });
  };

  const handleCreateCustom = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim() || !newTemplate.trim()) {
      notify.error("Title and Query Template are required");
      return;
    }

    const custom = createCustomSnippet({
      title: newTitle.trim(),
      category: newCategory,
      description: newDescription.trim() || "Custom investigator playbook snippet",
      queryTemplate: newTemplate.trim(),
      tags: newTags
        .split(",")
        .map((t) => t.trim().toLowerCase())
        .filter(Boolean),
      mitreTechnique: newTechnique.trim() || undefined,
    });

    const updated = [...snippets, custom];
    setSnippets(updated);
    saveCustomSnippets(updated);
    setSelectedSnippetId(custom.id);
    setIsCreatingCustom(false);

    // Reset Form
    setNewTitle("");
    setNewTechnique("");
    setNewDescription("");
    setNewTemplate("");
    setNewTags("");

    notify.success(`Created custom playbook "${custom.title}"`);
  };

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="hunting-arsenal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-2 sm:p-4 backdrop-blur-sm"
    >
      <div className="flex max-h-[92vh] w-full max-w-6xl min-w-0 flex-col overflow-hidden rounded-xl border border-subtle bg-surface-1 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-subtle bg-surface-0 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary border border-primary/20">
              <BookMarked className="h-4 w-4" />
            </div>
            <div className="min-w-0">
              <h2 id="hunting-arsenal-title" className="text-base font-semibold text-foreground truncate flex items-center gap-2">
                Threat Hunting Playbook Arsenal
                <span className="hidden sm:inline-flex items-center gap-1 rounded bg-primary/10 border border-primary/30 px-2 py-0.5 text-mono ba-text-3xs text-primary">
                  <SlidersHorizontal className="h-2.5 w-2.5" /> Sigma Rule Tuning
                </span>
              </h2>
              <p className="text-xs text-muted-foreground truncate">
                Curated multi-dialect queries (Splunk, Sentinel, Elastic, Suricata) with 1-click SIEM execution & automated Sigma tuning
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="shrink-0 rounded p-1.5 text-muted-foreground hover:bg-surface-2 hover:text-foreground transition-colors"
            aria-label="Close modal"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Categories Bar & Search Toolbar */}
        <div className="border-b border-subtle bg-surface-0/60 p-3 sm:px-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            {/* Category tabs */}
            <div className="flex flex-wrap items-center gap-1.5 min-w-0">
              {(["all", "splunk", "sentinel", "elastic", "suricata", "checklists"] as const).map((cat) => {
                const isSel = selectedCategory === cat;
                const count =
                  cat === "all"
                    ? telemetry.total
                    : cat === "splunk"
                    ? telemetry.splunkCount
                    : cat === "sentinel"
                    ? telemetry.sentinelCount
                    : cat === "elastic"
                    ? telemetry.elasticCount
                    : cat === "suricata"
                    ? telemetry.suricataCount
                    : telemetry.checklistsCount;

                return (
                  <button
                    key={cat}
                    onClick={() => setSelectedCategory(cat)}
                    className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-mono ba-text-2xs font-medium transition-all ${
                      isSel
                        ? "bg-primary text-primary-foreground shadow-sm"
                        : "bg-surface-2 text-muted-foreground hover:bg-surface-3 hover:text-foreground"
                    }`}
                  >
                    <span>{CATEGORY_LABELS[cat].label}</span>
                    <span
                      className={`rounded-full px-1.5 py-0.2 text-mono ba-text-3xs ${
                        isSel ? "bg-black/25 text-white" : "bg-surface-1 text-muted-foreground"
                      }`}
                    >
                      {count}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Actions: Search & Add Custom */}
            <div className="flex items-center gap-2 min-w-0">
              <div className="relative min-w-[200px] flex-1 sm:flex-none">
                <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Filter playbooks or technique..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="h-7 w-full rounded border border-subtle bg-surface-1 pl-8 pr-3 text-mono ba-text-2xs text-foreground placeholder:text-muted-foreground/60 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                />
                {searchQuery && (
                  <button
                    onClick={() => setSearchQuery("")}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    <X className="h-3 w-3" />
                  </button>
                )}
              </div>

              <button
                onClick={() => setIsCreatingCustom((v) => !v)}
                className={`inline-flex h-7 items-center gap-1 rounded border px-2.5 text-mono ba-text-2xs transition-colors ${
                  isCreatingCustom
                    ? "border-primary bg-primary/20 text-primary"
                    : "border-subtle bg-surface-2 text-foreground hover:border-primary/40 hover:text-primary"
                }`}
              >
                <Plus className="h-3 w-3" />
                <span className="hidden md:inline">{isCreatingCustom ? "Close Editor" : "New Snippet"}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Custom Snippet Creator Drawer */}
        {isCreatingCustom && (
          <form
            onSubmit={handleCreateCustom}
            className="border-b border-subtle bg-surface-2/70 p-4 space-y-3"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                <Plus className="h-3.5 w-3.5 text-primary" />
                <span>Create Custom Threat Hunting Playbook</span>
              </div>
              <span className="text-mono ba-text-3xs text-muted-foreground">
                Use {"{{VAR_NAME}}"} syntax to create interpolatable parameters
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div>
                <label className="text-mono ba-text-3xs text-muted-foreground">Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Cobalt Strike DNS Staging Detection"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="mt-1 h-7 w-full rounded border border-subtle bg-surface-1 px-2 text-mono ba-text-2xs text-foreground focus:border-primary focus:outline-none"
                />
              </div>

              <div>
                <label className="text-mono ba-text-3xs text-muted-foreground">Category *</label>
                <select
                  value={newCategory}
                  onChange={(e) => setNewCategory(e.target.value as SnippetCategory)}
                  className="mt-1 h-7 w-full rounded border border-subtle bg-surface-1 px-2 text-mono ba-text-2xs text-foreground focus:border-primary focus:outline-none"
                >
                  <option value="splunk">Splunk SPL</option>
                  <option value="sentinel">Sentinel KQL</option>
                  <option value="elastic">Elastic EQL</option>
                  <option value="suricata">Suricata IDS</option>
                  <option value="checklists">DFIR Runbook</option>
                </select>
              </div>

              <div>
                <label className="text-mono ba-text-3xs text-muted-foreground">MITRE Technique (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. T1071.004"
                  value={newTechnique}
                  onChange={(e) => setNewTechnique(e.target.value)}
                  className="mt-1 h-7 w-full rounded border border-subtle bg-surface-1 px-2 text-mono ba-text-2xs text-foreground focus:border-primary focus:outline-none"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="text-mono ba-text-3xs text-muted-foreground">Description</label>
                <input
                  type="text"
                  placeholder="Operational objective and detection logic rationale..."
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  className="mt-1 h-7 w-full rounded border border-subtle bg-surface-1 px-2 text-mono ba-text-2xs text-foreground focus:border-primary focus:outline-none"
                />
              </div>

              <div>
                <label className="text-mono ba-text-3xs text-muted-foreground">Tags (comma-separated)</label>
                <input
                  type="text"
                  placeholder="c2, dns, custom, priority"
                  value={newTags}
                  onChange={(e) => setNewTags(e.target.value)}
                  className="mt-1 h-7 w-full rounded border border-subtle bg-surface-1 px-2 text-mono ba-text-2xs text-foreground focus:border-primary focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="text-mono ba-text-3xs text-muted-foreground">Query Template *</label>
              <textarea
                required
                rows={3}
                placeholder="index=dns query_length > 45 dest_ip={{TARGET_IP}} | stats count by query"
                value={newTemplate}
                onChange={(e) => setNewTemplate(e.target.value)}
                className="mt-1 w-full rounded border border-subtle bg-surface-1 p-2 font-mono ba-text-2xs text-foreground focus:border-primary focus:outline-none"
              />
            </div>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setIsCreatingCustom(false)}
                className="rounded px-3 py-1 text-mono ba-text-2xs text-muted-foreground hover:bg-surface-3 hover:text-foreground"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="rounded bg-primary px-3 py-1 text-mono ba-text-2xs font-semibold text-primary-foreground hover:bg-primary/90"
              >
                Save Custom Snippet
              </button>
            </div>
          </form>
        )}

        {/* Modal Body: Split Pane (Left: Snippets List, Right: Workbench & Auto-Tuning) */}
        <div className="grid grid-cols-1 md:grid-cols-12 min-h-0 flex-1 overflow-hidden divide-y md:divide-y-0 md:divide-x divide-subtle">
          {/* Left Column: Snippet Catalog List */}
          <div className="md:col-span-4 flex flex-col min-h-0 overflow-y-auto bg-surface-0/40 p-3 space-y-2">
            <div className="flex items-center justify-between pb-1 border-b border-subtle">
              <span className="text-mono ba-text-3xs font-semibold text-muted-foreground uppercase tracking-wider">
                Playbook Catalog ({filteredSnippets.length})
              </span>
              {selectedCategory !== "all" && (
                <span className="text-mono ba-text-3xs text-primary font-medium">
                  {CATEGORY_LABELS[selectedCategory].label}
                </span>
              )}
            </div>

            {filteredSnippets.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 text-center text-muted-foreground">
                <Search className="h-8 w-8 mb-2 opacity-40" />
                <p className="text-xs">No playbooks found</p>
                <p className="text-mono ba-text-3xs opacity-70">Try adjusting your search filter or category</p>
              </div>
            ) : (
              filteredSnippets.map((snippet) => {
                const isSelected = snippet.id === activeSnippet?.id;
                return (
                  <button
                    key={snippet.id}
                    onClick={() => setSelectedSnippetId(snippet.id)}
                    className={`w-full text-left p-2.5 rounded-lg border transition-all ${
                      isSelected
                        ? "border-primary bg-primary/10 shadow-sm"
                        : "border-subtle bg-surface-1 hover:border-primary/40 hover:bg-surface-2"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1.5 mb-1">
                      <span
                        className={`text-mono ba-text-3xs font-bold uppercase tracking-wider ${
                          CATEGORY_LABELS[snippet.category].color
                        }`}
                      >
                        {snippet.category}
                      </span>
                      {snippet.mitreTechnique && (
                        <span className="rounded bg-surface-2 px-1.5 py-0.2 text-mono ba-text-3xs text-foreground font-mono">
                          {snippet.mitreTechnique}
                        </span>
                      )}
                    </div>
                    <div className="text-xs font-semibold text-foreground line-clamp-1">
                      {snippet.title}
                    </div>
                    <div className="text-mono ba-text-3xs text-muted-foreground line-clamp-2 mt-1">
                      {snippet.description}
                    </div>
                    {snippet.variables.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1 mt-2">
                        {snippet.variables.map((v) => (
                          <span
                            key={v}
                            className="rounded bg-surface-0 border border-subtle px-1 py-0.2 text-mono ba-text-3xs text-primary"
                          >
                            {v}
                          </span>
                        ))}
                      </div>
                    )}
                  </button>
                );
              })
            )}
          </div>

          {/* Right Column: Workbench & Auto-Tuning Engine */}
          <div className="md:col-span-8 flex flex-col min-h-0 overflow-y-auto p-4 sm:p-5 space-y-4 bg-surface-1">
            {activeSnippet ? (
              <>
                {/* Active Playbook Header */}
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2 border-b border-subtle pb-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span
                        className={`text-mono ba-text-2xs font-bold uppercase px-2 py-0.5 rounded border border-subtle bg-surface-0 ${
                          CATEGORY_LABELS[activeSnippet.category].color
                        }`}
                      >
                        {CATEGORY_LABELS[activeSnippet.category].label}
                      </span>
                      {activeSnippet.mitreTechnique && (
                        <span className="rounded bg-primary/10 border border-primary/30 px-2 py-0.5 text-mono ba-text-2xs text-primary font-mono">
                          MITRE: {activeSnippet.mitreTechnique}
                        </span>
                      )}
                      {activeSnippet.isCustom && (
                        <span className="rounded bg-warning/10 border border-warning/30 px-1.5 py-0.5 text-mono ba-text-3xs text-warning">
                          Custom
                        </span>
                      )}
                    </div>
                    <h3 className="text-base font-bold text-foreground">
                      {activeSnippet.title}
                    </h3>
                    <p className="text-xs text-muted-foreground mt-1">
                      {activeSnippet.description}
                    </p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={handleCopyQuery}
                      className="inline-flex h-7 items-center gap-1 rounded border border-subtle bg-surface-2 px-2.5 text-mono ba-text-2xs text-foreground transition-colors hover:border-primary/40 hover:text-primary"
                      title="Copy interpolated query to clipboard"
                    >
                      {copiedQuery ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                      <span>{copiedQuery ? "Copied" : "Copy Query"}</span>
                    </button>

                    {activeSnippet.category !== "checklists" && (
                      <button
                        onClick={handleLoadIntoSiem}
                        className="inline-flex h-7 items-center gap-1.5 rounded bg-primary px-3 text-mono ba-text-2xs font-semibold text-primary-foreground shadow-sm hover:bg-primary/90 transition-colors"
                        title="Load query into SIEM search bar and evaluate"
                      >
                        <Play className="h-3 w-3 fill-current" />
                        <span>Load into SIEM</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Variable Parameterizer (if variables exist) */}
                {activeSnippet.variables.length > 0 && (
                  <div className="rounded-lg border border-subtle bg-surface-0/60 p-3">
                    <div className="flex items-center gap-1.5 text-mono ba-text-3xs font-bold text-muted-foreground uppercase tracking-wider mb-2">
                      <SlidersHorizontal className="h-3 w-3 text-primary" />
                      <span>Parametric Variables</span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
                      {activeSnippet.variables.map((varName) => (
                        <div key={varName}>
                          <label className="text-mono ba-text-3xs text-muted-foreground block truncate">
                            {varName}
                          </label>
                          <input
                            type="text"
                            value={paramValues[varName] ?? ""}
                            onChange={(e) =>
                              setParamValues((prev) => ({
                                ...prev,
                                [varName]: e.target.value,
                              }))
                            }
                            placeholder={`Value for ${varName}`}
                            className="mt-1 h-7 w-full rounded border border-subtle bg-surface-1 px-2 text-mono ba-text-2xs text-foreground focus:border-primary focus:outline-none"
                          />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Live Interpolated Query Block */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-mono ba-text-3xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                      <Terminal className="h-3 w-3 text-primary" />
                      {activeSnippet.category === "checklists" ? "Runbook Blueprint" : "Interpolated Query (Execution Ready)"}
                    </span>
                  </div>
                  <pre className="max-h-48 overflow-x-auto rounded-lg border border-subtle bg-black/40 p-3 font-mono ba-text-2xs text-foreground whitespace-pre-wrap break-all select-all">
                    {interpolatedQuery}
                  </pre>
                </div>

                {/* Automated Sigma Rule Tuning & Noise Suppression Panel */}
                {activeSnippet.category !== "checklists" && tunedRule && (
                  <div className="rounded-xl border border-primary/30 bg-surface-0/90 p-4 space-y-3 shadow-inner">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-subtle pb-2.5">
                      <div className="flex items-center gap-2 min-w-0">
                        <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded bg-primary/20 text-primary">
                          <SlidersHorizontal className="h-3.5 w-3.5" />
                        </div>
                        <div className="min-w-0">
                          <h4 className="text-xs font-bold text-foreground truncate flex items-center gap-2">
                            Sigma Rule Tuning & False Positive Suppression
                            <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-1.5 py-0.2 text-mono ba-text-3xs text-emerald-400 font-semibold">
                              Score: {tunedRule.healthScore}/100
                            </span>
                          </h4>
                          <p className="text-mono ba-text-3xs text-muted-foreground">
                            Noise risk: <span className="font-semibold text-foreground uppercase">{tunedRule.noiseRisk}</span> · Estimated FP: {tunedRule.tuningSummary.fpEstimatedPct}%
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={handleCopyYaml}
                          className="inline-flex h-6 items-center gap-1 rounded border border-subtle bg-surface-2 px-2 text-mono ba-text-3xs text-foreground hover:border-primary/40 hover:text-primary transition-colors"
                        >
                          {copiedYaml ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                          <span>{copiedYaml ? "Copied" : "Copy YAML"}</span>
                        </button>

                        <button
                          onClick={handlePromoteToDetection}
                          className="inline-flex h-6 items-center gap-1 rounded bg-primary px-2.5 text-mono ba-text-3xs font-semibold text-primary-foreground hover:bg-primary/90 transition-colors shadow-sm"
                          title="Save as Draft in Detection Library and open in sandbox"
                        >
                          <ShieldCheck className="h-3 w-3" />
                          <span>Promote to Detection</span>
                          <ArrowRight className="h-2.5 w-2.5" />
                        </button>
                      </div>
                    </div>

                    {/* Auto-Tuning Summary Chips */}
                    <div className="flex flex-wrap items-center gap-1.5">
                      <div className="inline-flex items-center gap-1 rounded bg-surface-1 border border-subtle px-2 py-0.5 text-mono ba-text-3xs text-muted-foreground">
                        <CheckCircle2 className="h-2.5 w-2.5 text-emerald-400" />
                        <span>Noise Filters: {tunedRule.tuningSummary.noiseExclusionsCount} applied</span>
                      </div>
                      {tunedRule.techniqueId && (
                        <div className="inline-flex items-center gap-1 rounded bg-surface-1 border border-subtle px-2 py-0.5 text-mono ba-text-3xs text-muted-foreground">
                          <CheckCircle2 className="h-2.5 w-2.5 text-emerald-400" />
                          <span>MITRE: {tunedRule.techniqueId} ({tunedRule.tactic})</span>
                        </div>
                      )}
                      <div className="inline-flex items-center gap-1 rounded bg-surface-1 border border-subtle px-2 py-0.5 text-mono ba-text-3xs text-muted-foreground">
                        <CheckCircle2 className="h-2.5 w-2.5 text-emerald-400" />
                        <span>Anchored Conditions ({tunedRule.level} level)</span>
                      </div>
                    </div>

                    {/* Tuned Sigma YAML Preview */}
                    <pre className="max-h-48 overflow-x-auto rounded-lg border border-subtle bg-black/60 p-3 font-mono ba-text-3xs text-foreground/90 whitespace-pre-wrap break-all select-all">
                      {tunedRule.yaml}
                    </pre>
                  </div>
                )}
              </>
            ) : (
              <div className="flex flex-col items-center justify-center py-20 text-center text-muted-foreground">
                <Info className="h-8 w-8 mb-2 opacity-50" />
                <p className="text-sm font-semibold">Select a Playbook</p>
                <p className="text-xs">Choose a playbook from the left catalog to inspect and auto-tune.</p>
              </div>
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex flex-col sm:flex-row items-center justify-between border-t border-subtle bg-surface-0 px-4 py-2.5 sm:px-6 gap-2">
          <div className="flex items-center gap-3 text-mono ba-text-3xs text-muted-foreground">
            <span>BeyondLabs Threat Hunting Arsenal v3.2</span>
            <span>·</span>
            <span>{telemetry.total} Active Playbooks</span>
            <span>·</span>
            <span>Dialects: SPL, KQL, EQL, Suricata</span>
          </div>

          <button
            onClick={onClose}
            className="rounded border border-subtle bg-surface-2 px-3 py-1 text-mono ba-text-2xs text-foreground hover:bg-surface-3 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
