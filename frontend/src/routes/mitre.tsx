import { MitreNavigatorLayerBar, type PlatformFilter } from "@/components/mitre/MitreNavigatorLayerBar";
import { TechniqueDetailDrawer } from "@/components/mitre/TechniqueDetailDrawer";
import { exportNavigatorLayerJson, getTechniqueEnrichment, type CoverageLevel } from "@/lib/detection/navigator-layer-engine";
import { sendToCase } from "@/lib/handoff";
import { notify } from "@/lib/notify";
import { createFileRoute, useNavigate, useSearch } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Panel, SendToRow, Chip } from "@/components/soc";
import { ResultBanner, EvidenceCard } from "@/components/output";
import { sendArtifact } from "@/lib/handoff";
import { pushTimelineEvent } from "@/lib/timeline";
import { Target, ArrowRight, CornerDownRight, Database, ShieldAlert, RotateCcw, Search, StickyNote, Download, Users, X, Crosshair, Layers } from "lucide-react";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { TACTICS, type MitreTechnique as Technique, type MitreTactic as Tactic } from "@/data/mitre";
import { loadRules, ruleTechniques } from "@/data/detection";
import { getThreatActorByTitleOrAlias } from "@/data/intel";
import { useActiveCase } from "@/data/case";
import { AdversaryAttributionWorkspace } from "@/components/mitre/AdversaryAttributionWorkspace";
import { cn } from "@/lib/utils";

type MitreSearch = { q?: string; technique?: string };
export const Route = createFileRoute("/mitre")({
  component: MitrePage,
  validateSearch: (s: Record<string, unknown>): MitreSearch => ({
    q: typeof s.q === "string" ? s.q : undefined,
    technique: typeof s.technique === "string" ? s.technique : undefined,
  }),
});

type Cov = "none" | "partial" | "full";

const COV_KEY = "beyondlabs.mitre.coverage.v3";
const NOTE_KEY = "beyondlabs.mitre.notes.v3";

const tone: Record<Cov, "default" | "warning" | "success"> = { none: "default", partial: "warning", full: "success" };
const cell: Record<Cov, string> = {
  none:    "border-subtle bg-background/30 text-muted-foreground hover:border-warning/30",
  partial: "border-warning/40 bg-warning/10 text-warning hover:border-warning/60",
  full:    "border-success/40 bg-success/15 text-success hover:border-success/60",
};

type LookupDetection = { name: string; state: string; format: string };

function loadCov(): Record<string, Cov> {
  try { return JSON.parse(localStorage.getItem(COV_KEY) || "{}"); } catch { return {}; }
}
function saveCov(map: Record<string, Cov>) {
  localStorage.setItem(COV_KEY, JSON.stringify(map));
}
function loadNotes(): Record<string, string> {
  try { return JSON.parse(localStorage.getItem(NOTE_KEY) || "{}"); } catch { return {}; }
}
function saveNotes(map: Record<string, string>) {
  localStorage.setItem(NOTE_KEY, JSON.stringify(map));
}
function nextCov(c: Cov): Cov {
  if (c === "none") return "partial";
  if (c === "partial") return "full";
  return "none";
}
function techKey(tacticId: string, techId: string) { return `${tacticId}::${techId}`; }

function genCovExport(cov: Record<string, Cov>, notes: Record<string, string>, tactics: Tactic[]): string {
  const techniques = tactics.flatMap((t) =>
    t.techniques.map((x) => ({
      id: x.id, name: x.name, tactic: t.name, tacticId: t.id,
      coverage: cov[techKey(t.id, x.id)] || "none", note: notes[x.id] || "",
    }))
  );
  return JSON.stringify({
    version: "1.0", ts: new Date().toISOString(),
    stats: { total: techniques.length, full: techniques.filter((t) => t.coverage === "full").length, partial: techniques.filter((t) => t.coverage === "partial").length, none: techniques.filter((t) => t.coverage === "none").length },
    techniques,
  }, null, 2);
}

function MitrePage() {
  const navigate = useNavigate();
  const { activeCase } = useActiveCase();
  const [viewMode, setViewMode] = useState<"matrix" | "attribution">("matrix");
  const [filter, setFilter] = useState<Cov | "all">("all");
  const [tab, setTab] = useState<"matrix" | "gaps" | "notes">("matrix");
  const [selected, setSelected] = useState<{ tactic: Tactic; tech: Technique; cov: Cov } | null>(null);
  const [cov, setCov] = useState<Record<string, Cov>>(loadCov);
  const [notes, setNotes] = useState<Record<string, string>>(loadNotes);
  const [noteDraft, setNoteDraft] = useState("");
  const [noteTech, setNoteTech] = useState<string | null>(null);
  const { q: initialQ, technique: initialTech } = useSearch({ from: Route.id });
  const [matrixSearch, setMatrixSearch] = useState(() => initialQ ?? initialTech ?? "");
  const [search, setSearch] = useState("");
  const actorQueryMatch = useMemo(() => matrixSearch ? getThreatActorByTitleOrAlias(matrixSearch) : undefined, [matrixSearch]);
  const [lookupId, setLookupId] = useState("");
    const [platform, setPlatform] = useState<PlatformFilter>("all");
  const [activePreset, setActivePreset] = useState<string | null>(null);
  const [drawerTech, setDrawerTech] = useState<{ id: string; name: string; tactic: string; tacticId: string } | null>(null);
  const localRules = useMemo(() => loadRules(), []);
  const rulesByTech = useMemo(() => {
    const map = new Map<string, number>();
    for (const r of localRules) {
      for (const tid of ruleTechniques(r)) {
        map.set(tid, (map.get(tid) || 0) + 1);
      }
    }
    return map;
  }, [localRules]);
  const [lookupResult, setLookupResult] = useState<{ found: boolean; query: string; technique?: { id: string; name: string; tactic: string; detectionCount: number }; detections: LookupDetection[] } | null>(null);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") { setSelected(null); e.preventDefault(); }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  const cycleCov = useCallback((tacticId: string, techId: string) => {
    setCov((prev) => {
      const key = techKey(tacticId, techId);
      const newVal = nextCov(prev[key] || "none");
      const next = { ...prev, [key]: newVal };
      saveCov(next);
      pushTimelineEvent({ source: "mitre", verb: newVal === "none" ? "uncovered" : newVal === "partial" ? "partial-covered" : "fully-covered", detail: `${techId} coverage set to ${newVal}`, target: techId, result: newVal });
      return next;
    });
  }, []);

    const handleExportNavigator = useCallback(() => {
    const jsonStr = exportNavigatorLayerJson(cov, notes, TACTICS, "BeyondLabs Enterprise SOC Coverage");
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `mitre-attack-navigator-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    pushTimelineEvent({ source: "mitre", verb: "exported-navigator-layer", detail: "Exported MITRE ATT&CK Navigator v4.5 JSON layer" });
  }, [cov, notes]);

  const handleImportNavigator = useCallback((importedCov: Record<string, CoverageLevel>, importedNotes: Record<string, string>, layerName: string) => {
    setCov((prev) => {
      const next = { ...prev };
      for (const [k, v] of Object.entries(importedCov)) {
        next[k] = v;
      }
      saveCov(next);
      return next;
    });
    setNotes((prev) => {
      const next = { ...prev, ...importedNotes };
      saveNotes(next);
      return next;
    });
    pushTimelineEvent({ source: "mitre", verb: "imported-navigator-layer", detail: `Imported layer: ${layerName}` });
  }, []);

  const handleApplyPreset = useCallback((techIds: string[], presetName: string) => {
    setActivePreset(presetName);
    setMatrixSearch(techIds[0] || "");
    pushTimelineEvent({ source: "mitre", verb: "applied-preset", detail: `Applied preset: ${presetName}` });
  }, []);

  const resetAll = useCallback(() => {
    setCov({});
    localStorage.removeItem(COV_KEY);
    pushTimelineEvent({ source: "mitre", verb: "reset", detail: "All coverage data cleared" });
  }, []);

  const getTechCov = useCallback((tacticId: string, techId: string): Cov => {
    return cov[techKey(tacticId, techId)] || "none";
  }, [cov]);

  const doLookup = useCallback((techId: string) => {
    const id = techId.trim().toUpperCase();
    let tacticName: string | null = null;
    let techName: string | null = null;
    for (const t of TACTICS) {
      const m = t.techniques.find((x) => x.id === id);
      if (m) { tacticName = t.name; techName = m.name; break; }
    }
    if (!tacticName) { pushTimelineEvent({ source: "mitre", verb: "lookup-failed", detail: `Technique ${id} not found`, target: id }); setLookupResult({ found: false, query: id, detections: [] }); return; }
    const dets = loadRules()
      .filter((r) => ruleTechniques(r).includes(id))
      .map((r) => ({ name: r.name, state: r.state, format: r.format }));
    pushTimelineEvent({ source: "mitre", verb: "lookup", detail: `${id} — ${techName} (${dets.length} local detection rules)`, target: id, result: String(dets.length) });
    setLookupResult({ found: true, query: id, technique: { id, name: techName!, tactic: tacticName, detectionCount: dets.length }, detections: dets });
  }, []);

  const stats = useMemo(() => {
    const all = TACTICS.flatMap((t) => t.techniques.map((tech) => ({ ...tech, tacticId: t.id })));
    const n = all.filter((t) => getTechCov(t.tacticId, t.id) === "none").length;
    const p = all.filter((t) => getTechCov(t.tacticId, t.id) === "partial").length;
    const f = all.filter((t) => getTechCov(t.tacticId, t.id) === "full").length;
    return { total: all.length, full: f, partial: p, none: n };
  }, [getTechCov]);

  const pct = Math.round(((stats.full + stats.partial * 0.5) / stats.total) * 100);

  const tacticPct = (t: Tactic) => {
    const total = t.techniques.length;
    const score = t.techniques.reduce((s, x) => {
      const c = getTechCov(t.id, x.id);
      return s + (c === "full" ? 1 : c === "partial" ? 0.5 : 0);
    }, 0);
    return total ? score / total : 0;
  };

  const gaps = useMemo(() =>
    TACTICS.flatMap((t) =>
      t.techniques
        .filter((x) => getTechCov(t.id, x.id) === "none")
        .map((x) => ({ tactic: t.name, tacticId: t.id, ...x }))
    ), [getTechCov]);

  const partials = useMemo(() =>
    TACTICS.flatMap((t) =>
      t.techniques
        .filter((x) => getTechCov(t.id, x.id) === "partial")
        .map((x) => ({ tactic: t.name, tacticId: t.id, ...x }))
    ), [getTechCov]);

  const allTechniques = useMemo(() =>
    TACTICS.flatMap((t) => t.techniques.map((x) => ({ tactic: t.name, tacticId: t.id, ...x }))),
  []);

  const filteredGaps = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return gaps;
    return gaps.filter(x => x.id.toLowerCase().includes(q) || x.name.toLowerCase().includes(q) || x.tactic.toLowerCase().includes(q));
  }, [gaps, search]);

  const gapFindings = useMemo(() => {
    const f: { sev: "destructive" | "warning" | "info"; title: string; reason: string; action: string }[] = [];
    if (gaps.length) f.push({ sev: "destructive", title: `${gaps.length} techniques uncovered`, reason: `Gaps: ${gaps.slice(0, 8).map((x) => x.id).join(", ")}${gaps.length > 8 ? "…" : ""}`, action: "Prioritise detection sprints for uncovered techniques." });
    if (partials.length) f.push({ sev: "warning", title: `${partials.length} techniques partially covered`, reason: `Partial: ${partials.slice(0, 8).map((x) => x.id).join(", ")}${partials.length > 8 ? "…" : ""}`, action: "Flesh out detection logic to full coverage." });
    if (stats.full >= stats.total * 0.5) f.push({ sev: "info", title: `${pct}% weighted coverage`, reason: `${stats.full} full, ${stats.partial} partial, ${stats.none} none.`, action: "Maintain coverage with regular atomic test validation." });
    if (!f.length) f.push({ sev: "info", title: "No coverage data", reason: "All techniques are unrated.", action: "Click technique cells to mark coverage status." });
    return f;
  }, [gaps, partials, stats, pct]);

  function saveNote(techId: string) {
    if (!noteDraft.trim()) return;
    setNotes(prev => {
      const next = { ...prev, [techId]: noteDraft.trim() };
      saveNotes(next);
      return next;
    });
    setNoteDraft("");
    setNoteTech(null);
  }

  return (
    <ErrorBoundary name="MitrePage">
      <PageShell
        eyebrow="detection / mitre"
        title="MITRE ATT&CK Coverage"
        description="Interactive coverage matrix — click techniques to cycle none → partial → full. Stored locally in your browser."
        crumbs={[{ label: "Detection" }, { label: "MITRE" }]}
        actions={
          <div className="inline-flex items-center rounded-lg border border-border bg-muted/40 p-1 text-xs" id="mitre-view-switcher">
            <button
              type="button"
              onClick={() => setViewMode("matrix")}
              className={cn(
                "inline-flex items-center gap-1.5 px-3 py-1 rounded-md font-medium transition-all",
                viewMode === "matrix"
                  ? "bg-card text-foreground shadow-sm border border-border"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              <Layers className="h-3.5 w-3.5" />
              <span>14-Column Matrix</span>
            </button>
            <button
              type="button"
              onClick={() => setViewMode("attribution")}
              className={cn(
                "inline-flex items-center gap-1.5 px-3 py-1 rounded-md font-medium transition-all",
                viewMode === "attribution"
                  ? "bg-card text-foreground shadow-sm border border-border"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              <Crosshair className="h-3.5 w-3.5 text-destructive" />
              <span>Adversary Attribution &amp; C2</span>
            </button>
          </div>
        }
      >
        {viewMode === "attribution" ? (
          <AdversaryAttributionWorkspace
            activeCase={activeCase}
            onApplyTechniquesToMatrix={(techs, label) => {
              handleApplyPreset(techs, label);
              setViewMode("matrix");
            }}
            onNavigateToCase={() => navigate({ to: "/case" })}
          />
        ) : (
          <>
            <MitreNavigatorLayerBar
        platform={platform}
        onPlatformChange={setPlatform}
        onApplyPreset={handleApplyPreset}
        onImportLayer={handleImportNavigator}
        onExportLayer={handleExportNavigator}
        onResetCoverage={resetAll}
        activePreset={activePreset}
        actorMatch={actorQueryMatch ? { title: actorQueryMatch.title, techniques: actorQueryMatch.techniques } : null}
        onClearActor={() => { setMatrixSearch(""); setActivePreset(null); }}
      />

      <div className="pointer-events-none select-none">
        <ResultBanner
          badge="coverage"
          title={`${pct}% weighted coverage`}
          subtitle={`${stats.full} full · ${stats.partial} partial · ${stats.none} none`}
          metrics={[
            { label: "Tactics",    value: TACTICS.length, tone: "primary" },
            { label: "Techniques", value: stats.total },
            { label: "Full",       value: stats.full, tone: "success" },
            { label: "Gaps",       value: stats.none, tone: "warning" },
          ]}
        />
      </div>

      <div className="grid gap-3 grid-cols-2">
        {gapFindings.map((f, i) => (
          <EvidenceCard key={i} severity={f.sev} title={f.title} reason={f.reason} action={f.action} limitation="Click technique cells to update status. Coverage data is stored in browser localStorage." />
        ))}
      </div>

      <div className="mb-3">
        <Panel title="Technique Detection Lookup" icon={Search} collapsible defaultCollapsed storageKey="beyondlabs.mitre.detection-lookup.collapsed" meta="TID → your local rule library">
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <CornerDownRight className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  value={lookupId}
                  onChange={e => setLookupId(e.target.value.toUpperCase())}
                  onKeyDown={e => { if (e.key === "Enter" && lookupId.trim()) doLookup(lookupId.trim()); }}
                  placeholder="Enter technique ID, e.g. T1566, T1059.001…"
                  aria-label="Technique ID lookup"
                  className="h-8 w-full rounded border border-border bg-surface-0 pl-8 pr-2 text-mono ba-text-2xs text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/50"
                />
              </div>
              <button
                onClick={() => lookupId.trim() && doLookup(lookupId.trim())}
                className="inline-flex h-8 items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 text-mono ba-text-2xs text-primary hover:bg-primary/20"
              >
                <Search className="h-3 w-3" /> Look up
              </button>
              {lookupResult && (
                <button
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(lookupResult, null, 2)], { type: "application/json" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a"); a.href = url; a.download = `detection-lookup-${lookupResult.technique?.id || "unknown"}-${Date.now()}.json`; a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="inline-flex h-8 items-center gap-1.5 rounded border border-border px-2.5 text-mono ba-text-2xs text-muted-foreground hover:text-foreground"
                >
                  <Download className="h-3 w-3" /> Export
                </button>
              )}
            </div>

            {lookupResult && !lookupResult.found && (
              <div className="rounded border border-warning/40 bg-warning/10 px-3 py-2.5">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-warning" />
                  <span className="text-mono ba-text-2xs text-warning">
                    No match for <strong>{lookupResult.query}</strong>. Check the technique ID and try again.
                  </span>
                </div>
              </div>
            )}

            {lookupResult && lookupResult.found && (
              <div className="space-y-3">
                <div className="rounded border border-subtle bg-surface-1 px-3 py-2.5">
                  <div className="text-mono ba-text-2xs text-muted-foreground">Technique</div>
                  <div className="mt-0.5 flex items-baseline gap-2">
                    <span className="text-base text-foreground">{lookupResult.technique!.id}</span>
                    <span className="text-sm text-fg-dim">— {lookupResult.technique!.name}</span>
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    <Chip tone="info">{lookupResult.technique!.tactic}</Chip>
                    {lookupResult.technique!.detectionCount > 0 ? (
                      <Chip tone="success">{lookupResult.technique!.detectionCount} detection{lookupResult.technique!.detectionCount !== 1 ? "s" : ""}</Chip>
                    ) : (
                      <Chip tone="destructive">No detection rules</Chip>
                    )}
                  </div>
                </div>

                {lookupResult.detections.length === 0 ? (
                  <div className="rounded border border-warning/40 bg-warning/10 px-3 py-2.5 text-mono ba-text-2xs text-warning/90">
                    No rules in your local detection library cover this technique — a coverage gap. Create one in the Detection Editor.
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    {lookupResult.detections.map((d, i) => {
                      const stateTone: Record<string, "default" | "primary" | "warning" | "success" | "destructive" | "info"> = {
                        draft: "default", validated: "info", approved: "primary", deployed: "success", retired: "destructive",
                      };
                      return (
                        <div key={i} className="flex items-center justify-between rounded border border-subtle bg-surface-1 px-3 py-2">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="truncate ba-text-xs text-foreground">{d.name}</span>
                            <Chip tone="default">{d.format}</Chip>
                          </div>
                          <div className="flex items-center gap-1.5 shrink-0">
                            <Chip tone={stateTone[d.state] || "default"}>{d.state}</Chip>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {!lookupResult && (
              <div className="rounded border border-subtle bg-surface-1 px-3 py-4 text-center text-mono ba-text-2xs text-muted-foreground">
                Enter a technique ID to see which rules in your local detection library target it.
              </div>
            )}
          </div>
        </Panel>
      </div>

      <div className="mb-3 max-w-full min-w-0">
        <Panel title="Kill-chain coverage" icon={Target} meta="click a tactic bar for details" bodyClassName="!p-0" className="min-w-0 max-w-full overflow-hidden">
          <div className="flex items-stretch gap-1 overflow-x-auto p-3 pt-0 max-w-full">
            {TACTICS.map((t) => {
              const c = tacticPct(t);
              return (
                <div key={t.id} className="min-w-[96px] flex-1">
                  <div className="mb-1 flex items-center justify-between">
                    <span className="text-mono ba-text-3xs text-muted-foreground">{t.name}</span>
                    <span className="text-mono ba-text-3xs text-fg-dim">{Math.round(c * 100)}%</span>
                  </div>
                  <div className="h-2.5 overflow-hidden rounded-sm bg-border/40">
                    <div className={"h-full " + (c >= 0.7 ? "bg-success" : c >= 0.34 ? "bg-warning" : "bg-destructive/70")} style={{ width: `${c * 100}%` }} />
                  </div>
                  <div className="mt-1 text-mono ba-text-3xs text-muted-foreground">{t.id}</div>
                </div>
              );
            })}
          </div>
        </Panel>
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-2">
        {(["matrix", "gaps", "notes"] as const).map((t) => (
          <button key={t} onClick={() => { setTab(t); setSearch(""); }}
            className={"rounded border px-2.5 py-1 text-mono ba-text-2xs" + (tab === t ? "border-primary bg-primary/15 text-primary" : "border-border text-muted-foreground hover:text-foreground")}>
            {t} {t === "gaps" ? `(${gaps.length})` : t === "notes" ? `(${Object.keys(notes).length})` : ""}
          </button>
        ))}
        <div className="ml-auto flex flex-wrap items-center gap-1">
          {tab !== "matrix" && (
            <div className="relative">
              <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
              <input
                value={search} onChange={e => setSearch(e.target.value)}
                placeholder="filter…"
                className="h-7 w-40 rounded border border-border bg-surface-0 pl-6 pr-2 text-mono ba-text-2xs text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50"
              />
            </div>
          )}
          <button onClick={resetAll} className="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-foreground transition-colors duration-150">
            <RotateCcw className="h-3 w-3" /> reset
          </button>
        </div>
      </div>

      {tab === "matrix" && (
        <>
          <SectionBar id="MX" label="Coverage matrix" meta={`filter: ${filter}`}
            action={
              <div className="flex flex-wrap items-center gap-1">
                <div className="relative">
                  <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
                  <input value={matrixSearch} onChange={e => setMatrixSearch(e.target.value)} aria-label="Search MITRE matrix" placeholder="search…" className="h-7 w-32 rounded border border-border bg-surface-0 pl-6 pr-2 text-mono ba-text-2xs text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50" />
                </div>
                {(["all", "full", "partial", "none"] as const).map((f) => (
                  <button key={f} onClick={() => setFilter(f)} className={"rounded border px-1.5 py-0.5 text-mono ba-text-2xs" + (filter === f ? "border-primary bg-primary/15 text-primary" : "border-border text-muted-foreground hover:text-foreground")}>{f}</button>
                ))}
                <button onClick={() => { const json = genCovExport(cov, notes, TACTICS); const blob = new Blob([json], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `mitre-coverage-${Date.now()}.json`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-mono ba-text-2xs text-primary hover:bg-primary/20"><Download className="h-3 w-3" />export</button>
              </div>
            }
          />
          {actorQueryMatch && (
            <div className="mb-2 flex items-center justify-between gap-2 rounded border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-mono ba-text-xs">
              <div className="flex items-center gap-2">
                <Users className="h-4 w-4 text-amber-400" />
                <span className="text-foreground">
                  Adversary Profiling: <strong className="text-amber-300">{actorQueryMatch.title}</strong>
                </span>
                <span className="text-muted-foreground">({actorQueryMatch.techniques.length} techniques cataloged)</span>
              </div>
              <button
                onClick={() => setMatrixSearch("")}
                className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" /> Clear filter
              </button>
            </div>
          )}
          <div className="rounded-xl border border-border/70 bg-surface-0/60 p-3 shadow-xs">
            <div className="flex flex-wrap items-center justify-between gap-2 pb-3 mb-2 border-b border-subtle">
              <div className="flex flex-wrap items-center gap-2 sm:gap-3">
                <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  <Target className="h-3.5 w-3.5 text-primary" />
                  <span>Enterprise Kill-Chain (14 Tactics)</span>
                </div>
                <span className="hidden sm:inline text-border">|</span>
                <div className="flex items-center gap-2 text-mono ba-text-3xs text-muted-foreground">
                  <span className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-emerald-500" /> Full</span>
                  <span className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-amber-500" /> Partial</span>
                  <span className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-border" /> Unrated</span>
                </div>
              </div>
              <div className="text-mono ba-text-3xs text-muted-foreground">
                Scroll horizontally · Click card to cycle coverage
              </div>
            </div>

            <div className="overflow-x-auto pb-3 pt-1">
              <div className="flex gap-3 min-w-max">
                {TACTICS.map((t, idx) => {
                  const q = matrixSearch.trim().toLowerCase();
                  const isActorMatch = !!actorQueryMatch;
                  const ts = t.techniques.filter((x) => {
                    const c = getTechCov(t.id, x.id);
                    if (filter !== "all" && c !== filter) return false;
                    if (isActorMatch) return actorQueryMatch.techniques.includes(x.id);
                    if (platform !== "all") {
                      const enr = getTechniqueEnrichment(x.id);
                      if (!enr.platforms.includes(platform) && !enr.platforms.includes("Multi")) return false;
                    }
                    if (q && !x.id.toLowerCase().includes(q) && !x.name.toLowerCase().includes(q)) return false;
                    return true;
                  });
                  const c = tacticPct(t);
                  const heatPct = Math.round(c * 100);

                  return (
                    <div key={t.id} className="w-[230px] shrink-0 flex flex-col rounded-lg border border-subtle bg-surface-1/40 shadow-2xs">
                      {/* Column Header */}
                      <div className="rounded-t-lg border-b border-subtle bg-surface-1/90 p-2.5 backdrop-blur-xs">
                        <div className="flex items-center justify-between gap-1 text-mono ba-text-3xs text-muted-foreground">
                          <span className="font-semibold text-primary">{idx + 1}. {t.id}</span>
                          <span className="rounded bg-surface-2 px-1.5 py-0.5">{ts.length} tech</span>
                        </div>
                        <div className="mt-1 font-semibold ba-text-xs text-foreground truncate" title={t.name}>
                          {t.name}
                        </div>
                        <div className="mt-2 flex items-center gap-2">
                          <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-2">
                            <div
                              className={"h-full transition-all duration-300 " + (c >= 0.7 ? "bg-emerald-500" : c >= 0.3 ? "bg-amber-500" : c > 0 ? "bg-primary/80" : "bg-transparent")}
                              style={{ width: `${Math.max(c * 100, 0)}%` }}
                            />
                          </div>
                          <span className="text-mono ba-text-3xs font-medium text-muted-foreground">{heatPct}%</span>
                        </div>
                      </div>

                      {/* Technique Cards List */}
                      <div className="flex-1 p-2 space-y-1.5 max-h-[580px] overflow-y-auto">
                        {ts.length === 0 ? (
                          <div className="py-6 text-center text-mono ba-text-3xs text-muted-foreground">No matching techniques</div>
                        ) : (
                          ts.map((x) => {
                            const currentCov = getTechCov(t.id, x.id);
                            const isSel = selected?.tech.id === x.id;
                            const ruleCount = rulesByTech.get(x.id) || 0;
                            const hasNote = Boolean(notes[x.id]);

                            return (
                              <div
                                key={x.id}
                                onClick={() => {
                                  cycleCov(t.id, x.id);
                                  setSelected({ tactic: t, tech: x, cov: currentCov });
                                }}
                                onContextMenu={(e) => {
                                  e.preventDefault();
                                  setSelected({ tactic: t, tech: x, cov: currentCov });
                                  setDrawerTech({ id: x.id, name: x.name, tactic: t.name, tacticId: t.id });
                                }}
                                className={cn(
                                  "group relative flex flex-col justify-between rounded-md border p-2 text-left transition-all cursor-pointer select-none",
                                  currentCov === "full" && "border-emerald-500/40 border-l-4 border-l-emerald-500 bg-emerald-500/10 text-foreground hover:bg-emerald-500/15",
                                  currentCov === "partial" && "border-amber-500/40 border-l-4 border-l-amber-500 bg-amber-500/10 text-foreground hover:bg-amber-500/15",
                                  currentCov === "none" && "border-subtle border-l-2 border-l-muted-foreground/30 bg-surface-0/80 hover:bg-surface-2 text-muted-foreground hover:text-foreground",
                                  isSel && "ring-2 ring-primary shadow-xs"
                                )}
                                title={`${x.id}: ${x.name}\nCoverage: ${currentCov}\nClick: toggle coverage\nRight-click: inspect`}
                              >
                                <div className="flex items-center justify-between gap-1 mb-1">
                                  <span className="text-mono ba-text-2xs font-bold tracking-tight text-foreground">
                                    {x.id}
                                  </span>
                                  <div className="flex items-center gap-1">
                                    {ruleCount > 0 && (
                                      <span className="inline-flex items-center gap-0.5 rounded bg-primary/20 px-1 py-0.2 text-mono ba-text-3xs text-primary font-medium" title={`${ruleCount} local detection rules`}>
                                        <ShieldAlert className="h-2.5 w-2.5" />
                                        {ruleCount}
                                      </span>
                                    )}
                                    {hasNote && (
                                      <StickyNote className="h-3 w-3 text-amber-400" />
                                    )}
                                    <span className={cn(
                                      "inline-block h-2 w-2 rounded-full",
                                      currentCov === "full" ? "bg-emerald-500" : currentCov === "partial" ? "bg-amber-500" : "bg-border/60"
                                    )} />
                                  </div>
                                </div>

                                <div className="ba-text-2xs font-medium leading-snug line-clamp-2 text-foreground">
                                  {x.name}
                                </div>

                                <div className="mt-2 flex items-center justify-between pt-1 border-t border-subtle/50 opacity-80 group-hover:opacity-100 transition-opacity">
                                  <span className="text-mono ba-text-3xs uppercase tracking-wider text-muted-foreground">
                                    {currentCov}
                                  </span>
                                  <button
                                    type="button"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setSelected({ tactic: t, tech: x, cov: currentCov });
                                      setDrawerTech({ id: x.id, name: x.name, tactic: t.name, tacticId: t.id });
                                    }}
                                    className="text-mono ba-text-3xs text-primary hover:underline hover:text-primary/90 flex items-center gap-0.5"
                                  >
                                    inspect
                                  </button>
                                </div>
                              </div>
                            );
                          })
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          <Panel title="Technique detail" icon={Target}>
            {!selected ? (
              <p className="text-mono ba-text-sm text-muted-foreground">Click any technique cell to cycle through coverage states (none → partial → full) or right-click to inspect.</p>
            ) : (
              <div className="grid gap-3 grid-cols-[1fr_auto]">
                <div>
                  <div className="text-mono ba-text-2xs text-muted-foreground">{selected.tactic.name} · {selected.tactic.id}</div>
                  <div className="mt-0.5 text-lg text-foreground">{selected.tech.id} <span className="text-fg-dim">— {selected.tech.name}</span></div>
                  <div className="mt-2 flex items-center gap-2">
                    <Chip tone={tone[selected.cov]}>{selected.cov}</Chip>
                    <span className="text-mono ba-text-2xs text-muted-foreground">click to toggle</span>
                  </div>
                  {notes[selected.tech.id] && (
                    <div className="mt-2 rounded border border-subtle bg-surface-1 p-2 text-mono ba-text-sm text-fg-dim">
                      <span className="ba-text-2xs text-muted-foreground">note</span>
                      <p className="mt-1">{notes[selected.tech.id]}</p>
                    </div>
                  )}
                </div>
                <div className="flex items-start gap-2">
                  {noteTech !== selected.tech.id ? (
                    <button onClick={() => { setNoteTech(selected.tech.id); setNoteDraft(notes[selected.tech.id] || ""); }}
                      className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground">
                      <StickyNote className="h-3 w-3" /> {notes[selected.tech.id] ? "edit note" : "add note"}
                    </button>
                  ) : (
                    <div className="flex items-center gap-1">
                      <input
                        autoFocus
                        value={noteDraft}
                        onChange={e => setNoteDraft(e.target.value)}
                        onKeyDown={e => { if (e.key === "Enter") saveNote(selected.tech.id); if (e.key === "Escape") { setNoteTech(null); setNoteDraft(""); } }}
                        placeholder="note…"
                        className="w-36 rounded border border-border bg-surface-0 px-1.5 py-1 text-mono ba-text-2xs text-foreground outline-none focus:border-primary/50"
                      />
                      <button onClick={() => saveNote(selected.tech.id)} className="rounded border border-success/50 bg-success/10 px-1.5 py-1 text-mono ba-text-2xs text-success">ok</button>
                    </div>
                  )}
                  <button onClick={() => { sendArtifact({ kind: "raw", value: `${selected.tech.id} — ${selected.tech.name}`, source: "/mitre" }); navigate({ to: "/detection" }); }} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-1 text-mono ba-text-sm text-primary hover:bg-primary/20">
                    <ShieldAlert className="h-3 w-3" /> send to detection
                  </button>
                </div>
              </div>
            )}
          </Panel>
        </>
      )}

      {tab === "gaps" && (
        <>
          <SectionBar id="GP" label={`Gaps · ${gaps.length} uncovered`} meta="techniques with no coverage" />
          {filteredGaps.length === 0 ? (
            <div className="rounded border border-subtle bg-surface-1 p-6 text-center text-mono ba-text-sm text-muted-foreground">No uncovered techniques match the filter.</div>
          ) : (
            <div className="grid gap-2 grid-cols-4">
              {filteredGaps.map((g) => (
                <div key={g.id} className="rounded border border-subtle bg-surface-1 px-3 py-2">
                  <div className="flex items-center justify-between">
                    <Chip tone="default">{g.id}</Chip>
                    <span className="text-mono ba-text-3xs text-muted-foreground">{g.tactic}</span>
                  </div>
                  <div className="mt-1 ba-text-xs text-fg-dim">{g.name}</div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {tab === "notes" && (
        <>
          <SectionBar id="NT" label={`Notes · ${Object.keys(notes).length}`} meta="per-technique observations" />
          {Object.keys(notes).length === 0 ? (
            <div className="rounded border border-subtle bg-surface-1 p-6 text-center text-mono ba-text-sm text-muted-foreground">No notes yet. Click a technique in the matrix and add a note.</div>
          ) : (
            <div className="grid gap-2 grid-cols-3">
              {Object.entries(notes).map(([techId, noteText]) => {
                const t = allTechniques.find(x => x.id === techId);
                return (
                  <div key={techId} className="rounded border border-subtle bg-surface-1 px-3 py-2">
                    <div className="flex items-center justify-between">
                      <Chip tone="warning">{techId}</Chip>
                      {t && <span className="text-mono ba-text-3xs text-muted-foreground">{t.tactic}</span>}
                    </div>
                    {t && <div className="mt-0.5 ba-text-2xs text-fg-dim">{t.name}</div>}
                    <p className="mt-1.5 ba-text-2xs text-foreground">{noteText}</p>
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}

      
      <TechniqueDetailDrawer
        technique={drawerTech}
        coverage={drawerTech ? (cov[techKey(drawerTech.tacticId, drawerTech.id)] || "none") : "none"}
        onCoverageChange={(newCov) => {
          if (drawerTech) {
            setCov((prev) => {
              const next = { ...prev, [techKey(drawerTech.tacticId, drawerTech.id)]: newCov };
              saveCov(next);
              return next;
            });
          }
        }}
        note={drawerTech ? (notes[drawerTech.id] || "") : ""}
        onSaveNote={(newNote) => {
          if (drawerTech) {
            setNotes((prev) => {
              const next = { ...prev, [drawerTech.id]: newNote };
              saveNotes(next);
              return next;
            });
          }
        }}
        onClose={() => setDrawerTech(null)}
        onSendToDetection={(techId, techName) => {
          sendArtifact({ kind: "raw", value: `${techId} — ${techName}`, source: "/mitre" });
          navigate({ to: "/detection" });
        }}
        onSendToCase={(techId, techName) => {
          sendToCase({
            kind: "finding",
            source: "/mitre",
            body: `MITRE ATT&CK Observation: ${techId} (${techName})`,
          });
          notify.success(`Added ${techId} finding to active case`);
        }}
        localRulesCount={drawerTech ? localRules.filter((r) => ruleTechniques(r).includes(drawerTech.id)).length : 0}
      />
      </>
      )}

      <SendToRow targets={[
        { label: "Detection Editor", to: "/detection", icon: ShieldAlert },
        { label: "SIEM Workspace",   to: "/siem",      icon: ArrowRight },
        { label: "Case Notebook",    to: "/case",      icon: Database },
      ]} />
    </PageShell>
    </ErrorBoundary>
  );
}
