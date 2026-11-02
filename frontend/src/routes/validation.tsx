import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMemo, useState, useCallback, useEffect } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, SectionBar, Chip } from "@/components/soc";
import { VerdictBanner, MetricGrid, Empty } from "@/components/output";
import { BENCHMARK_SAMPLES, BENCHMARK_VERSION, BENCHMARK_GENERATED, BENCHMARK_TARGET,
  createEmptyRecord, STORAGE_KEY,
  type BenchmarkSample, type InvestigationRecord, type BenchmarkStatus,
  type Verdict, type Difficulty } from "@/data/benchmark";
import { Search, CircleCheck as CheckCircle2, Circle,
  Clock, Activity, Star, Download, Trash2, FlaskConical, ChevronRight, AlertTriangle, ExternalLink,
  BarChart3, ListChecks, Target, Filter, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { ErrorBoundary } from "@/components/ErrorBoundary";

export const Route = createFileRoute("/validation")({ component: ValidationPage });

const STORAGE_KEY_SESSION = "ba.benchmark.session.v1";

interface SessionState {
  startTime: number;
  currentId: string | null;
}

function loadRecords(): Record<string, InvestigationRecord> {
  try { const raw = localStorage.getItem(STORAGE_KEY); if (!raw) return {}; return JSON.parse(raw); } catch { return {}; }
}

function saveRecords(r: Record<string, InvestigationRecord>) { localStorage.setItem(STORAGE_KEY, JSON.stringify(r)); }

function loadSession(): SessionState | null {
  try { const raw = localStorage.getItem(STORAGE_KEY_SESSION); if (!raw) return null; return JSON.parse(raw); } catch { return null; }
}

function saveSession(s: SessionState) { localStorage.setItem(STORAGE_KEY_SESSION, JSON.stringify(s)); }

const DIFFICULTY_COLOR: Record<Difficulty, "default" | "warning" | "destructive"> = { Easy: "default", Medium: "warning", Hard: "destructive" };
const VERDICT_COLOR: Record<Verdict, "default" | "warning" | "destructive" | "success"> = { Malicious: "destructive", Suspicious: "warning", Benign: "success", Unknown: "default" };

function VerdictBadge({ verdict }: { verdict: Verdict }) { return <Chip tone={VERDICT_COLOR[verdict]}>{verdict}</Chip>; }

const INPUT = "w-full rounded border border-divider-strong bg-surface-0 px-2 py-1.5 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/50";
const RATER = "h-7 w-7 rounded border text-mono text-xs transition-colors duration-150";

function RatingGroup({ value, onChange, label }: { value: number; onChange: (v: number) => void; label: string }) {
  return (
    <div>
      <span className="text-mono ba-text-2xs text-muted-foreground">{label}</span>
      <div className="mt-1 flex items-center gap-1">
        {[1, 2, 3, 4, 5].map((n) => (
          <button key={n} onClick={() => onChange(n)} className={cn(RATER, value >= n ? "border-primary bg-primary/15 text-primary" : "border-divider-strong text-muted-foreground hover:text-foreground")}>{n}</button>
        ))}
      </div>
    </div>
  );
}

function FeedbackList({ items, onAdd, onRemove, placeholder, label }: {
  items: string[]; onAdd: (v: string) => void; onRemove: (i: number) => void; placeholder: string; label: string;
}) {
  const [val, setVal] = useState("");
  return (
    <div>
      <div className="flex items-center justify-between">
        <span className="text-mono ba-text-2xs text-muted-foreground">{label}</span>
        <span className="text-mono ba-text-3xs text-muted-foreground">{items.length}</span>
      </div>
      <div className="mt-1 flex gap-1">
        <input value={val} onChange={(e) => setVal(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); if (val.trim()) { onAdd(val.trim()); setVal(""); } } }} placeholder={placeholder} className={INPUT} />
        <button onClick={() => { if (val.trim()) { onAdd(val.trim()); setVal(""); } }} className="shrink-0 rounded border border-primary/30 bg-primary/10 px-2 text-mono ba-text-2xs text-primary hover:bg-primary/20">+</button>
      </div>
      {items.length > 0 && (
        <ul className="mt-1 space-y-0.5">
          {items.map((item, i) => (
            <li key={i} className="group flex items-center gap-2 rounded border border-divider-strong bg-surface-1 px-2 py-1 text-mono ba-text-sm text-fg-dim">
              <span className="flex-1">{item}</span>
              <button onClick={() => onRemove(i)} className="text-muted-foreground hover:text-destructive"><Trash2 className="h-3 w-3" /></button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function InvestigationForm({ sample, record, onChange }: {
  sample: BenchmarkSample; record: InvestigationRecord; onChange: (r: InvestigationRecord) => void;
}) {
  const set = <K extends keyof InvestigationRecord>(k: K, v: InvestigationRecord[K]) => onChange({ ...record, [k]: v });

  return (
    <div className="space-y-4">
      {/* Ground truth reference — compact, in sample header */}
      <div className="rounded border border-divider-strong bg-surface-1 p-3">
        <div className="flex items-center gap-3">
          <span className="text-mono ba-text-2xs text-muted-foreground">Expected</span>
          <VerdictBadge verdict={sample.expectedVerdict} />
          <span className="text-mono ba-text-2xs text-muted-foreground">Confidence: {sample.expectedConfidence}</span>
        </div>
        <div className="mt-2 grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <span className="text-mono ba-text-3xs text-muted-foreground">Findings ({sample.expectedFindings.length})</span>
            <ul className="mt-0.5 space-y-0.5">
              {sample.expectedFindings.map((f, i) => (
                <li key={i} className="flex items-start gap-1.5 text-mono ba-text-2xs text-fg-dim">
                  <span className="mt-0.5 text-primary">•</span>
                  <span>{f.label}{f.technique ? <span className="text-muted-foreground"> ({f.technique})</span> : null}</span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <span className="text-mono ba-text-3xs text-muted-foreground">IOCs ({sample.expectedIocs.length})</span>
            <div className="mt-0.5 flex flex-wrap gap-1">
              {sample.expectedIocs.length > 0 ? sample.expectedIocs.map((ioc, i) => <Chip key={i}>{ioc}</Chip>) : <span className="text-mono ba-text-2xs text-fg-dim">none</span>}
            </div>
          </div>
          <div>
            <span className="text-mono ba-text-3xs text-muted-foreground">MITRE ({sample.expectedMitre.length})</span>
            <div className="mt-0.5 flex flex-wrap gap-1">
              {sample.expectedMitre.length > 0 ? sample.expectedMitre.map((m, i) => (
                <Link key={i} to="/mitre" className="inline-flex items-center gap-1 rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-mono ba-text-3xs text-primary hover:bg-primary/20">{m} <ExternalLink className="h-2.5 w-2.5" /></Link>
              )) : <span className="text-mono ba-text-2xs text-fg-dim">none</span>}
            </div>
          </div>
        </div>
      </div>

      {/* Verdict + Coverage — side by side */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="rounded border border-divider-strong bg-surface-1 p-3">
          <span className="text-mono ba-text-2xs text-muted-foreground">Verdict correct?</span>
          <div className="mt-2 flex items-center gap-2">
            <label className="flex items-center gap-1.5 text-mono ba-text-sm cursor-pointer">
              <input type="checkbox" checked={record.correctVerdict === true} onChange={(e) => set("correctVerdict", e.target.checked ? true : undefined)} className="accent-primary h-3.5 w-3.5" />
              Matches ground truth
            </label>
          </div>
        </div>
        <div className="rounded border border-divider-strong bg-surface-1 p-3">
          <span className="text-mono ba-text-2xs text-muted-foreground">Trust result without double-checking?</span>
          <div className="mt-1 flex items-center gap-1">
            {[1, 2, 3, 4, 5].map((n) => (
              <button key={n} onClick={() => set("trustResult", n)} className={cn(RATER, (record.trustResult ?? 0) >= n ? "border-primary bg-primary/15 text-primary" : "border-divider-strong text-muted-foreground hover:text-foreground")}>{n}</button>
            ))}
            <span className="ml-2 text-mono ba-text-2xs text-muted-foreground">
              {record.trustResult ? (record.trustResult >= 4 ? "Trust it" : record.trustResult >= 2 ? "Would verify key points" : "Would not trust") : ""}
            </span>
          </div>
        </div>
      </div>

      {/* Coverage — compact row */}
      <div className="rounded border border-divider-strong bg-surface-1 p-3">
        <span className="text-mono ba-text-2xs text-muted-foreground">Coverage vs expected</span>
        <div className="mt-2 grid grid-cols-1 sm:grid-cols-3 gap-3">
          {[
            { label: "Findings found", key: "findingsFound" as const, max: sample.expectedFindings.length },
            { label: "IOCs found", key: "iocsFound" as const, max: sample.expectedIocs.length },
            { label: "MITRE mapped", key: "mitreFound" as const, max: sample.expectedMitre.length },
          ].map(({ label, key, max }) => (
            <div key={key} className="flex items-center gap-2">
              <span className="text-mono ba-text-2xs text-muted-foreground">{label}</span>
              <input type="number" min={0} max={max} value={record[key] ?? ""} onChange={(e) => set(key, e.target.value ? Math.min(max, Math.max(0, e.target.valueAsNumber)) : undefined)} className="w-16 rounded border border-divider-strong bg-surface-0 px-2 py-1 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50 text-center" />
              <span className="text-mono ba-text-2xs text-muted-foreground">/ {max}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Workflow — compact row */}
      <div className="rounded border border-divider-strong bg-surface-1 p-3">
        <span className="text-mono ba-text-2xs text-muted-foreground">Workflow</span>
        <div className="mt-2 grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div>
            <span className="text-mono ba-text-3xs text-muted-foreground">Duration (min)</span>
            <input type="number" min={0} value={record.duration ?? ""} onChange={(e) => set("duration", e.target.valueAsNumber || undefined)} className="mt-1 w-full rounded border border-divider-strong bg-surface-0 px-2 py-1.5 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50" />
          </div>
          <div>
            <span className="text-mono ba-text-3xs text-muted-foreground">Searches</span>
            <input type="number" min={0} value={record.searches} onChange={(e) => set("searches", Math.max(0, e.target.valueAsNumber || 0))} className="mt-1 w-full rounded border border-divider-strong bg-surface-0 px-2 py-1.5 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50" />
          </div>
          <div>
            <span className="text-mono ba-text-3xs text-muted-foreground">Context switches</span>
            <input type="number" min={0} value={record.contextSwitches} onChange={(e) => set("contextSwitches", Math.max(0, e.target.valueAsNumber || 0))} className="mt-1 w-full rounded border border-divider-strong bg-surface-0 px-2 py-1.5 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50" />
          </div>
          <div>
            <span className="text-mono ba-text-3xs text-muted-foreground">Report</span>
            <label className="mt-2 flex items-center gap-1.5 text-mono ba-text-sm cursor-pointer">
              <input type="checkbox" checked={record.reportGenerated} onChange={(e) => set("reportGenerated", e.target.checked)} className="accent-primary h-3.5 w-3.5" />
              Generated
            </label>
          </div>
        </div>
      </div>

      {/* Ratings */}
      <div className="rounded border border-divider-strong bg-surface-1 p-3">
        <span className="text-mono ba-text-2xs text-muted-foreground">Ratings</span>
        <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-3">
          <RatingGroup label="Workflow clarity" value={record.workflowClarity} onChange={(v) => set("workflowClarity", v)} />
          <RatingGroup label="Navigation" value={record.navigation} onChange={(v) => set("navigation", v)} />
          <RatingGroup label="Search usefulness" value={record.searchUsefulness} onChange={(v) => set("searchUsefulness", v)} />
          <RatingGroup label="Overall" value={record.overall} onChange={(v) => set("overall", v)} />
        </div>
      </div>

      {/* Feedback */}
      <div className="rounded border border-divider-strong bg-surface-1 p-3">
        <span className="text-mono ba-text-2xs text-muted-foreground">Feedback</span>
        <div className="mt-2 space-y-3">
          <FeedbackList label="Bugs" items={record.bugs} onAdd={(v) => set("bugs", [...record.bugs, v])} onRemove={(i) => set("bugs", record.bugs.filter((_, idx) => idx !== i))} placeholder="Describe a bug…" />
          <FeedbackList label="Friction" items={record.friction} onAdd={(v) => set("friction", [...record.friction, v])} onRemove={(i) => set("friction", record.friction.filter((_, idx) => idx !== i))} placeholder="What was awkward or slow?" />
          <FeedbackList label="Missing features" items={record.missingFeatures} onAdd={(v) => set("missingFeatures", [...record.missingFeatures, v])} onRemove={(i) => set("missingFeatures", record.missingFeatures.filter((_, idx) => idx !== i))} placeholder="What should exist but doesn't?" />
          <FeedbackList label="Wishes" items={record.wishes} onAdd={(v) => set("wishes", [...record.wishes, v])} onRemove={(i) => set("wishes", record.wishes.filter((_, idx) => idx !== i))} placeholder="What would make this better?" />
        </div>
      </div>

      {/* Notes */}
      <div className="rounded border border-divider-strong bg-surface-1 p-3">
        <span className="text-mono ba-text-2xs text-muted-foreground">Notes</span>
        <textarea value={record.notes} onChange={(e) => set("notes", e.target.value)} placeholder="Investigation notes, observations, thoughts…" rows={3} className="mt-2 w-full rounded border border-divider-strong bg-surface-0 p-2 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50 resize-none" />
      </div>
    </div>
  );
}

function sampleOf(id: string): BenchmarkSample | undefined { return BENCHMARK_SAMPLES.find((s) => s.id === id); }

function AnalyticsDashboard({ records }: { records: Record<string, InvestigationRecord> }) {
  const entries = Object.values(records).filter((r) => r.status === "completed");
  if (entries.length === 0) return null;

  const avgDuration = entries.reduce((s, r) => s + (r.duration ?? 0), 0) / entries.length;
  const avgSearches = entries.reduce((s, r) => s + r.searches, 0) / entries.length;
  const avgSwitches = entries.reduce((s, r) => s + r.contextSwitches, 0) / entries.length;
  const correctVerdicts = entries.filter((r) => r.correctVerdict === true).length;
  const reportsGenerated = entries.filter((r) => r.reportGenerated).length;

  const withTrust = entries.filter((r) => r.trustResult !== undefined);
  const avgTrust = withTrust.length > 0 ? withTrust.reduce((s, r) => s + (r.trustResult ?? 0), 0) / withTrust.length : 0;

  const findingsWithData = entries.filter((r) => r.findingsFound !== undefined && sampleOf(r.sampleId));
  const avgFindingsAcc = findingsWithData.length > 0
    ? findingsWithData.reduce((s, r) => s + (r.findingsFound! / sampleOf(r.sampleId)!.expectedFindings.length), 0) / findingsWithData.length * 100
    : undefined;
  const iocsWithData = entries.filter((r) => r.iocsFound !== undefined && sampleOf(r.sampleId));
  const avgIocsAcc = iocsWithData.length > 0
    ? iocsWithData.reduce((s, r) => {
        const exp = sampleOf(r.sampleId)!.expectedIocs.length;
        return s + (exp > 0 ? r.iocsFound! / exp : 1);
      }, 0) / iocsWithData.length * 100
    : undefined;

  const allFriction = entries.flatMap((r) => r.friction);
  const frictionCounts: Record<string, number> = {};
  allFriction.forEach((f) => { frictionCounts[f] = (frictionCounts[f] ?? 0) + 1; });
  const topFriction = Object.entries(frictionCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);

  const allWishes = entries.flatMap((r) => r.wishes);
  const wishCounts: Record<string, number> = {};
  allWishes.forEach((w) => { wishCounts[w] = (wishCounts[w] ?? 0) + 1; });
  const topWishes = Object.entries(wishCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);

  return (
    <div className="space-y-4">
      <SectionBar id="ANALYTICS" label="Campaign analytics" meta={`${entries.length} completed`} />
      <MetricGrid columns={4} metrics={[
        { label: "Completed", value: entries.length, tone: "primary", icon: CheckCircle2 },
        { label: "Avg duration", value: `${avgDuration.toFixed(1)}m`, tone: "default", icon: Clock },
        { label: "Searches/inv", value: avgSearches.toFixed(1), tone: "default", icon: Search },
        { label: "Context switches", value: avgSwitches.toFixed(1), tone: "default", icon: Activity },
      ]} />
      <MetricGrid columns={4} metrics={[
        { label: "Correct verdicts", value: `${Math.round((correctVerdicts / entries.length) * 100)}%`, tone: correctVerdicts / entries.length > 0.7 ? "success" : "warning", icon: CheckCircle2 },
        { label: "Avg trust score", value: avgTrust > 0 ? `${avgTrust.toFixed(1)}/5` : "—", tone: avgTrust >= 4 ? "success" : "muted" as const, icon: ShieldCheck },
        { label: "Findings coverage", value: avgFindingsAcc !== undefined ? `~${Math.round(avgFindingsAcc)}%` : "—", tone: "default", icon: Target },
        { label: "IOC coverage", value: avgIocsAcc !== undefined ? `~${Math.round(avgIocsAcc)}%` : "—", tone: "default", icon: Target },
      ]} />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Panel title="Top friction" icon={AlertTriangle} priority="secondary">{
          topFriction.length > 0
            ? <ul className="space-y-1">{topFriction.map(([f, c]) => <li key={f} className="flex items-start gap-2 text-mono ba-text-sm"><span className="mt-0.5 text-destructive">•</span><span className="flex-1 text-fg-dim">{f}</span><Chip tone="warning">{c}</Chip></li>)}</ul>
            : <p className="text-mono ba-text-sm text-muted-foreground">None recorded</p>
        }</Panel>
        <Panel title="Top wishes" icon={Star} priority="secondary">{
          topWishes.length > 0
            ? <ul className="space-y-1">{topWishes.map(([w, c]) => <li key={w} className="flex items-center justify-between text-mono ba-text-sm"><span className="text-fg-dim">{w}</span><Chip>{c}</Chip></li>)}</ul>
            : <p className="text-mono ba-text-sm text-muted-foreground">None recorded</p>
        }</Panel>
        <Panel title="Accuracy vs coverage" icon={Target} priority="secondary">
          <div className="space-y-1.5 text-mono ba-text-sm">
            <div className="flex items-center justify-between"><span className="text-fg-dim">Verdicts correct</span><span className="tabular-nums">{Math.round((correctVerdicts / entries.length) * 100)}%</span></div>
            <div className="flex items-center justify-between"><span className="text-fg-dim">Findings coverage</span><span className="tabular-nums">{avgFindingsAcc !== undefined ? `${Math.round(avgFindingsAcc)}%` : "—"}</span></div>
            <div className="flex items-center justify-between"><span className="text-fg-dim">IOC coverage</span><span className="tabular-nums">{avgIocsAcc !== undefined ? `${Math.round(avgIocsAcc)}%` : "—"}</span></div>
            <div className="flex items-center justify-between"><span className="text-fg-dim">Reports generated</span><span className="tabular-nums">{Math.round((reportsGenerated / entries.length) * 100)}%</span></div>
          </div>
        </Panel>
      </div>
    </div>
  );
}

function ValidationPage() {
  const navigate = useNavigate();
  useEffect(() => {
    navigate({ to: "/", replace: true });
  }, [navigate]);
  const [records, setRecords] = useState<Record<string, InvestigationRecord>>(loadRecords);
  const [session, setSession] = useState<SessionState | null>(loadSession);
  const [selectedId, setSelectedId] = useState<string | null>(session?.currentId ?? null);
  const [filterCat, setFilterCat] = useState<string>("ALL");
  const [filterStatus, setFilterStatus] = useState<BenchmarkStatus | "ALL">("ALL");
  const [query, setQuery] = useState("");
  const [showAnalytics, setShowAnalytics] = useState(false);

  const persist = useCallback((r: Record<string, InvestigationRecord>) => { setRecords(r); saveRecords(r); }, []);

  const filteredSamples = useMemo(() => BENCHMARK_SAMPLES.filter((s) => {
    if (filterCat !== "ALL" && s.category !== filterCat) return false;
    if (filterStatus !== "ALL") { const rec = records[s.id]; if (!rec || rec.status !== filterStatus) return false; }
    if (query.trim()) { const q = query.toLowerCase(); if (!s.title.toLowerCase().includes(q) && !s.id.toLowerCase().includes(q) && !s.description.toLowerCase().includes(q)) return false; }
    return true;
  }), [filterCat, filterStatus, query, records]);

  const selected = BENCHMARK_SAMPLES.find((s) => s.id === selectedId) ?? null;
  const selectedRecord = selectedId ? (records[selectedId] ?? createEmptyRecord(selectedId)) : null;

  const completed = Object.values(records).filter((r) => r.status === "completed").length;
  const inProgress = Object.values(records).filter((r) => r.status === "in_progress").length;
  const total = BENCHMARK_SAMPLES.length;

  const startInvestigation = (id: string) => {
    const current = records[id] ?? createEmptyRecord(id);
    persist({ ...records, [id]: { ...current, status: "in_progress" as const, date: new Date().toISOString() } });
    setSelectedId(id);
    setSession({ startTime: Date.now(), currentId: id }); saveSession({ startTime: Date.now(), currentId: id });
  };

  const completeInvestigation = (id: string) => {
    const current = records[id]; if (!current) return;
    persist({ ...records, [id]: { ...current, status: "completed" as const } });
    setSession(null); saveSession({ startTime: 0, currentId: null });
    toast("Investigation recorded");
  };

  const updateRecord = (id: string, record: InvestigationRecord) => persist({ ...records, [id]: record });

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(records, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `benchmark-results-${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  const exportMarkdown = () => {
    const completedEntries = Object.entries(records).filter(([, r]) => r.status === "completed");
    const lines = [
      "# BeyondLabs — Analyst Validation Results",
      "",
      `**Benchmark:** ${BENCHMARK_VERSION} (${BENCHMARK_GENERATED})`,
      `**Target:** ${BENCHMARK_TARGET}`,
      `**Campaign:** ${completedEntries.length}/${total} investigations completed`,
      `**Date:** ${new Date().toISOString().split("T")[0]}`,
      "",
      "## Summary",
      "",
      "| Metric | Value |",
      "|--------|-------|",
      `| Completed | ${completedEntries.length} |`,
      `| In progress | ${inProgress} |`,
      `| Total | ${total} |`,
      `| Avg duration | ${completedEntries.length > 0 ? (completedEntries.reduce((s, [, r]) => s + (r.duration ?? 0), 0) / completedEntries.length).toFixed(1) : "N/A"}m |`,
      `| Avg searches/inv | ${completedEntries.length > 0 ? (completedEntries.reduce((s, [, r]) => s + r.searches, 0) / completedEntries.length).toFixed(1) : "N/A"} |`,
      `| Avg context switches | ${completedEntries.length > 0 ? (completedEntries.reduce((s, [, r]) => s + r.contextSwitches, 0) / completedEntries.length).toFixed(1) : "N/A"} |`,
      `| Correct verdicts | ${completedEntries.filter(([, r]) => r.correctVerdict === true).length}/${completedEntries.length} |`,
      `| Avg trust score | ${completedEntries.filter(([, r]) => r.trustResult !== undefined).length > 0 ? (completedEntries.filter(([, r]) => r.trustResult !== undefined).reduce((s, [, r]) => s + (r.trustResult ?? 0), 0) / completedEntries.filter(([, r]) => r.trustResult !== undefined).length).toFixed(1) : "N/A"}/5 |`,
      `| Avg overall rating | ${completedEntries.length > 0 ? (completedEntries.reduce((s, [, r]) => s + r.overall, 0) / completedEntries.length).toFixed(1) : "N/A"} |`,
      "",
      "## Per-Sample Results",
      "",
      ...BENCHMARK_SAMPLES.filter((s) => records[s.id]?.status === "completed").map((s) => {
        const r = records[s.id];
        return [
          `### ${s.id} — ${s.title}`,
          "",
          `- **Category:** ${s.category} | **Difficulty:** ${s.difficulty}`,
          `- **Expected verdict:** ${s.expectedVerdict} | **Correct:** ${r.correctVerdict === true ? "Yes" : "No"}`,
          `- **Duration:** ${r.duration ?? "N/A"}m | **Searches:** ${r.searches} | **Context switches:** ${r.contextSwitches}`,
          `- **Coverage:** ${r.findingsFound ?? "?"}/${s.expectedFindings.length} findings · ${r.iocsFound ?? "?"}/${s.expectedIocs.length} IOCs · ${r.mitreFound ?? "?"}/${s.expectedMitre.length} MITRE`,
          `- **Trust:** ${r.trustResult ?? "—"}/5 | **Ratings:** Workflow ${r.workflowClarity}/5 · Navigation ${r.navigation}/5 · Search ${r.searchUsefulness}/5 · Overall ${r.overall}/5`,
          r.bugs.length > 0 ? `- **Bugs:** ${r.bugs.join("; ")}` : "",
          r.friction.length > 0 ? `- **Friction:** ${r.friction.join("; ")}` : "",
          r.wishes.length > 0 ? `- **Wishes:** ${r.wishes.join("; ")}` : "",
          r.notes ? `- **Notes:** ${r.notes}` : "",
          "",
        ].filter(Boolean).join("\n");
      }),
    ];
    const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
    const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `ANALYST_TEST_RESULTS-${Date.now()}.md`; a.click();
    URL.revokeObjectURL(url);
  };

  const resetAll = () => {
    if (!confirm("Reset all investigation records? This cannot be undone.")) return;
    persist({}); setSelectedId(null); setSession(null); saveSession({ startTime: 0, currentId: null });
    toast("Reset");
  };

  return (
    <ErrorBoundary name="ValidationPage">
      <PageShell
      eyebrow="developer / validation"
      title="Analyst Validation"
      description="Benchmark suite — run investigations through BeyondLabs, record metrics, and compare against ground truth."
      crumbs={[{ label: "Developer" }, { label: "Validation" }]}
      actions={
        <div className="flex flex-wrap items-center gap-1.5">
          <button onClick={() => setShowAnalytics((o) => !o)} className="inline-flex items-center gap-1 rounded border border-primary/30 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"><BarChart3 className="h-3.5 w-3.5" />{showAnalytics ? "Hide analytics" : "Analytics"}</button>
          <button onClick={exportJson} className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> JSON</button>
          <button onClick={exportMarkdown} className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> MD</button>
          <button onClick={resetAll} className="inline-flex items-center gap-1 rounded border border-destructive/40 px-2 py-1 text-mono ba-text-2xs text-destructive hover:bg-destructive/10"><Trash2 className="h-3 w-3" /> Reset</button>
        </div>
      }
    >
      <VerdictBanner
        verdict={`${completed}/${total} investigations completed`}
        tone={completed === total ? "success" : completed > 0 ? "info" : "info"}
        icon={FlaskConical}
        details={[`${total} samples · ${inProgress} in progress · ${completed} completed`, `${Math.round((completed / total) * 100)}% campaign progress`]}
      />

      <MetricGrid columns={4} metrics={[
        { label: "Total", value: total, tone: "primary", icon: ListChecks },
        ...(["Phishing", "URL", "Log", "File"] as const).map((cat) => {
          const done = Object.entries(records).filter(([id, r]) => BENCHMARK_SAMPLES.find((s) => s.id === id)?.category === cat && r.status === "completed").length;
          const totalCat = BENCHMARK_SAMPLES.filter((s) => s.category === cat).length;
          return { label: cat, value: `${done}/${totalCat}`, tone: (done === totalCat ? "success" : "default") as "success" | "default", icon: done === totalCat ? CheckCircle2 : Circle };
        }),
      ]} />

      {showAnalytics && <AnalyticsDashboard records={records} />}

      <SectionBar id="QUEUE" label="Sample queue" meta={`${filteredSamples.length} visible`} />

      <div className="grid gap-4 grid-cols-1 lg:grid-cols-[minmax(0,18rem)_minmax(0,1fr)]">
        <div className="space-y-2">
          <Panel>
            <div className="flex items-center gap-2 rounded border border-divider-strong bg-surface-0 px-2">
              <Search className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
              <input value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search validation samples" placeholder="search samples…" className="w-full bg-transparent py-1.5 text-mono ba-text-sm outline-none placeholder:text-fg-dim" />
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-1">
              <Filter className="h-3 w-3 text-muted-foreground shrink-0" />
              {(["ALL", "Phishing", "URL", "Log", "PCAP", "File"]).map((c) => (
                <button key={c} onClick={() => setFilterCat(c)} className={"rounded border px-1.5 py-0.5 text-mono ba-text-2xs" + (filterCat === c ? "border-primary bg-primary/15 text-primary" : "border-divider-strong text-muted-foreground hover:text-foreground")}>{c === "ALL" ? "All" : c}</button>
              ))}
            </div>
            <div className="mt-1.5 flex items-center gap-1">
              {(["ALL", "pending", "in_progress", "completed"] as const).map((s) => (
                <button key={s} onClick={() => setFilterStatus(s)} className={"rounded border px-1.5 py-0.5 text-mono ba-text-2xs" + (filterStatus === s ? "border-primary bg-primary/15 text-primary" : "border-divider-strong text-muted-foreground hover:text-foreground")}>{s === "ALL" ? "Any" : s.replace("_", " ")}</button>
              ))}
            </div>
          </Panel>

          <Panel bodyClassName="p-1.5 max-h-[calc(100vh-28rem)] overflow-y-auto">
            <ul className="space-y-1">
              {filteredSamples.map((s) => {
                const r = records[s.id];
                const status = r?.status ?? "pending";
                const isActive = s.id === selectedId;
                return (
                  <li key={s.id}>
                    <button onClick={() => setSelectedId(s.id)} className={cn("group flex w-full items-start gap-2 rounded-md border px-2 py-2 text-left transition-colors duration-150", isActive ? "border-primary/50 bg-primary/10" : "border-transparent hover:border-border hover:bg-surface-2")}>
                      <div className={cn("mt-1 h-2 w-2 shrink-0 rounded-full", status === "completed" ? "bg-success" : status === "in_progress" ? "bg-warning" : "bg-muted-foreground/40")} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate text-mono ba-text-sm text-foreground">{s.id}</span>
                          <Chip tone={DIFFICULTY_COLOR[s.difficulty]}>{s.difficulty}</Chip>
                        </div>
                        <div className="mt-0.5 truncate text-mono ba-text-2xs text-muted-foreground">{s.title}</div>
                        <div className="mt-0.5 flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground"><span>{s.category}</span><span>·</span><VerdictBadge verdict={s.expectedVerdict} /></div>
                      </div>
                      <ChevronRight className={cn("mt-1 h-3 w-3 shrink-0 text-muted-foreground transition-transform", isActive && "rotate-90")} />
                    </button>
                  </li>
                );
              })}
              {filteredSamples.length === 0 && <li className="px-3 py-6 text-center text-mono ba-text-2xs text-muted-foreground">no samples match</li>}
            </ul>
          </Panel>
        </div>

        <div className="space-y-3 min-w-0">
          {selected && selectedRecord ? (
            <>
              <Panel
                title={`${selected.id} — ${selected.title}`}
                icon={FlaskConical}
                meta={`${selected.category} · ${selected.difficulty}`}
                actions={
                  <div className="flex items-center gap-1.5">
                    <select value={selectedRecord.status} onChange={(e) => updateRecord(selected.id, { ...selectedRecord, status: e.target.value as BenchmarkStatus, date: e.target.value === "in_progress" && !selectedRecord.date ? new Date().toISOString() : selectedRecord.date })}
                      className="rounded border border-divider-strong bg-surface-2 px-1.5 py-0.5 text-mono ba-text-2xs text-foreground outline-none focus:border-primary/50">
                      <option value="pending">Pending</option>
                      <option value="in_progress">In Progress</option>
                      <option value="completed">Completed</option>
                    </select>
                    {selectedRecord.status === "pending" && <button onClick={() => startInvestigation(selected.id)} className="inline-flex items-center gap-1 rounded border border-primary/30 bg-primary/10 px-2 py-1 text-mono ba-text-2xs text-primary hover:bg-primary/20"><Activity className="h-3 w-3" /> Start</button>}
                    {selectedRecord.status === "in_progress" && <button onClick={() => completeInvestigation(selected.id)} className="inline-flex items-center gap-1 rounded border border-success/40 bg-success/10 px-2 py-1 text-mono ba-text-2xs text-success hover:bg-success/20"><CheckCircle2 className="h-3 w-3" /> Complete</button>}
                  </div>
                }
              >
                <p className="ba-text-sm leading-relaxed text-fg-dim">{selected.description}</p>
                <details className="mt-2 group">
                  <summary className="cursor-pointer text-mono ba-text-2xs text-muted-foreground hover:text-foreground select-none">evidence</summary>
                  <pre className="mt-2 whitespace-pre-wrap rounded border border-divider-strong bg-background/80 p-3 text-mono ba-text-sm text-fg-dim leading-relaxed overflow-x-auto">{selected.evidence}</pre>
                </details>
              </Panel>

              <InvestigationForm sample={selected} record={selectedRecord} onChange={(r) => updateRecord(selected.id, r)} />
            </>
          ) : (
            <Empty
              icon={FlaskConical}
              title="No sample selected"
              hint="Select a sample from the queue to begin — each sample has ground truth for objective comparison"
            />
          )}
        </div>
      </div>
    </PageShell>
    </ErrorBoundary>
  );
}
