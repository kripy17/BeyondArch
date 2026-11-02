import { createFileRoute, useNavigate, useSearch } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { toast } from "sonner";
import { ErrorBoundary } from "@/components/ErrorBoundary";

import { takePendingCaseEntry } from "@/lib/handoff";
import { pushTimelineEvent } from "@/lib/timeline";
import { useLocker, type LockerItem } from "@/lib/locker";
import { InvestigationProgress } from "@/components/InvestigationProgress";
import { InvestigationQuality } from "@/components/investigation/InvestigationQuality";
import { InvestigationRecommendations, dismissRecommendation } from "@/components/investigation/InvestigationRecommendations";
import { InvestigationAssistant, CorrelationMemoryPanel } from "@/components/investigation";
import { copyText } from "@/lib/copy";
import { togglePin, loadPinnedCaseIds } from "@/lib/pins";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Panel, Chip, SendToRow, BulkActionBar, useSelection } from "@/components/soc";
import { KeyFields, Empty, DataTable } from "@/components/output";

import { EntityHeader, EntitySection, MetricGrid, FindingCard, ProvenanceTrace, HeaderAction } from "@/components/entity";
import { Plus, Copy, Download, Trash2, FileText, Tag, X, Pin, Bug,
  ArrowRight, Database, Pencil, Check, FolderOpen, ClipboardList,
  Search, SearchX, ShieldAlert, Siren, GitBranch, Activity as ActivityIcon, Network, History,
  Paperclip, Clock, BookOpen, Printer, ExternalLink, RefreshCw, FileCode, CheckCircle2,
  PanelRightClose, PanelRightOpen, Shield, Crosshair, Sparkles, Briefcase } from "lucide-react";
import { CasePdfExportModal } from "@/components/case/CasePdfExportModal";
import { ShiftHandoverBriefingModal } from "@/components/case/ShiftHandoverBriefingModal";
import { CaseContextRail } from "@/components/case/CaseContextRail";
import { ExecutiveIncidentDossier } from "@/components/case/ExecutiveIncidentDossier";
import {
  calculateCaseIncidentMetrics,
  buildEnterpriseDfirMarkdown,
  generateEnterprisePrintHtml,
  type IncidentCalculatedMetrics,
} from "@/lib/real-world-report";
import { type Case, type Entry, type EntryKind, type CaseEvent, KIND_COLOR, LS_ACTIVE,
  loadCases, saveCases, newId, newCaseTitle, autoDetectKind, addCaseEvent, removeCaseEvent, ensureIocId, setActiveCaseId } from "@/data/case";
import { addAttachmentFiles, removeAttachmentPayloads, triggerAttachmentDownload,
  entryAttachments, MAX_FILE_BYTES, type EntryAttachment } from "@/lib/attachments";
import type { Finding, IOC } from "@/types/security";
import { useViewState } from "@/lib/use-session-view";
import { searchIntel } from "@/data/intel";
import { addEdge } from "@/lib/provenance";
import { loadReportHistory } from "@/lib/report-history";
import { REPORT_TYPES, buildReportMarkdown, type ReportType } from "@/lib/report";
import { buildExportBundle, htmlShell } from "@/lib/export-bundle";
import { downloadTextFile } from "@/lib/download";
import { explainNode, projectTimeline, getAllEdges, type NodeRef } from "@/lib/provenance";
import { getEntityById } from "@/data/intel";
import { buildCaseCreatedEvent, buildNoteAddedEvent, buildDecisionMadeEvent, buildStatusChangedEvent, buildAnalystActionEvent } from "@/data/case-factory";
import { seenBeforeForCase } from "@/lib/correlation/seen-before";
import { entityTimeline } from "@/lib/timeline/entity-timeline";
import { InvestigationActivityFeed, legacyEntriesToEvents, getUnifiedFindings, getUnifiedIOCs, EvidenceIntake, linkCount } from "@/components/investigation";
import { InvestigationGraph } from "@/components/investigation/InvestigationGraph";
import { HypothesesPanel } from "@/components/notebook/Hypotheses";
import { type NotebookHypothesis, type HypothesisStatus,
  loadHypotheses, saveHypotheses, hypothesesForCase, attachDecision, buildHypothesisDecisionEvent } from "@/data/notebook";

export type CaseTab = "overview" | "evidence" | "findings" | "observables" | "graph" | "timeline" | "notebook" | "reports" | "detection" | "activity";

export const CLASSIC_TABS: { id: CaseTab; label: (c: Case) => string }[] = [
  { id: "overview", label: () => "Overview" },
  { id: "evidence", label: (c) => `Evidence (${getUnifiedFindings(c).length + (c.evidenceItems?.length ?? 0)})` },
  { id: "findings", label: (c) => `Findings (${getUnifiedFindings(c).length})` },
  { id: "observables", label: (c) => `Observables (${getUnifiedIOCs(c).length})` },
  { id: "graph", label: () => "Graph" },
  { id: "timeline", label: (c) => `Timeline (${c.events ? c.events.length : legacyEntriesToEvents(c.entries).length})` },
  { id: "notebook", label: () => "Notebook" },
  { id: "reports", label: () => "Reports" },
  { id: "detection", label: () => "Detection" },
  { id: "activity", label: (c) => `Activity (${c.entries.length})` },
];

export const Route = createFileRoute("/case")({
  component: CasePage,
  validateSearch: (s: Record<string, unknown>): { q?: string; tab?: string; highlight?: string } => ({
    q: typeof s.q === "string" ? s.q : undefined,
    tab: typeof s.tab === "string" ? s.tab : undefined,
    highlight: typeof s.highlight === "string" ? s.highlight : undefined,
  }),
});

/* ── entry parsing helpers ── */

function parseSeverity(body: string): { severity: string | null; clean: string } {
  const m = body.match(/^\[(\w+)\]\s*/);
  if (m) return { severity: m[1].toLowerCase(), clean: body.slice(m[0].length) };
  return { severity: null, clean: body };
}

/* ── provenance trace (reader: explain an IOC / finding) ── */

function nodeRefLabel(ref: NodeRef, caseData: Case): string {
  switch (ref.kind) {
    case "artifact": return caseData.artifacts?.find((a) => a.id === ref.id)?.title ?? `artifact ${ref.id}`;
    case "evidence": return caseData.evidenceItems?.find((x) => x.id === ref.id)?.title ?? `evidence ${ref.id}`;
    case "finding": return caseData.findings?.find((f) => f.id === ref.id)?.title ?? `finding ${ref.id}`;
    case "ioc": return caseData.iocs?.find((x) => x.id === ref.id)?.value ?? ref.id;
    case "entity": return getEntityById(ref.id)?.title ?? `entity ${ref.id}`;
    default: return ref.id;
  }
}

function IocTrace({ ioc, caseData }: { ioc: IOC; caseData: Case }) {
  const { back, forward } = useMemo(() => (ioc.id ? explainNode("ioc", ioc.id) : { back: [], forward: [] }), [ioc.id]);
  return <ProvenanceTrace edges={[...back, ...forward]} resolveNodeLabel={(ref) => nodeRefLabel(ref, caseData)} />;
}

function EntityTimeline({ value, onOpenCase }: { value: string; onOpenCase: (id: string) => void }) {
  const tl = useMemo(() => entityTimeline(value), [value]);
  const navigate = useNavigate();
  if (!tl.appearances.length) return null;
  return (
    <div className="rounded border border-divider bg-surface-0 p-2.5">
      <div className="mb-1.5 font-mono ba-text-3xs text-muted-foreground">
        History · {tl.appearances.length} appearance{tl.appearances.length > 1 ? "s" : ""} across{" "}
        {tl.surfacesCovered.join(" + ")} stores · newest first · hunts and one-off analyses are not
        persisted, so they are not listed
      </div>
      <ul className="space-y-1">
        {tl.appearances.map((a, i) => (
          <li key={`${a.refId}-${i}`} className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono ba-text-3xs text-fg-dim">{new Date(a.ts).toLocaleDateString()}</span>
            <Chip tone={a.surface === "case" ? "primary" : "warning"}>{a.surface}</Chip>
            {a.state && <span className="font-mono ba-text-3xs text-muted-foreground">{a.state}</span>}
            {a.surface === "case" ? (
              <button
                onClick={() => onOpenCase(a.refId)}
                title={`Open ${a.title}`}
                className="rounded border border-divider px-1.5 py-0.5 font-mono ba-text-3xs text-muted-foreground transition-colors hover:border-primary/50 hover:text-primary"
              >
                {a.title}
              </button>
            ) : (
              <button
                onClick={() => navigate({ to: "/triage" })}
                title="Open triage"
                className="rounded border border-divider px-1.5 py-0.5 font-mono ba-text-3xs text-muted-foreground transition-colors hover:border-warning/50 hover:text-warning"
              >
                {a.title}
              </button>
            )}
            {a.detail && <span className="font-mono ba-text-3xs text-muted-foreground truncate max-w-[16rem]">{a.detail}</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

function parseSource(body: string): { source: string | null; clean: string } {
  const m = body.match(/\s*\(from:\s*([^)]+)\)\s*/);
  if (m) return { source: m[1], clean: body.replace(m[0], " ").trim() };
  return { source: null, clean: body };
}

function parseIocEntry(body: string): { type: string; value: string; source: string } | null {
  const lines = body.split("\n");
  const first = lines[0];
  const colon = first.indexOf(":");
  if (colon === -1) return null;
  return {
    type: first.slice(0, colon).trim(),
    value: first.slice(colon + 1).trim(),
    source: (lines[1] || "").replace("Source:", "").trim(),
  };
}

function parseSummaryEntry(body: string): { verdict: string; score: string; confidence: string } | null {
  const lines = body.split("\n");
  const v = lines.find(l => l.startsWith("Verdict:"));
  const s = lines.find(l => l.startsWith("Score:"));
  const c = lines.find(l => l.startsWith("Confidence:"));
  if (!v && !s && !c) return null;
  return {
    verdict: v?.replace("Verdict:", "").trim() ?? "",
    score: s?.replace("Score:", "").trim() ?? "",
    confidence: c?.replace("Confidence:", "").trim() ?? "",
  };
}

const SEVERITY_TONE: Record<string, "destructive" | "warning" | "success" | "info" | "default"> = {
  critical: "destructive", high: "warning", medium: "warning", low: "success", info: "info",
};

/* ── notebook template builders ── */

function buildFindingsReviewMd(entries: Entry[], findings?: Finding[]): string {
  const groups: Record<string, string[]> = { critical: [], high: [], medium: [], low: [], info: [] };
  const order = ["critical", "high", "medium", "low", "info"];

  if (findings?.length) {
    for (const f of findings) {
      const s = f.severity || "info";
      if (!groups[s]) groups[s] = [];
      groups[s].push(`- [ ] ${f.title} (from: ${f.source})`);
    }
  } else {
    for (const e of entries) {
      if (e.kind !== "evidence") continue;
      const { severity, clean: noSev } = parseSeverity(e.body);
      const { clean: bodyText, source } = parseSource(noSev);
      const s = severity || "info";
      const title = bodyText.split("\n")[0];
      if (!groups[s]) groups[s] = [];
      groups[s].push(`- [ ] ${title}${source ? ` (from: ${source})` : ""}`);
    }
  }

  let md = "# Findings Review\n\n";
  for (const sev of order) {
    const items = groups[sev];
    if (items?.length) {
      md += `## ${sev.charAt(0).toUpperCase() + sev.slice(1)} (${items.length})\n${items.join("\n")}\n\n`;
    }
  }
  return md;
}

function buildTimelineReconstructionMd(events: CaseEvent[]): string {
  if (events.length === 0) return "# Timeline Reconstruction\n\nNo events recorded yet.\n";
  const sorted = [...events].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
  const firstTs = new Date(sorted[0].ts).getTime();
  let md = "# Timeline Reconstruction\n\n| Time | Event | Source |\n|------|-------|--------|\n";
  for (const ev of sorted) {
    const d = new Date(ev.ts);
    const delta = d.getTime() - firstTs;
    const mins = Math.floor(delta / 60000);
    const secs = Math.floor((delta % 60000) / 1000);
    const timeOffset = mins > 0 ? `+${mins}m${secs}s` : `+${secs}s`;
    const timeStr = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
    const actorLabel = ev.actor === "analyst" ? "[analyst]" : ev.actor === "automation" ? "[auto]" : ev.actor === "integration" ? "[ext]" : "[sys]";
    md += `| ${timeStr} (${timeOffset}) | ${ev.title} | ${actorLabel} ${ev.origin} |\n`;
  }
  md += "\n## Notes\n- \n\n## Indicators\n- \n\n## Actions Taken\n- \n";
  return md;
}

function buildIocTriageMd(entries: Entry[], iocs?: IOC[]): string {
  const items: { type: string; value: string }[] = [];

  if (iocs?.length) {
    for (const i of iocs) items.push({ type: i.type, value: i.value });
  } else {
    for (const e of entries) {
      if (e.kind !== "ioc") continue;
      const p = parseIocEntry(e.body);
      if (p) items.push({ type: p.type, value: p.value });
    }
  }

  let md = "# IOC Triage\n\n| Type | Value | Action |\n|------|-------|--------|\n";
  for (const item of items) {
    md += `| ${item.type} | \`${item.value}\` | □ |\n`;
  }
  md += "\n**Blocklist:**\n- \n\n**Escalate:**\n- \n";
  return md;
}

function renderInlineMarkdown(str: string): ReactNode {
  const parts = str.split(/\*\*(.+?)\*\*/g);
  return parts.flatMap((part, j) => {
    if (j % 2 === 1) {
      return <strong key={j} className="font-semibold text-foreground">{part}</strong>;
    }
    return part.split(/`(.+?)`/g).map((codePart, k) => {
      if (k % 2 === 1) {
        return (
          <code key={`${j}-${k}`} className="rounded bg-surface-1 px-1.5 py-0.5 text-mono ba-text-2xs text-primary/95 border border-border/50">
            {codePart}
          </code>
        );
      }
      return codePart;
    });
  });
}

function MarkdownRenderer({ text, className }: { text: string; className?: string }) {
  const lines = text.split("\n");
  const out: ReactNode[] = [];
  let i = 0;
  const renderRow = (line: string, Tag: "th" | "td", key: string) => {
    const cells = line.split("|").filter(Boolean).map(c => c.trim());
    return (
      <tr key={key} className={Tag === "th" ? "border-b border-border bg-surface-1 font-semibold text-foreground" : "border-b border-subtle/80 hover:bg-surface-1/40"}>
        {cells.map((c, j) => (
          <Tag key={j} className={`px-3 py-2 text-mono ba-text-xs ${Tag === "th" ? "text-left text-muted-foreground uppercase tracking-wider ba-text-3xs font-semibold" : "text-foreground/90 font-mono"}`}>
            {renderInlineMarkdown(c)}
          </Tag>
        ))}
      </tr>
    );
  };
  while (i < lines.length) {
    const line = lines[i];
    if (line.startsWith("|")) {
      const block: string[] = [];
      while (i < lines.length && lines[i].startsWith("|")) { block.push(lines[i]); i++; }
      const hasHeader = block[1]?.includes("---");
      const body = hasHeader ? block.slice(2) : block;
      out.push(
        <div key={`table-wrapper-${i}`} className="my-3 overflow-x-auto rounded-lg border border-border/80 bg-surface-0/60 shadow-xs">
          <table className="w-full border-collapse text-left">
            {hasHeader && <thead>{renderRow(block[0], "th", "head")}</thead>}
            <tbody>{body.map((l, j) => renderRow(l, "td", `row-${j}`))}</tbody>
          </table>
        </div>
      );
      continue;
    }
    if (line.startsWith("> ")) {
      const quoteLines: string[] = [];
      while (i < lines.length && lines[i].startsWith("> ")) {
        quoteLines.push(lines[i].slice(2));
        i++;
      }
      out.push(
        <div key={`quote-${i}`} className="my-2.5 rounded-r-lg border-l-4 border-primary/70 bg-primary/5 p-3 text-mono ba-text-xs text-primary/95">
          {quoteLines.map((ql, qIdx) => <p key={qIdx} className="leading-relaxed">{renderInlineMarkdown(ql)}</p>)}
        </div>
      );
      continue;
    }
    if (line.trim() === "---") {
      out.push(<hr key={`hr-${i}`} className="my-4 border-t border-border/70" />);
      i++;
      continue;
    }
    if (line.startsWith("# ")) out.push(<h1 key={i} className="text-base font-bold text-foreground mt-4 mb-2 pb-1 border-b border-border/60">{renderInlineMarkdown(line.slice(2))}</h1>);
    else if (line.startsWith("## ")) out.push(<h2 key={i} className="text-sm font-semibold text-foreground mt-3 mb-1.5">{renderInlineMarkdown(line.slice(3))}</h2>);
    else if (line.startsWith("### ")) out.push(<h3 key={i} className="text-xs font-semibold text-primary mt-2 mb-1">{renderInlineMarkdown(line.slice(4))}</h3>);
    else if (line.startsWith("#### ")) out.push(<h4 key={i} className="text-mono ba-text-xs font-bold text-foreground mt-2 mb-1 tracking-wide">{renderInlineMarkdown(line.slice(5))}</h4>);
    else if (line.startsWith("- [ ] ")) out.push(
      <li key={i} className="text-mono ba-text-xs text-foreground/80 ml-4 list-none flex items-center gap-1.5 my-1">
        <span className="h-3.5 w-3.5 rounded border border-divider-strong inline-flex items-center justify-center shrink-0" />
        <span>{renderInlineMarkdown(line.slice(6))}</span>
      </li>
    );
    else if (line.startsWith("- [x] ")) out.push(
      <li key={i} className="text-mono ba-text-xs text-foreground/80 ml-4 list-none flex items-center gap-1.5 my-1">
        <span className="h-3.5 w-3.5 rounded border border-primary bg-primary/20 inline-flex items-center justify-center shrink-0 text-primary text-mono ba-text-3xs">✓</span>
        <span>{renderInlineMarkdown(line.slice(6))}</span>
      </li>
    );
    else if (line.startsWith("- ")) out.push(<li key={i} className="text-mono ba-text-xs text-fg-dim ml-4 list-disc my-0.5">{renderInlineMarkdown(line.slice(2))}</li>);
    else if (line.trim() === "") out.push(<div key={i} className="h-2" />);
    else {
      out.push(<p key={i} className="text-mono ba-text-xs text-foreground/85 my-1 leading-relaxed">{renderInlineMarkdown(line)}</p>);
    }
    i++;
  }
  return <div className={className}>{out}</div>;
}

function CasePage() {
  const locker = useLocker();
  const [cases, setCases] = useState<Case[]>([]);
  const [activeId, setActiveId] = useState<string>("");
  const [draft, setDraft] = useState("");
  const [kind, setKind] = useState<EntryKind>("note");
  const [pendingAttachments, setPendingAttachments] = useState<EntryAttachment[]>([]);
  const kindRef = useRef(kind);
  kindRef.current = kind;
  const [editingTitle, setEditingTitle] = useState(false);
  const [titleDraft, setTitleDraft] = useState("");
  const [selectedReportType, setSelectedReportType] = useState<ReportType>("incident-response");
  const [tagDraft, setTagDraft] = useState("");
  const [pinnedIds, setPinnedIds] = useState<string[]>(() => loadPinnedCaseIds());
  const [copied, setCopied] = useState(false);
  // Session-recovery depth: sidebar filters survive reloads.
  const [sidebarView, setSidebarView] = useViewState<{ q?: string; origin?: string; finding?: string }>("case-sidebar", {});
  const [originFilter, setOriginFilter] = useState(sidebarView.origin ?? "");
  const [findingFilter, setFindingFilter] = useState(sidebarView.finding ?? "");

  useEffect(() => {
    setSidebarView({ origin: originFilter, finding: findingFilter });
  }, [originFilter, findingFilter, setSidebarView]);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const [activeTab, setActiveTab] = useState<CaseTab>(() => {
    try {
      const saved = localStorage.getItem("ba.case.tab.v1");
      return saved && ["overview", "observables", "findings", "graph", "notebook", "timeline", "reports", "detection"].includes(saved) ? (saved as CaseTab) : "overview";
    } catch {
      return "overview";
    }
  });
  const [showDetails, setShowDetails] = useState(false);
  const [showIntel, setShowIntel] = useState(false);
  const [notebookMd, setNotebookMd] = useState("");
  const [hypotheses, setHypotheses] = useState<NotebookHypothesis[]>([]);
  const [showHandoff, setShowHandoff] = useState(false);
  const [showRawReport, setShowRawReport] = useState(false);
  const [checklistVer, setChecklistVer] = useState(0);
  const [tracedIocs, setTracedIocs] = useState<Set<string>>(new Set());
  const iocSel = useSelection();
  const [pdfModalOpen, setPdfModalOpen] = useState(false);
  const [shiftModalOpen, setShiftModalOpen] = useState(false);
  const [railCollapsed, setRailCollapsed] = useState(false);

  const active = cases.find(c => c.id === activeId);

  const incidentMetrics = useMemo(() => {
    if (!active) return null;
    return calculateCaseIncidentMetrics(active);
  }, [active]);

  const enterpriseMarkdown = useMemo(() => {
    if (!active) return "";
    return buildEnterpriseDfirMarkdown(active, hypotheses);
  }, [active, hypotheses]);

  const enterpriseHtml = useMemo(() => {
    if (!active || !enterpriseMarkdown) return "";
    return generateEnterprisePrintHtml(active, enterpriseMarkdown);
  }, [active, enterpriseMarkdown]);

  const timelineEvents = useMemo(
    () => (active ? (active.events ?? legacyEntriesToEvents(active.entries)) : []),
    [active],
  );
  const projection = useMemo(() => projectTimeline(timelineEvents), [timelineEvents]);

  const notebookTemplates = useMemo(() => {
    if (!active) return [];
    return [
      { label: "Findings Review", body: buildFindingsReviewMd(active.entries, active.findings) },
      { label: "IOC Triage", body: buildIocTriageMd(active.entries, active.iocs) },
      { label: "Timeline Rec.", body: buildTimelineReconstructionMd(active.events ?? legacyEntriesToEvents(active.entries)) },
    ];
  }, [active]);

  useEffect(() => {
    const list = loadCases();
    let nextCases = list;
    let nextActiveId = "";

    if (list.length === 0) {
      const c: Case = { id: newId("c"), title: newCaseTitle(), tags: [], createdAt: new Date().toISOString(), state: "active", entries: [] };
      nextCases = [c];
      nextActiveId = c.id;
    } else {
      const remembered = localStorage.getItem(LS_ACTIVE);
      nextActiveId = remembered && list.some(c => c.id === remembered) ? remembered : list[0].id;
    }

    const pending = takePendingCaseEntry();
    if (pending) {
      const ts = new Date().toISOString();
      const body = pending.source ? `[from ${pending.source}] ${pending.body}` : pending.body;
      const entry: Entry = { id: newId("e"), ts, kind: pending.kind as EntryKind, body };
      const event = buildNoteAddedEvent(pending.body.slice(0, 200), `handoff:${pending.source || "unknown"}`);
      nextCases = nextCases.map(c => c.id === nextActiveId ? { ...c, entries: [...c.entries, entry], events: [...(c.events || []), event] } : c);
    }

    setCases(nextCases);
    setActiveId(nextActiveId);
    saveCases(nextCases);
  }, []);

  useEffect(() => { if (cases.length) saveCases(cases); }, [cases]);
  useEffect(() => { if (activeId) setActiveCaseId(activeId); }, [activeId]);

  useEffect(() => {
    if (!activeId) { setHypotheses([]); return; }
    setHypotheses(hypothesesForCase(loadHypotheses(), activeId));
  }, [activeId]);

  useEffect(() => {
    if (!activeId) return;
    const rest = loadHypotheses().filter((h) => h.caseId !== activeId);
    saveHypotheses([...rest, ...hypotheses]);
  }, [hypotheses, activeId]);

  const recordHypothesisDecision = useCallback((h: NotebookHypothesis, verdict: Exclude<HypothesisStatus, "open">) => {
    setCases((prev) => prev.map((c) => (c.id === h.caseId ? attachDecision(c, h, verdict) ?? c : c)));
  }, []);

  useEffect(() => {
    if (!activeId) return;
    setCases((prev) => prev.map((c) => {
      if (c.id !== activeId || !c.events || c.events.length === 0) return c;
      let matchIdx = -1;
      for (let i = c.events.length - 1; i >= 0; i--) {
        const e = c.events[i];
        if (e.kind === "case_decision_made" && e.origin === "notebook") { matchIdx = i; break; }
      }
      if (matchIdx === -1) return c;
      const ev = c.events[matchIdx];
      const h = hypotheses.find((x) => x.status !== "open" && ev.references.some((r) => r.id === x.id));
      if (!h || h.status === "open") return c;
      const expected = buildHypothesisDecisionEvent(c, h, h.status as Exclude<HypothesisStatus, "open">);
      if (ev.detail === expected.detail) return c;
      const next = [...c.events];
      next[matchIdx] = { ...expected, id: ev.id, ts: ev.ts };
      return { ...c, events: next };
    }));
  }, [hypotheses, activeId]);

  const navigate = useNavigate({ from: Route.id });
  const searchParams = useSearch({ from: Route.id, select: (s: Record<string, string>) => ({ tab: s.tab, highlight: s.highlight ? Number(s.highlight) : undefined }) });
  const iocRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (searchParams.tab === "iocs") {
      setActiveTab("observables");
      setTimeout(() => iocRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 0);
      return;
    }
    const validTabs: CaseTab[] = ["overview", "evidence", "findings", "observables", "graph", "timeline", "notebook", "reports", "detection", "activity"];
    if (searchParams.tab && (validTabs as string[]).includes(searchParams.tab)) {
      setActiveTab(searchParams.tab as CaseTab);
    }
  }, [searchParams.tab]);

  const setTab = useCallback((tab: CaseTab) => {
    setActiveTab(tab);
    try { localStorage.setItem("ba.case.tab.v1", tab); } catch {}
    navigate({ search: (prev) => ({ ...prev, tab }) as { q?: string; tab?: string; highlight?: string } });
  }, [navigate]);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") { setShowHandoff(false); return; }
      const t = e.target as HTMLElement | null;
      const typing = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable);
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
        e.preventDefault();
        const idx = CLASSIC_TABS.findIndex((tab) => tab.id === activeTab);
        const next = e.key === "ArrowRight" ? (idx + 1) % CLASSIC_TABS.length : (idx - 1 + CLASSIC_TABS.length) % CLASSIC_TABS.length;
        setTab(CLASSIC_TABS[next].id);
      } else if (/^[1-9]$/.test(e.key)) {
        const tab = CLASSIC_TABS[Number(e.key) - 1];
        if (tab) setTab(tab.id);
      }
    }
    function handleChecklist() { setChecklistVer((v) => v + 1); }
    window.addEventListener("keydown", handleKey);
    window.addEventListener("checklist-update", handleChecklist);
    return () => { window.removeEventListener("keydown", handleKey); window.removeEventListener("checklist-update", handleChecklist); };
  }, [activeTab, setTab]);

  useEffect(() => {
    if (kindRef.current === "note") setKind(autoDetectKind(draft));
  }, [draft]);

  function updateActive(fn: (c: Case) => Case) {
    setCases(prev => prev.map(c => c.id === activeId ? fn(c) : c));
  }

  function addEntry() {
    if (!active || (!draft.trim() && pendingAttachments.length === 0)) return;
    const body = draft.trim() || (pendingAttachments.length === 1 ? `Attached: ${pendingAttachments[0].name}` : `Attached ${pendingAttachments.length} files`);
    const e: Entry = { id: newId("e"), ts: new Date().toISOString(), kind, body, ...(pendingAttachments.length ? { attachments: pendingAttachments } : {}) };
    let event: CaseEvent | null = null;
    if (kind === "note" || kind === "evidence") event = buildNoteAddedEvent(body, "case");
    else if (kind === "decision") event = buildDecisionMadeEvent(body, "case");
    else if (kind === "action" || kind === "ioc") event = buildAnalystActionEvent(`Added ${kind}`, body, "case");
    updateActive(c => event ? addCaseEvent({ ...c, entries: [...c.entries, e] }, event) : { ...c, entries: [...c.entries, e] });
    setDraft("");
    setPendingAttachments([]);
    pushTimelineEvent({ source: "case", verb: kind === "ioc" ? "added-ioc" : "added-entry", detail: `Added ${kind} to case: ${active.title}`, result: body.slice(0, 60) });
  }

  const handleAddRailEntry = useCallback((entryBody: string, entryKind: EntryKind, attachments?: EntryAttachment[]) => {
    if (!active || (!entryBody.trim() && (!attachments || attachments.length === 0))) return;
    const atts = attachments ?? [];
    const body = entryBody.trim() || (atts.length === 1 ? `Attached: ${atts[0].name}` : `Attached ${atts.length} files`);
    const e: Entry = { id: newId("e"), ts: new Date().toISOString(), kind: entryKind, body, ...(atts.length ? { attachments: atts } : {}) };
    let event: CaseEvent | null = null;
    if (entryKind === "note" || entryKind === "evidence") event = buildNoteAddedEvent(body, "case");
    else if (entryKind === "decision") event = buildDecisionMadeEvent(body, "case");
    else if (entryKind === "action" || entryKind === "ioc") event = buildAnalystActionEvent(`Added ${entryKind}`, body, "case");
    updateActive(c => event ? addCaseEvent({ ...c, entries: [...c.entries, e] }, event) : { ...c, entries: [...c.entries, e] });
    setPendingAttachments([]);
    pushTimelineEvent({ source: "case", verb: entryKind === "ioc" ? "added-ioc" : "added-entry", detail: `Added ${entryKind} to case: ${active.title}`, result: body.slice(0, 60) });
  }, [active]);

  async function onPickFiles(files: FileList | null) {
    if (!files || !files.length) return;
    const { added, errors } = await addAttachmentFiles([...files]);
    if (added.length) setPendingAttachments(prev => [...prev, ...added]);
    for (const err of errors) toast.error(err);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  function discardPendingAttachment(attOrId: EntryAttachment | string) {
    const id = typeof attOrId === "string" ? attOrId : attOrId.id;
    setPendingAttachments(prev => prev.filter(a => a.id !== id));
    removeAttachmentPayloads([id]);
  }

  function removeEntry(id: string, _body: string) {
    const caseId = activeId;
    if (!active) return;
    const snapshot = active.entries.find(e => e.id === id);
    setCases(prev => prev.map(c => c.id === caseId ? { ...c, entries: c.entries.filter(e => e.id !== id) } : c));
    if (snapshot) {
      removeAttachmentPayloads(entryAttachments(snapshot).map(a => a.id));
      toast("Entry deleted", {
        action: {
          label: "Undo",
          onClick: () => { setCases(prev => prev.map(c => c.id === caseId ? { ...c, entries: [...c.entries, snapshot] } : c)); },
        },
      });
    }
  }

  function addTag() {
    const t = tagDraft.trim().toLowerCase().replace(/\s+/g, "-");
    if (!t || !active || active.tags.includes(t)) { setTagDraft(""); return; }
    updateActive(c => ({ ...c, tags: [...c.tags, t] }));
    setTagDraft("");
  }
  function removeTag(t: string) { updateActive(c => ({ ...c, tags: c.tags.filter(x => x !== t) })); }

  function createCase() {
    const title = newCaseTitle();
    const c: Case = { id: newId("c"), title, tags: [], createdAt: new Date().toISOString(), state: "active", entries: [], events: [buildCaseCreatedEvent(title)] };
    setCases(prev => [c, ...prev]); setActiveId(c.id);
    pushTimelineEvent({ source: "case", verb: "created", detail: `Created case: ${c.title}`, target: c.id });
  }
  function deleteCase(id: string) {
    const caseToDelete = cases.find(c => c.id === id);
    if (!caseToDelete) return;
    const remaining = cases.filter(c => c.id !== id);
    setCases(remaining);
    if (remaining.length === 0) createCase();
    else if (id === activeId) setActiveId(remaining[0].id);

    toast(`Case "${caseToDelete.title}" deleted`, {
      action: {
        label: "Undo",
        onClick: () => {
          setCases(prev => {
            if (prev.some(c => c.id === caseToDelete.id)) return prev;
            return [...prev, caseToDelete].sort((a, b) =>
              new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
            );
          });
          setActiveId(caseToDelete.id);
        },
      },
    });
  }
  function toggleClosed() {
    updateActive(c => {
      const next = c.state === "active" ? "closed" : "active";
      return addCaseEvent({ ...c, state: next }, buildStatusChangedEvent(c.state, next, "case"));
    });
  }

  function toggleActivePin() {
    if (!activeId) return;
    const now = togglePin(activeId);
    setPinnedIds(loadPinnedCaseIds());
    toast.success(now ? "Pinned to dashboard" : "Unpinned");
  }

  const caseJson = useMemo(() => {
    if (!active) return "";
    return JSON.stringify({ version: "1.0", ts: new Date().toISOString(), case: active }, null, 2);
  }, [active]);

  const beyondcaseExport = useMemo(() => {
    if (!active) return "";
    return JSON.stringify({
      version: 1,
      exportedAt: new Date().toISOString(),
      case: active,
    }, null, 2);
  }, [active]);

  const handoffReport = useMemo(() => {
    if (!active) return "";
    const lines: string[] = [];
    lines.push(`# Handoff Report: ${active.title}`);
    lines.push(`**Case ID:** \`${active.id}\``);
    lines.push(`**Status:** ${active.state}`);
    lines.push(`**Generated:** ${new Date().toISOString()}`);
    lines.push("");
    lines.push("---");
    lines.push("## 1. Summary");
    lines.push(`Total entries: ${active.entries.length}`);
    lines.push("");
    const byKindH: Record<EntryKind, number> = { note: 0, evidence: 0, decision: 0, action: 0, ioc: 0 };
    active.entries.forEach(e => { if (byKindH[e.kind] !== undefined) byKindH[e.kind]++; });
    for (const [k, v] of Object.entries(byKindH)) { if (v) lines.push(`- **${k}**: ${v} entries`); }
    lines.push("");
    lines.push("## 2. IOCs");
    const iocTextH = active.entries.filter(e => e.kind === "ioc").map(e => e.body).join("\n");
    const ips = [...new Set(iocTextH.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || [])];
    const urls = [...new Set(iocTextH.match(/https?:\/\/[^\s)"']+/g) || [])];
    const hashes32 = [...new Set(iocTextH.match(/\b[a-f0-9]{32}\b/ig) || [])];
    const hashes64 = [...new Set(iocTextH.match(/\b[a-f0-9]{64}\b/ig) || [])];
    if (ips.length) { lines.push("### IP Addresses"); ips.forEach(ip => lines.push(`- \`${ip}\``)); }
    if (urls.length) { lines.push("### URLs"); urls.forEach(u => lines.push(`- \`${u}\``)); }
    if (hashes32.length) { lines.push("### Hashes (MD5/SHA1)"); hashes32.forEach(h => lines.push(`- \`${h}\``)); }
    if (hashes64.length) { lines.push("### Hashes (SHA256)"); hashes64.forEach(h => lines.push(`- \`${h}\``)); }
    lines.push("");
    const decActions = active.entries.filter(e => e.kind === "decision" || e.kind === "action");
    if (decActions.length) {
      lines.push("## 3. Decisions & Actions");
      decActions.forEach(d => lines.push(`- **${d.kind}:** ${d.body}`));
      lines.push("");
    }
    lines.push("## 4. Timeline");
    for (const section of ["evidence", "decision", "action", "ioc", "note"] as EntryKind[]) {
      const items = active.entries.filter(e => e.kind === section);
      if (!items.length) continue;
      lines.push(`### ${section.charAt(0).toUpperCase() + section.slice(1)}`);
      items.forEach(e => {
        const d = new Date(e.ts);
        lines.push(`- \`${d.toLocaleString()}\` ${e.body}`);
      });
      lines.push("");
    }
    lines.push("---");
    lines.push(`*Report generated by BeyondLabs at ${new Date().toISOString()}*`);
    return lines.join("\n");
  }, [active]);

  const markdown = useMemo(() => {
    if (!active) return "";
    return buildReportMarkdown(active, selectedReportType, hypotheses);
  }, [active, selectedReportType, hypotheses]);

  const reportVersions = loadReportHistory(active ? active.id : "");

  const counts = useMemo(() => {
    const c: Record<EntryKind, number> = { note: 0, evidence: 0, decision: 0, action: 0, ioc: 0 };
    active?.entries.forEach(e => { c[e.kind] += 1; });
    return c;
  }, [active]);
  const structuredCounts = useMemo(() => {
    if (!active) return { findings: 0, iocs: 0 };
    return { findings: getUnifiedFindings(active).length, iocs: getUnifiedIOCs(active).length };
  }, [active]);
  const tabLabels = useMemo(
    () => active ? CLASSIC_TABS.map((t) => ({ id: t.id, label: t.label(active) })) : [],
    [active],
  );

  async function copyMd() {
    try {
      await copyText(markdown);
      setCopied(true);
      toast.success(`Copied ${selectedReportType} report as markdown`);
      setTimeout(() => setCopied(false), 1400);
    } catch {/* noop */}
  }
  function download() {
    if (!active) return;
    downloadTextFile(`report-${active.id}-${selectedReportType}.md`, markdown, "text/markdown");
    toast.success(`Downloaded ${selectedReportType} report (.md)`);
  }
  function downloadHtml() {
    if (!active) return;
    const html = htmlShell(`${active.title} — ${selectedReportType} Report`, markdown);
    downloadTextFile(`report-${active.id}-${selectedReportType}.html`, html, "text/html");
    toast.success(`Downloaded standalone ${selectedReportType} report (.html)`);
  }
  function downloadZipBundle() {
    if (!active) return;
    try {
      const { blob } = buildExportBundle({ case: active, reportType: selectedReportType, hypotheses });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `beyondcase-${active.id}-${selectedReportType}.zip`;
      a.click();
      URL.revokeObjectURL(a.href);
      toast.success("Incident bundle (.zip) downloaded");
    } catch (e) {
      toast.error(`Bundle export failed: ${e instanceof Error ? e.message : "unknown error"}`);
    }
  }

  function handleImport(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target?.result as string);
        if (!data.version || !data.case || !data.case.id || !data.case.title || !Array.isArray(data.case.entries)) {
          toast.error("Invalid beyondcase file");
          return;
        }
        setCases(prev => {
          if (prev.some(c => c.id === data.case.id)) {
            toast.warning("A case with this ID already exists");
            return prev;
          }
          toast.success("Case imported");
          const imported = data.case;
          const event = buildAnalystActionEvent("Import case", `Imported case: ${imported.title}`, "case-import");
          return [{ ...imported, events: [...(imported.events || []), event] }, ...prev];
        });
      } catch {
        toast.error("Failed to parse file");
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  }

  return (
    <ErrorBoundary name="Case">
    <PageShell
      eyebrow="case / notebook"
      title="Case Notebook"
      description="Append-only timelines you build yourself. Nothing is pre-populated. Cases are persisted in this browser."
      crumbs={[{ label: "Case" }]}
      meta={[
        { label: "cases", value: String(cases.length), tone: "primary" },
        { label: "active", value: cases.filter(c => c.state === "active").length + "" },
      ]}
      actions={
        <button onClick={createCase} className="inline-flex items-center gap-1.5 rounded-md border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs text-primary hover:bg-primary/20 transition-colors duration-150">
          <Plus className="h-3 w-3" /> new case
        </button>
      }
    >
      <div className="space-y-4">
        {!active ? (
          <Empty title="No case selected" hint="Create a new case or pick one from the sidebar." />
        ) : (
          <div className="space-y-4">
            {/* Incident Command Cockpit Header */}
            <div className="rounded-xl border border-border/80 bg-surface-0 shadow-sm p-4 space-y-3">
              {/* Row 1: Case Switcher, Title (with inline editing), Severity, Duration, Status, Actions */}
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-3 border-b border-border/60">
                <div className="flex items-center gap-2.5 flex-wrap min-w-0">
                  {/* Case Switcher & Ref */}
                  <div className="flex items-center gap-1.5 rounded-lg border border-border/80 bg-surface-1 px-2.5 py-1 text-mono ba-text-xs">
                    <span className="text-muted-foreground font-semibold">CASE</span>
                    <select
                      aria-label="Select case"
                      value={activeId}
                      onChange={(e) => setActiveId(e.target.value)}
                      className="bg-transparent font-bold text-foreground outline-none cursor-pointer max-w-[160px] truncate"
                    >
                      {cases.map((c) => (
                        <option key={c.id} value={c.id} className="bg-surface-0 text-foreground">
                          {c.id} · {c.title.slice(0, 24)}{c.title.length > 24 ? "…" : ""}{c.state === "closed" ? " (closed)" : ""}
                        </option>
                      ))}
                    </select>
                    {pinnedIds.includes(activeId) && <Pin className="h-3 w-3 text-primary shrink-0" aria-hidden="true" />}
                    <button
                      onClick={() => { copyText(active.id); toast.success(`Copied Case ID: ${active.id}`); }}
                      title="Copy Case ID"
                      className="text-muted-foreground hover:text-primary transition-colors ml-0.5"
                    >
                      <Copy className="h-3 w-3" />
                    </button>
                  </div>

                  {/* Title & inline edit */}
                  {editingTitle ? (
                    <div className="flex items-center gap-1.5 flex-1 min-w-[220px]">
                      <input
                        autoFocus
                        value={titleDraft}
                        onChange={(e) => setTitleDraft(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            updateActive(c => ({ ...c, title: titleDraft.trim() || c.title }));
                            setEditingTitle(false);
                            toast.success("Case title updated");
                          } else if (e.key === "Escape") {
                            setEditingTitle(false);
                          }
                        }}
                        className="flex-1 rounded border border-primary bg-surface-1 px-2 py-0.5 text-sm font-semibold text-foreground outline-none"
                      />
                      <button
                        onClick={() => {
                          updateActive(c => ({ ...c, title: titleDraft.trim() || c.title }));
                          setEditingTitle(false);
                          toast.success("Case title updated");
                        }}
                        className="p-1 rounded bg-primary/20 text-primary hover:bg-primary/30"
                        title="Save title"
                      >
                        <Check className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() => setEditingTitle(false)}
                        className="p-1 rounded bg-surface-2 text-muted-foreground hover:text-foreground"
                        title="Cancel"
                      >
                        <X className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2 group min-w-0">
                      <h2 className="text-lg font-bold tracking-tight text-foreground truncate max-w-[500px]">
                        {active.title}
                      </h2>
                      <button
                        onClick={() => { setTitleDraft(active.title); setEditingTitle(true); }}
                        className="opacity-60 group-hover:opacity-100 transition-opacity p-1 rounded hover:bg-surface-2 text-muted-foreground hover:text-foreground"
                        title="Edit case title"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  )}

                  {/* Severity badge */}
                  {incidentMetrics && (
                    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full font-mono ba-text-3xs font-bold uppercase tracking-wider ${
                      incidentMetrics.maxSeverity === "critical"
                        ? "border border-destructive/40 bg-destructive/15 text-destructive"
                        : incidentMetrics.maxSeverity === "high"
                        ? "border border-amber-500/40 bg-amber-500/15 text-amber-400"
                        : incidentMetrics.maxSeverity === "medium"
                        ? "border border-warning/40 bg-warning/15 text-warning"
                        : "border border-info/40 bg-info/15 text-info"
                    }`}>
                      <ShieldAlert className="h-3 w-3" />
                      {incidentMetrics.maxSeverity}
                    </span>
                  )}

                  {/* TLP classification */}
                  <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border border-amber-500/40 bg-amber-500/10 text-amber-400 font-mono ba-text-3xs font-bold tracking-wider">
                    TLP:AMBER+STRICT
                  </span>

                  {/* Elapsed duration */}
                  {incidentMetrics && (
                    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border border-border bg-surface-1 font-mono ba-text-3xs text-muted-foreground">
                      <Clock className="h-2.5 w-2.5" />
                      <span>{incidentMetrics.durationFormatted}</span>
                    </span>
                  )}

                  {/* State badge */}
                  <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border border-border bg-surface-1 font-mono ba-text-3xs">
                    <span className={`h-2 w-2 rounded-full ${active.state === "active" ? "bg-emerald-500 animate-pulse" : "bg-zinc-500"}`} />
                    <span className="font-semibold uppercase tracking-wider text-muted-foreground">
                      {active.state === "active" ? "Active Investigation" : "Closed"}
                    </span>
                  </div>
                </div>

                {/* Quick actions bar */}
                <div className="flex items-center gap-1.5 shrink-0 flex-wrap">
                  {/* Primary Print / PDF Export Button */}
                  <button
                    onClick={() => setPdfModalOpen(true)}
                    className="inline-flex items-center gap-1.5 rounded-md border border-primary/50 bg-primary/15 px-3 py-1.5 text-mono ba-text-2xs font-bold text-primary hover:bg-primary/25 transition-all shadow-xs"
                    title="Export Publication-Ready DFIR PDF Report"
                  >
                    <Printer className="h-3.5 w-3.5" />
                    <span>Export PDF</span>
                  </button>

                  {/* SOC Shift Handover Briefing Button */}
                  <button
                    onClick={() => setShiftModalOpen(true)}
                    className="inline-flex items-center gap-1.5 rounded-md border border-amber-500/50 bg-amber-500/15 px-3 py-1.5 text-mono ba-text-2xs font-bold text-amber-400 hover:bg-amber-500/25 transition-all shadow-xs"
                    title="Generate SOC Shift Handover & Incident Briefing"
                    id="btn-case-shift-handover"
                  >
                    <Briefcase className="h-3.5 w-3.5" />
                    <span>Shift Briefing</span>
                  </button>

                  {/* Export Markdown Button */}
                  <button
                    onClick={() => {
                      downloadTextFile(`dfir-report-${active.id}.md`, enterpriseMarkdown, "text/markdown");
                      toast.success("Downloaded enterprise DFIR report (.md)");
                    }}
                    className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-1 px-2.5 py-1.5 text-mono ba-text-2xs font-medium text-foreground hover:bg-surface-2 transition-colors"
                    title="Download Enterprise Markdown Report with YAML frontmatter"
                  >
                    <FileText className="h-3.5 w-3.5" />
                    <span>Export MD</span>
                  </button>

                  {/* Toggle Context Rail */}
                  <button
                    onClick={() => setRailCollapsed(c => !c)}
                    className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-mono ba-text-2xs transition-colors ${
                      !railCollapsed
                        ? "border-primary/40 bg-primary/10 text-primary font-semibold"
                        : "border-border bg-surface-1 text-muted-foreground hover:text-foreground hover:bg-surface-2"
                    }`}
                    title={railCollapsed ? "Expand Incident Context & Intake Rail" : "Collapse Incident Context Rail"}
                  >
                    {railCollapsed ? <PanelRightOpen className="h-3.5 w-3.5" /> : <PanelRightClose className="h-3.5 w-3.5" />}
                    <span className="hidden sm:inline">{railCollapsed ? "Open Rail" : "Rail"}</span>
                  </button>

                  <button
                    onClick={toggleActivePin}
                    className={`inline-flex items-center gap-1 rounded-md border px-2 py-1.5 text-mono ba-text-2xs transition-colors ${pinnedIds.includes(active.id) ? "border-primary/50 bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground"}`}
                    title={pinnedIds.includes(active.id) ? "Unpin from dashboard" : "Pin to dashboard"}
                  >
                    <Pin className="h-3 w-3" />
                    <span>{pinnedIds.includes(active.id) ? "Pinned" : "Pin"}</span>
                  </button>

                  <button
                    onClick={toggleClosed}
                    className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1.5 text-mono ba-text-2xs text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {active.state === "active" ? "Close Case" : "Re-open"}
                  </button>

                  <button
                    onClick={() => deleteCase(active.id)}
                    className="inline-flex items-center gap-1 rounded-md border border-destructive/40 px-2 py-1.5 text-mono ba-text-2xs text-destructive hover:bg-destructive/10 transition-colors"
                    title="Delete case"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>
              </div>

              {/* Row 2: Tags */}
              <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
                <span className="text-mono ba-text-3xs text-muted-foreground mr-1">Tags:</span>
                {active.tags.map(t => (
                  <span key={t} className="inline-flex items-center gap-1 rounded-md border border-border/80 bg-surface-1 px-2 py-0.5 font-mono ba-text-2xs text-foreground/90">
                    <Tag className="h-2.5 w-2.5 text-primary/70" />
                    {t}
                    <button onClick={() => removeTag(t)} aria-label={`Remove tag ${t}`} className="text-muted-foreground hover:text-destructive transition-colors">
                      <X className="h-2.5 w-2.5" />
                    </button>
                  </span>
                ))}
                <input
                  value={tagDraft}
                  onChange={e => setTagDraft(e.target.value)}
                  onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); addTag(); } }}
                  placeholder="+ add tag (Enter)…"
                  className="rounded-md border border-dashed border-border/80 bg-surface-1/60 px-2 py-0.5 font-mono ba-text-2xs text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
                />
              </div>

              {/* Row 3: Elevated 6-KPI Metric Strip */}
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 pt-1">
                {/* 1. Severity & Status */}
                <div className={`rounded-xl border p-2.5 transition-all ${
                  incidentMetrics?.maxSeverity === "critical"
                    ? "border-destructive/30 bg-destructive/5 hover:border-destructive/50"
                    : incidentMetrics?.maxSeverity === "high"
                    ? "border-amber-500/30 bg-amber-500/5 hover:border-amber-500/50"
                    : incidentMetrics?.maxSeverity === "medium"
                    ? "border-warning/30 bg-warning/5 hover:border-warning/50"
                    : "border-border/70 bg-surface-1/50 hover:border-primary/40"
                }`}>
                  <div className="flex items-center justify-between text-muted-foreground">
                    <span className="font-mono ba-text-3xs uppercase tracking-wider font-semibold">Max Severity</span>
                    <ShieldAlert className={`h-3.5 w-3.5 ${
                      incidentMetrics?.maxSeverity === "critical" ? "text-destructive" : incidentMetrics?.maxSeverity === "high" ? "text-amber-400" : "text-muted-foreground"
                    }`} />
                  </div>
                  <div className={`text-base font-bold font-mono mt-1 uppercase ${
                    incidentMetrics?.maxSeverity === "critical" ? "text-destructive" : incidentMetrics?.maxSeverity === "high" ? "text-amber-400" : "text-foreground"
                  }`}>
                    {incidentMetrics?.maxSeverity ?? "Low"}
                  </div>
                  <div className="font-mono ba-text-3xs text-muted-foreground truncate mt-0.5">
                    {incidentMetrics?.containmentStatus ?? "Under Analysis"}
                  </div>
                </div>

                {/* 2. Evidence Ledger */}
                <div
                  onClick={() => setTab("evidence")}
                  className="cursor-pointer rounded-xl border border-border/70 bg-surface-1/50 p-2.5 hover:border-primary/40 hover:bg-surface-1 transition-all"
                >
                  <div className="flex items-center justify-between text-muted-foreground">
                    <span className="font-mono ba-text-3xs uppercase tracking-wider font-semibold">Evidence Ledger</span>
                    <ClipboardList className="h-3.5 w-3.5 text-primary/70" />
                  </div>
                  <div className="text-base font-bold font-mono text-foreground mt-1">
                    {(active.artifacts?.length ?? 0) + (active.evidenceItems?.length ?? 0) + counts.evidence}
                  </div>
                  <div className="font-mono ba-text-3xs text-muted-foreground truncate mt-0.5">
                    CoC Tracked
                  </div>
                </div>

                {/* 3. Correlated Findings */}
                <div
                  onClick={() => setTab("findings")}
                  className="cursor-pointer rounded-xl border border-border/70 bg-surface-1/50 p-2.5 hover:border-primary/40 hover:bg-surface-1 transition-all"
                >
                  <div className="flex items-center justify-between text-muted-foreground">
                    <span className="font-mono ba-text-3xs uppercase tracking-wider font-semibold">Findings</span>
                    <Shield className="h-3.5 w-3.5 text-primary/70" />
                  </div>
                  <div className="text-base font-bold font-mono text-foreground mt-1">
                    {structuredCounts.findings}
                  </div>
                  <div className="font-mono ba-text-3xs text-muted-foreground truncate mt-0.5">
                    {incidentMetrics?.mitreTechniquesCount ?? 0} MITRE tags
                  </div>
                </div>

                {/* 4. Threat Observables */}
                <div
                  onClick={() => setTab("observables")}
                  className="cursor-pointer rounded-xl border border-border/70 bg-surface-1/50 p-2.5 hover:border-primary/40 hover:bg-surface-1 transition-all"
                >
                  <div className="flex items-center justify-between text-muted-foreground">
                    <span className="font-mono ba-text-3xs uppercase tracking-wider font-semibold">Observables</span>
                    <Crosshair className="h-3.5 w-3.5 text-destructive/70" />
                  </div>
                  <div className="text-base font-bold font-mono text-foreground mt-1">
                    {structuredCounts.iocs}
                  </div>
                  <div className="font-mono ba-text-3xs text-muted-foreground truncate mt-0.5">
                    {incidentMetrics?.criticalIocsCount ?? 0} critical/high
                  </div>
                </div>

                {/* 5. Forensic Events */}
                <div
                  onClick={() => setTab("timeline")}
                  className="cursor-pointer rounded-xl border border-border/70 bg-surface-1/50 p-2.5 hover:border-primary/40 hover:bg-surface-1 transition-all"
                >
                  <div className="flex items-center justify-between text-muted-foreground">
                    <span className="font-mono ba-text-3xs uppercase tracking-wider font-semibold">Timeline Events</span>
                    <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                  </div>
                  <div className="text-base font-bold font-mono text-foreground mt-1">
                    {timelineEvents.length}
                  </div>
                  <div className="font-mono ba-text-3xs text-muted-foreground truncate mt-0.5">
                    {incidentMetrics?.durationFormatted ?? "Live"}
                  </div>
                </div>

                {/* 6. Hypotheses & Reports */}
                <div
                  onClick={() => setTab("reports")}
                  className="cursor-pointer rounded-xl border border-border/70 bg-surface-1/50 p-2.5 hover:border-primary/40 hover:bg-surface-1 transition-all"
                >
                  <div className="flex items-center justify-between text-muted-foreground">
                    <span className="font-mono ba-text-3xs uppercase tracking-wider font-semibold">Reports / Intel</span>
                    <BookOpen className="h-3.5 w-3.5 text-muted-foreground" />
                  </div>
                  <div className="text-base font-bold font-mono text-foreground mt-1">
                    {reportVersions.length}
                  </div>
                  <div className="font-mono ba-text-3xs text-muted-foreground truncate mt-0.5">
                    {hypotheses.length} hypotheses
                  </div>
                </div>
              </div>
            </div>

            {/* Unified Single-Row Tab Strip */}
            {(() => {
              const uFindings = getUnifiedFindings(active).length;
              const uIocs = getUnifiedIOCs(active).length;
              const evCount = (active.artifacts?.length ?? 0) + (active.evidenceItems?.length ?? 0) + counts.evidence;
              const eventCount = (active.events ?? legacyEntriesToEvents(active.entries)).length;

              const tabs: { id: CaseTab; label: string; icon: any; badge?: number | string }[] = [
                { id: "overview", label: "Overview", icon: ActivityIcon },
                { id: "evidence", label: "Evidence", icon: ClipboardList, badge: evCount },
                { id: "findings", label: "Findings", icon: ShieldAlert, badge: uFindings },
                { id: "observables", label: "Observables", icon: Bug, badge: uIocs },
                { id: "timeline", label: "Timeline", icon: Clock, badge: eventCount },
                { id: "graph", label: "Graph", icon: Network },
                { id: "notebook", label: "Notebook", icon: BookOpen, badge: hypotheses.length },
                { id: "reports", label: "Reports & Export", icon: FileText, badge: reportVersions.length || undefined },
                { id: "detection", label: "Detection", icon: ShieldAlert },
                { id: "activity", label: "Raw Activity", icon: History, badge: active.entries.length },
              ];

              return (
                <div className="sticky top-[calc(var(--ba-topbar-h)+1rem+var(--ba-header-h))] z-10 flex items-center gap-1 overflow-x-auto no-scrollbar border-b border-border bg-background/95 py-1.5 backdrop-blur-sm">
                  {tabs.map((tab) => {
                    const isActive = activeTab === tab.id;
                    const Icon = tab.icon;
                    return (
                      <button
                        key={tab.id}
                        onClick={() => setTab(tab.id)}
                        className={`inline-flex items-center gap-1.5 shrink-0 whitespace-nowrap rounded-md px-3 py-1.5 text-mono ba-text-2xs font-medium transition-all duration-150 ${
                          isActive
                            ? "border border-primary/50 bg-primary/10 text-primary font-semibold shadow-xs"
                            : "border border-transparent text-muted-foreground hover:text-foreground hover:bg-surface-1"
                        }`}
                      >
                        <Icon className="h-3 w-3 shrink-0" />
                        <span>{tab.label}</span>
                        {tab.badge !== undefined && (
                          <span className={`ml-0.5 rounded px-1.5 py-0.2 font-mono ba-text-3xs ${
                            isActive ? "bg-primary/25 text-primary font-bold" : "bg-surface-2 text-muted-foreground"
                          }`}>
                            {tab.badge}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              );
            })()}

            {/* Dual-Pane Investigation Stage: 70% Primary Stage + 30% Context & Intake Rail */}
            <div className="flex flex-col lg:flex-row items-start gap-4 min-w-0">
              <div className="flex-1 min-w-0 w-full space-y-4">
                {activeTab === "overview" ? (
                <>
                <ExecutiveIncidentDossier caseData={active} />
                <EntitySection title="Investigation Overview">
                  <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
                    <div className="flex items-center gap-3">
                      {(() => {
                        const allFindings = getUnifiedFindings(active);
                        const findingSevs = allFindings.map(f => f.severity);
                        const maxSev = findingSevs.includes("critical") ? "critical" : findingSevs.includes("high") ? "high" : findingSevs.includes("medium") ? "medium" : findingSevs.length > 0 ? "info" : null;
                        if (!maxSev) return null;
                        const sevTone = SEVERITY_TONE[maxSev] || "default";
                        const sevColor = sevTone === "destructive" ? "border-destructive/30 bg-destructive/10 text-destructive" : sevTone === "warning" ? "border-warning/30 bg-warning/10 text-warning" : "border-info/30 bg-info/10 text-info";
                        return <span className={`rounded border px-2 py-0.5 font-mono ba-text-3xs font-semibold ${sevColor}`}>{maxSev}</span>;
                      })()}
                      {(() => {
                        const s = active.analysisSummary
                          ? { verdict: active.analysisSummary.verdict, score: `${active.analysisSummary.score}`, confidence: `${Math.round(active.analysisSummary.confidence * 100)}` }
                          : (() => {
                              const decEntry = active.entries.find(e => e.kind === "decision" && parseSummaryEntry(e.body));
                              return decEntry ? parseSummaryEntry(decEntry.body) : null;
                            })();
                        if (!s) return null;
                        return (
                          <div className="flex flex-wrap gap-3 font-mono ba-text-2xs text-muted-foreground">
                            {s.verdict && <span>Verdict: <span className="text-fg-dim">{s.verdict}</span></span>}
                            {s.score && <span>Score: <span className="text-fg-dim">{s.score}</span></span>}
                            {s.confidence && <span>Confidence: <span className="text-fg-dim">{s.confidence}</span></span>}
                          </div>
                        );
                      })()}
                    </div>
                    <Chip tone={active.state === "active" ? "warning" : "default"}>{active.state === "active" ? "open" : "closed"}</Chip>
                  </div>
                  <MetricGrid metrics={[
                    { label: "Findings", value: structuredCounts.findings, tone: "primary" },
                    { label: "IOCs", value: structuredCounts.iocs, tone: "destructive" },
                    { label: "Evidence", value: counts.evidence, tone: "primary" },
                    { label: "Decisions", value: counts.decision, tone: "warning" },
                  ]} />
                  {(() => {
                    const sb = seenBeforeForCase(active);
                    if (!sb.cards.length) return null;
                    return (
                      <div className="mt-4 rounded border border-info/25 bg-info/5 p-3">
                        <div className="mb-2 font-mono ba-text-2xs text-muted-foreground">
                          Seen before · {sb.cards.length} observable{sb.cards.length > 1 ? "s" : ""} shared with{" "}
                          {sb.priorCaseIds.length} prior case{sb.priorCaseIds.length > 1 ? "s" : ""} · review only
                        </div>
                        <div className="space-y-1.5">
                          {sb.cards.map(card => (
                            <div key={card.value} className="flex flex-wrap items-center gap-1.5">
                              <Chip tone="destructive">{card.kind}</Chip>
                              <span className="font-mono ba-text-2xs text-foreground break-all">{card.value}</span>
                              {card.priorCases.map(p => (
                                <button key={p.id}
                                  onClick={() => setActiveId(p.id)}
                                  title={`Open prior case "${p.title}"${p.state === "closed" ? " (closed)" : ""}`}
                                  className="rounded border border-divider px-1.5 py-0.5 font-mono ba-text-3xs text-muted-foreground transition-colors hover:border-primary/50 hover:text-primary"
                                >
                                  {p.title}{p.state === "closed" ? " ·closed" : ""}
                                </button>
                              ))}
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })()}
                </EntitySection>
                <Panel title="Case metadata">
                  <KeyFields items={[
                    { label: "ID", value: active.id, tone: "primary" },
                    { label: "Opened", value: new Date(active.createdAt).toLocaleString() },
                    { label: "State", value: active.state, tone: active.state === "active" ? "warning" : "default" },
                    { label: "Entries", value: active.entries.length, tone: "primary" },
                  ]} />
                </Panel>
                <div className="grid gap-4 md:grid-cols-2">
                  <InvestigationProgress key={checklistVer} case={active} goToTab={(tab) => setTab(tab as CaseTab)} goToRoute={(path) => navigate({ to: path as any })} />
                  <InvestigationQuality case={active} goToTab={(tab) => setTab(tab as CaseTab)} goToRoute={(path) => navigate({ to: path as any })} />
                </div>
                <div className="rounded border border-border">
                  <button onClick={() => setShowIntel((v) => !v)} aria-expanded={showIntel} className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left">
                    <span className="text-mono ba-text-2xs text-muted-foreground">case intelligence</span>
                    <span className="text-mono ba-text-3xs text-muted-foreground">{showIntel ? "−" : "+"}</span>
                  </button>
                  {showIntel && (
                    <div className="space-y-4 border-t border-border p-3">
                      <InvestigationRecommendations case={active} goToTab={(tab) => setTab(tab as CaseTab)} goToRoute={(path) => navigate({ to: path as any })} onDismiss={(id) => dismissRecommendation(active.id, id)} closeCase={() => toggleClosed()} />
                      <InvestigationAssistant case={active} />
                      <CorrelationMemoryPanel />
                    </div>
                  )}
                </div>
                </>
              ) : activeTab === "evidence" ? (
                <EntitySection title="Evidence" meta={`${active.artifacts?.length ?? 0} artifacts · ${active.evidenceItems?.length ?? 0} evidence items · ${counts.evidence} entries`}>
                  <div className="space-y-2">
                    <EvidenceIntake caseData={active} updateActive={updateActive} />
                    {(active.artifacts ?? []).length > 0 && (
                      <DataTable
                        rows={active.artifacts ?? []}
                        columns={[
                          { key: "title", label: "Artifact", render: (a: any) => <span className="font-medium text-foreground">{a.title}</span> },
                          { key: "kind", label: "Type", render: (a: any) => <Chip tone="primary">{a.kind}</Chip> },
                          { key: "source", label: "Source", render: (a: any) => <span className="text-mono ba-text-2xs text-muted-foreground">{a.source ?? "—"}</span> },
                        ]}
                      />
                    )}
                    {(active.evidenceItems ?? []).length > 0 && (
                      <DataTable
                        rows={active.evidenceItems ?? []}
                        columns={[
                          { key: "title", label: "Evidence", render: (e: any) => <span className="font-medium text-foreground">{e.title}</span> },
                          { key: "type", label: "Kind", render: (e: any) => <Chip tone="default">{e.type}</Chip> },
                          { key: "source", label: "Source", render: (e: any) => <span className="text-mono ba-text-2xs text-muted-foreground">{e.source ?? "—"}</span> },
                          { key: "links", label: "Links", render: (e: any) => <span className="font-mono ba-text-2xs text-muted-foreground">{linkCount(e.id)} provenance edge{linkCount(e.id) === 1 ? "" : "s"}</span> },
                        ]}
                      />
                    )}
                    {counts.evidence === 0 && (active.artifacts ?? []).length === 0 && (active.evidenceItems ?? []).length === 0 && (
                      <Empty icon={ClipboardList} title="No evidence yet" hint="Evidence appears here when analyzers attribute artifacts, or when you append an evidence entry via intake." />
                    )}
                  </div>
                </EntitySection>
              ) : activeTab === "findings" ? (
                <EntitySection title="Findings" meta={findingFilter ? `filtered: ${findingFilter}` : `${getUnifiedFindings(active).length} items`}>
                  {findingFilter && (
                    <div className="flex items-center gap-2 mb-3 font-mono ba-text-2xs text-muted-foreground">
                      <span>Filter: <span className="text-primary">{findingFilter}</span></span>
                      <button onClick={() => setFindingFilter("")} className="rounded border border-subtle px-1.5 py-0.5 font-mono ba-text-3xs text-muted-foreground hover:text-foreground">clear</button>
                    </div>
                  )}
                  {(() => {
                    const allIocs = getUnifiedIOCs(active);
                    const allFindings = getUnifiedFindings(active);
                    const filtered = findingFilter ? allFindings.filter(f => f.source === findingFilter) : allFindings;
                    if (filtered.length === 0) return (
                      <Empty
                        icon={findingFilter ? Search : SearchX}
                        title={findingFilter ? "No findings from this source" : "No findings yet"}
                        hint={findingFilter ? "Clear the filter to see findings from every source." : "Findings appear here when analyzers run against the case. Run an analyzer on an artifact or add a finding via intake."}
                      />
                    );
                    return (
                      <div className="space-y-2">
                        {filtered.map(f => (
                          <FindingCard
                            key={f.id}
                            finding={f}
                            relatedIocs={f.iocs ?? allIocs.filter(ioc => ioc.source === f.source)}
                            onFilterSource={(src) => setFindingFilter(findingFilter === src ? "" : src)}
                            filterActive={findingFilter === f.source}
                            trace={f.id ? explainNode("finding", f.id) : null}
                            resolveNodeLabel={(ref) => nodeRefLabel(ref, active)}
                          />
                        ))}
                      </div>
                    );
                  })()}
                </EntitySection>
              ) : activeTab === "timeline" ? (
                <EntitySection title="Timeline" meta={`${(active.events ?? legacyEntriesToEvents(active.entries)).length} events`}>
                  <InvestigationActivityFeed
                    events={active.events ?? legacyEntriesToEvents(active.entries)}
                    onReferenceClick={ref => {
                      if (ref.kind === "ioc" || ref.kind === "finding" || ref.kind === "artifact") {
                        setTab("findings");
                      }
                    }}
                    originFilter={originFilter || undefined}
                    onOriginFilter={origin => setOriginFilter(originFilter === origin ? "" : origin)}
                    loading={!active}
                    emptyTitle={active.events ? "No events" : "No entries"}
                    emptyHint={active.events ? "Events appear here as the investigation progresses." : "Append your first observation, decision, or IOC above."}
                     provenance={projection}
                     resolveNodeLabel={(ref) => nodeRefLabel(ref, active)}
                     deletableEvent={(ev) => ev.origin === "/parser timeline-import"}
                     onDeleteEvent={(id) => {
                       const ev = (active.events ?? []).find((e) => e.id === id);
                       if (!ev || !active) return;
                       updateActive((c) => removeCaseEvent(c, id) ?? c);
                       pushTimelineEvent({ source: "case", verb: "removed-event", detail: `Deleted timeline event "${ev.title}"`, result: "manual delete" });
                       toast.success("Event deleted");
                     }}
                   />
                </EntitySection>
              ) : activeTab === "graph" ? (
                <EntitySection title="Knowledge Graph" meta={projection.size > 0 ? `${projection.size} linked events` : undefined}>
                  {(() => {
                    const links = getAllEdges().length;
                    if (links === 0) {
                      return (
                        <Empty icon={Network} title="No provenance links yet" hint="Run an analyzer on an artifact, add findings, or extract IOCs to build the graph."
                          examples={["artifact → evidence → finding → IOC → MITRE spine", "click a node for detail"]} />
                      );
                    }
                    return <InvestigationGraph
                      caseData={active}
                      className="h-[560px]"
                      onSnapshot={(body) => {
                        const e: Entry = { id: newId("e"), ts: new Date().toISOString(), kind: "note", body };
                        updateActive(c => addCaseEvent({ ...c, entries: [...c.entries, e] }, buildNoteAddedEvent(body, "graph-snapshot")));
                        toast.success("Graph snapshot filed to notebook");
                      }}
                    />;
                  })()}
                </EntitySection>
              ) : activeTab === "activity" ? (
                <EntitySection title="Activity" meta={`${active.entries.length} entries`}>
                  {active.entries.length === 0 ? (
                    <Empty icon={ActivityIcon} title="No activity yet" hint="Timeline entries land here. Append your first observation, decision, or IOC via intake." />
                  ) : (
                    <ul className="space-y-1">
                      {[...active.entries].reverse().map(e => (
                        <li key={e.id} className="flex items-start gap-2 rounded px-2 py-1 hover:bg-surface-1">
                          <span className={"mt-1 h-2 w-2 shrink-0 rounded-full " + KIND_COLOR[e.kind]} />
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2">
                              <span className="font-mono ba-text-2xs font-semibold uppercase text-muted-foreground">{e.kind}</span>
                              <span className="font-mono ba-text-3xs text-fg-dim">{new Date(e.ts).toLocaleString()}</span>
                            </div>
                            <div className="text-mono ba-text-sm text-foreground/90 whitespace-pre-wrap">{e.body}</div>
                            {entryAttachments(e).length > 0 && (
                              <div className="mt-1 flex flex-wrap items-center gap-1.5">
                                {entryAttachments(e).map(a => (
                                  <span key={a.id} className="inline-flex max-w-[240px] items-center gap-1 rounded border border-border bg-surface-1 px-1.5 py-0.5 font-mono ba-text-2xs text-muted-foreground">
                                    <Paperclip className="h-3 w-3 shrink-0" />
                                    <button
                                      onClick={() => {
                                        if (triggerAttachmentDownload(a)) toast.success(`Downloaded ${a.name}`);
                                        else toast.error("Attachment payload missing from local storage");
                                      }}
                                      title={`Download ${a.name} (${Math.max(1, Math.round(a.size / 1024))} KB)`}
                                      className="truncate hover:text-foreground"
                                    >
                                      {a.name}
                                    </button>
                                    <span className="shrink-0 text-fg-dim">{Math.max(1, Math.round(a.size / 1024))} KB</span>
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                          <button onClick={() => removeEntry(e.id, e.body)} aria-label="Delete entry" title="Delete entry" className="shrink-0 rounded border border-border p-1 text-muted-foreground hover:border-destructive/50 hover:text-destructive">
                            <Trash2 className="h-3 w-3" />
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </EntitySection>
              ) : activeTab === "notebook" ? (
                <EntitySection title="Notebook">
                  <HypothesesPanel
                    caseId={active?.id ?? ""}
                    hypotheses={hypotheses}
                    onChange={setHypotheses}
                    onDecision={(h, verdict) => recordHypothesisDecision(h, verdict)}
                  />
                  <div className="mb-3 flex flex-wrap items-center gap-1">
                    {notebookTemplates.map(t => (
                      <button key={t.label} onClick={() => setNotebookMd(t.body)}
                        className="rounded border border-subtle bg-surface-1 px-1.5 py-0.5 font-mono ba-text-2xs text-muted-foreground hover:text-foreground hover:border-primary/30">
                        {t.label}
                      </button>
                    ))}
                  </div>
                  <textarea
                    value={notebookMd}
                    onChange={e => setNotebookMd(e.target.value)}
                    rows={12}
                    placeholder={"Write investigation notes in markdown...\n\n# Observations\n- \n\n# Analysis\n- \n\n# Next Steps\n- "}
                    className="w-full resize-y rounded border border-divider-strong bg-surface-0 p-3 font-mono ba-text-sm text-foreground outline-none focus:border-primary/50 mb-3"
                  />
                  <div className="rounded border border-border/60 bg-background/30 p-3">
                    <MarkdownRenderer text={notebookMd} />
                  </div>
                </EntitySection>
              ) : null}

              {/* IOC extraction summary */}
              {activeTab === "observables" && (
              <div ref={iocRef}>
                <EntitySection title="IOCs" meta={`${getUnifiedIOCs(active).length} indicators`}>
                  <div className="flex items-center justify-end gap-2 mb-2">
                    <button onClick={() => {
                      const allIocs = getUnifiedIOCs(active);
                      allIocs.forEach(ioc => locker.add({ value: ioc.value, type: ioc.type as LockerItem["type"], source: ioc.source || "/case" }));
                      toast("All IOCs added to locker");
                    }} className="rounded border border-border px-2 py-0.5 font-mono ba-text-3xs text-muted-foreground hover:text-foreground">
                      <Database className="h-3 w-3" /> all to locker
                    </button>
                  </div>
                  {(() => {
                    const allIocs = getUnifiedIOCs(active);
                    if (allIocs.length === 0) return (
                      <Empty
                        icon={Siren}
                        title="No indicators extracted yet"
                        hint="Indicators appear here once analysis runs against case artifacts."
                        examples={["Run an analyzer to scan artifacts", "Add an IOC manually via intake", "Import from another investigation"]}
                      />
                    );
                    const structured = active.iocs;
                    return (
                      <>
                        {structured && (
                          <BulkActionBar
                            selected={iocSel.selected}
                            total={allIocs.length}
                            onSelectAll={() => iocSel.selectAll(allIocs.length)}
                            onClear={iocSel.clear}
                            actions={[
                              { label: "add to locker", icon: Database, onClick: (indices: number[]) => { indices.forEach(i => { const ioc = allIocs[i]; locker.add({ value: ioc.value, type: ioc.type as LockerItem["type"], source: ioc.source || "/case" }); }); toast(`Added ${indices.length} IOC${indices.length > 1 ? "s" : ""} to locker`); iocSel.clear(); } },
                              { label: "copy values", icon: Copy, onClick: (indices: number[]) => { const vals = indices.map(i => allIocs[i].value).join("\n"); copyText(vals); toast("Copied"); iocSel.clear(); } },
                              { label: "enrich", icon: Bug, onClick: (indices: number[]) => {
                                  let enriched = 0;
                                  for (const i of indices) {
                                    const ioc = allIocs[i];
                                    if (!ioc?.value || !ioc.id) continue;
                                    const res = searchIntel(ioc.value);
                                    const top = res.entityGroups?.[0]?.entities?.[0];
                                    if (!top) continue;
                                    addEdge({ relation: "enriched-by", from: { kind: "ioc", id: ioc.id }, to: { kind: "entity", id: top.id }, source: "/case", confidence: top.score / 100, reason: `Bulk enrichment of ${ioc.value}` });
                                    enriched++;
                                  }
                                  if (enriched > 0) {
                                    pushTimelineEvent({ source: "intel", verb: "enriched", detail: `Bulk-enriched ${enriched} of ${indices.length} selected IOCs`, target: active!.id });
                                    toast.success(`Enriched ${enriched}/${indices.length} IOCs`);
                                  } else {
                                    toast.info("No intel matches for the selection");
                                  }
                                  iocSel.clear();
                                } },
                              { label: "new case", icon: FolderOpen, onClick: (indices: number[]) => {
                                  const picked = indices.map(i => allIocs[i]).filter(Boolean);
                                  if (picked.length === 0) return;
                                  const c: Case = {
                                    id: newId("c"),
                                    title: newCaseTitle(),
                                    tags: ["from-observables"],
                                    createdAt: new Date().toISOString(),
                                    state: "active",
                                    entries: [{ id: newId("e"), ts: new Date().toISOString(), kind: "note", body: `Created from ${active!.title} observables: ${picked.map(p => p.value).join(", ")}` }],
                                    iocs: picked.map(p => ensureIocId({ ...p })),
                                    events: [],
                                  };
                                  c.events = [buildCaseCreatedEvent(c.title)];
                                  setCases(prev => [c, ...prev]);
                                  setActiveId(c.id);
                                  setActiveCaseId(c.id);
                                  saveCases([c, ...cases]);
                                  toast.success(`Case "${c.title}" created with ${picked.length} IOC${picked.length > 1 ? "s" : ""}`);
                                  iocSel.clear();
                                } },
                              ...(structured ? [{ label: "remove", icon: X, onClick: (indices: number[]) => { updateActive(c => { const remaining = (c.iocs ?? []).filter((_, i) => !indices.includes(i)); return { ...c, iocs: remaining }; }); iocSel.clear(); toast(`Removed ${indices.length} IOC${indices.length > 1 ? "s" : ""}`); }, tone: "destructive" as const }] : []),
                            ]}
                          />
                        )}
                        <DataTable
                          rows={allIocs}
                          isRowSelected={(_ioc, i) => iocSel.selected.has(i)}
                          renderExpanded={(ioc) => (
                            <div className="space-y-3">
                              {tracedIocs.has(`${ioc.type}|${ioc.value}`) ? <IocTrace ioc={ioc} caseData={active} /> : null}
                              <EntityTimeline value={ioc.value} onOpenCase={setActiveId} />
                            </div>
                          )}
                          columns={[
                            ...(structured ? [{
                              key: "sel", label: "", width: "32px",
                              render: (ioc: any, i: number) => (
                                <label className="flex h-5 w-5 cursor-pointer items-center justify-center rounded border border-divider-strong bg-surface-2 text-muted-foreground hover:border-primary/50 hover:text-primary has-[:checked]:border-primary/60 has-[:checked]:bg-primary/10 has-[:checked]:text-primary">
                                  <input type="checkbox" checked={iocSel.selected.has(i)} onChange={() => iocSel.toggle(i, false)} onClick={(e) => { if (e.shiftKey) { e.preventDefault(); iocSel.toggle(i, true); } }} className="h-3 w-3 accent-primary" />
                                </label>
                              ),
                            }] : []),
                            {
                              key: "value", label: "Value",
                              render: (ioc: any) => (
                                <div className="flex items-center gap-1">
                                  <button
                                    onClick={() => navigate({ to: "/intel", search: { q: ioc.value } })}
                                    title="Search Intel for this IOC"
                                    className="max-w-[320px] truncate rounded px-1 py-0.5 text-left font-medium text-foreground transition-colors duration-150 hover:bg-primary/5 hover:text-primary"
                                  >
                                    {ioc.value}
                                  </button>
                                  {ioc.id && (
                                    <button
                                      onClick={() => setTracedIocs((prev) => {
                                        const key = `${ioc.type}|${ioc.value}`;
                                        const next = new Set(prev);
                                        if (next.has(key)) next.delete(key); else next.add(key);
                                        return next;
                                      })}
                                      title="Why is this IOC here?"
                                      className="shrink-0 rounded p-0.5 text-muted-foreground transition-colors duration-150 hover:bg-primary/10 hover:text-primary"
                                    >
                                      <GitBranch className={"h-3 w-3 " + (tracedIocs.has(`${ioc.type}|${ioc.value}`) ? "text-primary" : "")} />
                                    </button>
                                  )}
                                </div>
                              ),
                            },
                            ...(structured ? [{
                              key: "severity", label: "Severity",
                              render: (ioc: any) => (
                                <Chip tone={ioc.severity === "critical" || ioc.severity === "high" ? "destructive" : ioc.severity === "medium" ? "warning" : "default"}>{ioc.severity}</Chip>
                              ),
                            }] : []),
                            {
                              key: "type", label: "Type",
                              render: (ioc: any) => <Chip tone="destructive">{ioc.type}</Chip>,
                            },
                            {
                              key: "source", label: "Source",
                              render: (ioc: any) => ioc.source ? (
                                <button onClick={() => { setTab("findings"); setFindingFilter(ioc.source); }}
                                  className="rounded px-1 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-primary hover:bg-surface-2">
                                  {ioc.source}
                                </button>
                              ) : (
                                <span className="text-mono ba-text-2xs text-muted-foreground">—</span>
                              ),
                            },
                          ]}
                        />
                      </>
                    );
                  })()}
                </EntitySection>
              </div>
              )}

              {/* Enterprise DFIR Reporting Station */}
              {activeTab === "reports" && (
              <div className="space-y-4">
                {/* Enterprise Post-Mortem Hero Card */}
                <div className="rounded-xl border border-primary/40 bg-linear-to-r from-primary/10 via-surface-0 to-surface-0 p-4 shadow-sm space-y-3">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="grid h-7 w-7 place-items-center rounded-lg bg-primary/20 text-primary border border-primary/30">
                          <FileText className="h-4 w-4" />
                        </span>
                        <h3 className="text-base font-bold text-foreground">
                          Enterprise DFIR Post-Mortem & Incident Dossier
                        </h3>
                        <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 font-mono ba-text-3xs font-bold text-amber-400">
                          TLP:AMBER+STRICT
                        </span>
                        <span className="rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 font-mono ba-text-3xs font-semibold text-primary">
                          SANS IR · NIST SP 800-61r2
                        </span>
                      </div>
                      <p className="font-mono ba-text-2xs text-muted-foreground max-w-3xl">
                        Publication-grade incident post-mortem with executive briefing, cryptographic evidence ledger, attack kill chain, defanged observables, 3-phase remediation roadmap, and forensic sign-offs.
                      </p>
                    </div>

                    {/* 1-Click Launchers */}
                    <div className="flex items-center gap-2 flex-wrap shrink-0">
                      <button
                        onClick={() => setPdfModalOpen(true)}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-primary/60 bg-primary px-3.5 py-1.5 font-mono ba-text-2xs font-bold text-primary-foreground hover:bg-primary/90 transition-all shadow-md"
                      >
                        <Printer className="h-3.5 w-3.5" />
                        <span>Print / Save as PDF</span>
                      </button>
                      <button
                        onClick={() => {
                          downloadTextFile(`dfir-report-${active.id}.md`, enterpriseMarkdown, "text/markdown");
                          toast.success("Downloaded enterprise DFIR markdown report");
                        }}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface-1 px-3 py-1.5 font-mono ba-text-2xs font-medium text-foreground hover:bg-surface-2 transition-colors"
                      >
                        <Download className="h-3.5 w-3.5" />
                        <span>Download .md</span>
                      </button>
                      <button
                        onClick={downloadHtml}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface-1 px-3 py-1.5 font-mono ba-text-2xs font-medium text-foreground hover:bg-surface-2 transition-colors"
                      >
                        <Download className="h-3.5 w-3.5" />
                        <span>Standalone .html</span>
                      </button>
                    </div>
                  </div>
                </div>

                <div className="rounded-xl border border-border/80 bg-surface-0 p-4 shadow-sm space-y-4">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-border/60">
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-sm font-bold text-foreground">Custom Report Perspectives</h3>
                      </div>
                      <p className="text-mono ba-text-2xs text-muted-foreground mt-0.5">
                        Select specific audience perspectives (SOC shift handover, executive summary, or technical post-mortem).
                      </p>
                    </div>

                    {/* Report Type Selector */}
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className="text-mono ba-text-3xs text-muted-foreground mr-1">Perspective:</span>
                      {REPORT_TYPES.map((t) => (
                        <button
                          key={t.id}
                          onClick={() => setSelectedReportType(t.id)}
                          className={`rounded-md px-2.5 py-1 text-mono ba-text-2xs font-semibold transition-all ${
                            selectedReportType === t.id
                              ? "border border-primary/60 bg-primary/15 text-primary shadow-xs"
                              : "border border-border/70 bg-surface-1 text-muted-foreground hover:text-foreground hover:bg-surface-2"
                          }`}
                          title={t.audience}
                        >
                          {t.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Action Toolbar */}
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <button
                        onClick={copyMd}
                        className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-1 px-3 py-1.5 text-mono ba-text-2xs font-medium text-foreground hover:bg-surface-2 transition-colors"
                      >
                        {copied ? <><Check className="h-3.5 w-3.5 text-emerald-500" /> Copied</> : <><Copy className="h-3.5 w-3.5" /> Copy Markdown</>}
                      </button>
                      <button
                        onClick={download}
                        className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-1 px-3 py-1.5 text-mono ba-text-2xs font-medium text-foreground hover:bg-surface-2 transition-colors"
                        title="Download DFIR Markdown Report"
                      >
                        <Download className="h-3.5 w-3.5" /> .md Report
                      </button>
                      <button
                        onClick={downloadHtml}
                        className="inline-flex items-center gap-1.5 rounded-md border border-primary/50 bg-primary/10 px-3 py-1.5 text-mono ba-text-2xs font-semibold text-primary hover:bg-primary/20 transition-colors shadow-xs"
                        title="Download Standalone Executive Report with Print Styles"
                      >
                        <Download className="h-3.5 w-3.5" /> Standalone .html
                      </button>
                      <button
                        onClick={downloadZipBundle}
                        className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-1 px-3 py-1.5 text-mono ba-text-2xs font-medium text-foreground hover:bg-surface-2 transition-colors"
                        title="Download full incident bundle zip with case data, report, attachments, and manifest"
                      >
                        <Download className="h-3.5 w-3.5" /> Incident Bundle (.zip)
                      </button>
                      <button
                        onClick={() => setPdfModalOpen(true)}
                        className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-1 px-3 py-1.5 text-mono ba-text-2xs font-medium text-foreground hover:bg-surface-2 transition-colors"
                        title="Print / Save PDF via browser dialog"
                      >
                        <Printer className="h-3.5 w-3.5" /> Print / PDF
                      </button>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setShowRawReport(r => !r)}
                        className="inline-flex items-center gap-1 rounded-md border border-subtle bg-surface-1 px-2.5 py-1 text-mono ba-text-3xs text-muted-foreground hover:text-foreground"
                      >
                        <FileCode className="h-3 w-3" />
                        <span>{showRawReport ? "View Rendered" : "View Raw Markdown"}</span>
                      </button>
                      <button
                        onClick={() => navigate({ to: "/report/$caseId", params: { caseId: active.id } })}
                        className="inline-flex items-center gap-1 rounded-md border border-primary/40 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs font-semibold text-primary hover:bg-primary/20"
                      >
                        <span>Open Report Studio</span>
                        <ExternalLink className="h-3 w-3" />
                      </button>
                    </div>
                  </div>

                  {/* Case Interchange / Migration Buttons */}
                  <div className="flex items-center gap-2 pt-2 border-t border-border/50 text-mono ba-text-3xs text-muted-foreground">
                    <span>Interchange:</span>
                    <button
                      onClick={() => { const blob = new Blob([caseJson], { type: "application/json" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `${active?.title ?? "case"}.json`; a.click(); }}
                      className="hover:text-primary transition-colors"
                    >
                      export case.json
                    </button>
                    <span>·</span>
                    <button
                      onClick={() => { const blob = new Blob([beyondcaseExport], { type: "application/json" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `${active?.title ?? "case"}.beyondcase.json`; a.click(); }}
                      className="hover:text-primary transition-colors"
                    >
                      export .beyondcase
                    </button>
                    <span>·</span>
                    <input ref={fileInputRef} type="file" accept=".json" className="hidden" onChange={handleImport} />
                    <button onClick={() => fileInputRef.current?.click()} className="hover:text-primary transition-colors">
                      import case file
                    </button>
                  </div>
                </div>

                {/* Report Live Viewport */}
                <div className="rounded-xl border border-border/80 bg-surface-0 shadow-sm p-6">
                  {showRawReport ? (
                    <pre className="max-h-[640px] overflow-auto rounded-lg bg-surface-1 p-4 font-mono ba-text-xs text-foreground leading-relaxed whitespace-pre-wrap">
                      {markdown}
                    </pre>
                  ) : (
                    <div className="max-h-[720px] overflow-auto px-2">
                      <MarkdownRenderer text={markdown} />
                    </div>
                  )}
                </div>

                {/* Handoff Report Collapsible */}
                <Panel title="Handoff Report (L2/IR Shift Handover)" priority="raw" icon={ClipboardList}
                  actions={
                    <button onClick={() => setShowHandoff(o => !o)} className="text-mono ba-text-2xs text-primary font-semibold">
                      {showHandoff ? "− Collapse" : "+ Expand"}
                    </button>
                  }
                >
                  {showHandoff ? (
                    <div className="space-y-3 pt-2">
                      <pre className="max-h-80 overflow-auto rounded-lg bg-surface-1 p-3 font-mono ba-text-xs text-foreground whitespace-pre-wrap leading-relaxed">
                        {handoffReport}
                      </pre>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={async () => { try { await copyText(handoffReport); toast.success("Handoff report copied"); } catch {} }}
                          className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-1 px-2.5 py-1 text-mono ba-text-2xs text-foreground hover:bg-surface-2"
                        >
                          <Copy className="h-3 w-3" /> copy text
                        </button>
                        <button
                          onClick={() => { const blob = new Blob([handoffReport], { type: "text/markdown" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `${active?.title ?? "case"}-handoff.md`; a.click(); }}
                          className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-1 px-2.5 py-1 text-mono ba-text-2xs text-foreground hover:bg-surface-2"
                        >
                          <Download className="h-3 w-3" /> download .md
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="text-mono ba-text-2xs text-muted-foreground">
                      Consolidated L2/IR shift handoff report with IOC summary, key decisions, and chronological timeline.
                    </div>
                  )}
                </Panel>

                {/* Attached Report Versions */}
                <Panel
                  title="Saved Report Snapshots & Historical Versions" priority="secondary" icon={History}
                  actions={
                    <button onClick={() => navigate({ to: "/report/$caseId", params: { caseId: active.id } })} className="text-mono ba-text-2xs text-primary font-semibold">
                      open report studio →
                    </button>
                  }
                >
                  {reportVersions.length === 0 ? (
                    <div className="text-mono ba-text-2xs text-muted-foreground">
                      No report versions saved for this case yet — save snapshots in the Report Studio to track differential changes.
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left font-mono ba-text-xs">
                        <thead>
                          <tr className="border-b border-border ba-text-3xs text-muted-foreground uppercase">
                            <th scope="col" className="pb-2 pr-4">Saved At</th>
                            <th scope="col" className="pb-2 pr-4">Report Type</th>
                            <th scope="col" className="pb-2 pr-4">Findings</th>
                            <th scope="col" className="pb-2 pr-4">IOCs</th>
                            <th scope="col" className="pb-2">Events</th>
                          </tr>
                        </thead>
                        <tbody>
                          {reportVersions.map((v) => (
                            <tr key={v.id} className="border-b border-subtle hover:bg-surface-1/40">
                              <td className="py-2 pr-4 text-muted-foreground">{new Date(v.generatedAt).toLocaleString()}</td>
                              <td className="py-2 pr-4"><Chip tone="primary">{REPORT_TYPES.find((t) => t.id === v.reportType)?.label ?? v.reportType}</Chip></td>
                              <td className="py-2 pr-4 text-foreground font-semibold">{v.summary.findings}</td>
                              <td className="py-2 pr-4 text-foreground font-semibold">{v.summary.iocs}</td>
                              <td className="py-2 text-foreground font-semibold">{v.summary.events}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Panel>
              </div>
              )}

              {activeTab === "detection" && (
              <div className="mt-4">
                <div className="mb-2 text-mono ba-text-2xs text-muted-foreground">
                  Hand this case off to a detection workspace — route the case context, MITRE mapping, and log sources to where rules are built.
                </div>
                <SendToRow targets={[
                  { label: "Detection", to: "/detection", icon: ShieldAlert },
                  { label: "MITRE Coverage", to: "/mitre", icon: ArrowRight },
                  { label: "Logs & Alerts", to: "/logs", icon: Database },
                ]} />
              </div>
              )}

              {/* Intake Dock — available on chronological/investigative tabs when rail is collapsed */}
              {railCollapsed && activeTab !== "graph" && activeTab !== "reports" && activeTab !== "detection" && (
              <div className="sticky bottom-0 z-10 rounded-lg bg-background/95 pt-2 pb-2 backdrop-blur-sm mt-4">
                <SectionBar id="IN" label="Intake · append observation, decision, action, or IOC" />
                <Panel>
                  <div className="mb-2 flex flex-wrap items-center gap-1.5">
                    {(["note", "evidence", "decision", "action", "ioc"] as EntryKind[]).map(k => (
                      <button
                        key={k}
                        onClick={() => setKind(k)}
                        className={"rounded border px-2 py-1 text-mono ba-text-2xs" + (kind === k ? "border-primary bg-primary/15 text-primary font-semibold" : "border-border text-muted-foreground hover:text-foreground")}
                      >{k}</button>
                    ))}
                  </div>
                  <textarea
                    value={draft}
                    onChange={e => setDraft(e.target.value)}
                    onKeyDown={e => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); addEntry(); } }}
                    rows={3}
                    aria-label="New investigation entry"
                    placeholder="What did you observe / decide / do?"
                    className="w-full resize-y rounded border border-divider-strong bg-surface-0 p-2 text-mono ba-text-base text-foreground outline-none focus:border-primary/50"
                  />
                  {pendingAttachments.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      {pendingAttachments.map(a => (
                        <span key={`${a.id}-${a.name}`} className="inline-flex max-w-[220px] items-center gap-1 rounded border border-border bg-surface-1 px-1.5 py-0.5 font-mono ba-text-2xs text-muted-foreground">
                          <Paperclip className="h-3 w-3 shrink-0" />
                          <span className="truncate">{a.name}</span>
                          <span className="shrink-0 text-fg-dim">{Math.max(1, Math.round(a.size / 1024))} KB</span>
                          <button onClick={() => discardPendingAttachment(a)} aria-label={`Discard ${a.name}`} title="Discard attachment" className="text-fg-dim hover:text-destructive">
                            <X className="h-3 w-3" />
                          </button>
                        </span>
                      ))}
                    </div>
                  )}
                  <input ref={fileInputRef} type="file" multiple hidden aria-label="Attach files"
                    onChange={e => void onPickFiles(e.target.files)} />
                  <div className="mt-2 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => fileInputRef.current?.click()}
                        title={`Attach files (≤ ${MAX_FILE_BYTES / 1024} KB each, stored locally)`}
                        aria-label="Attach files to this entry"
                        className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground hover:border-primary/30"
                      >
                        <Paperclip className="h-3 w-3" /> attach
                      </button>
                      <span className="text-mono ba-text-2xs text-muted-foreground">{draft.length} chars</span>
                    </div>
                    <button
                      onClick={addEntry}
                      disabled={!draft.trim() && pendingAttachments.length === 0}
                      className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs text-primary disabled:opacity-40"
                    >
                      <Plus className="h-3 w-3" /> append
                    </button>
                  </div>
                </Panel>
              </div>
              )}
              </div>

              {/* Collapsible Incident Context & Fast Intake Rail */}
              <CaseContextRail
                caseData={active}
                onAddEntry={handleAddRailEntry}
                pendingAttachments={pendingAttachments}
                onAddAttachmentFiles={(files) => void onPickFiles(files)}
                onRemoveAttachment={discardPendingAttachment}
                collapsed={railCollapsed}
                onToggleCollapse={() => setRailCollapsed((c) => !c)}
                className="lg:sticky lg:top-[calc(var(--ba-topbar-h)+4rem)]"
              />
            </div>

            {/* Enterprise DFIR PDF / Print Export Modal */}
            <CasePdfExportModal
              open={pdfModalOpen}
              onClose={() => setPdfModalOpen(false)}
              caseData={active}
              markdown={enterpriseMarkdown}
              printHtml={enterpriseHtml}
            />

            {/* SOC Shift Handover & Incident Briefing Modal */}
            <ShiftHandoverBriefingModal
              open={shiftModalOpen}
              onClose={() => setShiftModalOpen(false)}
              cases={cases}
            />
            </div>
          )}
        </div>
      </PageShell>
    </ErrorBoundary>
  );
}
