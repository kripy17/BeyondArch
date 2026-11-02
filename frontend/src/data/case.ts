import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { ShieldAlert, Siren, Activity, StickyNote, Search, GitBranch, Crosshair } from "lucide-react";
import type { Artifact, Finding, IOC } from "@/types/security";
import type { EvidenceItem, AnalysisSummary } from "@/types/analysis";
import { backfillCaseEdges, backfillMitreEdges } from "@/lib/provenance";

export type EntryKind = "note" | "evidence" | "decision" | "action" | "ioc";
export type Entry = { id: string; ts: string; kind: EntryKind; body: string; attachments?: import("@/lib/attachments").EntryAttachment[] };
export type ActivityEntry = { id: string; ts: string; kind: "note" | "comment" | "decision" | "action" | "status_change"; body: string };

export type EventCategory = "artifact" | "analysis" | "finding" | "ioc" | "case" | "detection" | "report" | "analyst";
export type CaseEventKind =
  | "artifact_uploaded"
  | "analysis_started" | "analysis_completed"
  | "finding_created" | "finding_updated" | "finding_severity_changed" | "finding_status_changed"
  | "ioc_created" | "ioc_enriched"
  | "case_created" | "case_status_changed" | "case_note_added" | "case_decision_made"
  | "detection_created" | "detection_status_changed"
  | "alert_ingested"
  | "report_generated"
  | "analyst_action" | "analyst_comment";
export type EventActor = "system" | "analyst" | "automation" | "integration";
export type EventImportance = "critical" | "high" | "normal" | "low";
export type EventReference = { kind: "artifact" | "alert" | "finding" | "ioc" | "detection" | "report" | "evidence"; id: string };
export type CaseEvent = {
  id: string;
  ts: string;
  kind: CaseEventKind;
  category: EventCategory;
  importance: EventImportance;
  actor: EventActor;
  origin: string;
  title: string;
  detail: string;
  references: EventReference[];
};

export type Case = {
  id: string;
  title: string;
  tags: string[];
  createdAt: string;
  state: "active" | "closed";
  entries: Entry[];
  events?: CaseEvent[];
  artifacts?: Artifact[];
  findings?: Finding[];
  iocs?: IOC[];
  evidenceItems?: EvidenceItem[];
  analysisSummary?: AnalysisSummary | null;
};

export function addCaseEvent(c: Case, event: CaseEvent): Case {
  return { ...c, events: [...(c.events || []), event] };
}

/** Removes an event by id. Returns null when the event does not exist on the case. */
export function removeCaseEvent(c: Case, eventId: string): Case | null {
  const events = c.events ?? [];
  if (!events.some((e) => e.id === eventId)) return null;
  return { ...c, events: events.filter((e) => e.id !== eventId) };
}

export const LS_KEY = "ba.cases.v2";
export const LS_ACTIVE = "ba.cases.active";
export const ACTIVE_CASE_EVENT = "ba:active-case-changed";

export function setActiveCaseId(id: string | null) {
  try {
    if (id) localStorage.setItem(LS_ACTIVE, id);
    else localStorage.removeItem(LS_ACTIVE);
  } catch { /* storage unavailable */ }
  try { window.dispatchEvent(new Event(ACTIVE_CASE_EVENT)); } catch { /* non-window */ }
}

const MAX_BODY = 5000;

export const KIND_TONE: Record<EntryKind, "default" | "primary" | "warning" | "success" | "destructive"> = {
  note: "default", evidence: "primary", decision: "warning", action: "success", ioc: "destructive",
};
export const KIND_ICON: Record<EntryKind, typeof StickyNote> = {
  note: StickyNote, evidence: Search, decision: GitBranch, action: Crosshair, ioc: Siren,
};
export const KIND_COLOR: Record<EntryKind, string> = {
  note: "bg-muted-foreground/40", evidence: "bg-primary/60", decision: "bg-warning/60", action: "bg-success/60", ioc: "bg-destructive/60",
};

export function loadCases(): Case[] {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as Case[];
    return parsed.map((c) => {
      const upgraded = ensureCaseNodeIds(c);
      backfillCaseEdges(upgraded);
      backfillMitreEdges(upgraded);
      return upgraded;
    });
  } catch { return []; }
}
export function saveCases(list: Case[]) {
  try {
    const serialized = JSON.stringify(list);
    if (serialized.length > 5_000_000) { return; }
    localStorage.setItem(LS_KEY, serialized);
    try { window.dispatchEvent(new Event("search-index-invalidate")); } catch {}
  } catch { /* noop */ }
}
export function newId(prefix: string) {
  return `${prefix}-${crypto.randomUUID().slice(0, 8)}`;
}

/* ── Stable node ids (provenance) ───────────────────────── */

function fnv1a(str: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/** Deterministic id for an IOC — stable across reloads, idempotent for reruns. */
export function ensureIocId(ioc: IOC): IOC {
  if (ioc.id) return ioc;
  return { ...ioc, id: `ioc-${fnv1a(`${ioc.type}|${ioc.value}`)}` };
}

/** Deterministic id for an evidence item — same properties. */
export function ensureEvidenceId(ev: EvidenceItem): EvidenceItem {
  if (ev.id) return ev;
  return { ...ev, id: `ev-${fnv1a(`${ev.source}|${ev.type}|${ev.title}`)}` };
}

export function ensureCaseNodeIds(c: Case): Case {
  let changed = false;
  const iocs = (c.iocs ?? []).map(ensureIocId);
  if (iocs.some((i, idx) => (c.iocs?.[idx].id ?? null) !== i.id)) changed = true;
  const evidenceItems = (c.evidenceItems ?? []).map(ensureEvidenceId);
  if (evidenceItems.some((e, idx) => (c.evidenceItems?.[idx].id ?? null) !== e.id)) changed = true;
  if (!changed) return c;
  return { ...c, iocs, evidenceItems };
}

/* ── React bindings (single canonical module for cases) ── */

export function useCaseList(): Case[] {
  const [list, setList] = useState<Case[]>([]);

  useEffect(() => {
    const sync = () => setList(loadCases().sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1)));
    sync();
    window.addEventListener("storage", sync);
    return () => window.removeEventListener("storage", sync);
  }, []);

  return list;
}

export function useActiveCase() {
  const [active, setActive] = useState<Case | null>(null);

  useEffect(() => {
    const sync = () => {
      const list = loadCases();
      let remembered: string | null = null;
      try { remembered = localStorage.getItem(LS_ACTIVE); } catch {}
      const found = remembered ? list.find((c) => c.id === remembered) : null;
      setActive(found ?? list[0] ?? null);
    };
    sync();
    window.addEventListener(ACTIVE_CASE_EVENT, sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener(ACTIVE_CASE_EVENT, sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  const setActiveId = useCallback((id: string) => {
    setActiveCaseId(id);
    const list = loadCases();
    const found = list.find((c) => c.id === id) ?? null;
    setActive(found);
  }, []);

  const addEntry = useCallback((body: string, kind: EntryKind, source?: string) => {
    if (!active) { toast.error("No active case"); return; }
    const prefix = source ? `[from ${source}] ` : "";
    const truncated = (prefix + body).slice(0, MAX_BODY);
    const entry: Entry = { id: newId("e"), ts: new Date().toISOString(), kind, body: truncated };
    const updated: Case = { ...active, entries: [...active.entries, entry] };
    setActive(updated);
    const list = loadCases();
    saveCases(list.map((c) => (c.id === active.id ? updated : c)));
    toast.success("Added to case");
  }, [active]);

  return { activeCase: active, setActiveId, addEntry };
}
export function newCaseTitle() {
  const d = new Date();
  const yy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  return `BA-${yy}${mm}${dd}-${hh}${mi}`;
}

export function autoDetectKind(text: string): EntryKind {
  if (!text.trim()) return "note";
  if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(text) || /https?:\/\//.test(text) || /\b[a-f0-9]{32}\b/i.test(text) || /\b[a-f0-9]{40}\b/i.test(text) || /\b[a-f0-9]{64}\b/i.test(text)) return "ioc";
  if (/^(decision|verdict|conclusion):/im.test(text)) return "decision";
  if (/^(action|todo|investigate|escalate):/im.test(text)) return "action";
  if (/\b(analysis|found|detected|evidence|observed):/im.test(text)) return "evidence";
  return "note";
}

export type TemplateDef = {
  id: string;
  label: string;
  icon: import("lucide-react").LucideIcon;
  entries: { kind: EntryKind; body: string }[];
};
export const CASE_TEMPLATES: TemplateDef[] = [
  {
    id: "phishing", label: "Phishing Triage", icon: ShieldAlert,
    entries: [
      { kind: "evidence", body: "## Header Analysis\n- **From:** \n- **Reply-To:** \n- **SPF:** \n- **DKIM:** \n- **DMARC:**" },
      { kind: "evidence", body: "## URL Analysis\n- **Original:** \n- **Redirect:** \n- **VT:**" },
      { kind: "evidence", body: "## Attachment\n- **Name:** \n- **Hash:** \n- **VT ratio:**" },
      { kind: "decision", body: "**Verdict:** [malicious / suspicious / benign]" },
      { kind: "action", body: "**Action:** [block sender / delete / escalate]" },
    ],
  },
  {
    id: "ransomware", label: "Ransomware Triage", icon: Siren,
    entries: [
      { kind: "evidence", body: "## Access\n- **Method:** \n- **Source IP:** \n- **User:**" },
      { kind: "evidence", body: "## Affected\n- **Hosts:** \n- **Count:**" },
      { kind: "evidence", body: "## Ransom Note\n- **File:** \n- **Contact:**" },
      { kind: "evidence", body: "## IOCs\n- **Hashes:** \n- **C2 IPs:** \n- **Registry:**" },
      { kind: "decision", body: "**Verdict:** [confirmed / suspicious / FP]" },
      { kind: "action", body: "**Action:** [isolate / block IOCs / notify]" },
    ],
  },
  {
    id: "suspicious-login", label: "Suspicious Login", icon: Activity,
    entries: [
      { kind: "evidence", body: "## Event\n- **Time:** \n- **User:** \n- **Source IP:** \n- **Geo:** \n- **UA:**" },
      { kind: "evidence", body: "## Risk\n- **Same IP before:** \n- **Impossible travel:** \n- **Known malicious IP:**" },
      { kind: "decision", body: "**Verdict:** [compromised / suspicious / valid]" },
      { kind: "action", body: "**Action:** [reset password / block IP / escalate]" },
    ],
  },
];
