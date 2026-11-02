import type { ReportType } from "@/lib/report";
import type { Case, CaseEvent } from "@/data/case";
import { addCaseEvent, newId } from "@/data/case";
import type { Finding, IOC } from "@/types/security";
import type { NotebookHypothesis } from "@/data/notebook";
import { fnv1a } from "@/lib/provenance";

export const LS_KEY = "ba.reports.v1";
export const MAX_VERSIONS = 12;

export type ReportVersion = {
  id: string;
  caseId: string;
  generatedAt: string;
  reportType: ReportType;
  summary: { findings: number; iocs: number; events: number; techniques: number; hypotheses: number };
  findings: { id: string; title: string; severity: string; technique?: string }[];
  iocs: { value: string; type: string; source: string }[];
  hypotheses: { id: string; hypothesis: string; status: string; confidence: string }[];
  techniques: string[];
  eventCount: number;
  source?: "manual" | "scheduled";
  scheduledFor?: string;
  /** Reproducibility stamp (v4): hash of the exact inputs this snapshot was
   *  built from, so a reader can tell whether two versions saw the same
   *  data. FNV-1a is a change-detection hash, not cryptographic. */
  repro?: { generator: string; inputHash: string; algorithm: "fnv1a-64" };
};

export type ReportDeltaKind =
  | "finding-new"
  | "finding-severity"
  | "ioc-new"
  | "hypothesis-status"
  | "hypothesis-confidence"
  | "technique-new"
  | "events";

export type ReportDelta = { kind: ReportDeltaKind; label: string; detail: string };

/** Stable JSON stringify — sorted keys, so the same logical input always
 *  hashes to the same value regardless of object key order. */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

export function reproBlock(input: { caseId: string; reportType: string; findings: unknown; iocs: unknown; hypotheses: unknown; techniques: unknown }): NonNullable<ReportVersion["repro"]> {
  const hashedPayload = canonicalJson({
    caseId: input.caseId,
    reportType: input.reportType,
    findings: input.findings,
    iocs: input.iocs,
    hypotheses: input.hypotheses,
    techniques: input.techniques,
  });
  return {
    generator: "BeyondLabs report-versions v4",
    inputHash: fnv1a(hashedPayload),
    algorithm: "fnv1a-64",
  };
}

export function snapshotFrom(input: {
  caseId: string;
  reportType: ReportType;
  findings: Finding[];
  iocs: IOC[];
  hypotheses: NotebookHypothesis[];
  techniques: string[];
  eventCount: number;
  generatedAt?: string;
  source?: "manual" | "scheduled";
  scheduledFor?: string;
}): ReportVersion {
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  return {
    id: `${input.caseId}:${generatedAt}`,
    caseId: input.caseId,
    generatedAt,
    reportType: input.reportType,
    ...(input.source ? { source: input.source } : {}),
    ...(input.scheduledFor ? { scheduledFor: input.scheduledFor } : {}),
    summary: {
      findings: input.findings.length,
      iocs: input.iocs.length,
      events: input.eventCount,
      techniques: input.techniques.length,
      hypotheses: input.hypotheses.length,
    },
    findings: input.findings.map((f) => ({ id: f.id, title: f.title, severity: f.severity, ...(f.technique ? { technique: f.technique } : {}) })),
    iocs: input.iocs.map((i) => ({ value: i.value, type: i.type, source: i.source })),
    hypotheses: input.hypotheses.map((h) => ({ id: h.id, hypothesis: h.hypothesis, status: h.status, confidence: h.confidence })),
    techniques: [...input.techniques],
    eventCount: input.eventCount,
    repro: reproBlock(input),
  };
}

const DETAIL_CAP = 3;

function capped(items: string[]): string {
  if (items.length === 0) return "—";
  const shown = items.slice(0, DETAIL_CAP);
  const rest = items.length - shown.length;
  return shown.join(", ") + (rest > 0 ? ` (+${rest} more)` : "");
}

export function deltaBetween(prev: ReportVersion, curr: ReportVersion): ReportDelta[] {
  const deltas: ReportDelta[] = [];

  const prevSeverity = new Map(prev.findings.map((f) => [f.id, f.severity]));
  for (const f of curr.findings) {
    const seen = prevSeverity.has(f.id);
    if (!seen) {
      deltas.push({ kind: "finding-new", label: "New finding", detail: f.title });
      continue;
    }
    const before = prevSeverity.get(f.id)!;
    if (before !== f.severity) {
      deltas.push({ kind: "finding-severity", label: "Severity changed", detail: `${f.title}: ${before} → ${f.severity}` });
    }
  }

  const prevIocs = new Set(prev.iocs.map((i) => i.value));
  const newIocs = curr.iocs.filter((i) => !prevIocs.has(i.value)).map((i) => i.value);
  if (newIocs.length > 0) {
    deltas.push({ kind: "ioc-new", label: "New indicators", detail: capped(newIocs) });
  }

  const prevHyps = new Map(prev.hypotheses.map((h) => [h.id, h]));
  for (const h of curr.hypotheses) {
    const seen = prevHyps.get(h.id);
    if (!seen) continue;
    if (seen.status !== h.status) {
      deltas.push({ kind: "hypothesis-status", label: "Hypothesis status", detail: `${h.hypothesis}: ${seen.status} → ${h.status}` });
    } else if (seen.confidence !== h.confidence) {
      deltas.push({ kind: "hypothesis-confidence", label: "Hypothesis confidence", detail: `${h.hypothesis}: ${seen.confidence} → ${h.confidence}` });
    }
  }

  const prevTechniques = new Set(prev.techniques);
  const newTechniques = curr.techniques.filter((t) => !prevTechniques.has(t));
  if (newTechniques.length > 0) {
    deltas.push({ kind: "technique-new", label: "MITRE techniques added", detail: capped(newTechniques) });
  }

  const delta = curr.eventCount - prev.eventCount;
  if (delta !== 0) {
    deltas.push({ kind: "events", label: "Timeline", detail: delta > 0 ? `+${delta} event${delta === 1 ? "" : "s"} since the previous version` : `${delta} event${delta === -1 ? "" : "s"} since the previous version` });
  }

  return deltas;
}

export function isReportVersion(v: unknown): v is ReportVersion {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.id === "string" &&
    typeof o.caseId === "string" &&
    typeof o.generatedAt === "string" && !Number.isNaN(Date.parse(o.generatedAt)) &&
    typeof o.reportType === "string" &&
    typeof o.eventCount === "number" &&
    Array.isArray(o.findings) &&
    Array.isArray(o.iocs) &&
    Array.isArray(o.hypotheses) &&
    Array.isArray(o.techniques) &&
    !!o.summary && typeof o.summary === "object"
  );
}

/** Diff two saved versions (older → newer direction is derived from
 *  generatedAt, not argument order). Returns the same delta vocabulary as
 *  deltaBetween so one renderer handles both current-vs-latest and A/B. */
export function diffSavedVersions(a: ReportVersion, b: ReportVersion): { older: ReportVersion; newer: ReportVersion; deltas: ReportDelta[] } {
  const [older, newer] = new Date(a.generatedAt) <= new Date(b.generatedAt) ? [a, b] : [b, a];
  return { older, newer, deltas: deltaBetween(older, newer) };
}

/** Same inputs as an existing version? The inputHash answers this even when
 *  timestamps differ — that is the whole point of embedding it. */
export function sameInputs(a: ReportVersion, b: ReportVersion): boolean {
  return !!a.repro && !!b.repro && a.repro.inputHash === b.repro.inputHash;
}

type ReportStore = Record<string, ReportVersion[]>;

function readStore(): ReportStore {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as ReportStore;
    const out: ReportStore = {};
    for (const [caseId, list] of Object.entries(parsed)) {
      if (Array.isArray(list)) {
        out[caseId] = list.filter(isReportVersion);
      }
    }
    return out;
  } catch {
    return {};
  }
}

function writeStore(store: ReportStore) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(store));
  } catch {
    /* noop */
  }
}

export function loadReportHistory(caseId: string): ReportVersion[] {
  return (readStore()[caseId] ?? []).sort((a, b) => new Date(b.generatedAt).getTime() - new Date(a.generatedAt).getTime());
}

export function saveReportVersion(version: ReportVersion): ReportVersion[] {
  const store = readStore();
  const list = store[version.caseId] ?? [];
  const without = list.filter((v) => v.id !== version.id);
  const next = [...without, version].sort((a, b) => new Date(a.generatedAt).getTime() - new Date(b.generatedAt).getTime());
  const cappedList = next.length > MAX_VERSIONS ? next.slice(next.length - MAX_VERSIONS) : next;
  store[version.caseId] = cappedList;
  writeStore(store);
  return [...cappedList].sort((a, b) => new Date(b.generatedAt).getTime() - new Date(a.generatedAt).getTime());
}

export function buildReportVersionEvent(c: Case, v: ReportVersion): CaseEvent {
  return {
    id: newId("ev"),
    ts: v.generatedAt,
    kind: "report_generated",
    category: "report",
    importance: "normal",
    actor: "analyst",
    origin: "report-versions",
    title: `Report version saved (${v.reportType})`,
    detail: `${v.summary.findings} findings · ${v.summary.iocs} IOCs · ${v.summary.events} events`,
    references: [{ kind: "report", id: v.id }],
  };
}

export function attachVersionEvent(c: Case, v: ReportVersion): Case {
  if (!c) return c;
  const expected = buildReportVersionEvent(c, v);
  const events = c.events ?? [];
  if (events.some((e) => e.origin === "report-versions" && e.references.some((r) => r.id === v.id))) {
    return c;
  }
  return addCaseEvent(c, expected);
}