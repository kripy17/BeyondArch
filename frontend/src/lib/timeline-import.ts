/* Timeline import: map CSV/JSONL columns onto case-timeline event fields
 * (ts/title/detail) through the parser's mapping review, then append rows as
 * real CaseEvents. Honest by construction: rows whose timestamp doesn't parse
 * are reported and skipped — never fabricated, never silently dropped.
 * Reuses the log parser's format detection (csv/json/zeek/cef) so the same
 * pasted artifact feeds both IOC extraction and timeline import.
 */

import { detectLogFields, extractValue, type GuessConfidence } from "@/lib/log-mapping";
import { loadCases, saveCases, type CaseEvent } from "@/data/case";
import { pushTimelineEvent } from "@/lib/timeline";

export const TIMELINE_FIELDS = ["ts", "title", "detail"] as const;
export type TimelineField = (typeof TIMELINE_FIELDS)[number];

export interface TimelineFieldGuess {
  source: string;
  columns: string[];
  guess: Partial<Record<TimelineField, string>>;
  confidence: Partial<Record<TimelineField, GuessConfidence>>;
}

export interface StoredTimelineMapping {
  fields: Partial<Record<TimelineField, string>>;
  updatedAt: number;
}

export const TIMELINE_MAPPINGS_KEY = "ba.parser.timeline-mappings.v1";

type MappingStore = Record<string, StoredTimelineMapping>;

function readStore(): MappingStore {
  try {
    return JSON.parse(localStorage.getItem(TIMELINE_MAPPINGS_KEY) || "{}") as MappingStore;
  } catch {
    return {};
  }
}

export function loadStoredTimelineMapping(source: string): StoredTimelineMapping | null {
  return readStore()[source] ?? null;
}

export function saveTimelineMapping(source: string, field: TimelineField, key: string | null): void {
  const store = readStore();
  const cur = store[source] ?? { fields: {}, updatedAt: Date.now() };
  const fields = { ...cur.fields };
  if (key === null) delete fields[field];
  else fields[field] = key;
  store[source] = { fields, updatedAt: Date.now() };
  try { localStorage.setItem(TIMELINE_MAPPINGS_KEY, JSON.stringify(store)); } catch {}
}

const CANONICAL_T: Record<TimelineField, RegExp[]> = {
  ts: [/^@?timestamp$/i, /^event[._]?time(_stamp)?$/i, /^time(_stamp)?$/i, /^ts$/i, /^date_?time$/i],
  title: [/^(event\.)?(title|name)$/i, /^summary$/i, /^signature$/i, /^rule_name$/i],
  detail: [/^(event\.)?(details?|description)$/i, /^message$/i],
};

const ALIASES_T: Record<TimelineField, RegExp[]> = {
  ts: [/[._]time(_stamp)?$/i, /^date(time)?$/i, /^created(_at|_on)?$/i, /^first_seen(_at)?$/i, /^start(_time)?$/i],
  title: [/(alert|event)_?name$/i, /^headline$/i, /^action$/i, /^(event|description|summary)$/i],
  detail: [/^msg$/i, /^message$/i, /^raw$/i, /^notes?$/i, /^data$/i],
};

function bestTimelineMatch(columns: string[], field: TimelineField): { col: string; level: GuessConfidence } | null {
  for (const rx of CANONICAL_T[field]) {
    const hit = columns.find((c) => rx.test(c));
    if (hit) return { col: hit, level: "high" };
  }
  for (const rx of ALIASES_T[field]) {
    const hit = columns.find((c) => rx.test(c));
    if (hit) return { col: hit, level: "medium" };
  }
  return null;
}

/** Detect the columnar format (same detector as log mapping) and guess timeline fields. */
export function detectTimelineFields(text: string): TimelineFieldGuess | null {
  const base = detectLogFields(text);
  if (!base || !base.columns.length) return null;
  const guess: Partial<Record<TimelineField, string>> = {};
  const confidence: Partial<Record<TimelineField, GuessConfidence>> = {};
  for (const f of TIMELINE_FIELDS) {
    const m = bestTimelineMatch(base.columns, f);
    if (m) {
      guess[f] = m.col;
      confidence[f] = m.level;
    }
  }
  return { source: base.source, columns: base.columns, guess, confidence };
}

/** Effective mapping: analyst correction wins over auto-guess. Absent key = auto guess. */
export function effectiveTimelineMapping(
  guess: TimelineFieldGuess,
  stored: StoredTimelineMapping | null,
): Partial<Record<TimelineField, string>> {
  const merged: Partial<Record<TimelineField, string>> = { ...guess.guess };
  if (!stored) return merged;
  for (const f of TIMELINE_FIELDS) {
    const v = stored.fields[f];
    if (typeof v === "string") merged[f] = v;
  }
  return merged;
}

/** Split raw input into per-row texts shaped so extractValue(row, source, key) works on each. */
export function timelineRowTexts(text: string, source: string): string[] {
  const t = text.trim();
  if (!t) return [];
  if (source === "json") {
    return t.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.startsWith("{"));
  }
  if (source === "zeek-tsv") {
    const fieldsLine = t.match(/^#fields\s+.+$/m)?.[0];
    if (!fieldsLine) return [];
    return t
      .split(/\r?\n/)
      .filter((l) => l && !l.startsWith("#"))
      .map((l) => `${fieldsLine}\n${l}`);
  }
  if (source === "csv") {
    const lines = t.split(/\r?\n/).filter((l) => l.trim());
    if (lines.length < 2) return [];
    const header = lines[0];
    return lines.slice(1).map((l) => `${header}\n${l}`);
  }
  return t.split(/\r?\n/).filter((l) => l.trim());
}

/** Parse a timestamp honestly: ISO strings, epoch seconds/millis — anything else is rejected. */
export function normalizeTimestamp(raw: string | null): string | null {
  if (!raw) return null;
  const v = raw.trim();
  let ms: number;
  if (/^\d{13}$/.test(v)) ms = Number(v);
  else if (/^\d{10}$/.test(v)) ms = Number(v) * 1000;
  else ms = Date.parse(v);
  if (!Number.isFinite(ms)) return null;
  const d = new Date(ms);
  const year = d.getUTCFullYear();
  if (year < 1970 || year > 2100) return null;
  return d.toISOString();
}

export interface ParsedTimelineRow {
  index: number;
  ts: string;
  title: string;
  detail: string;
}

export interface SkippedRow {
  row: number;
  reason: string;
}

export interface TimelineParseResult {
  rows: ParsedTimelineRow[];
  skipped: SkippedRow[];
}

export function parseTimelineRows(
  text: string,
  source: string,
  mapping: Partial<Record<TimelineField, string>>,
): TimelineParseResult {
  const rows: ParsedTimelineRow[] = [];
  const skipped: SkippedRow[] = [];
  if (!mapping.ts) {
    return { rows: [], skipped: [{ row: 0, reason: "no timestamp column mapped — map one to enable import" }] };
  }
  const texts = timelineRowTexts(text, source);
  texts.forEach((rowText, i) => {
    const rowNo = i + 1;
    const iso = normalizeTimestamp(extractValue(rowText, source, mapping.ts!));
    if (!iso) {
      const raw = mapping.ts ? extractValue(rowText, source, mapping.ts) : null;
      skipped.push({ row: rowNo, reason: raw ? `unparseable timestamp "${raw.slice(0, 40)}"` : "missing timestamp value" });
      return;
    }
    let title = mapping.title ? extractValue(rowText, source, mapping.title) ?? "" : "";
    const detail = mapping.detail ? extractValue(rowText, source, mapping.detail) ?? "" : "";
    if (!title.trim()) title = detail ? detail.slice(0, 80) : "Imported timeline event";
    rows.push({ index: rowNo, ts: iso, title, detail });
  });
  return { rows, skipped };
}

function fnv1a32(str: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/** Deterministic event id — identical row imported twice into the same case dedupes instead of duplicating. */
export function makeImportedEvent(caseId: string, row: ParsedTimelineRow): CaseEvent {
  return {
    id: `evt-${fnv1a32(`${caseId}|${row.ts}|${row.title}|${row.detail}`)}`,
    ts: row.ts,
    kind: "analyst_action",
    category: "analyst",
    importance: "normal",
    actor: "integration",
    origin: "/parser timeline-import",
    title: row.title,
    detail: row.detail,
    references: [],
  };
}

export const TIMELINE_IMPORT_CAP = 200;

export interface TimelineImportReport {
  imported: number;
  added: CaseEvent[];
  skipped: SkippedRow[];
}

/** Append parsed rows to a case's timeline through loadCases/saveCases. Idempotent per case+content. */
export function importCaseTimeline(
  caseId: string,
  text: string,
  mapping: Partial<Record<TimelineField, string>>,
): TimelineImportReport {
  const cases = loadCases();
  const target = cases.find((c) => c.id === caseId);
  if (!target) {
    return { imported: 0, added: [], skipped: [{ row: 0, reason: "target case not found" }] };
  }
  const { rows, skipped } = parseTimelineRows(text, detectLogFields(text)?.source ?? "", mapping);
  const seen = new Set((target.events ?? []).map((e) => e.id));
  const added: CaseEvent[] = [];
  const skips = [...skipped];
  for (const row of rows) {
    if (added.length >= TIMELINE_IMPORT_CAP) {
      skips.push({ row: row.index, reason: `import cap reached (${TIMELINE_IMPORT_CAP} events per import)` });
      continue;
    }
    const ev = makeImportedEvent(caseId, row);
    if (seen.has(ev.id)) {
      skips.push({ row: row.index, reason: "duplicate — identical event already in case" });
      continue;
    }
    seen.add(ev.id);
    added.push(ev);
  }
  if (added.length) {
    saveCases(cases.map((c) => (c.id === caseId ? { ...c, events: [...(c.events || []), ...added] } : c)));
    pushTimelineEvent({
      source: "/parser",
      verb: "imported",
      detail: `Imported ${added.length} timeline events into ${target.title}`,
      result: `${added.length} added · ${skips.length} skipped`,
    });
  }
  return { imported: added.length, added, skipped: skips };
}
