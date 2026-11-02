import { objectId } from "@/lib/ids";
import { addEdge } from "@/lib/provenance";
import type { CorrelationMatch } from "./engine";
import type { Relationship } from "@/types/objects";

/**
 * Correlation memory (ANALYSIS_ENGINE §4e): a durable, analyst-reviewable
 * ledger of correlation matches. Unlike the in-memory matches returned by
 * `correlate`, records here persist across sessions and surfaces — the same
 * value re-observed in a new analysis updates `lastSeen`/`seen` on the same
 * record instead of creating a duplicate.
 *
 * Records never influence raw analysis: they exist for analyst review and
 * graph projection only. Storage is written here (the memory is a projection
 * of analysis output), never read by the engine — history is still injected
 * at call sites.
 */

export const L_CORRELATION = "ba.correlation.v1";

export type CorrelationStatus = "new" | "dismissed" | "confirmed";

export interface CorrelationRecord {
  id: string;
  dimension: CorrelationMatch["dimension"];
  value: string;
  label: string;
  matches: { ref: string; label: string }[];
  confidence: number;
  evidenceRefs: string[];
  /** surfaces/alerts that observed this match (merged, de-duplicated) */
  sources: string[];
  /** alert-created cases the match was projected into */
  caseIds: string[];
  /** analyst review state — re-observation never resets this */
  status: CorrelationStatus;
  /** number of times this same value was re-observed */
  seen: number;
  firstSeen: string;
  lastSeen: string;
  schemaVersion: 1;
}

export function correlationRecordId(dimension: CorrelationMatch["dimension"], value: string): string {
  return objectId("correlation", dimension, value);
}

function unique<T>(items: T[]): T[] {
  return [...new Set(items)];
}

function sortByLastSeen(records: CorrelationRecord[]): CorrelationRecord[] {
  return [...records].sort((a, b) => (a.lastSeen < b.lastSeen ? 1 : a.lastSeen > b.lastSeen ? -1 : 0));
}

export function loadCorrelationMemory(): CorrelationRecord[] {
  try {
    const raw = localStorage.getItem(L_CORRELATION);
    return raw ? sortByLastSeen(JSON.parse(raw) as CorrelationRecord[]) : [];
  } catch {
    return [];
  }
}

function saveCorrelationMemory(records: CorrelationRecord[]) {
  try {
    localStorage.setItem(L_CORRELATION, JSON.stringify(sortByLastSeen(records)));
  } catch {
    /* best-effort */
  }
}

/**
 * Persist correlation matches. Idempotent per (dimension, value): a
 * re-observation merges sources/caseIds/matches and bumps `seen`/`lastSeen`
 * on the existing record — no duplicates, no status resets.
 */
export function rememberCorrelation(
  matches: CorrelationMatch[],
  opts: { source: string; caseId?: string; ts?: Date },
): CorrelationRecord[] {
  const now = (opts.ts ?? new Date()).toISOString();
  const byId = new Map(loadCorrelationMemory().map((r) => [r.id, r]));

  for (const m of matches) {
    const id = correlationRecordId(m.dimension, m.value);
    const prior = byId.get(id);
    if (prior) {
      prior.lastSeen = now;
      prior.seen += 1;
      prior.label = m.label;
      prior.matches = m.matches;
      prior.confidence = m.confidence;
      prior.evidenceRefs = m.evidenceRefs;
      prior.sources = unique([...prior.sources, opts.source]);
      if (opts.caseId) prior.caseIds = unique([...(prior.caseIds ?? []), opts.caseId]);
      continue;
    }
    byId.set(id, {
      id,
      dimension: m.dimension,
      value: m.value,
      label: m.label,
      matches: m.matches,
      confidence: m.confidence,
      evidenceRefs: m.evidenceRefs,
      sources: [opts.source],
      caseIds: opts.caseId ? [opts.caseId] : [],
      status: "new",
      seen: 1,
      firstSeen: now,
      lastSeen: now,
      schemaVersion: 1,
    });
  }

  saveCorrelationMemory([...byId.values()]);
  return sortByLastSeen([...byId.values()]);
}

export function getCorrelationRecord(id: string): CorrelationRecord | undefined {
  return loadCorrelationMemory().find((r) => r.id === id);
}

export function setCorrelationStatus(id: string, status: CorrelationStatus): CorrelationRecord | undefined {
  const records = loadCorrelationMemory();
  const record = records.find((r) => r.id === id);
  if (!record) return undefined;
  record.status = status;
  saveCorrelationMemory(records);
  return record;
}

export function countCorrelationMemory(): number {
  return loadCorrelationMemory().length;
}

/**
 * Project entity-overlap correlation relationships into the provenance graph
 * as `enriched-by` ioc→entity edges (origin "correlation"). Skips matches
 * whose observation has no canonical ioc node (e.g. outside a case context).
 * addEdge is append-only and deterministic, so repeated projection is safe.
 */
export function projectCorrelationEdges(opts: {
  relationships: Relationship[];
  /** resolve an observation id to the canonical ioc node id (or undefined to skip) */
  iocNodeFor: (observationId: string) => string | undefined;
  source?: string;
}): number {
  const { relationships, iocNodeFor, source = "correlation" } = opts;
  let count = 0;
  for (const rel of relationships) {
    const iocId = iocNodeFor(rel.from.id);
    if (!iocId) continue;
    addEdge({
      relation: rel.relation,
      from: { kind: "ioc", id: iocId },
      to: rel.to,
      source,
      confidence: rel.confidence,
      reason: `correlation: ${rel.evidenceRefs.join(",")}`,
    });
    count += 1;
  }
  return count;
}