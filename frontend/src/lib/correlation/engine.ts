import { objectId } from "@/lib/ids";
import type { Relationship } from "@/types/objects";
import { INVESTIGATION_OBJECTS_V1 } from "@/types/objects";

/**
 * Correlation Engine v1 (ANALYSIS_ENGINE §4e).
 * Runs AFTER analysis so reasoning stays deterministic and unadjusted by
 * history. Local-only: matches prior-case values, existing detections, and
 * intel-corpus observable overlap. Matches are analyst-reviewed (origin
 * "correlation") — they never re-rank raw analysis.
 *
 * Storage is never read directly: history is injected (ANALYSIS_ENGINE §4d).
 */

export interface HistoryCase {
  id: string;
  title: string;
  /** canonical IOC values observed in that case (ip/domain/url/hash/email) */
  values: string[];
}

export interface HistoryDetection {
  id: string;
  name: string;
  technique?: string;
}

export interface HistoryEntity {
  id: string;
  name: string;
  observables: string[];
}

export interface CorrelationHistory {
  cases?: HistoryCase[];
  detections?: HistoryDetection[];
  entities?: HistoryEntity[];
}

export interface CorrelationMatch {
  dimension: "same-value-previous" | "existing-detection" | "entity-overlap";
  value: string;
  label: string;
  matches: { ref: string; label: string }[];
  confidence: number;
  evidenceRefs: string[];
}

export function correlate(
  observations: { id: string; kind: string; value: string }[],
  findings: { id: string; technique?: string; observationIds: string[] }[],
  history: CorrelationHistory,
): CorrelationMatch[] {
  const matches: CorrelationMatch[] = [];
  const valuesByCase = new Map<string, HistoryCase[]>();

  for (const c of history.cases ?? []) {
    for (const v of c.values) {
      const list = valuesByCase.get(v) ?? [];
      list.push(c);
      valuesByCase.set(v, list);
    }
  }

  const valueKinds = new Set(["ip", "domain", "url", "hash", "email"]);
  for (const o of observations) {
    if (!valueKinds.has(o.kind)) continue;
    const prior = valuesByCase.get(o.value);
    if (!prior || prior.length === 0) continue;
    matches.push({
      dimension: "same-value-previous",
      value: o.value,
      label: prior.length > 1 ? `seen in ${prior.length} prior cases` : `seen in prior case`,
      matches: prior.map((c) => ({ ref: c.id, label: c.title })),
      confidence: prior.length >= 2 ? 0.7 : 0.5,
      evidenceRefs: [o.id],
    });
  }

  const detectionByTechnique = new Map<string, HistoryDetection[]>();
  for (const d of history.detections ?? []) {
    if (!d.technique) continue;
    const list = detectionByTechnique.get(d.technique) ?? [];
    list.push(d);
    detectionByTechnique.set(d.technique, list);
  }
  for (const f of findings) {
    if (!f.technique) continue;
    const rule = detectionByTechnique.get(f.technique);
    if (!rule || rule.length === 0) continue;
    matches.push({
      dimension: "existing-detection",
      value: f.technique,
      label: `covered by existing detection`,
      matches: rule.map((r) => ({ ref: r.id, label: r.name })),
      confidence: 0.8,
      evidenceRefs: f.observationIds,
    });
  }

  const entityByObservable = new Map<string, HistoryEntity>();
  for (const e of history.entities ?? []) {
    for (const obs of e.observables) entityByObservable.set(obs, e);
  }
  for (const o of observations) {
    if (!valueKinds.has(o.kind)) continue;
    const entity = entityByObservable.get(o.value);
    if (!entity) continue;
    matches.push({
      dimension: "entity-overlap",
      value: entity.name,
      label: `observable of ${entity.name}`,
      matches: [{ ref: entity.id, label: entity.name }],
      confidence: 0.6,
      evidenceRefs: [o.id],
    });
  }

  return dedupe(matches);
}

function dedupe(matches: CorrelationMatch[]): CorrelationMatch[] {
  const seen = new Set<string>();
  return matches.filter((m) => {
    const key = `${m.dimension}|${m.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Correlation relationships for the graph — origin "correlation", analyst-reviewed. */
export function correlationRelationships(
  matches: CorrelationMatch[],
  source = "correlation-engine",
  ts: string,
) {
  const out: Relationship[] = [];
  for (const m of matches) {
    if (m.dimension !== "entity-overlap") continue;
    for (const hit of m.matches) {
      const from = { kind: "ioc" as const, id: m.evidenceRefs[0] ?? "unknown-observation" };
      const to = { kind: "entity" as const, id: hit.ref };
      out.push({
        id: objectId("relationship", "enriched-by", from.kind, from.id, to.kind, to.id),
        relation: "enriched-by",
        from,
        to,
        confidence: m.confidence,
        evidenceRefs: m.evidenceRefs,
        origin: "correlation",
        source,
        ts,
        schemaVersion: INVESTIGATION_OBJECTS_V1,
      });
    }
  }
  return out;
}