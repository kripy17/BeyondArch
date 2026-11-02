import { loadCases } from "@/data/case";
import { loadItems } from "@/data/triage";
import { refang } from "@/lib/ioc-patterns";

/**
 * Entity timeline (ROADMAP-v4 V4.2): unified per-value appearance history
 * across the workspace stores that actually persist observable values —
 * cases and triaged alerts. Hunts and one-off analyses are NOT included:
 * their results are never written to storage with values attached, and
 * inventing appearances would be dishonest. The response states which
 * surfaces were covered so callers can say so.
 */

export type EntitySurface = "case" | "alert";

export interface EntityAppearance {
  ts: string;
  surface: EntitySurface;
  /** case id or triage item id */
  refId: string;
  title: string;
  /** case state or triage status */
  state?: string;
  detail: string;
}

export interface EntityTimelineResult {
  value: string;
  appearances: EntityAppearance[];
  surfacesCovered: EntitySurface[];
}

export function normalizeEntityValue(v: string): string {
  return refang(v).trim().toLowerCase();
}

function caseAppearances(norm: string): EntityAppearance[] {
  const out: EntityAppearance[] = [];
  for (const c of loadCases()) {
    let hit = false;
    let detail = "";
    for (const ioc of c.iocs ?? []) {
      if (!hit && normalizeEntityValue(ioc.value) === norm) {
        hit = true;
        detail = ioc.context || ioc.source || "";
      }
    }
    for (const e of c.entries) {
      if (e.kind !== "ioc") continue;
      if (!hit && normalizeEntityValue(e.body.trim()) === norm) {
        hit = true;
        detail = detail || "ioc entry";
      }
    }
    if (hit) {
      out.push({
        ts: c.createdAt,
        surface: "case",
        refId: c.id,
        title: c.title,
        state: c.state,
        detail,
      });
    }
  }
  return out;
}

function alertAppearances(norm: string): EntityAppearance[] {
  const out: EntityAppearance[] = [];
  for (const item of loadItems()) {
    const match = (item.iocs ?? []).some((i) => normalizeEntityValue(i.value) === norm);
    if (!match) continue;
    out.push({
      ts: item.ts,
      surface: "alert",
      refId: item.id,
      title: item.title,
      state: item.status,
      detail: item.source,
    });
  }
  return out;
}

export function entityTimeline(value: string): EntityTimelineResult {
  const norm = normalizeEntityValue(value);
  if (!norm) return { value, appearances: [], surfacesCovered: [] };
  const appearances = [
    ...caseAppearances(norm),
    ...alertAppearances(norm),
  ].sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
  return {
    value,
    appearances,
    surfacesCovered: [...new Set(appearances.map((a) => a.surface))] as EntitySurface[],
  };
}
