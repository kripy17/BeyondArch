import { ALL_TECHNIQUES } from "@/data/mitre";
import type { Finding } from "@/types/objects";

/**
 * MITRE Mapper (ANALYSIS_ENGINE §4c module 6).
 * A chain, not just an id: behavior → tactic → technique → evidence refs →
 * confidence. Techniques come from the frozen corpus (data/mitre.ts).
 */

export interface MitreMapping {
  technique: string;
  name: string;
  tactic: string;
  evidenceRefs: string[];
  confidence: Finding["confidence"];
  source: string;
}

export function techniqueInfo(id: string): { name: string; tactic: string } {
  const t = ALL_TECHNIQUES.find((x) => x.id === id);
  if (t) return { name: t.name, tactic: t.tactic };
  return { name: id, tactic: "unknown" };
}

export function mapFindings(findings: Finding[], source = "mitre-mapper"): MitreMapping[] {
  const out: MitreMapping[] = [];
  const seen = new Set<string>();
  for (const f of findings) {
    if (!f.technique || seen.has(f.technique)) continue;
    seen.add(f.technique);
    const { name, tactic } = techniqueInfo(f.technique);
    out.push({
      technique: f.technique,
      name,
      tactic,
      evidenceRefs: (f.observations ?? []).map((o) => o.id),
      confidence: f.confidence,
      source,
    });
  }
  return out;
}