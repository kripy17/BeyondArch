import { explainNode, getAllEdges, type Edge } from "@/lib/provenance";
import type { Case } from "@/data/case";
import { getUnifiedFindings, getUnifiedIOCs } from "@/components/investigation/legacy-adapter";

export interface ExplainableRef {
  kind: "ioc" | "finding" | "evidence";
  id: string;
}

/** Provenance recap answering Why / How / Source / Confidence / Relationships. */
export interface ObjectExplain {
  kind: "ioc" | "finding" | "evidence";
  id: string;
  label: string;
  /** Why does this exist? — the origin artifact (or the honest absence of one). */
  why: string;
  /** What created it? — the spine of supporting edges. */
  how: string[];
  /** Source — the union of origin edge sources. */
  source: string[];
  /** Confidence — the strongest edge confidence in the spine, or null. */
  confidence: number | null;
  /** Confidence — the weakest edge confidence in the spine, or null. */
  weakestConfidence: number | null;
  /** Relationships — all incident edges, newest first. */
  relationships: Edge[];
}

const LABEL_BY_KIND = { ioc: "observable", finding: "finding", evidence: "evidence" } as const;

export function explainableRefs(c: Case): ExplainableRef[] {
  const refs: ExplainableRef[] = [];
  for (const f of getUnifiedFindings(c)) refs.push({ kind: "finding", id: f.id });
  for (const io of getUnifiedIOCs(c)) refs.push({ kind: "ioc", id: io.id ?? io.value });
  for (const ev of (c.evidenceItems ?? [])) if (ev.id) refs.push({ kind: "evidence", id: ev.id });
  return refs;
}

/**
 * Explain one case object against the provenance store. Deterministic and
 * pure when `edges` is supplied — the five ROADMAP questions: why / how /
 * source / confidence / relationships.
 */
export function explainObject(c: Case, ref: ExplainableRef, edges: Edge[] = getAllEdges()): ObjectExplain {
  const { back, forward } = explainNode(ref.kind, ref.id, edges);
  const spine = [...back, ...forward];
  const label = objectLabel(c, ref);

  const origin = back.find((e) => e.from.kind === "artifact");
  const why = origin
    ? `originates from artifact "${origin.from.id}" via ${origin.relation} (${origin.source})`
    : back.length > 0
      ? `supported by ${back.length} provenance edge${back.length === 1 ? "" : "s"} but not linked to an artifact`
      : "no provenance edges found — created directly in the case";

  const sources = Array.from(new Set(spine.map((e) => e.source).filter(Boolean)));
  const conf = spine.filter((e) => typeof e.confidence === "number").map((e) => e.confidence as number);
  const confidence = conf.length ? Math.max(...conf) : null;
  const weakest = conf.length ? Math.min(...conf) : null;

  return {
    kind: ref.kind,
    id: ref.id,
    label,
    why,
    how: spine.map((e) => `${e.relation} ${e.from.kind}→${e.to.kind} · ${e.reason ?? ""} · ${e.source}`),
    source: sources,
    confidence,
    weakestConfidence: weakest,
    relationships: [...spine].sort((a, b) => b.ts.localeCompare(a.ts)),
  };
}

function objectLabel(c: Case, ref: ExplainableRef): string {
  if (ref.kind === "finding") {
    const f = getUnifiedFindings(c).find((x) => x.id === ref.id);
    return f?.title ?? `finding ${ref.id.slice(0, 8)}`;
  }
  if (ref.kind === "ioc") {
    const io = getUnifiedIOCs(c).find((x) => (x.id ?? x.value) === ref.id);
    return io ? `${io.type} · ${io.value}` : `observable ${ref.id.slice(0, 12)}`;
  }
  const ev = (c.evidenceItems ?? []).find((x) => x.id === ref.id);
  return ev?.title ?? `evidence ${ref.id.slice(0, 8)}`;
}

export { LABEL_BY_KIND };