import type { Case, CaseEvent } from "@/data/case";

export type NodeKind = "artifact" | "evidence" | "finding" | "ioc" | "entity" | "mitre" | "detection" | "simulation" | "deployment" | "alert" | "case" | "enrichment";

export interface NodeRef {
  kind: NodeKind;
  id: string;
}

export type ProvenanceRelation = "produced" | "supports" | "extracts" | "enriched-by" | "mapped-to" | "drives" | "validates" | "deploys" | "fires" | "creates";

export const NODE_KIND_LIST = ["artifact", "evidence", "finding", "ioc", "entity", "mitre", "detection", "simulation", "deployment", "alert", "case", "enrichment"] as const satisfies readonly NodeKind[];

export const RELATION_LIST = ["produced", "supports", "extracts", "enriched-by", "mapped-to", "drives", "validates", "deploys", "fires", "creates"] as const satisfies readonly ProvenanceRelation[];

export interface Edge {
  id: string;
  relation: ProvenanceRelation;
  from: NodeRef;
  to: NodeRef;
  source: string;
  confidence?: number;
  ts: string;
  reason?: string;
}

export const LS_PROVENANCE = "ba.provenance.v1";

export function fnv1a(str: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/* ── deterministic node ids (detection lifecycle, §3) ───── */

export type LifecycleKind = "detection" | "simulation" | "deployment" | "alert";

/**
 * Deterministic node id for detection-lifecycle nodes. Identity derives from
 * stable content keys, never from random uuids — reruns reconnect (§9.3).
 */
export function lifecycleNodeId(kind: LifecycleKind, ...parts: string[]): string {
  const prefix = { detection: "det", simulation: "sim", deployment: "dep", alert: "al" }[kind];
  return `${prefix}-${fnv1a(parts.join("|"))}`;
}

/** Event digest used to key simulation nodes on (ruleId|eventDigest). */
export function eventDigest(text: string): string {
  return fnv1a(text.trim());
}

export function loadEdges(): Record<string, Edge> {
  try {
    const raw = localStorage.getItem(LS_PROVENANCE);
    return raw ? (JSON.parse(raw) as Record<string, Edge>) : {};
  } catch {
    return {};
  }
}

function saveEdges(map: Record<string, Edge>) {
  try {
    localStorage.setItem(LS_PROVENANCE, JSON.stringify(map));
  } catch {
    /* quota/private mode — provenance is best-effort */
  }
}

export function getAllEdges(): Edge[] {
  return Object.values(loadEdges());
}

/**
 * Append-only, idempotent edge write. Edge id is a stable hash of the triple
 * (relation, from, to) — re-asserting the same fact never duplicates it, and
 * an existing edge is never mutated (history stays immutable).
 */
export function addEdge(e: Omit<Edge, "id" | "ts"> & { ts?: string }): Edge {
  const id = `e-${fnv1a(`${e.relation}|${e.from.kind}:${e.from.id}|${e.to.kind}:${e.to.id}`)}`;
  const map = loadEdges();
  const existing = map[id];
  if (existing) return existing;
  const edge: Edge = { ...e, id, ts: e.ts ?? new Date().toISOString() };
  map[id] = edge;
  saveEdges(map);
  return edge;
}

export function getEdgesFor(kind: NodeKind, id: string) {
  const edges = getAllEdges();
  return {
    out: edges.filter((e) => e.from.kind === kind && e.from.id === id),
    in: edges.filter((e) => e.to.kind === kind && e.to.id === id),
  };
}

/* ── readers ────────────────────────────────────────────── */

function neighbors(edges: Edge[], node: NodeRef, dir: "in" | "out", relations?: ProvenanceRelation[]) {
  return edges
    .filter((e) => (dir === "in" ? e.to.kind === node.kind && e.to.id === node.id : e.from.kind === node.kind && e.from.id === node.id))
    .filter((e) => !relations || relations.includes(e.relation))
    .map((e) => (dir === "in" ? { next: e.from, edge: e } : { next: e.to, edge: e }));
}

/**
 * Shortest directed path between two nodes. Returns the edge list in
 * traversal order, or null when unreachable.
 */
export function path(from: NodeRef, to: NodeRef, relations?: ProvenanceRelation[]): Edge[] | null {
  const edges = getAllEdges();
  const queue: { node: NodeRef; edge: Edge | null }[] = [{ node: from, edge: null }];
  const visited = new Set<string>();
  const prev = new Map<string, Edge>();
  visited.add(`${from.kind}:${from.id}`);
  while (queue.length) {
    const { node, edge } = queue.shift()!;
    if (edge) prev.set(`${node.kind}:${node.id}`, edge);
    if (node.kind === to.kind && node.id === to.id) {
      const result: Edge[] = [];
      let cur = node;
      let guard = 0;
      while (cur.kind !== from.kind || cur.id !== from.id) {
        const e = prev.get(`${cur.kind}:${cur.id}`);
        if (!e || guard++ > 500) return null;
        result.unshift(e);
        cur = e.from;
      }
      return result;
    }
    for (const { next, edge: e } of neighbors(edges, node, "out", relations)) {
      const key = `${next.kind}:${next.id}`;
      if (!visited.has(key)) {
        visited.add(key);
        queue.push({ node: next, edge: e });
      }
    }
  }
  return null;
}

const BACK_RELATIONS: ProvenanceRelation[] = ["extracts", "supports", "produced"];
const FORWARD_RELATIONS: ProvenanceRelation[] = ["produced", "supports", "extracts", "enriched-by", "mapped-to", "drives", "validates", "deploys", "fires", "creates"];

/* ── backfill (§9 step 4) ───────────────────────────────── */

/**
 * Derive produced/supports/extracts edges from a legacy case's embedded
 * structure. Idempotent: runs once per artifact (guard: a produced edge for
 * that artifact already exists), stamps `source: "backfill"`.
 */
export function backfillCaseEdges(c: Case) {
  const artifactId = c.artifacts?.[0]?.id;
  if (!artifactId) return;
  const existing = getAllEdges();
  if (existing.some((e) => e.from.kind === "artifact" && e.from.id === artifactId)) return;
  const artifactRef: NodeRef = { kind: "artifact", id: artifactId };
  const iocsById = new Map((c.iocs ?? []).map((i) => [`${i.type}|${i.value}`, i.id!]));
  for (const ev of c.evidenceItems ?? []) {
    addEdge({ relation: "produced", from: artifactRef, to: { kind: "evidence", id: ev.id! }, source: "backfill", reason: "legacy embedded evidence" });
    if (ev.type === "finding") {
      const finding = (c.findings ?? []).find((f) => f.title === ev.title);
      if (finding) {
        addEdge({ relation: "supports", from: { kind: "evidence", id: ev.id! }, to: { kind: "finding", id: finding.id }, source: "backfill", reason: "legacy embedded evidence" });
      }
    }
  }
  for (const f of c.findings ?? []) {
    for (const ioc of f.iocs ?? []) {
      const id = iocsById.get(`${ioc.type}|${ioc.value}`);
      if (id) {
        addEdge({ relation: "extracts", from: { kind: "finding", id: f.id }, to: { kind: "ioc", id }, source: "backfill", reason: "legacy embedded ioc" });
      }
    }
  }
}

/**
 * Map findings with a MITRE technique onto technique nodes (`mapped-to`).
 * Runs independently of the artifact-spine backfill so pre-existing cases
 * still gain technique links. Idempotent via addEdge's stable hash.
 */
export function backfillMitreEdges(c: Case) {
  for (const f of c.findings ?? []) {
    if (!f.technique) continue;
    addEdge({
      relation: "mapped-to",
      from: { kind: "finding", id: f.id },
      to: { kind: "mitre", id: f.technique },
      source: "backfill",
      reason: "finding technique mapping",
    });
  }
}

/**
 * Explain a node: walk back to its artifact along the extraction spine,
 * walk forward through intel enrichment to the case finding.
 *
 * Forward walks continue until no eligible out-edge remains — a case finding
 * reached via `creates` has no further out-edges and terminates naturally,
 * which keeps the walk honest for finding/artifact start nodes too.
 */
export function explainNode(kind: NodeKind, id: string, edges: Edge[] = getAllEdges()): { back: Edge[]; forward: Edge[] } {
  const node = { kind, id };
  const spine: Edge[] = [];
  let cur = node;
  let guard = 0;
  while (cur.kind !== "artifact" && guard++ < 50) {
    const hop = neighbors(edges, cur, "in", BACK_RELATIONS)[0];
    if (!hop) break;
    spine.unshift(hop.edge);
    cur = hop.next;
  }
  const fwd: Edge[] = [];
  cur = node;
  guard = 0;
  while (guard++ < 50) {
    const hop = neighbors(edges, cur, "out", FORWARD_RELATIONS)[0];
    if (!hop) break;
    fwd.push(hop.edge);
    cur = hop.next;
  }
  return { back: spine, forward: fwd };
}

/* ── timeline projection (§9.5) ─────────────────────────── */

export interface ProjectedEvent {
  /** true when the event's referenced node participates in at least one stored edge */
  hasProvenance: boolean;
  /** causal spine in graph direction (back spine then forward), empty when no edges exist */
  edges: Edge[];
}

const EVENT_NODE_KINDS: Partial<Record<string, NodeKind>> = {
  artifact: "artifact",
  evidence: "evidence",
  finding: "finding",
  ioc: "ioc",
  detection: "detection",
  simulation: "simulation",
  deployment: "deployment",
  alert: "alert",
};

/**
 * Pure projection of CaseEvents onto the provenance graph. The result is
 * renderable directly — the UI never touches BFS or edge stores. Events
 * whose references do not map to a graph node (notes, decisions, status
 * changes) yield hasProvenance:false and are rendered as "no provenance
 * link" rather than being synthesized into the graph.
 */
export function projectTimeline(events: CaseEvent[], edges: Edge[] = getAllEdges()): Map<string, ProjectedEvent> {
  const out = new Map<string, ProjectedEvent>();
  for (const ev of events) {
    const ref = (ev.references ?? []).find((r) => EVENT_NODE_KINDS[r.kind]);
    if (!ref) {
      out.set(ev.id, { hasProvenance: false, edges: [] });
      continue;
    }
    const kind = EVENT_NODE_KINDS[ref.kind]!;
    const { back, forward } = explainNode(kind, ref.id, edges);
    out.set(ev.id, { hasProvenance: back.length + forward.length > 0, edges: [...back, ...forward] });
  }
  return out;
}
