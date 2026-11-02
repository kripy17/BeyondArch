import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  useNodesState,
  useEdgesState,
  type Edge as FlowEdge,
  type Node as FlowNode,
  type NodeMouseHandler,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  X, Network, PackageOpen, Box, FileSearch, Siren, Crosshair, FolderOpen,
  Radar, ShieldCheck, FlaskConical, Send, Bell, RotateCcw, Search, ZoomIn,
  BookmarkPlus, Bookmark, Camera, Globe,
} from "lucide-react";
import type { Case } from "@/data/case";
import { useActiveCase } from "@/data/case";
import { getEntityById } from "@/data/intel";
import { ALL_TECHNIQUES } from "@/data/mitre";
import { detectionNodeId, loadRules, type SavedRule } from "@/data/detection";
import { ADAPTER_META, enrichmentHistory } from "@/lib/enrichment";
import { getAllEdges, explainNode, NODE_KIND_LIST, RELATION_LIST, type Edge, type NodeKind, type NodeRef, type ProvenanceRelation } from "@/lib/provenance";
import { useViewState } from "@/lib/use-session-view";
import {
  loadGraphViews, saveNamedView, deleteNamedView,
  type NamedGraphView,
} from "@/lib/graph-views";
import { graphSnapshotBody } from "@/lib/graph/snapshot";

const LAYER_ORDER: NodeKind[] = ["artifact", "evidence", "finding", "ioc", "entity", "mitre", "enrichment", "detection", "simulation", "deployment", "alert", "case"];
const LAYER_RANK: Record<NodeKind, number> = Object.fromEntries(LAYER_ORDER.map((k, i) => [k, i])) as Record<NodeKind, number>;

export type GraphMode = "relationship" | "timeline" | "detection" | "infrastructure" | "campaign";

const GRAPH_MODES: { id: GraphMode; label: string; hint: string }[] = [
  { id: "relationship", label: "Relationship", hint: "full provenance spine" },
  { id: "timeline", label: "Timeline", hint: "chronological ordering" },
  { id: "detection", label: "Detection", hint: "detection chain projection" },
  { id: "infrastructure", label: "Infrastructure", hint: "entities and observables" },
  { id: "campaign", label: "Campaign", hint: "techniques and TTPs" },
];

const MODE_LAYERS: Record<GraphMode, NodeKind[]> = {
  relationship: LAYER_ORDER,
  timeline: LAYER_ORDER,
  detection: ["artifact", "evidence", "finding", "mitre", "detection", "simulation", "deployment", "alert", "case"],
  infrastructure: ["artifact", "entity", "enrichment", "ioc", "mitre", "case"],
  campaign: ["finding", "ioc", "mitre", "detection", "case"],
};

const MODE_RELATIONS: Record<GraphMode, ProvenanceRelation[] | null> = {
  relationship: null,
  timeline: null,
  detection: ["mapped-to", "drives", "validates", "deploys", "fires", "creates", "supports"],
  infrastructure: ["extracts", "enriched-by", "produced", "creates"],
  campaign: ["mapped-to", "supports", "extracts", "produced"],
};

const HOP_LEVELS = [1, 2, 3] as const;

/** Session-recovery depth: graph controls persist per case so a reload
 * resumes the same projection. Sets serialize as arrays; hydration validates
 * against the type unions — junk never enters the filter state. */
interface GraphViewState {
  mode?: GraphMode;
  hops?: number | null;
  source?: string;
  confidence?: number | null;
  kinds?: NodeKind[] | null;
  relations?: ProvenanceRelation[] | null;
  viewport?: { x: number; y: number; zoom: number };
}

const NODE_KIND_SET = new Set<string>(NODE_KIND_LIST);
const RELATION_SET = new Set<string>(RELATION_LIST);

type HydratedGraphView = Required<Omit<GraphViewState, "kinds" | "relations" | "viewport">> & { kinds: NodeKind[] | null; relations: ProvenanceRelation[] | null; viewport?: { x: number; y: number; zoom: number } };

function hydrateGraphView(raw: GraphViewState | null): HydratedGraphView {
  const v = raw ?? {};
  const zoomOk = typeof v.viewport?.zoom === "number" && Number.isFinite(v.viewport.zoom) && v.viewport.zoom >= 0.15 && v.viewport.zoom <= 1.75;
  return {
    mode: GRAPH_MODES.some((m) => m.id === v.mode) ? (v.mode as GraphMode) : "relationship",
    hops: typeof v.hops === "number" && (HOP_LEVELS as readonly number[]).includes(v.hops) ? v.hops : null,
    source: typeof v.source === "string" ? v.source : "all",
    confidence: typeof v.confidence === "number" && v.confidence >= 0 ? v.confidence : null,
    kinds: Array.isArray(v.kinds) ? v.kinds.filter((k): k is NodeKind => NODE_KIND_SET.has(k)) : null,
    relations: Array.isArray(v.relations) ? v.relations.filter((r): r is ProvenanceRelation => RELATION_SET.has(r)) : null,
    viewport: zoomOk && Number.isFinite(v.viewport!.x) && Number.isFinite(v.viewport!.y)
      ? { x: v.viewport!.x, y: v.viewport!.y, zoom: v.viewport!.zoom }
      : undefined,
  };
}

const NODE_W = 208;
const GAP_X = 56;
const GAP_Y = 96;

const KIND_STYLE: Record<NodeKind, { border: string; text: string; chip: string; icon: typeof Box }> = {
  artifact: { border: "border-primary/50", text: "text-primary", chip: "border-primary/40 bg-primary/10", icon: Box },
  evidence: { border: "border-info/40", text: "text-info", chip: "border-info/40 bg-info/10", icon: FileSearch },
  finding: { border: "border-warning/40", text: "text-warning", chip: "border-warning/40 bg-warning/10", icon: Crosshair },
  ioc: { border: "border-destructive/50", text: "text-destructive", chip: "border-destructive/40 bg-destructive/10", icon: Siren },
  entity: { border: "border-primary/40", text: "text-primary", chip: "border-primary/40 bg-primary/10", icon: PackageOpen },
  enrichment: { border: "border-info/40", text: "text-info", chip: "border-info/40 bg-info/10", icon: Globe },
  mitre: { border: "border-accent/50", text: "text-accent", chip: "border-accent/40 bg-accent/10", icon: Radar },
  detection: { border: "border-success/40", text: "text-success", chip: "border-success/40 bg-success/10", icon: ShieldCheck },
  simulation: { border: "border-chart-1/50", text: "text-chart-1", chip: "border-chart-1/40 bg-chart-1/10", icon: FlaskConical },
  deployment: { border: "border-chart-2/50", text: "text-chart-2", chip: "border-chart-2/40 bg-chart-2/10", icon: Send },
  alert: { border: "border-chart-3/50", text: "text-chart-3", chip: "border-chart-3/40 bg-chart-3/10", icon: Bell },
  case: { border: "border-border", text: "text-foreground", chip: "border-border bg-surface-1", icon: FolderOpen },
};

interface GraphNode {
  ref: NodeRef;
  label: string;
  sub?: string;
}

interface GraphData {
  nodes: GraphNode[];
  edges: Edge[];
}

interface LabelCtx {
  edges: Edge[];
  rules: SavedRule[];
}

/** Walk an incident edge chain back to the detection heading the rule — or (mitre) its upstream. */
function findRuleName(ref: NodeRef, edges: Edge[], rules: SavedRule[]): string | null {
  const visited = new Set<string>();
  let cur = ref;
  for (let i = 0; i < 5; i++) {
    const key = `${cur.kind}:${cur.id}`;
    if (visited.has(key)) return null;
    visited.add(key);
    if (cur.kind === "mitre") {
      const t = ALL_TECHNIQUES.find((x) => x.id === cur.id);
      return t ? `${t.id} · ${t.name}` : cur.id;
    }
    if (cur.kind === "detection") {
      const rule = rules.find((r) => detectionNodeId(r.ruleKey) === cur.id);
      return rule ? rule.name : cur.id;
    }
    const incoming = edges.find((e) => e.to.kind === cur.kind && e.to.id === cur.id);
    if (!incoming) return null;
    cur = incoming.from;
  }
  return null;
}

function caseLabel(ref: NodeRef, c: Case, ctx?: LabelCtx): string | null {
  const ruleName = ctx ? findRuleName(ref, ctx.edges, ctx.rules) : null;
  switch (ref.kind) {
    case "artifact": return c.artifacts?.find((a) => a.id === ref.id)?.title ?? null;
    case "evidence": return c.evidenceItems?.find((x) => x.id === ref.id)?.title ?? null;
    case "finding": return c.findings?.find((f) => f.id === ref.id)?.title ?? null;
    case "ioc": return c.iocs?.find((x) => x.id === ref.id)?.value ?? null;
    case "enrichment": {
      const r = enrichmentHistory().find((x) => x.id === ref.id);
      if (!r) return null;
      return `${ADAPTER_META[r.adapter].label} · ${r.query}`;
    }
    case "entity": return getEntityById(ref.id)?.title ?? null;
    case "mitre": {
      const t = ALL_TECHNIQUES.find((x) => x.id === ref.id);
      return t ? `${t.id} · ${t.name}` : ref.id;
    }
    case "case": return ref.id === c.id ? c.title : null;
    case "detection": return ruleName;
    case "simulation": return ruleName ? `${ruleName} · simulation` : "simulation";
    case "deployment": return ruleName ? `${ruleName} · deployment` : "deployment";
    case "alert": return ruleName ? `${ruleName} · alert` : "alert";
    default: return null;
  }
}

function incidentReason(ref: NodeRef, ctx?: LabelCtx): string | undefined {
  if (!ctx) return undefined;
  const e = ctx.edges.find((x) => x.to.kind === ref.kind && x.to.id === ref.id);
  return e?.reason ?? (ref.kind === "detection" ? "no provenance link" : undefined);
}

function nodeSub(ref: NodeRef, c: Case, ctx?: LabelCtx): string | undefined {
  switch (ref.kind) {
    case "ioc": {
      const ioc = c.iocs?.find((x) => x.id === ref.id);
      return ioc ? `${ioc.type} · ${ioc.severity}` : undefined;
    }
    case "finding": {
      const f = c.findings?.find((x) => x.id === ref.id);
      return f ? `sev: ${f.severity}` : undefined;
    }
    case "artifact": {
      const a = c.artifacts?.find((x) => x.id === ref.id);
      return a ? a.kind : undefined;
    }
    case "mitre": {
      const t = ALL_TECHNIQUES.find((x) => x.id === ref.id);
      return t ? t.tactic : undefined;
    }
    case "enrichment": {
      const r = enrichmentHistory().find((x) => x.id === ref.id);
      return r ? `${r.confidence} · ${r.collectedAt.slice(0, 10)}` : undefined;
    }
    case "detection": {
      const rule = ctx?.rules.find((r) => detectionNodeId(r.ruleKey) === ref.id);
      return rule ? `${rule.state} · v${rule.version}` : undefined;
    }
    case "simulation":
    case "deployment":
    case "alert":
      return incidentReason(ref, ctx);
    case "case": {
      const fromTriage = c.tags.includes("triage") || (c.events ?? []).some((e) => e.origin === "triage-escalation");
      return fromTriage ? `triage escalation · ${c.state}` : undefined;
    }
    default: return undefined;
  }
}

export function buildGraphData(c: Case): GraphData {
  const edges = getAllEdges();
  const ctx: LabelCtx = { edges, rules: loadRules() };
  const filtered = edges.filter((e) => {
    const from = caseLabel(e.from, c, ctx);
    const to = caseLabel(e.to, c, ctx);
    if (from === null || to === null) return false;
    const rankFrom = LAYER_RANK[e.from.kind] ?? 99;
    const rankTo = LAYER_RANK[e.to.kind] ?? 99;
    return rankFrom < rankTo;
  });
  const byRef = new Map<string, GraphNode>();
  for (const e of filtered) {
    for (const ref of [e.from, e.to]) {
      const key = `${ref.kind}:${ref.id}`;
      if (byRef.has(key)) continue;
      const label = caseLabel(ref, c, ctx);
      if (label === null) continue;
      byRef.set(key, { ref, label, sub: nodeSub(ref, c, ctx) });
    }
  }
  return { nodes: [...byRef.values()], edges: filtered };
}

/** Node timestamp: earliest incident edge ts, else the case creation time. */
export function nodeTime(ref: NodeRef, c: Case, edges: Edge[]): string {
  const incident = edges
    .filter((e) => (e.from.kind === ref.kind && e.from.id === ref.id) || (e.to.kind === ref.kind && e.to.id === ref.id))
    .map((e) => e.ts)
    .sort();
  return incident[0] ?? c.createdAt;
}

/**
 * Expand levels: nodes within `hops` undirected edges of the focus node.
 * Returns null when no focus is set. The focus node itself is always kept.
 */
export function expandHops(edges: Edge[], focusKey: string, hops: number): Set<string> | null {
  if (!focusKey) return null;
  const adj = new Map<string, Set<string>>();
  for (const e of edges) {
    const a = `${e.from.kind}:${e.from.id}`;
    const b = `${e.to.kind}:${e.to.id}`;
    if (!adj.has(a)) adj.set(a, new Set());
    if (!adj.has(b)) adj.set(b, new Set());
    adj.get(a)!.add(b);
    adj.get(b)!.add(a);
  }
  const seen = new Set<string>([focusKey]);
  let frontier = [focusKey];
  for (let h = 0; h < hops; h++) {
    const next: string[] = [];
    for (const key of frontier) {
      for (const nb of adj.get(key) ?? []) {
        if (!seen.has(nb)) {
          seen.add(nb);
          next.push(nb);
        }
      }
    }
    frontier = next;
    if (frontier.length === 0) break;
  }
  return seen;
}

/** Rank lookup for a mode's layer order. */
export function modeRankOf(mode: GraphMode, kind: NodeKind): number {
  const order = MODE_LAYERS[mode];
  const idx = order.indexOf(kind);
  return idx === -1 ? 99 : idx;
}

/* ── React Flow adapters ───────────────────────────────── */

type KindNodeData = { label: string; sub?: string; kind: NodeKind };
type KindFlowNode = FlowNode<KindNodeData, "kind">;
type KindFlowEdge = FlowEdge<{ e: Edge }>;

type NodeDerived = { dim: boolean; match: boolean; sel: boolean };
const GraphDerivedContext = createContext<Map<string, NodeDerived> | null>(null);

function nodeKey(ref: NodeRef) {
  return `${ref.kind}:${ref.id}`;
}

function KindNodeComponent({ id, data }: NodeProps<KindFlowNode>) {
  const style = KIND_STYLE[data.kind];
  const Icon = style.icon;
  const derived = useContext(GraphDerivedContext)?.get(id);
  return (
    <div
      className={
        "flex w-[208px] items-center gap-2 rounded-md border bg-surface-0 px-2.5 py-2 text-left shadow-sm transition-opacity duration-150 " +
        (derived?.sel ? "border-primary bg-primary/10" : style.border) + " " +
        (derived?.dim ? "opacity-25" : "") + " " +
        (derived?.match ? "border-accent ring-1 ring-accent/50" : "")
      }
    >
      <Handle type="target" position={Position.Top} className="!h-1 !w-1 !opacity-0" />
      <span className={"grid h-6 w-6 shrink-0 place-items-center rounded border " + style.chip}>
        <Icon className={"h-3 w-3 " + style.text} />
      </span>
      <span className="min-w-0 flex-1">
        <span className={"block truncate text-mono ba-text-xs " + style.text}>{data.label}</span>
        {data.sub && <span className="block truncate text-mono ba-text-3xs text-muted-foreground">{data.sub}</span>}
      </span>
      <span className="shrink-0 text-mono ba-text-3xs uppercase text-fg-dim">{data.kind}</span>
      <Handle type="source" position={Position.Bottom} className="!h-1 !w-1 !opacity-0" />
    </div>
  );
}

const nodeTypes = { kind: KindNodeComponent };

const EDGE_COLOR = "var(--color-border)";
const EDGE_LABEL_STYLE: CSSProperties = { fontSize: 9, fontFamily: "var(--font-mono)", fill: "var(--color-muted-foreground)", pointerEvents: "none" };
const EDGE_LABEL_BG: CSSProperties = { fill: "var(--color-background)", fillOpacity: 0.92 };

/* ── graph component ────────────────────────────────────── */

function GraphInner({ caseData, className, onSnapshot }: { caseData: Case; className?: string; onSnapshot?: (body: string) => void }) {
  const { nodes: baseNodes, edges: baseEdges } = useMemo(() => buildGraphData(caseData), [caseData]);
  const [selected, setSelected] = useState<NodeRef | null>(null);
  const [hover, setHover] = useState<NodeRef | null>(null);
  const [search, setSearch] = useState("");
  const [view, setView, resetViewState] = useViewState<GraphViewState>(`graph:${caseData.id}`, {});
  const restored = useMemo(() => hydrateGraphView(view), []); // eslint-disable-line react-hooks/exhaustive-deps -- hydrate once per case mount
  const restoredViewportRef = useRef(restored.viewport);
  const [mode, setMode] = useState<GraphMode>(restored.mode);
  const [hopLimit, setHopLimit] = useState<number | null>(restored.hops);
  const [sourceFilter, setSourceFilter] = useState<string>(restored.source);
  const [minConfidence, setMinConfidence] = useState<number | null>(restored.confidence);
  const [kindFilter, setKindFilter] = useState<Set<NodeKind> | null>(() => (restored.kinds ? new Set(restored.kinds) : null));
  const [relationFilter, setRelationFilter] = useState<Set<ProvenanceRelation> | null>(() => (restored.relations ? new Set(restored.relations) : null));

  // Controls merge-write so concurrent viewport writes (onMoveEnd) survive.
  useEffect(() => {
    setView((prev) => ({
      ...prev,
      mode,
      hops: hopLimit,
      source: sourceFilter,
      confidence: minConfidence,
      kinds: kindFilter ? [...kindFilter] : null,
      relations: relationFilter ? [...relationFilter] : null,
    }));
  }, [mode, hopLimit, sourceFilter, minConfidence, kindFilter, relationFilter, setView]);

  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<KindFlowNode>([]);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState<KindFlowEdge>([]);
  const { fitView, getViewport, setViewport } = useReactFlow();
  const mounted = useRef(false);
  const userModeChange = useRef(false);
  const changeMode = useCallback((m: GraphMode) => {
    userModeChange.current = true;
    setMode(m);
  }, []);
  const posRef = useRef(new Map<string, { x: number; y: number }>());

  const onMoveEnd = useCallback(() => {
    const vp = getViewport();
    setView((prev) => ({ ...prev, viewport: vp }));
  }, [getViewport, setView]);

  const modeKinds = useMemo(() => new Set(MODE_LAYERS[mode]), [mode]);
  const modeRels = useMemo(() => new Set(MODE_RELATIONS[mode] ?? []), [mode]);

  const presentKinds = useMemo(() => new Set(baseNodes.filter((n) => modeKinds.has(n.ref.kind)).map((n) => n.ref.kind)), [baseNodes, modeKinds]);
  const presentRelations = useMemo(() => new Set(baseEdges.map((e) => e.relation).filter((r) => (MODE_RELATIONS[mode] === null ? true : modeRels.has(r)))) as Set<ProvenanceRelation>, [baseEdges, mode, modeRels]);

  const presentSources = useMemo(() => ["all", ...new Set(baseEdges.map((e) => e.source))], [baseEdges]);

  const focusKey = useMemo(() => {
    const f = hover ?? selected;
    return f ? nodeKey(f) : null;
  }, [hover, selected]);

  const visible = useMemo(() => {
    const kinds = kindFilter ?? presentKinds;
    const rels = relationFilter ?? presentRelations;
    const edges = baseEdges.filter(
      (e) =>
        rels.has(e.relation) &&
        kinds.has(e.from.kind) &&
        kinds.has(e.to.kind) &&
        modeKinds.has(e.from.kind) &&
        modeKinds.has(e.to.kind) &&
        (modeRels.size === 0 || modeRels.has(e.relation)) &&
        (sourceFilter === "all" || e.source === sourceFilter) &&
        (minConfidence === null || (e.confidence ?? 0) >= minConfidence),
    );
    let nodes = baseNodes.filter((n) => kinds.has(n.ref.kind) && modeKinds.has(n.ref.kind));
    const focused = focusKey
      ? () => {
          const [k, id] = focusKey.split(":");
          return nodes.find((n) => n.ref.kind === k && n.ref.id === id) ?? null;
        }
      : () => null;
    const hopSet = hopLimit !== null && focusKey ? expandHops(edges, focusKey, hopLimit) : null;
    let outEdges = edges;
    if (hopSet) {
      const keep = new Set(hopSet);
      const f = focused();
      if (f) keep.add(`${f.ref.kind}:${f.ref.id}`);
      nodes = nodes.filter((n) => keep.has(nodeKey(n.ref)));
      outEdges = edges.filter((e) => keep.has(nodeKey(e.from)) && keep.has(nodeKey(e.to)));
    }
    return { nodes, edges: outEdges };
  }, [baseNodes, baseEdges, kindFilter, relationFilter, presentKinds, presentRelations, modeKinds, modeRels, sourceFilter, minConfidence, hopLimit, focusKey]);

  const neighborSet = useMemo(() => {
    if (!focusKey) return null;
    const set = new Set<string>([focusKey]);
    for (const e of visible.edges) {
      const a = nodeKey(e.from);
      const b = nodeKey(e.to);
      if (a === focusKey) set.add(b);
      else if (b === focusKey) set.add(a);
    }
    return set;
  }, [focusKey, visible.edges]);

  const derived = useMemo(() => {
    const map = new Map<string, NodeDerived>();
    const q = search.trim().toLowerCase();
    for (const n of visible.nodes) {
      const key = nodeKey(n.ref);
      map.set(key, {
        dim: focusKey !== null && !(neighborSet?.has(key) ?? false),
        match: q !== "" && n.label.toLowerCase().includes(q),
        sel: selected !== null && key === nodeKey(selected),
      });
    }
    return map;
  }, [visible.nodes, focusKey, neighborSet, selected, search]);

  useEffect(() => {
    if (!userModeChange.current) return;
    userModeChange.current = false;
    posRef.current.clear();
    const id = requestAnimationFrame(() => fitView({ padding: 0.15, maxZoom: 1 }));
    return () => cancelAnimationFrame(id);
  }, [mode, fitView]);

  useEffect(() => {
    const layers = new Map<number, GraphNode[]>();
    for (const n of visible.nodes) {
      const rank = modeRankOf(mode, n.ref.kind);
      layers.set(rank, [...(layers.get(rank) ?? []), n]);
    }
    for (const [rank, group] of layers) {
      const width = group.length * NODE_W + (group.length - 1) * GAP_X;
      const x0 = -width / 2;
      const ordered = mode === "timeline"
        ? [...group].sort((a, b) => (nodeTime(a.ref, caseData, visible.edges) < nodeTime(b.ref, caseData, visible.edges) ? -1 : 1))
        : group;
      ordered.forEach((n, i) => {
        const key = nodeKey(n.ref);
        if (!posRef.current.has(key)) {
          posRef.current.set(key, { x: x0 + i * (NODE_W + GAP_X), y: rank * GAP_Y });
        }
      });
    }
    const flowNodes: KindFlowNode[] = visible.nodes.map((n) => {
      const key = nodeKey(n.ref);
      return {
        id: key,
        type: "kind",
        position: posRef.current.get(key) ?? { x: 0, y: modeRankOf(mode, n.ref.kind) * GAP_Y },
        data: { label: n.label, sub: n.sub, kind: n.ref.kind },
      };
    });
    setRfNodes(flowNodes);
    if (!mounted.current && !restoredViewportRef.current) {
      mounted.current = true;
      const id = requestAnimationFrame(() => fitView({ padding: 0.15, maxZoom: 1 }));
      return () => cancelAnimationFrame(id);
    }
    mounted.current = true;
  }, [visible, mode, caseData, setRfNodes, fitView]);

  useEffect(() => {
    const q = search.trim().toLowerCase();
    const qMatch = q === "" ? null : (n: NodeRef) => {
      const node = baseNodes.find((x) => x.ref.kind === n.kind && x.ref.id === n.id);
      return node ? node.label.toLowerCase().includes(q) : false;
    };
    const flowEdges: KindFlowEdge[] = visible.edges.map((e) => {
      const onFocus = focusKey !== null && (nodeKey(e.from) === focusKey || nodeKey(e.to) === focusKey);
      const matchPair = qMatch !== null && qMatch(e.from) && qMatch(e.to);
      return {
        id: e.id,
        source: nodeKey(e.from),
        target: nodeKey(e.to),
        markerEnd: { type: MarkerType.ArrowClosed, width: 13, height: 13, color: EDGE_COLOR },
        style: {
          stroke: EDGE_COLOR,
          strokeWidth: 1,
          opacity: focusKey !== null && !onFocus ? 0.15 : matchPair === false ? 0.15 : 1,
        },
        label: onFocus ? e.relation : undefined,
        labelStyle: EDGE_LABEL_STYLE,
        labelBgStyle: EDGE_LABEL_BG,
        labelBgPadding: [3, 2] as [number, number],
        data: { e },
      };
    });
    setRfEdges(flowEdges);
  }, [visible.edges, focusKey, search, baseNodes, setRfEdges]);

  const setFocus = useCallback((ref: NodeRef | null, which: "hover" | "selected") => {
    const setter = which === "hover" ? setHover : setSelected;
    setter((cur) => (cur && ref && cur.kind === ref.kind && cur.id === ref.id ? cur : ref));
  }, []);

  const onNodeClick: NodeMouseHandler<KindFlowNode> = useCallback((_, node) => {
    const ref: NodeRef = { kind: node.data.kind, id: node.id.slice(node.id.indexOf(":") + 1) };
    setSelected((cur) => (cur && cur.kind === ref.kind && cur.id === ref.id ? null : ref));
    setHover(null);
  }, []);

  const onNodeMouseEnter: NodeMouseHandler<KindFlowNode> = useCallback((_, node) => {
    setFocus({ kind: node.data.kind, id: node.id.slice(node.id.indexOf(":") + 1) }, "hover");
  }, [setFocus]);

  const onNodeMouseLeave = useCallback(() => setFocus(null, "hover"), [setFocus]);

  const resetView = useCallback(() => {
    setSelected(null);
    setHover(null);
    setSearch("");
    setHopLimit(null);
    setSourceFilter("all");
    setMinConfidence(null);
    setKindFilter(null);
    setRelationFilter(null);
    resetViewState();
    posRef.current.clear();
    requestAnimationFrame(() => fitView({ padding: 0.15, maxZoom: 1 }));
  }, [fitView, resetViewState]);

  const [namedViews, setNamedViews] = useState<NamedGraphView[]>(() => loadGraphViews(caseData.id));
  const [viewNameDraft, setViewNameDraft] = useState("");

  const saveCurrentView = useCallback(() => {
    const name = viewNameDraft.trim();
    if (!name) return;
    try {
      saveNamedView(
        caseData.id,
        name,
        {
          mode,
          hops: hopLimit,
          source: sourceFilter,
          confidence: minConfidence,
          kinds: kindFilter ? [...kindFilter] : null,
          relations: relationFilter ? [...relationFilter] : null,
        },
        selected ? nodeKey(selected) : null,
        getViewport(),
      );
      setNamedViews(loadGraphViews(caseData.id));
      setViewNameDraft("");
    } catch { /* empty name — button disabled anyway */ }
  }, [caseData.id, viewNameDraft, mode, hopLimit, sourceFilter, minConfidence, kindFilter, relationFilter, selected, getViewport]);

  const applyNamedView = useCallback((v: NamedGraphView) => {
    const st = v.state;
    const hasVp = v.viewport !== null;
    const targetMode: GraphMode = GRAPH_MODES.some((m) => m.id === st.mode) ? (st.mode as GraphMode) : "relationship";
    if (targetMode !== mode && !hasVp) changeMode(targetMode);
    else setMode(targetMode);
    setHopLimit(typeof st.hops === "number" && (HOP_LEVELS as readonly number[]).includes(st.hops) ? st.hops : null);
    setSourceFilter(typeof st.source === "string" ? st.source : "all");
    setMinConfidence(typeof st.confidence === "number" && st.confidence >= 0 ? st.confidence : null);
    setKindFilter(Array.isArray(st.kinds) && st.kinds.length > 0
      ? new Set(st.kinds.filter((k): k is NodeKind => typeof k === "string" && NODE_KIND_SET.has(k)))
      : null);
    setRelationFilter(Array.isArray(st.relations) && st.relations.length > 0
      ? new Set(st.relations.filter((r): r is ProvenanceRelation => typeof r === "string" && RELATION_SET.has(r)))
      : null);
    const idx = v.focus !== null ? v.focus.indexOf(":") : -1;
    const focusRef: NodeRef | null = idx > 0
      ? { kind: v.focus!.slice(0, idx) as NodeKind, id: v.focus!.slice(idx + 1) }
      : null;
    setSelected(focusRef && baseNodes.some((n) => n.ref.kind === focusRef.kind && n.ref.id === focusRef.id) ? focusRef : null);
    if (hasVp && v.viewport) {
      const vp = v.viewport;
      requestAnimationFrame(() => setViewport(vp));
    }
  }, [baseNodes, changeMode, mode, setMode, setViewport]);

  const removeNamedView = useCallback((id: string) => {
    deleteNamedView(caseData.id, id);
    setNamedViews(loadGraphViews(caseData.id));
  }, [caseData.id]);

  const takeSnapshot = useCallback(() => {
    if (!onSnapshot) return;
    onSnapshot(graphSnapshotBody({
      mode,
      hopLimit,
      sourceFilter,
      minConfidence,
      kindFilter: kindFilter ? [...kindFilter] : null,
      relationFilter: relationFilter ? [...relationFilter] : null,
      focus: focusKey,
      nodeCount: visible.nodes.length,
      edgeCount: visible.edges.length,
    }));
  }, [onSnapshot, mode, hopLimit, sourceFilter, minConfidence, kindFilter, relationFilter, focusKey, visible]);

  const toggleKind = (k: NodeKind) => {
    setKindFilter((cur) => {
      const base = cur ?? presentKinds;
      const next = new Set(base);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  };

  const toggleRelation = (r: ProvenanceRelation) => {
    setRelationFilter((cur) => {
      const base = cur ?? presentRelations;
      const next = new Set(base);
      if (next.has(r)) next.delete(r);
      else next.add(r);
      return next;
    });
  };

  const selectedDetail = selected
    ? (() => {
        const node = baseNodes.find((n) => n.ref.kind === selected.kind && n.ref.id === selected.id);
        if (!node) return null;
        const { back, forward } = explainNode(selected.kind, selected.id);
        const detail: Record<string, string> = {};
        if (selected.kind === "ioc") {
          const ioc = caseData.iocs?.find((x) => x.id === selected.id);
          if (ioc) { detail["type"] = ioc.type; detail["severity"] = ioc.severity; detail["source"] = ioc.source; }
        } else if (selected.kind === "finding") {
          const f = caseData.findings?.find((x) => x.id === selected.id);
          if (f) { detail["severity"] = f.severity; detail["source"] = f.source; if (f.technique) detail["technique"] = f.technique; }
        } else if (selected.kind === "artifact") {
          const a = caseData.artifacts?.find((x) => x.id === selected.id);
          if (a) detail["kind"] = a.kind;
        } else if (selected.kind === "mitre") {
          const t = ALL_TECHNIQUES.find((x) => x.id === selected.id);
          if (t) detail["tactic"] = t.tactic;
        }
        const origin = back[0] ? labelFor(back[0].from) : null;
        const createdBy = back.map((e) => e.source).filter(Boolean);
        const evidenceFor = [...back, ...forward].filter((e) => e.relation === "supports" || e.relation === "validates");
        const usedIn = forward.map((e) => labelFor(e.to)).filter(Boolean);
        return { node, edges: [...back, ...forward], detail, origin, createdBy, evidenceFor, usedIn };
      })()
    : null;

  function labelFor(ref: NodeRef): string | null {
    return baseNodes.find((n) => n.ref.kind === ref.kind && n.ref.id === ref.id)?.label ?? null;
  }

  if (baseEdges.length === 0) {
    return (
      <div className={"flex flex-col items-center gap-2 px-4 py-14 text-mono ba-text-2xs text-muted-foreground " + (className ?? "")}>
        <Network className="h-8 w-8 opacity-40" />
        <p>No provenance links yet.</p>
        <p className="ba-text-2xs text-center">Run an analyzer on an artifact, add findings, or extract IOCs to build the graph.</p>
      </div>
    );
  }

  return (
    <div className={className ?? ""}>
      <div className="mb-2 flex flex-wrap items-center gap-1.5">
        {GRAPH_MODES.map((m) => (
          <button
            key={m.id}
            onClick={() => changeMode(m.id)}
            title={m.hint}
            className={
              "rounded border px-1.5 py-0.5 text-mono ba-text-3xs transition-colors " +
              (mode === m.id ? "border-accent/50 bg-accent/10 text-accent" : "border-border text-muted-foreground hover:text-foreground")
            }
          >
            {m.label}
          </button>
        ))}
        <span className="text-mono ba-text-3xs text-muted-foreground">{GRAPH_MODES.find((m) => m.id === mode)?.hint}</span>
      </div>
      <div className="mb-2 flex flex-wrap items-center gap-1.5">
        <div className="relative flex items-center">
          <Search className="pointer-events-none absolute left-2 h-3 w-3 text-muted-foreground" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="find node…"
            className="h-6 w-44 rounded border border-border bg-surface-0 pl-6 pr-1.5 text-mono ba-text-3xs text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/60"
          />
        </div>
        <select
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value)}
          title="Filter by provenance source"
          className="h-6 rounded border border-border bg-surface-0 px-1.5 text-mono ba-text-3xs text-foreground outline-none focus:border-primary/60"
        >
          {presentSources.map((s) => <option key={s} value={s}>{s === "all" ? "source: all" : s}</option>)}
        </select>
        <select
          value={minConfidence ?? "any"}
          onChange={(e) => setMinConfidence(e.target.value === "any" ? null : Number(e.target.value))}
          title="Minimum edge confidence"
          className="h-6 rounded border border-border bg-surface-0 px-1.5 text-mono ba-text-3xs text-foreground outline-none focus:border-primary/60"
        >
          <option value="any">confidence: any</option>
          <option value="50">confidence ≥ 50</option>
          <option value="75">confidence ≥ 75</option>
          <option value="90">confidence ≥ 90</option>
        </select>
        <div className="flex items-center gap-1">
          {HOP_LEVELS.map((h) => (
            <button
              key={h}
              onClick={() => setHopLimit((cur) => (cur === h ? null : h))}
              disabled={!focusKey}
              title={focusKey ? `${h}-hop expansion from focused node` : "select a node to expand around it"}
              className={
                "rounded border px-1.5 py-0.5 text-mono ba-text-3xs transition-colors " +
                (hopLimit === h ? "border-info/50 bg-info/10 text-info" : "border-border text-muted-foreground hover:text-foreground") +
                (focusKey ? "" : " opacity-40")
              }
            >
              {h} hop{h > 1 ? "s" : ""}
            </button>
          ))}
        </div>
        <button onClick={resetView} title="Fit graph and reset filters" className="grid h-6 w-6 place-items-center rounded border border-border text-muted-foreground hover:bg-surface-1 hover:text-foreground">
          <ZoomIn className="h-3 w-3" />
        </button>
        <button onClick={resetView} title="Reset layout" className="grid h-6 w-6 place-items-center rounded border border-border text-muted-foreground hover:bg-surface-1 hover:text-foreground">
          <RotateCcw className="h-3 w-3" />
        </button>
        <div className="mx-1 h-4 w-px bg-divider-strong" />
        <input
          value={viewNameDraft}
          onChange={(e) => setViewNameDraft(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") saveCurrentView(); }}
          placeholder="view name…"
          aria-label="Name for saved graph view"
          className="h-6 w-28 rounded border border-border bg-surface-0 px-1.5 text-mono ba-text-3xs text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/60"
        />
        <button
          onClick={saveCurrentView}
          disabled={!viewNameDraft.trim()}
          title={selected ? `Save filters, focus (${nodeKey(selected)}) and viewport` : "Save filters and viewport"}
          className={"grid h-6 w-6 place-items-center rounded border text-muted-foreground hover:bg-surface-1 hover:text-foreground " + (!viewNameDraft.trim() ? "border-border opacity-40" : "border-primary/50 text-primary")}
        >
          <BookmarkPlus className="h-3 w-3" />
        </button>
        {namedViews.length > 0 && (
          <div className="flex flex-wrap items-center gap-1">
            {namedViews.map((v) => (
              <span key={v.id} className="inline-flex items-center gap-0.5 rounded border border-accent/40 bg-accent/10 py-0 pl-1">
                <button
                  onClick={() => applyNamedView(v)}
                  title={`Apply view "${v.name}"`}
                  className="inline-flex items-center gap-0.5 py-0.5 text-mono ba-text-3xs text-accent transition-colors hover:brightness-125"
                >
                  <Bookmark className="h-2.5 w-2.5" /> {v.name}
                </button>
                <button
                  onClick={() => removeNamedView(v.id)}
                  aria-label={`Delete view ${v.name}`}
                  className="grid h-4 w-4 place-items-center rounded text-muted-foreground transition-colors hover:text-destructive"
                >
                  <X className="h-2.5 w-2.5" />
                </button>
              </span>
            ))}
          </div>
        )}
        {onSnapshot && (
          <button
            onClick={takeSnapshot}
            title="File the current graph state (filters, focus, visible counts) as a case notebook entry"
            className="grid h-6 w-6 place-items-center rounded border border-border text-muted-foreground hover:bg-surface-1 hover:text-foreground"
          >
            <Camera className="h-3 w-3" />
          </button>
        )}
        <span className="ml-auto text-mono ba-text-3xs text-muted-foreground">{visible.nodes.length} nodes · {visible.edges.length} edges</span>
      </div>
      {visible.nodes.length === 0 ? (
        <div className="flex items-center justify-center py-14 text-mono ba-text-2xs text-muted-foreground">No nodes match the current filters.</div>
      ) : (
        <div className="relative z-30 h-[420px] w-full rounded-md border border-border bg-surface-0/50">
          <GraphDerivedContext.Provider value={derived}>
            <ReactFlow
            nodes={rfNodes}
            edges={rfEdges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            onNodeMouseEnter={onNodeMouseEnter}
            onNodeMouseLeave={onNodeMouseLeave}
            onPaneClick={() => { setSelected(null); setHover(null); }}
            onMoveEnd={onMoveEnd}
            nodeTypes={nodeTypes}
            nodesConnectable={false}
            elementsSelectable={false}
            nodesFocusable={false}
            deleteKeyCode={null}
            minZoom={0.15}
            maxZoom={1.75}
            defaultViewport={restoredViewportRef.current ?? undefined}
            proOptions={{ hideAttribution: true }}
            fitViewOptions={{ padding: 0.15 }}
          >
            <Background color="var(--color-border)" gap={20} size={1} />
            <Controls showInteractive={false} />
            </ReactFlow>
          </GraphDerivedContext.Provider>
        </div>
      )}
      {presentKinds.size > 1 && (
        <div className="mt-2 flex flex-wrap items-center gap-1">
          {[...presentKinds].sort((a, b) => LAYER_RANK[a] - LAYER_RANK[b]).map((k) => {
            const on = kindFilter === null || kindFilter.has(k);
            return (
              <button
                key={k}
                onClick={() => toggleKind(k)}
                className={
                  "rounded border px-1.5 py-0.5 text-mono ba-text-3xs capitalize transition-colors " +
                  (on ? "border-primary/50 bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground")
                }
              >
                {k}
              </button>
            );
          })}
          <button onClick={() => setKindFilter(null)} className="rounded border border-border px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-foreground">show all</button>
        </div>
      )}
      {presentRelations.size > 1 && (
        <div className="mt-1 flex flex-wrap items-center gap-1">
          {[...presentRelations].map((r) => {
            const on = relationFilter === null || relationFilter.has(r);
            return (
              <button
                key={r}
                onClick={() => toggleRelation(r)}
                className={
                  "rounded border px-1.5 py-0.5 text-mono ba-text-3xs transition-colors " +
                  (on ? "border-info/50 bg-info/10 text-info" : "border-border text-muted-foreground hover:text-foreground")
                }
              >
                {r}
              </button>
            );
          })}
          <button onClick={() => setRelationFilter(null)} className="rounded border border-border px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-foreground">show all</button>
        </div>
      )}
      {selectedDetail && (
        <div className="mt-2 rounded border border-border bg-surface-0">
          <div className="flex items-center gap-2 border-b border-divider-strong px-3 py-2">
            <span className={"grid h-5 w-5 place-items-center rounded border " + KIND_STYLE[selectedDetail.node.ref.kind].chip}>
              {(() => { const I = KIND_STYLE[selectedDetail.node.ref.kind].icon; return <I className={"h-3 w-3 " + KIND_STYLE[selectedDetail.node.ref.kind].text} />; })()}
            </span>
            <span className="truncate text-mono ba-text-xs text-foreground">{selectedDetail.node.label}</span>
            <button onClick={() => setSelected(null)} aria-label="Close node details" title="Close" className="ml-auto grid h-5 w-5 place-items-center rounded border border-border text-muted-foreground hover:text-foreground">
              <X className="h-3 w-3" />
            </button>
          </div>
          <div className="space-y-2 px-3 py-2">
            {Object.keys(selectedDetail.detail).length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(selectedDetail.detail).map(([k, v]) => (
                  <span key={k} className="inline-flex items-center gap-1 rounded border border-border bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground">
                    {k}: <span className="text-foreground">{v}</span>
                  </span>
                ))}
              </div>
            )}
            <div className="space-y-1 rounded border border-subtle bg-surface-1 px-2 py-1.5 text-mono ba-text-3xs">
              <div><span className="text-fg-dim">why does this exist?</span> <span className="text-foreground">{selectedDetail.origin ?? "no provenance origin"}</span></div>
              <div><span className="text-fg-dim">what created it?</span> <span className="text-foreground">{(selectedDetail.createdBy.length > 0 ? [...new Set(selectedDetail.createdBy)].join(", ") : "unknown")}</span></div>
              <div><span className="text-fg-dim">what evidence supports it?</span> <span className="text-foreground">{(selectedDetail.evidenceFor.length > 0 ? selectedDetail.evidenceFor.length + " edge(s)" : "none")}</span></div>
              <div><span className="text-fg-dim">where is it used?</span> <span className="text-foreground">{(selectedDetail.usedIn.length > 0 ? selectedDetail.usedIn.join(", ") : "not referenced downstream")}</span></div>
            </div>
            {selectedDetail.edges.length > 0 ? (
              <div className="rounded border border-subtle bg-surface-1 px-2 py-1.5">
                {selectedDetail.edges.map((e) => {
                  const other = e.from.kind === selectedDetail.node.ref.kind && e.from.id === selectedDetail.node.ref.id ? e.to : e.from;
                  const otherLabel = baseNodes.find((n) => n.ref.kind === other.kind && n.ref.id === other.id)?.label ?? other.id;
                  return (
                    <div key={e.id} className="flex items-baseline gap-2 py-0.5 text-mono ba-text-3xs">
                      <span className="shrink-0 text-fg-dim">{e.relation}</span>
                      <span className="shrink-0 text-muted-foreground">[{other.kind}]</span>
                      <span className="truncate text-foreground">{otherLabel}</span>
                      {e.source && <span className="ml-auto shrink-0 text-muted-foreground">· {e.source}</span>}
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-mono ba-text-3xs text-muted-foreground">No provenance edges for this node.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export function InvestigationGraph({ caseData, className, onSnapshot }: { caseData: Case; className?: string; onSnapshot?: (body: string) => void }) {
  return (
    <ReactFlowProvider>
      <GraphInner caseData={caseData} className={className} onSnapshot={onSnapshot} />
    </ReactFlowProvider>
  );
}

export function InvestigationGraphPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { activeCase } = useActiveCase();
  const drawerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) drawerRef.current?.querySelector<HTMLElement>("button")?.focus();
  }, [open]);

  return (
    <>
      {open && <div className="fixed inset-0 z-50 bg-black/30 backdrop-blur-sm" onClick={onClose} />}
      <div
        ref={drawerRef}
        inert={!open}
        aria-hidden={!open}
        className={
          "fixed bottom-0 right-0 top-0 z-50 flex w-full max-w-2xl flex-col border-l border-border bg-background/95 backdrop-blur transition-transform duration-300 " +
          (open ? "translate-x-0" : "translate-x-full")
        }
      >
        <header className="flex items-center gap-2 border-b border-divider-strong px-3 py-2">
          <span className="grid h-6 w-6 place-items-center rounded border border-primary/40 bg-primary/10 text-primary">
            <Network className="h-3.5 w-3.5" />
          </span>
          <span className="text-mono ba-text-3xs text-foreground">Investigation Graph</span>
          {activeCase && <span className="truncate text-mono ba-text-3xs text-muted-foreground">· {activeCase.title}</span>}
          <div className="ml-auto flex items-center gap-1">
            <button onClick={onClose} aria-label="Close investigation graph" title="Close" className="grid h-5 w-5 place-items-center rounded border border-border text-muted-foreground hover:text-foreground"><X className="h-3 w-3" /></button>
          </div>
        </header>
        <div className="flex-1 overflow-y-auto p-3">
          {!activeCase ? (
            <div className="flex flex-col items-center gap-2 px-4 py-16 text-mono ba-text-2xs text-muted-foreground">
              <FolderOpen className="h-8 w-8 opacity-40" />
              <p>No active case.</p>
              <p className="ba-text-2xs">Open a case from the Case workspace to see its provenance graph.</p>
            </div>
          ) : (
            <InvestigationGraph caseData={activeCase} />
          )}
        </div>
        <footer className="flex items-center justify-between border-t border-border px-3 py-2 text-mono ba-text-3xs text-muted-foreground">
          <span>artifact → evidence → finding → IOC → MITRE spine</span>
          <span>click a node for detail</span>
        </footer>
      </div>
    </>
  );
}
