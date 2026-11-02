# Investigation Graph — Design Document

Status: LIVING · Frontend implementation of the provenance graph (`PROVENANCE_MODEL.md` §3 edges, `INVESTIGATION_OBJECTS.md` nodes). Reader should know the node/edge model first.

## 1. Purpose

The Graph tab on `/case` renders the case's provenance store as an interactive
directed graph: artifacts → evidence → findings → IOCs → MITRE techniques,
plus the detection chain (rule → simulation → deployment → alert) and intel
entities. It is a *visualization of the provenance store*, never a separate
data model — every node and edge renders from `lib/provenance.ts` state.

## 2. Data flow

```
provenance store (ba.provenance.v1) + case objects (ba.cases.v2)
        │  lib/provenance: getAllEdges(), explainNode()
        ▼
case.tsx: buildGraphData(case)        ← pure, memoized per case
        │   nodes: NodeRef → {kind, id, label, sub}
        │   edges: Edge[] (relation, from, to, confidence, source, ts)
        ▼
InvestigationGraph (ReactFlow / @xyflow/react)
        │   layered layout (see §4)
        ▼
SVG canvas: nodes, bezier edges, markers, background, controls
```

- `buildGraphData` is exported from `InvestigationGraph.tsx:175` and memoized
  with `useMemo(..., [caseData])` — it is the contract between case state and
  the canvas.
- Node labels come from `caseLabel` (artifact/evidence/finding/IOC/event text
  from the live case) — the graph never duplicates case fields it can read.
- Detection nodes resolve through `data/detection.ts` (`detectionNodeId`,
  `loadRules`); MITRE nodes through `data/mitre.ts` (`ALL_TECHNIQUES`).

## 3. Modes

`GraphMode = "relationship" | "timeline" | "detection" | "infrastructure" | "campaign"`

| Mode | Layer filter | Relation filter | Intended read |
|------|--------------|-----------------|---------------|
| relationship | all kinds | none | full provenance spine |
| timeline | all kinds | none | chronological ordering (rank by node time) |
| detection | artifact…case (no entity/ioc) | mapped-to, drives, validates, deploys, fires, creates, supports | detection chain projection |
| infrastructure | artifact, entity, ioc, mitre, case | extracts, enriched-by, produced, creates | entities + observables |
| campaign | finding, ioc, mitre, detection, case | mapped-to, supports, extracts, produced | techniques/TTP story |

Mode = (kind filter, relation filter) — `MODE_LAYERS`/`MODE_RELATIONS` at
`InvestigationGraph.tsx:43-57`.

## 4. Layout

- Layers follow `LAYER_ORDER`: artifact → evidence → finding → ioc → entity →
  mitre → detection → simulation → deployment → alert → case; `LAYER_RANK`
  fixes rank per kind.
- Fixed node width (`NODE_W = 208`), `GAP_X = 56`, `GAP_Y = 96`; positions are
  computed deterministically (rank, index) so reloads are stable.
- Timeline mode re-ranks nodes by `nodeTime` instead of kind, giving
  chronological flow.

## 5. Interaction

- **Hop expansion**: clicking a node focuses it; `HOP_LEVELS = [1, 2, 3]`
  expand to nodes within N undirected edges (`expandHops`, `InvestigationGraph.tsx:212`).
- **Filters**: kind, relation, source, minimum confidence — intersection of
  mode filter and explicit filters.
- **Explanations**: a focused node opens its "why" panel via `explainNode`
  (the same engine as the provenance recap and assistant).
- Canvas: zoom/pan controls, minimap-style overview via ReactFlow `Controls`.

## 6. Rendering rules

- Node style per kind (`KIND_STYLE`): border/text/chip colors follow semantic
  tokens (primary = artifact/entity, warning = finding, destructive = ioc,
  success = detection, accent = MITRE, chart-1/2/3 = simulation/deployment/alert).
- Edge markers (arrows) show relation direction; confidence renders as
  annotation on the edge (and is a filter dimension).
- Empty store degrades honestly: "No provenance links yet — run an analyzer on
  an artifact, add findings, or extract IOCs to build the graph."

## 7. Performance

- `buildGraphData` memoized on the case; filtering/`expandHops` memoized on
  their inputs (`InvestigationGraph.tsx:297,357`).
- Graph renders only what passes mode+filters; hop expansion bounds to 3.
- ReactFlow mounted once per active tab — unmount on tab switch, no hidden
  canvases.

## 8. Related documents

- `PROVENANCE_MODEL.md` — canonical nodes/edges (frozen).
- `INVESTIGATION_OBJECTS.md` — node access helpers (`getUnifiedFindings` etc.).
- `ROADMAP.md` §Phase 3 explain / §Phase 4 performance, graph rendering.