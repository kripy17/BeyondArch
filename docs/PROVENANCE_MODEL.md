# Provenance Model — Design Document

Status: FROZEN · 2026-07-31 · Part of the platform constitution (with `ROADMAP.md`, `DETECTION_LIFECYCLE.md`, `ANALYSIS_ENGINE.md`, `INVESTIGATION_OBJECTS.md`). Frontend v1.0 frozen; provenance is the storage backbone the Analysis Engine writes through and every workspace reads.

## 1. Goals

1. Make every claim in a case *derivable* — findings, IOCs, and reports must trace back to the artifact, analyzer run, intel entity, and analyst action that produced them.
2. Unlock downstream features without further modeling: detection lifecycle (finding → rule → validate → deploy), investigation graph (timeline/tree/relationship explorer), analyst assistance ("why is this suspicious?" must cite the chain), enrichment merge (provider data attaching to a node, not a page).
3. Fix the existing dual-`Case` shape hazard: `lib/case.ts` and `data/case.ts` both manage `ba.cases.v2` with different types (minimal vs. rich). Provenance needs exactly one canonical model.

Non-goals: a graph-visualization UI, a database migration, backend rewrite. Storage stays localStorage for v1.

## 2. Canonical entities (nodes)

| Node | Current state | Gap |
|------|---------------|-----|
| `Artifact` | `types/security.ts:23` `{id, kind, ...}` | OK; carried on Case.artifacts |
| `Evidence` | `types/security.ts:34` — **embedded** `{artifact, findings[], iocs[], notes}` inside case | Must become a node with stable id; `evidenceItems` on Case |
| `Finding` | `types/security.ts:13` — `id` exists | `source` is a path string, not a link; `iocs[]` embedded (should become edges) |
| `IOC` | `types/security.ts:5` — **no id**; identity = value+type | Add stable `id`; keep value+type as dedup key |
| `TimelineEvent` | `lib/timeline.ts` — `target?` is loose text | `target` must become `reference[]` of node ids |
| `CaseEvent` | `data/case.ts:22` — **already has `references: EventReference[]`** | Correct model exists; unused by some flows (`pushTimelineEvent` bypasses it) |
| `IntelEntity` | `data/intel/types.ts` — `id`, `confidence`, `observables` | OK; static corpus today, becomes enrichable |
| `Observable` | `data/intel/types.ts` — has `id, source, timestamp` | OK; bridge between IOC (case side) and entity observables |
| `DetectionRule` | `data/detection.ts` (editor-only) | No lifecycle state; see §6 |
| `MitreTechnique` | `data/mitre.ts` (`ALL_TECHNIQUES`) | Node per technique id (`T1059`); reached via `mapped-to` from findings carrying `technique?` |
| `Simulation` | none | Sigma/YARA rule validation run (test corpus + result) |
| `Deployment` | none | Rule shipped to a collector/EDR stack |
| `Alert` | triage queue (`ba.triage.v1`) | Detection fired; `fires` → `creates` case on escalation |

Every node: `id: string` (existing `newId(prefix)` / `crypto.randomUUID()` conventions), `createdAt`, optional `updatedAt`.

## 3. Edge types

Adopt the relationship vocabulary already proven in Intel (`data/intel/types.ts:103`): `uses-tool, associated-with, linked-to, implements, resolves-to, originates-from, targets, related-to` — and add the investigation layer:

| Edge | From → To | Semantics | Currently |
|------|-----------|-----------|-----------|
| `produced` | Analyzer run → Evidence | artifact analyzed | convention (case entries from `case-factory`) |
| `supports` | Evidence → Finding | evidence backs the claim | embedded arrays |
| `extracts` | Finding → IOC | finding produced the observable | embedded `iocs[]` |
| `enriched-by` | IOC → IntelEntity | intel lookup result | `?q=` navigation only |
| `mapped-to` | Finding/IOC → MITRE technique | ATT&CK mapping | `technique?: string` on Finding |
| `drives` | Finding → DetectionRule | rule authored from finding | none |
| `validates` | DetectionRule → Simulation | rule tested against corpus | none |
| `deploys` | Simulation → Deployment | validated rule shipped | none |
| `fires` | Deployment → Alert | live rule fired on telemetry | none |
| `resolves-to` | IOC → Observable | case IOC ↔ corpus observable (same value) | none |

## 4. Graph schema

```ts
type Edge = {
  id: string;
  relation: EdgeType;          // §3 vocabulary
  from: { kind: NodeKind; id: string };
  to: { kind: NodeKind; id: string };
  source: string;              // where the edge was declared: "/url", "/intel", "analyst", ...
  confidence?: "high" | "medium" | "low" | "unknown";
  ts: string;
  reason?: string;             // human-readable why (mirrors intel Relationship.reason)
};
```

Store as a separate store: `ba.provenance.v1: Edge[]`. **Do not** nest edges in node objects (keeps nodes embeddable, matches how `CaseEvent.references` already works, avoids write amplification on small updates). Node stores stay where they are today (`ba.cases.v2`, `ba.timeline.v1`, intel corpus).

Migration: `produced`/`supports`/`extracts` edges are derivable from existing `case-factory` structure on first load of a case (backfill job, §9); hand-written edges (analyst notes, decisions) get created at write time going forward.

## 5. Lifecycle

- **Creation:** analyzer produces evidence → factory writes nodes + edges atomically into one localStorage batch.
- **Enrichment:** IOC → Intel lookup writes `enriched-by` edge with provider, confidence, timestamp (the intel `Observable.source` + `Relationship.confidence` already carry this shape).
- **Mutation:** findings severity/status changes append `CaseEvent` (already typed: `finding_severity_changed` etc.) — events ARE the lifecycle, edges are the structure.
- **Deletion:** soft-delete flag on nodes; edges survive with a `superseded-by` successor chain (later lifecycle work).
- **Ownership:** edges are append-only; `ba.provenance.v1` is never mutated in place (LS set of `[edge.id] = edge` map or append log).

## 6. Storage model

```text
ba.cases.v2          → Case[]            (single canonical shape; §1 fix)
ba.cases.active      → string
ba.provenance.v1     → Record<edgeId, Edge>   (append-only map)
ba.timeline.v1       → TimelineEvent[]   (keep; events reference edge/node ids)
intel corpus         → in-code data     (static; enrichment writes edges only)
```

Dedup rules: `IOC` key = `value|type` (one node per unique observable per case); edge id = stable hash of `relation|from|to` to make idempotent writes cheap (analyzer reruns re-assert rather than duplicate).

## 7. Query patterns

The operations the UI actually needs:

1. **Case provenance view** — `edges.filter(from.kind === "case" || from.id ∈ case.artifacts)` → traverse to findings/IOCs. This is the "investigation graph" starting point.
2. **Explain an IOC** — walk back: `extracts` → Finding → `supports` → Evidence → `produced` → Artifact; walk forward: `enriched-by` → IntelEntity → `mapped-to` → MITRE. One BFS over `ba.provenance.v1`.
3. **Why this finding?** — reverse edges into evidence; render as the existing `RelationshipList` component (already built for Intel).
4. **Detection authoring** — `drives` from finding collects IOCs + MITRE techniques for rule scaffolding.
5. **Report generation** — walk the full case subgraph; the current `MarkdownRenderer` tables become a serialization of the graph, not a bespoke string.

Keep graph reads in a single module (`lib/provenance.ts`) with `getEdgesFor(nodeId)`, `path(from, to)`, `subgraph(kind, id)` — no component ever queries localStorage directly.

## 8. UI implications

- **No new navigation, no new pages.** The freeze holds.
- Case IOC table: value already pivots to Intel (§F7). Next, a provenance affordance on findings (existing `EntitySection`/`RelationshipList` patterns) — "show evidence chain".
- Intel entity detail: `RelationshipList` extends to include case-side edges (`IOC → enriched-by`).
- Detection editor: findings list becomes a picker (existing list components), pre-populating IOCs + MITRE (existing data shapes).
- Analyst assistance ("explain this IOC") renders the `path()` output — grounded, citable, zero new UI primitives.

## 9. Migration strategy

1. Canonicalize the dual `Case` type first (lib/case.ts and data/case.ts to one module; runtime check tolerates both shapes on read).
2. Add `id` to IOC (`data/case.ts` + `intel-handoff.ts` writers).
3. Ship `lib/provenance.ts` + `ba.provenance.v1` with writers in: `case-factory` (produced/supports/extracts), intel enrichment (enriched-by), finding creation (`intel-handoff`).
4. Backfill: on case load, if `ba.provenance.v1` has no edges for a case and the case has `evidenceItems`, derive edges from the legacy embedded structure and stamp `source: "backfill"`.
5. Cut over views (case provenance, IOC explain) — they degrade gracefully (empty edge store → today's behavior).

## 10. Open questions

- **Scope of a "case":** is provenance per-case or global? Recommendation: per-case subgraphs; global union only for Intel-facing edges (`enriched-by`).
- **ID stability across reruns:** analyzer rerun on the same artifact — new evidence node (append) vs. replace (supersede)? Recommendation: append; `superseded-by` later.
- **Timeline vs. CaseEvent:** two event systems exist. Do they merge (`CaseEvent.references` becomes the canonical event, `lib/timeline.ts` becomes a projection)? Recommendation: yes, but out of scope for the first slice.
- **Detection lifecycle state machine:** `draft → validate → deploy → monitor → retire` — fold into this model or separate doc? Recommendation: separate doc after provenance lands (it depends on `drives` edges).
- **Enrichment providers:** first slice is local-corpus-only; provider edges carry `source`/`confidence`/`ts` today, so remote providers drop in without schema change.

---

Sequencing (frozen frontend allows): §9 steps 1–3 first (pure model + writers, zero UI), then step 5's provenance view via existing primitives, then Detection lifecycle, then analyst assistance. Dogfood Round 3 validates with a larger corpus.
