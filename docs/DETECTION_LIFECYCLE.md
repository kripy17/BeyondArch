# Detection Lifecycle — Design Document

Status: FROZEN effective 2026-08-07 (implemented) · Part of the platform constitution (with `ROADMAP.md`, `PROVENANCE_MODEL.md`, `ANALYSIS_ENGINE.md`, `INVESTIGATION_OBJECTS.md`). Extends the Provenance Model (§10 open question "detection lifecycle state machine" — this is that separate doc).

## 1. Purpose

Close the SOC loop: evidence → rule → validation → deployment → alert → investigation → feedback. Today the detection editor (`routes/detection.tsx`, `data/detection.ts`) manages rules as static editor artifacts (`ba.detection.rules.v2`, no lifecycle state). The provenance model already makes findings derivable; this lifecycle makes *detections* derivable too.

1. **Rule evolution** — a rule has a state (draft → validated → approved → deployed → retired), not just created/updated timestamps.
2. **Rule traceability** — every rule answers "why does this rule exist?" via `mapped-to`/`drives` edges back to findings, evidence, and artifacts.
3. **Analyst feedback loop** — investigation outcomes attach to the alert and rule that produced them, so revisions are grounded in what actually fired.
4. **Provenance integration** — the closed chain Artifact → Evidence → Finding → Technique → Detection → Simulation → Deployment → Alert → Case uses the existing edge store, append-only semantics, and deterministic IDs.
5. **Deployment history** — every deployment/rollback is an immutable node, never a mutation of the previous one.

## 2. Scope

**In scope**

- Rule lifecycle state machine (the `detection` node kind).
- New node kinds: `technique`, `detection`, `simulation`, `deployment`, `alert`.
- New provenance relations: `mapped-to`, `drives`, `validates`, `deploys`, `fires` (plus reuse of `creates` for Alert → Case).
- Provenance writers at existing write sites + the detection editor.
- Timeline integration: detection lifecycle events use the existing `detection` category in `CaseEvent`; the timeline projection renders them for free.
- Investigation links: alert → case edges; analyst feedback appends `CaseEvent`s to the case and `revises` the rule state.

**Out of scope**

- Real SIEM deployment, rule execution engines, or log sources — validation is the existing static `validateRule` + event-sample matching in the editor.
- Version-control backend — history lives in append-only edges + events, not a git-style store.
- Analytics, ML suggestions, false-positive dashboards.
- Alert ingestion UI — the `alert` node and `fires` writer are defined now; the ingestion surface lands with the future alert capability.
- No new UI primitives. Lifecycle state renders via existing `Panel`/`Chip` patterns; readers get no new pages.

## 3. Domain Model (node kinds)

| Node | Kind | Nature | Identity | Current state |
|------|------|--------|----------|---------------|
| `Technique` | `technique` | **Immutable reference** — ATT&CK corpus | `T1059`-style id from the existing `MITRE_MAP`/`SIGNAL_TECHNIQUE` data | Findings carry `technique?: string` (`types/security.ts`) |
| `Detection` | `detection` | **Mutable entity** — the only stateful node | `det-<fnv1a(ruleKey)>`; `ruleKey` = stable slug assigned at creation (renames/edits keep identity) | `SavedRule` in `data/detection.ts`; no lifecycle |
| `Simulation` | `simulation` | Immutable — one per validation run | `sim-<fnv1a(ruleId\|eventDigest)>`; same rule + same event input re-asserts | `validateRule` output only; not persisted |
| `Deployment` | `deployment` | Immutable — one per deploy/rollback action | `dep-<fnv1a(ruleId\|version)>` | none |
| `Alert` | `alert` | Immutable — one per (deployment, triggering event) | `al-<fnv1a(deploymentId\|eventDigest)>` | none |
| `Case` | `case` | Mutable entity (existing) | existing `case-*` | `ba.cases.v2` |

Rules:

1. Immutable nodes are never edited; a changed rule version or rerun appends a new node and the graph grows.
2. The `detection` node's *identity* is stable; its *state* is a projection of its event log (see §4). Edges never point "at a version" — the deployment/rollback history is carried by `deployment` nodes.
3. Every node keeps `createdAt`; `detection` additionally keeps `updatedAt` (state-change time, not content edit time).

## 4. State Machine (detection node)

States: `draft` → `validated` → `approved` → `deployed` → `retired`. `failed` is a transient outcome of validation, not a persisted state.

| From | To | Trigger | Notes |
|------|----|---------|-------|
| draft | draft | edit content | no transition; content edits append events |
| draft | validated | validation pass (`validateRule` 0 errors + sample match) | writes `validates` edge + simulation node |
| draft | failed | validation fail | transient; stays draft |
| validated | approved | analyst approval | |
| validated | draft | needs revision | rollback allowed from any state except retired |
| approved | deployed | deployment action | writes `deploys` edge + deployment node |
| approved | draft | needs revision | |
| deployed | retired | retirement | terminal by policy |
| deployed | draft | rollback | revision after production exposure |
| retired | draft | reactivation | explicit analyst action; new approval required |

**Forbidden:** draft → deployed (must validate); draft → retired; validated → deployed (must approve); deployed → validated (must revise to draft first); approved → retired.

**Terminal:** `retired` is terminal by policy; reactivation is a deliberate analyst action that returns to draft.

**Rollback semantics:** a rollback is a new `deployment` node for the previously-approved version with the `deploys` edge stamped `source: "rollback"`. The superseded deployment node is never mutated — append-only holds.

**Transition events:** every transition appends a `CaseEvent` (existing `detection` category — `CATEGORY_LABEL` already renders it) referencing the detection node id. The node's `state` field is the current state; the event log is the history.

## 5. Provenance Relations

Semantics only — traversal is unchanged (relation sets are data, see §9 invariant 2).

| Edge | From → To | Semantics | Writer |
|------|-----------|-----------|--------|
| `mapped-to` | Finding → Technique | the finding's ATT&CK mapping (today: `finding.technique` string) | analyzer writers (`case-factory`); backfill from legacy `technique` field |
| `drives` | Technique → Detection | the rule was authored to detect this technique | detection editor "create rule from finding" |
| `validates` | Detection → Simulation | a validation run against this rule | detection editor validation |
| `deploys` | Simulation → Deployment | the validated rule shipped as a deployment | detection editor deployment action |
| `fires` | Deployment → Alert | the deployment produced an alert | alert ingestion (future capability) |
| `creates` | Alert → Case | the alert opened the investigation (existing relation reused) | `case-factory` when a case is created from an alert |

Closed chain (all existing readers traverse it without changes):

```text
Artifact ─produced→ Evidence ─supports→ Finding ─mapped-to→ Technique ─drives→ Detection
   Detection ─validates→ Simulation ─deploys→ Deployment ─fires→ Alert ─creates→ Case
```

"Create rule from finding" scaffolding uses existing data shapes: the finding's `technique` (edge lookup) and the finding's IOCs (for rule tokens) — the IOCs stay rule content, not edges.

## 6. Writer Sites

| Site | Emits | Relation(s) |
|------|-------|-------------|
| `case-factory` `writeAnalysisEdges` | `mapped-to` when `finding.technique` set | mapped-to |
| case load backfill | `mapped-to` for legacy findings with `technique` field (documented backfill, §8) | mapped-to |
| detection editor — "create rule from finding" | detection node + `drives` | drives |
| detection editor — save draft | detection node (no edge) | — |
| detection editor — validate run | simulation node + `validates` | validates |
| detection editor — deploy/rollback | deployment node + `deploys` (`source: "rollback"`) | deploys |
| alert ingestion (future) | alert node + `fires` | fires |
| `case-factory` — case from alert | `creates` alert → case | creates |

Writers emit edges at the existing write sites; no new stores beyond `ba.provenance.v1` and the existing `ba.detection.rules.v2`.

## 7. Reader Effects

What the existing readers gain automatically (zero reader changes):

1. **Explain a finding** — forward walk (relation list append only) now extends `mapped-to → technique → drives → detection → validates → simulation → deploys → deployment → fires → alert → creates → case`. "Why does this rule exist?" is the same `explainNode` output.
2. **Timeline projection** — `EVENT_NODE_KINDS` gains `detection`/`simulation`/`deployment`/`alert`; detection lifecycle events render causal chains, standalone ones render `no provenance link`, exactly like today.
3. **Investigation provenance** — alert-created cases trace to the firing deployment without new code.
4. **IOC explain** — unchanged (mapped-to applies to findings, not IOCs, this milestone).
5. **UI** — the detection editor shows lifecycle state via existing `Chip`/`Panel`; no new pages, routes, or primitives.

## 8. Acceptance Criteria

- Deterministic node identities: `det-*`/`sim-*`/`dep-*`/`al-*` via FNV-1a of stable keys; technique id = ATT&CK id.
- Append-only provenance: reruns re-assert, never duplicate (`edge id = hash(relation|from|to)` holds).
- Traversal unchanged: `path`/`explainNode`/`projectTimeline` algorithms untouched; only `ProvenanceRelation`/`NodeKind` unions, relation-set lists, and `EVENT_NODE_KINDS` extend.
- Backfill: `mapped-to` derivable from legacy `finding.technique` at case load, stamped `source: "backfill"`, guarded like `backfillCaseEdges`. `drives`/`validates`/`deploys`/`fires` are write-time only — never backfilled.
- State machine: transitions per §4 table; forbidden transitions rejected; rollback appends, never mutates.
- No new UI primitives; detection state renders with existing components.
- `npm run lint` 0 errors, `npm run build` green; driver suite extended with C-checks (chain) and D-checks (lifecycle transitions) alongside the existing S/R/A/B checks; 0 console errors.
- Existing regression suites stay green (frozen-surface bar).

## 9. Architectural Invariants

These outlive this milestone and must never be violated by future work:

1. **Provenance remains append-only.** Edges are never mutated or deleted; supersession is expressed with new nodes, never edits.
2. **Readers remain relation-driven.** Traversal, projection, and explain operate over relation-set lists and node-kind maps as data. Adding a relation = extending the union + appending to a list. No reader may special-case a relation type.
3. **Node IDs remain deterministic.** Identity derives from stable content keys (or corpus ids), never from `crypto.randomUUID()` at write time. Re-analysis and reruns reconnect to the same nodes.
4. **State transitions emit events; history is never rewritten.** Current state is a field; the event log is the record.
5. **The timeline is always projected, never stored.** No second timeline store; projection stays the only view.
6. **Explain readers never synthesize.** Missing edges render as missing (`no provenance link`), never inferred — in readers, the timeline, and lifecycle views alike.
7. **Capability mindset:** every future action asks "should this action emit an edge?" Provenance is part of the domain model, not a subsystem.

## 10. Open Questions

- **Rule versioning vs. identity:** this doc fixes identity to `ruleKey`; content evolution is carried by deployment nodes + events. A future `superseded-by` chain can express rule→rule succession without breaking identity. Deferred.
- **Alert ingestion surface:** the `fires` writer is defined; the UI route that produces alerts is a future capability. Alert nodes must exist before case-from-alert `creates` edges can be written.
- **Finding-ID determinism (known debt):** analyzer findings still use `crypto.randomUUID()` (§9 invariant 3 violation). Fix = `fnv1a(analyzer|signalKey|evidenceKey)` per the Provenance Model's §10 rerun discussion. Lands with this milestone's `mapped-to` work since both touch `case-factory` writers. Implementation decision deferred to the implementation sprint.

---

Sequencing (after this doc is reviewed and frozen): extend unions/lists + node kinds → `mapped-to` writer + backfill → detection editor lifecycle (state, transitions, events) → `validates`/`deploys` writers → drivers (C/D-checks) → regression + freeze. No implementation in this sprint.
