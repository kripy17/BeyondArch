# Analysis Engine — Design Document

Status: FROZEN · 2026-08-07 · Part of the platform constitution (with `ROADMAP.md`, `PROVENANCE_MODEL.md`, `DETECTION_LIFECYCLE.md`, `INVESTIGATION_OBJECTS.md`). Supersedes the draft dated the same day. This is the architecture doc for the vNext direction adopted 2026-08-07: a layered Analysis Engine over a passive knowledge graph. `INVESTIGATION_OBJECTS.md` freezes the object contracts; this doc freezes the engine that produces them.

## 1. Purpose

Stop treating analyzers as verdict-producing endpoints. Make every analyzer a **producer of structured investigation knowledge**, and make every higher-level capability (intel, detection, reports, search, timeline, assistant) a **consumer of that knowledge** rather than an owner of its own reasoning.

The unit of value is no longer the analyzer's verdict — it is the structured investigation knowledge the analyzer contributes to the platform.

Today (`types/analysis.ts`), analyzers emit a monolithic `AnalysisResult` carrying `findings`, `iocs`, `evidenceItems`, and a `summary { verdict, score, confidence }`. Findings embed a `technique?: string` and free-text `detail`. There is no shared weighting, no explained confidence, no relationship discovery, no detection-gap output, and no correlation across cases. This doc defines the layered engine that produces those.

### The architecture now

```
                Evidence
                   │
                   ▼
        ┌─────────────────────┐
        │ Extraction Layer    │
        │ (facts only)        │
        └─────────────────────┘
                   │
                   ▼
        ┌─────────────────────┐
        │ Analysis Engine     │
        │ (reasoning)         │
        └─────────────────────┘
                   │
                   ▼
        Investigation Objects
                   │
                   ▼
        ┌─────────────────────┐
        │ Correlation Engine  │
        └─────────────────────┘
                   │
                   ▼
        Provenance + Knowledge Graph
                   │
      ┌────────────┼─────────────┐
      ▼            ▼             ▼
 Investigation   Intel      Detection
      ▼            ▼             ▼
 Reports      Recommendations   Timeline
```

Differentiation ranking (why this platform wins):
1. Investigation Knowledge Graph
2. Analysis Engine
3. Correlation Engine
4. Detection Opportunities
5. Provenance
6. Detection Lifecycle
7. Investigation Reports
8. Analyst Assistant

UI is not on the list — the platform compounds analytical capability, not presentation.

## 2. Scope

**In scope**

- The three cooperating subsystems: **Extraction Layer**, **Analysis Engine**, **Correlation Engine** — as pure, replaceable, testable modules (no UI deps).
- Canonical Investigation Objects (contracts frozen in `INVESTIGATION_OBJECTS.md`) as the stable interface all analyzers emit and all consumers read.
- A shared, passive **Knowledge Graph** store that never performs reasoning (writes via existing `addEdge`, reads via existing `path`/`explainNode`/`projectTimeline`).
- Detection-opportunity generation wired into the existing detection editor ("create rule" surface), reusing `ruleFromSignal` + `drives` provenance.
- Report composition from Investigation Objects + graph relationships (reproducible reasoning, not handwritten).
- Evidence normalization: a shared canonical input pipeline for every evidence format (see §4b).

**Out of scope**

- Real log/SIEM ingestion, alert execution, or ML model training.
- Any new UI primitives or new user-facing pages beyond layered projections.
- Non-local enrichment (MISP/VT/Shodan stay opt-in behind the intel surface; the Correlation Engine is local-history only).
- Making the graph reason — business logic lives in the engines, never in the edge store.

## 3. Canonical Investigation Objects

**Frozen in `INVESTIGATION_OBJECTS.md`.** This section points, it does not duplicate.

Objects: `Artifact`, `Observation`, `Evidence`, `Finding`, `IOC / Observable`, `Entity`, `Technique`, `Relationship`, `DetectionOpportunity`, `Recommendation`, `Decision`, `TimelineEvent`, `AnalysisQuality`. Contracts include identity determinism, immutability, no-UI-state, explainable conclusions, schema versioning.

## 4. The Four Layers

### 4a. Extraction Layer — "What is here?"

- Convert raw evidence into `Observation`s. **Never infers** malicious/suspicious/phishing — facts (URL parts, IP, domain, hash, email, header, PE import, macro, string, registry key, process, command) only.
- Today analyzers do this inline (e.g. `decodePunycode`, `extractIocs`, host signals in `analyzers/url.ts`); this layer consolidates it into a shared library of pure functions.
- Shared library: `frontend/src/lib/extraction/` — pure, deterministic, side-effect free:
  - `extractObservations(raw, kind): Observation[]`
  - `normalizeIp/domain/email/hash` (canonical form), `classifyIoc(value): IocType`
  - `observationsFromIocs(iocs, source, context): Observation[]`
- The URL analyzer must go deep: hostname, root domain, TLD, path depth, query params, entropy, redirects, IP literals, punycode/unicode tricks, embedded credentials, suspicious extensions, uncommon ports, download filenames, shorteners, PowerShell cradles, JS payloads, Base64 blobs — not just "looks suspicious".

### 4b. Evidence Normalization — "one canonical surface"

**New subsystem, explicit.** Every parser produces exactly the same canonical objects.

```
Raw Input (EVTX | PCAP | Email | File | URL | Browser | Registry | CloudTrail | Sysmon | Log...)
   ↓
Normalization (per-format adapter)
   ↓
Canonical Investigation Objects
```

- Purpose: prevent every analyzer from inventing its own format. The parser that today produces ad-hoc fields becomes a format adapter to the canonical `Observation` set.
- The existing parser (`data/parser.ts` — EVTX/Sysmon XML, Suricata EVE, Zeek conn.log, syslog/sshd, Apache combined, Nginx access, CSV IOC sheets, JSON) is the first adapter target.
- Acceptance: analysis of an EVTX file, a PCAP, and a CSV reach the same `Observation` vocabulary (different values, same shape).

### 4c. Analysis Engine — "What does this mean?"

Consumes `Observation`s; emits investigation objects. **The engine is not one algorithm — it is independent, replaceable modules** (each with input/output/deterministic/testable, documented):

```
Extraction (observations)
   ↓
   Evidence Weighting
   ↓
Relationship Discovery
   ↓
Correlation (secondary, see §4e)
   ↓
Threat Reasoning
   ↓
Confidence
   ↓
MITRE
   ↓
Detection Opportunities
   ↓
Recommendations
   ↓
Quality Validation
   ↓
Investigation Objects
```

Module independence is a first-class property: **Relationship Discovery v2 can replace v1 without touching anything else.** Each module:

- input (explicitly typed)
- output (explicitly typed)
- deterministic (same input → same output)
- independently testable (pure functions in `frontend/src/lib/analysis/`)

Modules:

1. **Evidence Weighting** — replaces ad-hoc `+20/+10/+15` with weighted per-observation weights (PowerShell cradle 0.92, EncodedCommand 0.88, DownloadString 0.91). Output: `weight(observation) → { score, rationale[] }`.
2. **Relationship Discovery** — finds links between observations/objects: same host, shared IP, embedded token, reused cert, shared infrastructure.
3. **Correlation** — "have we seen this before?" (dimensions below); **feeds back into reasoning but is marked for analyst review §4e**.
4. **Threat Reasoning** — hypothesis-style conclusions, each an edge not a verdict string: "Observed PowerShell+DownloadString+Remote URL ⇒ likely initial payload retrieval".
5. **Confidence** — never a bare percentage. `Confidence: High` + **Because** (N independent signals, M strong indicators, no contradictions) + contributor list. Reproducible.
6. **MITRE Mapper** — a chain, not just an id: `observation behavior → tactic → technique → evidence refs → confidence`.
7. **Detection Opportunities** — §5. First-class output.
8. **Recommendations** — every recommendation references evidence (§6).
9. **Quality Checker** — self-grade: coverage %, missing fields, weak/conflicting signals, recommended next step.
10. **Investigation Object Builder** — assembly + provenance writes.

### 4d. Analysis Quality

Every analyzer should eventually produce:

```
Analysis Quality
  Coverage
  Confidence
  Missing Evidence
  Weak Signals
  Conflicting Signals
  Recommended Next Step
```

Different from `Malicious: 87%`. It answers **"How complete is this investigation?"**

**Engine rules:** modules operate on Observations only; no module writes UI state; no module reads localStorage directly (injected stores).

### 4e. Correlation Engine — "Where have we seen this before?"

- Runs **after** Analysis on the main path so reasoning stays deterministic and un-adjusted by history.
- Local-only correlation over the graph + cases + search + rule/entity history:
  - shared: certificate (spki/fingerprint), favicon hash, JA3, ASN owner, registrar, sender domain, mutex (normalized prefix), YARA hits, infra (host/domain/IP pairs), campaign, malware family.
  - structural: "same as previous case", "already has a detection", "related by technique/tactic", "appears in earlier reports".
- API: `correlate(objects, edges): { dimension, value, matches, confidence, evidenceRefs }[]`, projected into report and graph as relationships marked `origin: correlation`, analyst review (doesn't re-rank raw analysis).

### 4f. Knowledge Graph — the memory, intentionally dumb

- The existing `ba.provenance.v1` + `addEdge`/`path`/`explainNode`/`projectTimeline` are the graph. **No analysis code in the graph.**
- Good: IOC ↔ mapped-to ↔ technique ; Finding --supports-- Evidence.
- Bad: "the graph calculates confidence". Anything decision-aware is an engine module.

## 5. Detection Opportunities (first-class output)

Replace "malicious-NN" as the headline of an analysis:

```
Observed behavior → Mapped technique → Existing detections?
   → coverage gap? → Suggested rule (via ruleFromSignal scaffolding)
                   → Suggested hunt (concrete query)
```

Concretely, a PowerShell-encoded-download extraction yields:

- `TECHNIQUE: T1059.001`
- `COVERAGE: no sigma covers this`
- `DETECTION_OPP: Sigma matching PowerShell with EncodedCommand + WebClient.DownloadString`
- `SUGGESTED_HUNT: query the PowerShell Operational log`

These are first-class objects (contracts in `INVESTIGATION_OBJECTS.md §11`); the existing `/detection` editor takes the opportunity through the "create rule from …" flow (existing `drives` writer). Output compounds: pipeline, not a score.

## 6. Writers and Consumers

The bottleneck "an analytical improvement benefits ≥3 features" is satisfied automatically because every capability is a data expansion, not a code path.

| Capability | Writes | Consumers |
|-----------|--------|-----------|
| Analysis modules | objects (findings/observations/confidence) | Investigation, Graph, Reports, Timeline, Detection |
| Evidence normalization | canonical Observation set | engine modules, evidence |
| Relationship Discovery | relationships | Graph, Reports, Search, correlation |
| Correlation | edges (marked correlation) + same-again markers | Graph, Reports, Search ranking |
| MITRE mapping | `mapped-to` (existing) | Graph, Detection, Reports |
| Detection opportunities | objects + optional `drives` | Detection editor, Reports |
| Recommendations | objects | Investigation, Reports |
| Confidence | objects | everywhere (recomputed from evidence) |
| Quality | AnalysisQuality object | reports, Investigation lint |

Existing write sites are untouched (`case-factory`, detection editor writers). New writers emit at the same seam — engine object → `addEdge` when it belongs in provenance, object store otherwise.

## 7. Recommended Migration Sequence

1. `ANALYSIS_ENGINE.md` + `INVESTIGATION_OBJECTS.md` (this doc) — freeze contracts + layers. ✔
2. **Canonical Investigation Objects** — types in `types/analysis.ts`/`types/investigation.ts` per INVESTIGATION_OBJECTS.
3. **Shared Extraction Library** — `lib/extraction/*` + Evidence normalization for the first parser.
4. **Analysis Engine v1** — modules in §4c (weighting, relationship discovery, reasoning, confidence, MITRE, recommendations, detection opportunities, quality).
5. **Correlation Engine v1** — local history/similarity/relationship/detection correlation.
6. **Analyzer migration** — URL, file, phishing, parser/pcap, logs stop self-reasoning; they emit objects that feed the engines.

Each step keeps every existing regression/check green; it degrades gracefully (missing object ⇒ "no X" as today).

## 8. Engineering Principles (binding)

1. Every analytical improvement benefits at least three features.
2. Extraction never infers.
3. Analysis never stores UI state.
4. Graph never performs reasoning.
5. Every conclusion is explainable (with confidence qualifier + evidence ref).
6. Every recommendation references evidence.
7. Every confidence score is reproducible.
8. Every new capability deepens or connects — never decorates.
9. Detection opportunity outputs are first-class, not optional extras.
10. Reports are generated from Investigation Objects, never handwritten.
11. **Analysis First, Presentation Second** — pages never invent analytical logic. Pages display Investigation Objects and query the graph; pages never compute confidence, MITRE, recommendations, or relationships. All analysis happens in engine modules.

### Rationale — Analysis First, Presentation Second

Separation of concerns:
- Pages query the graph.
- Pages display objects.
- Pages filter/order/group (presentation).
- No page computes confidence, MITRE, recommendations, or relationships.

This keeps the platform maintainable as it grows, and is precisely why principles 1–10 stay true.

## 9. Acceptance Criteria

- A new analyzer requires extraction logic + a declaration, with no changes to consumers.
- Evidence Normalization: EVTX/PCAP/CSV reach a common Observation vocabulary.
- Confidence always ships with an explanation; Quality flags unexplained confidence as a gap.
- MITRE produces a chain (technique → evidence → confidence) not an id.
- Detection opportunities produce a gap/covered result + `suggestedRule` request + `suggestedHunt`.
- Correlation finds "same as previous case / existing detection / shared infra" from local data.
- Reports derive sections from objects; no report path writes reasoning inline.
- Relationships/confidence/recommendations are never computed on pages.
- `npm run lint` 0 errors, `npm run build` green; module unit tests + one end-to-end engine→graph→report; 0 console errors.
- No regression on frozen surfaces (URL/file/phishing/parser, case-editing, report pages).

## 10. Open Questions / Deferred

- IOC↔Observation identity; whether IOCs become a projection or stay first-class — deferred to extraction.
- Non-local vs local: only local knowledge now; intel enrichment opt-in later.
- Report types become section selectors on the shared object renderer; template-free at v1.
- Whether `Decision`/`Recommendation` objects persist as first-class nodes or stay events.
- Storage schema versioning shim (INVESTIGATION_OBJECTS §17).

---

Sequencing (from §7): types → extraction → modules → detection → correlation → analyze/migrate. The four-layer turn lives behind a new `lib/analysis` facade; existing `/url`, `/file`, `/phishing`, `/parser`, `/logs`, `/pcap` routes are consumers until migration. No implementation in this sprint.