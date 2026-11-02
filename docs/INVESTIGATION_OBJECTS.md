# Investigation Objects — Canonical Contracts

Status: FROZEN · 2026-08-07 · Part of the platform constitution (with `ROADMAP.md`, `PROVENANCE_MODEL.md`, `DETECTION_LIFECYCLE.md`, `ANALYSIS_ENGINE.md`). Contracts only — no code. This is the interface between every analyzer and every consumer. Analyzers emit only these objects; consumers read only these objects; the Analysis Engine and Correlation Engine consume and produce these objects.

## 1. Purpose

Every analyzer, every engine module, and every consumer (Investigation, Intel, Detection, Reports, Timeline, Search, Assistant) speaks one vocabulary. A new analyzer therefore needs one new extraction surface and nothing else (ANALYSIS_ENGINE §7). A new capability can consume the objects without knowing any single analyzer's schema.

**Invariants**

1. An object's identity is **deterministic**, derived from stable content keys — never `crypto.randomUUID()` at write time for anything that participates in provenance (PROVENANCE_MODEL §9.3).
2. Objects are **immutable after creation**; evolution is expressed by new objects and supersession edges, never by mutation (PROVENANCE_MODEL §5).
3. **Analysis never stores UI state:** a contract has no presentation fields (color, layout, ordering). Pages derive presentation from objects, never the reverse.
4. **Every conclusion is explainable:** any object that states a conclusion carries a confidence explanation and an evidence reference (ANALYSIS_ENGINE Principles 5–7).
5. **Versioning:** each object carries a schema `v` so storage migrations are mechanical (ANALYSIS_ENGINE §10).

## 2. Object map

| Object | Producer | Consumer |
|--------|----------|----------|
| Artifact | intake / parser | Evidence, Graph, Investigation |
| Observation | Extraction Layer | Analysis Engine |
| Evidence | Analysis Engine / analyst | Investigation, reports, graph |
| Finding | Analysis Engine | Investigation, detection, reports |
| IOC / Observable | Analysis Engine, intel | search, intel, reports, graph |
| Entity | intel corpus | intel, graph |
| Technique | MITRE corpus | detection, graph |
| Relationship | Analysis Engine, Correlation Engine | graph, reports, search |
| DetectionOpportunity | Analysis Engine | detection editor, reports |
| Recommendation | Analysis Engine | Investigation, reports |
| Decision | analyst | reports, timeline |
| TimelineEvent | any workflow action | timeline, graph |
| AnalysisQuality | Analysis Engine | Investigation, reports |

## 3. Artifact

**Identity:** `id` — deterministic where the raw input allows (file hash, mail message id); `crypto.randomUUID()` only for unstructured intake.

**Fields**
```
id            string
kind          email | file | pcap | log | url | text
title         string
raw?          string
metadata      Record<string, string>
created       iso
schemaVersion number
```

**Lifecycle:** created once at intake; never modified. Reruns produce new Evidence, never a new Artifact.

**Who creates:** parser / intake (existing `Artifact` in `types/security.ts`).
**Who can modify:** none (immutable).
**Relations:** `produced` edge → Evidence (existing writer).
**Consumers:** Evidence, Investigation, graph, report appendix, quality (missing-attach check).

## 4. Observation

**Identity:** deterministic id = fnv1a(`observation|kind|value`); re-injection re-asserts, never duplicates.

**Fields**
```
id         string
kind       observation-kind   url-part | domain | ip | hash | email | header |
                              string | macro | import | registry-key | process |
                              command | ua | ja3 | cert | dns | ...
value      string
meta       Record<string,string>   // normalized forms, sub-observations
source     string                  // extraction layer describing the origin
ts         iso
```

**Rule:** extraction-layer facts only. **Never** infers intent ("malicious"/"suspicious"/"phishing"). Intent arrives from the Analysis Engine.

**Who creates:** Extraction Layer (`lib/extraction`).
**Who can modify:** nobody (immutable).
**Relations:** none directly; consumed by analysis modules; aggregated into Evidence.
**Consumers:** Analysis Engine, Evidence aggregator, Correlation (pattern matching on value).

## 5. Evidence

**Identity:** `id` — existing `Evidence` (`types/security.ts`).

**Fields**
```
id           string
artifact     Artifact
observations Observation[]     // replaces the raw nested iocs at the seam
findings     Finding[]
iocs         IocType[]
notes        string
created      string
```

**Who creates:** Analysis Object Builder / case factory.
**Who can modify:** analyst notes only (append).
**Relations:** `produced` (Artifact→Evidence), `supports` (Evidence→Finding).
**Consumers:** Graph readers, Investigation tab, reports.

## 6. Finding

**Identity:** `id`.

**Fields**
```
id        string
severity  Severity
title     string
detail    string
source    string
technique?  string           // ATT&CK id
observations? Observation[]
iocs?        IocType[]
confidence?: ConfidenceExplanation
schemaVersion number
```

**Invariant:** a Finding never carries a bare confidence number — it carries an explanation (`ConfidenceExplanation` has `level` + contributors). Confidence is reprojected from the observation set, never embedded opaque.

**Who creates:** Analysis Engine Threat Reasoner; backfill from legacy finding shapes.
**Who modifies:** nobody; change = new finding.
**Relations:** `supports` from Evidence; `mapped-to` → Technique; `extracts` → IOC.
**Consumers:** DetectionOpportunity, Investigation tabs, MITRE, reports, search.

## 7. IOC / Observable

**Identity:** dedup key `value|type` + durable `id`.

**Fields:** value, type, context, source, severity, id.

**Who creates:** Extraction / parser; `intel-handoff`.
**Who modifies:** — (immutable); status changes are events.
**Relations:** `extracts` (Finding→IOC), `enriched-by` (IOC→Entity, existing), `resolves-to` (IOC↔Entity observable).
**Consumers:** Graph, intel, detection, search, reports.

## 8. Entity

**Identity:** `id` — seed corpus.

**Fields:** name, kind, aliases, attributes, confidence, source, observables.

**Lifecycle:** static seed corpus today; enrichment attaches edges only.
**Relations:** `enriched-by` (IOC→Entity), intra-entity (uses-tool, associated-with, etc.)
**Consumers:** intel page, graph, correlation.

## 9. Technique

**Identity:** ATT&CK id.

**Fields:** id, name, tactic, source (MITRE corpus `data/mitre.ts`).

**Lifecycle:** reference only — immutable.
**Relations:** `mapped-to` (Finding→Technique), `drives` (Technique→Detection), used by detection opportunity.
**Consumers:** Detection, Graph, reports, correlation.

## 10. Relationship

**Identity:** deterministic id = hash of `(relation, from, to)` (PROVENANCE §4).

**Fields**
```
relation      ProvenanceRelation
from, to      { kind, id }
confidence?   number
evidenceRefs  string[]
origin        extraction | analysis | correlation | backfill | analyst
source        string
ts            string
```

**Who creates:** analysis/correlation writers + analyst actions.
**Who modifies:** nobody — append-only (PROVENANCE §5).
**Consumers:** graph readers (`path`/`explainNode` unchanged), reports, search.

## 11. DetectionOpportunity

First-class output — ANALYSIS_ENGINE §5.

**Identity:** deterministic from (technique, behavior).

**Fields**
```
id              string
technique       string       // ATT&CK id
behavior        string
coverage        detected | gap | unknown
existingRule?   string       // rule that already covers
suggestedRule?  { fmt: sigma|yara|kql; name; draft }
suggestedHunt?  string
priority        low | medium | high
confidence?     number
status          open | dismissed | rule-created
```

**Who creates:** Detection Opportunity Generator.
**Who modifies:** analyst only (status).
**Relations:** `drives` from the covering technique.
**Consumers:** Detection editor "create rule from finding" flow (reuses the existing `drives` writer); reports "coverage gap"; Investigation.

## 12. Recommendation

**Identity:** deterministic id.

**Fields**
```
kind         enrich-ioc | create-rule | generate-report | attach-evidence |
             add-mitre | close | collect-logs | next-step
priority     low | medium | high
statement    string
reason       string
evidenceRefs string[]
confidence?  number
target?      { route | object-ref }
status       open | dismissed | done
```

**Who creates:** Analysis Engine Recommendation Generator; complements/unifies the existing `InvestigationRecommendations` widget.
**Who modifies:** analyst only (status).
**Consumers:** Investigation sidebar, reports, search.

## 13. Decision

**Identity:** deterministic (derived from case + round).

**Fields**
```
id           string
case
conclusion   string
confidenceRef string     // resolution, evidence
options      string[]
chosen       string
reason       string
ts           string
```

**Rule:** Decision derives from, never substitutes, analyst judgment — the engine never makes findings, only the analyst confirms.
**Who creates / modifies:** analyst (append-only).
**Consumers:** reports, timeline.

## 14. TimelineEvent

**Identity:** `id` — existing `CaseEvent`.

**Fields:** kind, id, ts, title, detail, source, `references {kind,id}`.

**Who creates:** every workflow action (writers append events).
**Who modifies:** append-only.
**Consumers:** timeline projection (`projectTimeline`), graph, search.

## 15. AnalysisQuality

Formal analysis quality — answers "How complete is this investigation?" not "malicious 87%".

**Fields**
```
coverage           { score: 0..1; gaps: string[] }   // missing artifact attach,
                            cert, asn, whois, dns-history, sandbox, conflict-missing...
confidence         number | none
weakSignals        string[]
conflictingSignals string[]
recommendedNextStep string
missing            string[]
```

**Who creates:** Quality Checker (last pipeline stage).
**Consumers:** Investigation quality widget, reports "quality" section, recommendation prioritization, assistant gating.

## 16. AnalysisSummary (transitional)

**Decision:** `AnalysisSummary { verdict, score, confidence }` stays for now, but its `confidence` is re-derivable from the observation set (never opaque), and the verdict text is an honest summary of observations + reasoning — never a fabricated judgment. Migrating to the object set v2 replaces it. Deferred.

## 17. Schema versioning and storage

- Each object holds `schemaVersion`; material changes bump the version, storage keeps a shim.
- Storage: objects follow their existing stores (`ba.cases.v2`, `ba.provenance.v1`, `ba.detection.rules.v2`); no new stores for the initial engine objects — they ride on existing envelopes.

## 18. What each consumer may never do

| Surface | Reads | Must never do |
|---------|-------|---------------|
| Investigation tabs | Artifact, Evidence, Finding, IOC, Recommendation, AnalysisQuality | compute analysis reasoning |
| Knowledge Graph | Relationship, nodes | synthesize analysis |
| Detection editor | Finding, Technique, DetectionOpportunity, suggestedRule | derive rule from raw input directly (must go through engine) |
| Reports | all objects | write reasoning inline at page time |
| Search | indexed object fields | re-rank from page-specific heuristics |
| Assistant | Recommendation, Evidence chain, Relationships | solve raw data itself |

## 19. Implementation bound

Contracts are frozen here. Implementation of objects and engines proceeds per `ANALYSIS_ENGINE.md` migration sequence (types → extraction → modules → detection opportunities → correlation).

---

Sequencing: contracts frozen; all implementation lands only through the analysis engine track. No implementation in this document.