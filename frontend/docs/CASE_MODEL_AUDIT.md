# Case Model Audit

## 1. Current State

### Data Model

```ts
// src/data/case.ts
Case {
  id: string;
  title: string;
  tags: string[];
  createdAt: string;
  state: "active" | "closed";
  entries: Entry[];       // flat heterogeneous list
}

Entry {
  id: string;
  ts: string;
  kind: "note" | "evidence" | "decision" | "action" | "ioc";
  body: string;           // everything flattened to text
}
```

### Persistence

- `localStorage` key `ba.cases.v2`
- `saveCases()` silently drops writes >5 MB
- `loadCases()` returns `[]` on parse failure

### Wrapper (unsaved)

```ts
// src/types/investigation.ts
Investigation {
  case: Case;
  analysisResults: AnalysisResult[];  // NOT persisted
  timeline: InvestigationTimelineEvent[]; // NOT persisted
}
```

### Data Flow

```
Analyzer → AnalysisResult (structured, typed)

createCaseFromAnalysis()
         ↓
  entry.body = `[${f.severity}] ${f.title} (from: ${a})\n${f.detail}`
         ↓
Case.entries[] (flat strings)
         ↓
localStorage (serialized JSON)
         ↓
loadCases() → Case.entries[]
         ↓
case.tsx: parseSeverity(), parseSource(), parseIocEntry(), parseSummaryEntry()
  regex → typed values → render
```

### All Serialization Sites (case-factory.ts)

| Function | Input Type | Output | Lost Fields |
|---|---|---|---|
| `findingToEntry()` | `Finding` (severity, title, detail, source, technique) | string | source, technique, type safety |
| `iocToEntry()` | `IOC` (value, type, context, source, severity) | string | severity, source, type safety |
| `evidenceItemToEntry()` | `EvidenceItem` (type, title, detail, source) | string | type safety |
| `createCaseFromAnalysis()` | `AnalysisSummary` (verdict, score, confidence) | string | numeric types for score, confidence |

### All Parse Sites (case.tsx)

| Function | Regex Target | Returns | Used Where |
|---|---|---|---|
| `parseSeverity()` | `[CRITICAL|HIGH|...]` | severity + clean body | entry rendering, timeline |
| `parseSource()` | `(from: analyzer)` | source + clean body | entry rendering, timeline |
| `parseIocEntry()` | `type: value\n...` | { type, value, source } | IOC table, card rendering |
| `parseSummaryEntry()` | `Verdict: ...\nScore: ...` | { verdict, score, confidence } | summary card, timeline |

---

## 2. Pain Points

### P1. Structured → String → Structured (Round-Trip Loss)

**Problem**: `AnalysisResult` enters `createCaseFromAnalysis()` as typed objects, leaves as strings, and must be re-parsed by regex in the case UI.

**Why**: `Case.entries` is the only storage mechanism and only accepts `body: string`.

**What it blocks**:
- `Finding.technique` (MITRE ID) — silently dropped, never persisted
- `IOC.severity` — dropped, cannot show risk-weighted IOC tables
- `AnalysisSummary.score` — converted to string, cannot do numeric comparisons
- Any new field on `Finding`/`IOC` requires changing both the format string *and* the parse regex

### P2. Brittle Implicit Contract

**Problem**: The string format in `case-factory.ts` and the regex in `case.tsx` have no shared schema. Changing one without the other causes silent data loss or misrendering.

**Why**: No type links the two directions. No tests enforce the contract.

**What it blocks**: Safe refactoring. Any change to serialization is a minefield.

### P3. Investigation Wrapper is Dead Code

**Problem**: `Investigation { case, analysisResults, timeline }` is constructed by `createCaseFromAnalysis()` but:
- `analysisResults` is never persisted
- `timeline` is never persisted
- No caller uses either field — all 5 callers destructure only `investigation.case`
- `isNew` on `InvestigationResult` is never consumed

**Why**: The wrapper was introduced as a bridge but the persistence layer was never updated.

**What it blocks**: Adds confusion. Suggests analysis data is available when it isn't.

### P4. IOC Regex Duplication

**Problem**: IP/URL/hash regex patterns for IOC detection are redefined in ~5 locations across the codebase.

**Why**: No shared IOC detection utility used consistently.

**What it blocks**: Inconsistent behavior. Adding a new IOC type requires hunting down every copy.

### P5. Parse Functions Locked in Route Component

**Problem**: `parseSeverity`, `parseSource`, `parseIocEntry`, `parseSummaryEntry` are local functions in `case.tsx`. Any other consumer must copy them.

**What it blocks**: Export/migration logic, dashboard widgets, API consumers cannot reuse the parsing.

### P6. Silent localStorage Data Loss

**Problem**: `saveCases()` silently refuses writes >5 MB with no user feedback.

**What it blocks**: Large investigations silently truncated. No upgrade path to IndexedDB or other storage.

---

## 3. Proposed Evolution

### Principle

**`Case` becomes the persistent source of truth for investigations.**

`entries` stops being a serialization dump of analysis results and becomes **human-authored activity only** (notes, decisions, actions, status changes).

Structured investigation data moves into dedicated typed fields on `Case`.

### Model

```ts
Case {
  // ── Identity ──
  id: string;
  title: string;
  tags: string[];
  createdAt: string;
  state: "active" | "closed";

  // ── Machine-produced (structured) ──
  artifacts: Artifact[];
  findings: Finding[];
  iocs: IOC[];
  evidenceItems: EvidenceItem[];

  // ── Derived / generated ──
  analysisSummary: AnalysisSummary | null;
  timeline: TimelineEvent[];
  mitre: MitreTechnique[];

  // ── Human activity only ──
  activity: ActivityEntry[];

  // ── Outputs ──
  reports: Report[];
  detections: DetectionCandidate[];
}
```

### Redesigned `ActivityEntry`

```ts
ActivityEntry {
  id: string;
  ts: string;
  kind: "note" | "comment" | "decision" | "action" | "status_change" | "assignment";
  author: string;          // analyst identifier
  body: string;            // free text — analyst's own writing
}
```

Note: no `"ioc"` or `"evidence"` kind here. Those are machine-produced structured data now.

### `TimelineEvent`

```ts
TimelineEvent {
  id: string;
  ts: string;
  kind: "analysis_completed" | "finding_generated" | "ioc_extracted"
      | "detection_created" | "report_generated"
      | "note_added" | "decision_made" | "status_changed";
  source: string;      // analyzer name or "analyst"
  title: string;
  detail: string;
}
```

Timeline is **generated** from both machine events (analysis results) and human events (activity entries). It is persisted so it works offline and survives page reload.

### `Report`

```ts
Report {
  id: string;
  ts: string;
  format: "markdown" | "json" | "pdf";
  title: string;
  body: string;
  generatedFrom: string;   // template or trigger
}
```

### `DetectionCandidate`

```ts
DetectionCandidate {
  id: string;
  ts: string;
  source: string;              // analyzer or finding ID
  mitreTechnique: string;      // MITRE ID
  title: string;
  status: "draft" | "tested" | "deployed" | "rejected";
  sigma: string | null;
}
```

---

## 4. Field Justification

| Field | Producer | Consumers | Why Now |
|---|---|---|---|
| `id` | System | Case UI, Reports, Linking | Already exists |
| `title` | System + Analyst | Case UI, Reports | Already exists |
| `tags` | Analyst | Case UI, Filtering | Already exists |
| `state` | System | Case UI, Filtering | Already exists |
| `artifacts[]` | Analyzers (via createCaseFromAnalysis) | Evidence, Reports, Timeline | Analysts need to know what was analyzed; currently reconstructed from entry text |
| `findings[]` | Analyzers | Case UI, Detection, Timeline, Reports | Currently flattened into entry bodies — drives Detection Candidates |
| `iocs[]` | Analyzers | IOC table, Threat Intel, Reports | Currently flattened then re-parsed by regex |
| `evidenceItems[]` | Analyzers | Case UI, Reports, Timeline | Currently flattened |
| `analysisSummary` | Analyzers | Case header, Reports | Currently parsed from a decision entry |
| `timeline[]` | System (generated) | Timeline UI, Reports | Generated once on creation, persisted so it survives page reload |
| `mitre[]` | Analyzers | Detection, MITRE UI | Currently stored in Investigation wrapper (not persisted) |
| `activity[]` | Analyst | Case UI, Reports | Redefined `entries` — analyst-authored only |
| `reports[]` | Export system | Report history, Re-export | Persists generated reports so they don't need regeneration |
| `detections[]` | Analyst (from findings) | Detection workspace, Sigma generation | Enables the Detection phase without reparsing findings |

---

## 5. Migration Strategy

### Additive (no breaking changes)

**Phase 1 — Dual-write**: `createCaseFromAnalysis()` writes both:
- Structured fields: `artifacts`, `findings`, `iocs`, `evidenceItems`, `analysisSummary` (new fields)
- Legacy: `entries[]` (keep existing format)

`case.tsx` reads structured fields when available, falls back to parsing `entries[]` for legacy cases.

**Phase 2 — Read from structured**: Update `case.tsx` to prefer `case.findings`, `case.iocs`, etc. Remove parse functions after confirming legacy coverage.

**Phase 3 — Stop writing entries**: `createCaseFromAnalysis()` stops populating `entries[]` for analysis data. `entries` now only holds `activity`.

**Phase 4 — Clean up**: Remove `parseSeverity`, `parseSource`, `parseIocEntry`, `parseSummaryEntry`. Remove `Investigation` wrapper. Rename `entries` to `activity`.

### Compatibility

- All existing `localStorage` cases continue to work
- Legacy cases render via fallback parse path
- New cases always write structured fields
- `saveCases()` and `loadCases()` unchanged during Phases 1-2

---

## 6. Future Features Enabled

| Feature | Required Field | Previously Blocked By |
|---|---|---|
| **Detection Candidates** (H.4) | `case.findings` with `technique` | Findings buried in strings, technique never persisted |
| **Report Engine** (H.5) | `case.*` all fields | Everything had to be re-parsed from strings |
| **Timeline Engine** (H.2) | `case.timeline` | Timeline rebuilt on every page load |
| **Evidence Relationships** (H.3) | `case.artifacts`, `case.findings`, `case.iocs` | Structured IDs lost in flattening |
| **IOC Intelligence** (Phase I) | `case.iocs` with `severity` | IOC severity never persisted |
| **Aggregated MITRE view** | `case.mitre` | Only computed transiently in Investigation wrapper |
| **Offline timeline** | `case.timeline` persisted | Timeline was ephemeral |

---

## 7. Canonical vs Derived Classification

| Field | Classification | Rationale |
|---|---|---|
| `artifacts[]` | **Canonical** | Primary evidence of what was analyzed — not recomputable |
| `findings[]` | **Canonical** | Judgments from analyzers — single source of truth |
| `evidenceItems[]` | **Canonical** | Supporting excerpts — distinct from findings |
| `iocs[]` | **Canonical** | Atomic indicators (IPs, hashes, URLs) — not derivable |
| `activity[]` | **Canonical** | Human decisions and notes — irreproducible |
| `analysisSummary` | **Derived (cache)** | Verdict/score/confidence recomputable from findings + iocs |
| `timeline[]` | **Derived (cache)** | Reconstructable from timestamps across all canonical fields |
| `mitre[]` | **Derived** | Deduplicated from `findings[].technique` — one-liner |
| `detections[]` | **Derived (initially)** | Computed from findings + analyst decisions; may become canonical later |

### Implication

Phase 1 should only persist canonical fields + analysisSummary (already computed, trivial to dual-write). Derived fields like `timeline`, `mitre`, and `detections` should be computed on access or deferred to their respective feature phases.

## 9. Risks

| Risk | Mitigation |
|---|---|
| More data per Case (larger localStorage) | Additive migration — existing data unchanged. Evaluate IndexedDB if size exceeds limits. No silent 5MB drop. |
| Dual-write increases `createCaseFromAnalysis()` complexity | Extraction is linear — `findings.map`, `iocs.map`. No branching logic. |
| Legacy parse path retained too long | Remove parse functions in Phase 4 after verifying all active cases have migrated. |
| `activity` rename breaks external consumers | Phase 4 only — no external consumers exist yet. |
| Field duplication (`findings[]` + `entries[]`) | Temporary — entries stop carrying findings in Phase 3. |

### Tradeoff Assessment

```
More data stored → less reparsing → cleaner architecture → faster rendering → enables features
```

The tradeoff is overwhelmingly positive because every blocked feature requires the structured data that is currently being discarded.

---

## 10. Recommendation

**Investigation wrapper should be absorbed into Case.**

`Investigation` exists only because `Case` couldn't hold structured data. Once `Case` has `findings[]`, `iocs[]`, `evidenceItems[]`, and `analysisSummary`, the wrapper has no remaining purpose. The `analysisResults` array (unpersisted) should become a transient cache, not a wrapper field.

**Result**: One model. One persistence layer. One source of truth.

## 11. Phase 1 Scope (Implementation)

### Fields to Add

```
artifacts[]     — canonical, primary evidence
findings[]      — canonical, analyzer judgments
evidenceItems[] — canonical, supporting excerpts
iocs[]          — canonical, atomic indicators
analysisSummary — cache, already computed, trivial to dual-write
```

### Fields Deferred

```
timeline[]          — derived, compute on access
mitre[]             — derived, compute from findings[].technique
detections[]        — future feature, no consumer yet
reports[]           — future feature, no consumer yet
activity[] rename   — Phase 4, cosmetic
```

### Migration Pattern

1. **Case model** adds new fields as optional (`?`) for backward compatibility with existing localStorage data.
2. **case-factory.ts** dual-writes: populates both new structured fields AND legacy `entries[]`.
3. **case.tsx** reads structured fields when available (`case.findings`, `case.iocs`, `case.analysisSummary`); falls back to legacy parse functions for old cases.
4. **Persistence** unchanged — `saveCases()`/`loadCases()` still manage `Case[]` in localStorage. New fields serialize naturally with the rest of the object.

## 12. Phase H.2 Scope (Eliminate Legacy Parsing)

### Target

Every screen that currently uses regex or string parsing to consume analysis data must be converted to read directly from `Case` structured fields. After this phase, the 4 legacy parse functions only exist inside the migration layer (legacy fallback paths for old cases).

### All Parse Sites in `case.tsx`

| # | Site | Lines | Uses | Can Read From |
|---|---|---|---|---|
| 1 | `entryEventTitle()` — decision branch | 71-73 | `parseSummaryEntry` | `case.analysisSummary` |
| 2 | `entryEventTitle()` — ioc branch | 76-83 | `parseIocEntry` | `case.iocs[]` |
| 3 | `entryEventTitle()` — evidence branch | 85-89 | `parseSeverity`, `parseSource` | `case.findings[]` |
| 4 | `filteredEntries` — analyzer filter | 142 | `parseSource` | `case.findings[].source`, `case.iocs[].source` |
| 5 | Investigation Overview | 621-627 | `parseSummaryEntry`, `parseSeverity` | `case.analysisSummary`, `case.findings[]` |
| 6 | Findings tab (legacy fallback) | 895-938 | `parseSeverity`, `parseSource` | `case.findings[]` |
| 7 | IOC panel (legacy fallback) | 736-840 | `parseIocEntry`, regex | `case.iocs[]` |
| 8 | Timeline rendering | 1004, 1011 | `parseSeverity`, `parseSource` | `case.findings[]`, `case.iocs[]` |
| 9 | Handoff report IOC extraction | 311-314 | raw regex (ip, url, hash) | `case.iocs[]` |
| 10 | Markdown export IOC extraction | 370-377 | raw regex (ip, url, hash) | `case.iocs[]` |
| 11 | HTML export IOC extraction | 434-440 | raw regex (ip, url, hash) | `case.iocs[]` |
| 12 | Timeline IOC rendering | 742, 748 | `parseIocEntry` | `case.iocs[]` |

### Outside `case.tsx`

| # | File | Line | What |
|---|---|---|---|
| 13 | `case.ts` | 53 | `autoDetectKind` — regex for IOC detection (entry-side, not structured) |

### Work Plan

**Step 1 — Shared IOC utility**: Extract IP/URL/hash regexes into a single `@/lib/iocs` module with a function like `extractIocs(text: string): { ips, urls, hashes32, hashes64 }`. Import everywhere instead of redefining.

**Step 2 — Structured entryEventTitle**: Replace `parseSummaryEntry`/`parseIocEntry`/`parseSeverity`/`parseSource` in `entryEventTitle()` with lookups against `case.analysisSummary`, `case.findings[]`, `case.iocs[]`. The entry body is only used for analyst-written notes.

**Step 3 — Structured timeline rendering**: Replace parse calls in the timeline JSX with structured field lookups. Remove `parseSource` from `filteredEntries` analyzer filter — filter against `case.iocs[].source` instead.

**Step 4 — Structured reports/exports**: Replace regex IOC extraction in handoff report, markdown export, and HTML export with `case.iocs[]`. After Step 1, the shared IOC utility handles the legacy fallback case.

**Step 5 — Delete legacy fallback**: Once all 5 analyzers have been dual-writing long enough (no active legacy-only cases), remove `parseSeverity`, `parseSource`, `parseIocEntry`, `parseSummaryEntry`, and all legacy fallback code branches.

### Completion Criteria

- [ ] `extractIocs()` in shared module replaces all inline regex
- [ ] `entryEventTitle()` reads structured fields, not entry body
- [ ] `filteredEntries` analyzer filter reads `case.iocs[].source`
- [ ] Investigation Overview reads only `case.analysisSummary`
- [ ] Findings tab reads only `case.findings[]` (no legacy fallback)
- [ ] IOC panel reads only `case.iocs[]` (no legacy fallback)
- [ ] Handoff/markdown/HTML export reads `case.iocs[]`
- [ ] `parseSeverity`, `parseSource`, `parseIocEntry`, `parseSummaryEntry` deleted
- [ ] `autoDetectKind` updated to use shared IOC utility
- [ ] `tsc --noEmit` and `npm run build` pass
