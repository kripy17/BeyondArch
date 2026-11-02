# H.3 Investigation Timeline — Design Proposal

## 1. Current State (Two Disconnected Systems)

### System A: Global Timeline (`lib/timeline.ts`)

```ts
TimelineEvent {
  id: string;
  ts: string;
  source: string;     // free-form: "case", "phishing", "nmap", "detection"...
  verb: string;       // free-form: "analyzed", "scanned", "added-entry"...
  detail: string;
  target?: string;
  result?: string;
}
```

- Stored in localStorage under `ba.timeline.v1`
- Called from **20+ route files** via `pushTimelineEvent()`
- Not scoped to any Case — app-wide activity stream
- Free-form `verb` strings make filtering/reliability impossible
- No references to artifacts, findings, IOCs, or detections

### System B: Case Timeline (`case.tsx`)

```ts
// Case.entries (legacy) rendered with entryEventTitle()
// Each entry parsed from string body via:
//   - parseSummaryEntry()  — "Verdict: malicious\nScore: 85/100..."
//   - parseIocEntry()      — "ipv4: 1.2.3.4\nSource: phishing"
//   - parseSeverity()      — "[CRITICAL] finding title..."
//   - parseSource()        — "...(from: phishing)"
```

- Derived from Case.entries on every render
- No structured event types — just entry kinds (`note`, `evidence`, `ioc`, etc.)
- No references to external objects (findings, IOCs by ID)
- No system events (analysis started, case created, etc.)
- Analyzer filter works by parsing source from entry body strings

### InvestigationTimelineEvent (`types/investigation.ts`)

```ts
InvestigationTimelineEvent {
  id: string; ts: string;
  kind: "analysis" | "finding" | "ioc" | "note" | "action" | "decision";
  title: string; detail: string; source: string;
}
```

- **Never persisted** — constructed transiently in `createCaseFromAnalysis()`
- Only populated for `analysis` and `finding` events — misses everything else
- Not consumed by any UI

---

## 2. Proposed CaseEvent Model

```ts
// ── Category taxonomy ──
type EventCategory =
  | "artifact"
  | "analysis"
  | "finding"
  | "ioc"
  | "case"
  | "detection"
  | "report"
  | "analyst";

// ── Event kind taxonomy ──
type CaseEventKind =
  // Artifact lifecycle
  | "artifact_uploaded"

  // Analysis lifecycle
  | "analysis_started"
  | "analysis_completed"

  // Finding lifecycle
  | "finding_created"
  | "finding_severity_changed"
  | "finding_status_changed"       // e.g. analyst marks as FP

  // IOC lifecycle
  | "ioc_created"
  | "ioc_enriched"                 // threat intel lookup completed

  // Case lifecycle
  | "case_created"
  | "case_status_changed"
  | "case_note_added"
  | "case_decision_made"

  // Detection lifecycle
  | "detection_created"
  | "detection_status_changed"

  // Report lifecycle
  | "report_generated"

  // Analyst activity
  | "analyst_action"               // generic manual action
  | "analyst_comment";             // annotation on an entry/finding

// ── Actor taxonomy (future-proofed) ──
type EventActor = "system" | "analyst" | "automation" | "integration";

// ── Importance taxonomy ──
type EventImportance = "critical" | "high" | "normal" | "low";

// ── Referenced object ──
type EventReference = {
  kind: "artifact" | "finding" | "ioc" | "detection" | "report" | "evidence";
  id: string;
};

// ── The event ──
interface CaseEvent {
  id: string;
  ts: string;
  kind: CaseEventKind;
  category: EventCategory;
  importance: EventImportance;
  actor: EventActor;
  origin: string;                  // source analyzer: "phishing", "url", "logs"...

  // Human-readable — always displayable without context
  title: string;
  detail: string;

  // Typed reference list — scales with new domain objects
  references: EventReference[];
}
```

---

## 3. Key Design Decisions

### 3a. Events live on Case

Not in a separate global store. `Case.events: CaseEvent[]` is the canonical timeline for that investigation.

Rationale:
- Global timeline (`lib/timeline.ts`) serves a different purpose — app-wide activity, not case-specific
- Events should persist with the Case (survive page reload, export, etc.)
- No querying across cases needed yet (future can add a search index)

### 3b. Strongly-typed kinds over free-form verbs

`verb: "analyzed"` becomes `kind: "analysis_completed"`. This enables:
- Reliable filtering by event type
- UI rendering strategies per kind (icons, colors, layout)
- TypeScript narrowing — switch on `kind` and get typed references

### 3c. Typed reference list over fixed fields

`references: [{ kind: "finding", id: "f-001" }]` instead of `references: { findingId: "f-001" }`. This enables:
- Clickable navigation between timeline events and detail panels
- Report assembly (trace finding → IOC → detection)
- Graph queries ("show me everything related to finding X")
- Future domain objects (playbooks, yara rules, tickets) don't require type changes — just a new `EventReference.kind` value

### 3d. Importance and category enable smart filtering

Every event carries `category` (high-level grouping) and `importance` (relative weight). This decouples structural classification from display priority. The dashboard can surface "critical" events while the timeline filter can group by category.

### 3e. `events` is additive only

Events are never edited or deleted (analyst annotations and status changes produce new events). This preserves chronological integrity — the timeline is an append-only record.

---

## 4. Producer/Consumer Map

| Event Kind | Category | Importance | Producer | Consumers |
|---|---|---|
| `artifact_uploaded` | artifact | normal | Analyzer pages | Evidence panel |
| `analysis_started` | analysis | normal | Analyzer pipeline | Dashboard |
| `analysis_completed` | analysis | high | Analyzer pipeline | Overview panel |
| `finding_created` | finding | high | createCaseFromAnalysis | Findings tab, Detection |
| `finding_severity_changed` | finding | normal | Analyst | Timeline UI |
| `finding_status_changed` | finding | high | Analyst | Detection |
| `ioc_created` | ioc | normal | createCaseFromAnalysis | IOC panel, Intel |
| `ioc_enriched` | ioc | low | Intel pipeline | IOC panel |
| `case_created` | case | high | createCaseFromAnalysis | Dashboard |
| `case_status_changed` | case | high | Analyst | Dashboard |
| `case_note_added` | analyst | low | Analyst | Timeline UI |
| `case_decision_made` | case | critical | Analyst | Overview |
| `detection_created` | detection | high | Detection workspace | Detection panel |
| `detection_status_changed` | detection | normal | Analyst | Timeline UI |
| `report_generated` | report | normal | Report engine | Report history |
| `analyst_action` | analyst | normal | Analyst | Timeline UI |
| `analyst_comment` | analyst | low | Analyst | Timeline UI |

---

## 5. Migration Strategy

### Phase H.3a — Model + Events on New Cases

1. Add `events: CaseEvent[]` to Case (as optional `?` for legacy)
2. Update `createCaseFromAnalysis()` to emit structured events alongside legacy entries:
   - `case_created`
   - `artifact_uploaded`
   - `analysis_completed`
   - `finding_created` (per finding)
   - `ioc_created` (per IOC)
3. Case page UI prefers `events` when available, falls back to entries for legacy cases

### Phase H.3b — Analyst Activity Events

4. Update `addEntry()` in case.tsx to emit `case_note_added` or `case_decision_made` events
5. Update `toggleClosed()` to emit `investigation_status_changed`
6. Update `applyTemplate()` to emit `analyst_action` events

### Phase H.3c — Structured Timeline UI

7. Build a `TimelineView` component that renders `CaseEvent[]`:
   - Per-kind icon and color (no more `entryEventTitle()`)
   - Clickable references (e.g., finding ID links to Findings tab)
   - Filter by `category`, `importance`, `origin`, `actor`
8. Replace the case timeline tab with `TimelineView`

### Phase H.3d — Legacy Fallback Removal

9. Once all active cases have migrated, remove:
   - `entryEventTitle()`
   - `parseSeverity()`, `parseSource()`, `parseIocEntry()`, `parseSummaryEntry()`
   - `filteredEntries` timeline rendering
   - entry-based filtering in timeline

### Non-Goal

- The global `lib/timeline.ts` is left untouched — it serves as the app-wide activity log. It can be replaced separately if needed, but is not part of this scope.

---

## 6. Example: Phishing Investigation Timeline

```
ts                    category    imprt  kind                      title                          references
────────────────────────────────────────────────────────────────────────────────────────────────────────────
09:15:00              case        high   case_created              Phishing Investigation          []
09:15:01              artifact    normal artifact_uploaded         Email: invoice@evil.ru          [{kind:"artifact",id:"art-001"}]
09:15:02              analysis    normal analysis_started          Phishinger analysis             [{kind:"artifact",id:"art-001"}]
09:15:05              analysis    high   analysis_completed        4 findings · 2 IOCs             [{kind:"artifact",id:"art-001"}]
09:15:05              finding     high   finding_created           [CRITICAL] Sender spoofed      [{kind:"artifact",id:"art-001"},{kind:"finding",id:"f-001"}]
09:15:05              finding     high   finding_created           [HIGH] Suspicious URL           [{kind:"artifact",id:"art-001"},{kind:"finding",id:"f-002"}]
09:15:06              ioc         normal ioc_created               ipv4: 203.0.113.1              [{kind:"artifact",id:"art-001"},{kind:"ioc",id:"ioc-001"}]
09:15:06              ioc         normal ioc_created               url: https://evil-phish.com    [{kind:"artifact",id:"art-001"},{kind:"ioc",id:"ioc-002"}]
09:16:00              analyst     low    case_note_added           Starting investigation          []
09:16:15              case        crit   case_decision_made        Verdict: malicious              []
09:17:00              analyst     normal analyst_action            Template applied: Phishing     []
09:18:00              detection   high   detection_created         Sigma: Suspicious URL           [{kind:"ioc",id:"ioc-002"},{kind:"detection",id:"det-001"}]
09:19:00              report      normal report_generated          Handoff report generated        [{kind:"report",id:"rpt-001"}]
```

---

## 7. Integration with Case Model

```ts
Case {
  // ...existing fields...
  entries: Entry[];           // legacy — persists unchanged during H.3a-c
  events: CaseEvent[]; // new — canonical timeline

  // ...structured fields (Phase 1)...
  artifacts: Artifact[];
  findings: Finding[];
  iocs: IOC[];
  evidenceItems: EvidenceItem[];
  analysisSummary: AnalysisSummary | null;
}
```

### open questions

| Question | Decision |
|---|---|---|
| Should `events` include ALL data or just references? | **Typed reference list** — details live on the referred objects. Events are metadata + pointers. |
| Should the timeline be persisted or reconstructed? | **Persisted** — generated once on creation, enriched by analyst actions. Survives reload. |
| Is there a max event count? | **Not enforced** — investigations are bounded. If performance becomes an issue, paginate. |
| Should events be editable? | **No** — append-only. Status changes and corrections produce new events. |
| Why `references[]` instead of fixed fields? | **Scales with new domain objects** — adding playbooks, yara rules, or tickets doesn't require type changes, just a new `EventReference.kind` value. |
| Why `origin` separate from `actor`? | **Actor** is who performed the action; **origin** is the system component that initiated it. Example: `actor: "system"`, `origin: "logs analyzer"`. |

---

## 8. Risks

| Risk | Mitigation |
|---|---|
| Event model duplicates info in entries (H.3a-c dual-write) | Temporary — entries phased out in H.3d |
| Events array grows unbounded | Investigations rarely exceed 500 events. If needed, paginate at 1000. |
| References become stale (finding deleted) | Soft-delete findings (status: "removed") rather than hard-delete. Event references remain valid. |
| Too many event types to maintain | 17 kinds cover all current producers. New types added as features arrive. No need to predict future needs. |

---

## 9. H.3b.5 — Event Producer Audit

### Event Producer Matrix

| # | Mutation | Site | Emits CaseEvent | Should Emit? | Recommendation |
|---|---|---|---|---|---|
| 1 | `createCaseFromAnalysis` | case-factory.ts | ✅ 3-10 events | ✅ | Already complete |
| 2 | `addEntry` (note/evidence) | case.tsx | ✅ `case_note_added` | ✅ | Complete |
| 3 | `addEntry` (decision) | case.tsx | ✅ `case_decision_made` | ✅ | Complete |
| 4 | `addEntry` (action/ioc) | case.tsx | ✅ `analyst_action` | ✅ | Complete |
| 5 | `applyTemplate` | case.tsx | ✅ `analyst_action` | ✅ | Complete |
| 6 | `toggleClosed` | case.tsx | ✅ `case_status_changed` | ✅ | Complete |
| 7 | `createCase()` (blank) | case.tsx | ❌ | ⚠️ Optional | **Add `case_created`** — creating a blank case is a meaningful investigation action |
| 8 | Handoff entry on mount | case.tsx | ❌ | ✅ | **Add `case_note_added`** — handoff entries are analyst content from other pages |
| 9 | Case import from file | case.tsx | ❌ | ⚠️ Optional | **Add `analyst_action`** — importing is an explicit analyst action |
| 10 | Title edit | case.tsx | ❌ | ❌ | **Skip** — metadata change, not investigation history |
| 11 | Tag add/remove | case.tsx | ❌ | ❌ | **Skip** — metadata, not investigation history |
| 12 | Entry removal (with undo) | case.tsx | ❌ | ❌ | **Skip** — UI action with undo, events are append-only |
| 13 | Case deletion (with undo) | case.tsx | ❌ | ❌ | **Skip** — case no longer exists, event would be orphaned |
| 14 | Notebook content | case.tsx | ❌ | ❌ | **Skip** — not persisted (state issue, not event issue) |
| 15 | `useActiveCase.addEntry` | lib/case.ts | ❌ | ⚠️ High risk | **Flagged** — parallel implementation bypasses event system entirely |

### Critical Finding: Parallel Case Implementation

**`src/lib/case.ts`** defines its own `Case`, `Entry`, `EntryKind` types and its own `useActiveCase` hook with `addEntry`. This hook:
- Writes to the same localStorage key (`ba.cases.v2`)
- Does **not** include `events`, `findings`, `iocs`, `evidenceItems`, or `analysisSummary` on its Case type
- Does **not** emit any CaseEvents
- Is consumed by `AttachButton.tsx`, `AppSidebar.tsx`, and `ActiveCaseBar.tsx`

**Impact**: Entries added via these components create cases that are structurally incompatible with the new event system. The cases they create will never have events, even after the legacy path is removed.

**Recommendation**: 
- Short-term: Replace `useActiveCase` with the handoff mechanism (`sendToCase` from `lib/handoff.ts`). The 3 consumers already have access to case routing.
- Long-term: Remove `src/lib/case.ts` entirely after migrating consumers.

### Missing Producers (Recommended for H.3b.5 Implementation)

| Mutation | Event Kind | Category | Importance | Actor |
|---|---|---|---|---|
| `createCase()` (blank) | `case_created` | case | normal | analyst |
| Handoff entry processed | `case_note_added` | analyst | low | system (origin: handoff) |
| Case imported from file | `analyst_action` | analyst | normal | analyst |

### Producers Correctly Skipped

| Mutation | Reason |
|---|---|
| Title edit | Metadata — doesn't represent investigation progress |
| Tag add/remove | Metadata — doesn't represent investigation progress |
| Entry removal | Append-only principle — removal with undo would create conflicting events |
| Case deletion | Case destroyed — event would be orphaned |
| Notebook content | Not persisted — separate issue from the event system |

### Event Quality Check

Every emitted event was validated against the model:

| Field | Status |
|---|---|
| `id` | ✅ Always present (newId) |
| `ts` | ✅ Always present (ISO timestamp) |
| `kind` | ✅ Correct kind per producer |
| `category` | ✅ Appropriate for each kind |
| `importance` | ✅ Differentiated (low for notes, high for findings, critical for decisions) |
| `actor` | ✅ system vs analyst correctly assigned |
| `origin` | ✅ Identifies source analyzer or "case" |
| `references` | ✅ Present for machine events, empty for analyst events where appropriate |
| `title` | ✅ Human-readable |
| `detail` | ✅ Contextual, not overlong (200 char limit on analyst events) |

### Event Ordering Check

Events are always appended chronologically:
- Machine events: generated during `createCaseFromAnalysis` in correct sequence order
- Analyst events: appended at time of action via `addCaseEvent`
- No reordering needed or performed

### Taxonomy Validation

```
case_created           ✅ Used (H.3a case-factory, H.3b.5 candidate for blank case)
artifact_uploaded      ✅ Used (H.3a case-factory)
analysis_started       ⚠️ Defined but not yet emitted (reserved for future)
analysis_completed     ✅ Used (H.3a case-factory)
finding_created        ✅ Used (H.3a case-factory)
finding_updated        ✅ Defined but not yet emitted (reserved for future analyst actions)
finding_severity_changed ⚠️ Defined but not emitted (reserved)
finding_status_changed ⚠️ Defined but not emitted (reserved)
ioc_created            ✅ Used (H.3a case-factory)
ioc_enriched           ⚠️ Defined but not emitted (reserved for intel phase)
case_status_changed    ✅ Used (H.3b)
case_note_added        ✅ Used (H.3b)
case_decision_made     ✅ Used (H.3b)
detection_created      ⚠️ Defined but not emitted (reserved)
detection_status_changed ⚠️ Defined but not emitted (reserved)
report_generated       ⚠️ Defined but not emitted (reserved)
analyst_action         ✅ Used (H.3b)
analyst_comment        ⚠️ Defined but not emitted (reserved for annotations)

Active: 9 kinds
Reserved (defined, not yet emitted): 8 kinds
```

### Recommendations

**Before H.3c**:
1. Add 3 missing producers (blank case, handoff, import) — quick wins
2. Flag `useActiveCase` as technical debt — document but don't block
3. Proceed with H.3c — the event coverage is sufficient for the structured TimelineView

**After H.3c**:
4. Replace `useActiveCase` consumers with handoff mechanism
5. Remove `src/lib/case.ts`

---

## 10. H.3c.5 — Event Consumers Audit

### Matrix 1: Legacy Consumers

| # | File | Structured | Hybrid | Legacy | Role |
|---|------|-----------|--------|--------|------|
| 1 | `src/data/case.ts` | — | — | ✅ | Canonical `Entry`/`EntryKind` definition. `Case.entries` required field. `KIND_TONE`/`KIND_COLOR`/`autoDetectKind`/`CASE_TEMPLATES` all typed to `Entry`. |
| 2 | `src/data/case-factory.ts` | ✅ | ✅ | — | Dual-writes structured fields + entries. `*ToEntry()` converters are redundant with structured data. |
| 3 | `src/routes/case.tsx` | ✅ | ✅ | ✅ | Heaviest consumer. Uses `??` fallback everywhere. Defines 4 parse-only functions. |
| 4 | `src/routes/report.$caseId.tsx` | — | — | ✅ | Deepest standalone duplicate. Own `EntryKind`/`Entry`/`Case` types. Zero structured fields. |
| 5 | `src/lib/case.ts` | — | — | ✅ | Duplicate hook with own `EntryKind`/`Entry`/`Case`. No structured fields, no events. |
| 6 | `src/components/ActiveCaseBar.tsx` | — | — | ✅ | Reads `activeCase.entries` via `useActiveCase()`. |
| 7 | `src/components/AttachButton.tsx` | — | — | ✅ | Calls `addEntry()` via `useActiveCase()`. |
| 8 | `src/components/AppSidebar.tsx` | ✅ | — | — | `useActiveCase()` only for title/state display. Entry-agnostic. |
| 9 | `src/components/investigation/InvestigationActivityFeed.tsx` | ✅ | — | — | Fully migrated. Only consumes `CaseEvent[]`. |
| 10 | `src/components/investigation/legacy-adapter.ts` | — | ✅ | — | Adapter — `legacyEntriesToEvents()` converts Entry[] → CaseEvent[]. |
| 11 | `src/types/investigation.ts` | ✅ | — | — | Imports `Case` type. Blocked on `entries` field removal. |
| 12 | `src/lib/handoff.ts` | — | — | ✅ | `sendToCase()` stores `{ body, source, kind }`. 27 call sites. |
| 13 | `src/routes/logs.tsx`, `url.tsx`, `pcap.tsx`, `phishing.tsx`, `file.tsx` | ✅ | — | — | Factory callers. No direct Entry manipulation. |

### Matrix 2: Canonical Data

| Concept | Canonical Source | Derived From | Legacy Fallback |
|---------|-----------------|-------------|-----------------|
| Findings | `case.findings[]` | AnalysisResult structured field | `entries.filter(e => e.kind === "evidence")` |
| IOCs | `case.iocs[]` | AnalysisResult structured field | `entries.filter(e => e.kind === "ioc")` |
| Events | `case.events[]` | CaseEvent stream | `legacyEntriesToEvents(entries)` |
| Summary | `case.analysisSummary` | AnalysisResult structured field | `parseSummaryEntry(entries.find(...))` |
| Evidence | `case.evidenceItems[]` | AnalysisResult structured field | `entries.filter(e => e.kind === "evidence")` |
| Artifacts | `case.artifacts[]` | AnalysisResult structured field | None |
| Notes/Manual entries | `entries[]` (temporary) | User input via addEntry/template/handoff | N/A |
| Audit trail | `case.events[]` | CaseEvent stream — append-only | None |

**Rule**: Every derived field must be computable from its canonical source. If they diverge, canonical wins.

### Matrix 3: Safe Removal

| Legacy Code | Blocked By | Removable When | Difficulty |
|------------|-----------|----------------|-----------|
| `parseSeverity` | case.tsx findings tab (structured fallback) | `case.findings` is always populated | **Now** |
| `parseSource` | case.tsx findings tab (structured fallback) | `case.findings[n].source` is always populated | **Now** |
| `parseIocEntry` | case.tsx findings tab (legacy IOC display) | `case.iocs` always populated | **Now** |
| `parseSummaryEntry` | case.tsx overview section | `case.analysisSummary` always populated | **Now** |
| `KIND_COLOR` | case.tsx markdown/HTML export | Export uses structured data instead of entry body | **After** export migration |
| `Case.entries` field | `report.$caseId.tsx`, `lib/case.ts`, handoff path | All 3 are migrated to structured equivalents | After H.3d |
| `case-factory.ts *ToEntry()` | `createCaseFromAnalysis` dual-write | No Entry[] consumer reads it | **Now** |
| `legacyEntriesToEvents()` | case.tsx `events ?? legacy()` | All cases have events | After handoff emits events |
| `report.$caseId.tsx` | No structured alternatives for timeline/IOC/evidence | `case.events` + `case.iocs` + `case.findings` available | After structured fields |
| `lib/case.ts` | ActiveCaseBar, AttachButton, AppSidebar | Hooks replaced with handoff + addCaseEvent | After handoff migration |

### Meta-Question

**"If BeyondLabs started today, would Entry[] exist?"**

No. Every feature `Entry[]` provides is now replaced by structured equivalents:
- Findings → `case.findings[]`
- IOCs → `case.iocs[]`
- Timeline → `case.events[]`
- Summary → `case.analysisSummary`
- Evidence → `case.evidenceItems[]`
- Audit trail → `case.events[]`

`Entry[]` is 100% technical debt. Zero product value in keeping it.

### Recommendation

| Phase | Action | Unlocks |
|-------|--------|---------|
| Immediately | Remove unused `KIND_TONE` import. Remove 4 parser functions from case.tsx (redirect to structured reads). | Cleaner case.tsx |
| H.3d | Remove legacy entries rendering paths in case.tsx. Delete `legacy-adapter.ts`. | Full event-only UI |
| Post-H.3d | Migrate `report.$caseId.tsx` to consume structured Case type. | Legacy report removal |
| Post-H.3d | Replace `lib/case.ts` with handoff + addCaseEvent. | Remove duplicate Case model |
| Post-H.3d | Remove `Case.entries` field. | Core model cleanup |
