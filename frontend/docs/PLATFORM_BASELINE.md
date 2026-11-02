# Platform Baseline

> Snapshot of BeyondLabs architecture as of architecture freeze.
> Not a vision document. Record of what exists and the rules that govern it.

---

## Domain Objects

| Object | File | Status |
|---|---|---|
| `Artifact` | `src/types/security.ts` | Stable |
| `Finding` | `src/types/security.ts` | Stable |
| `IOC` | `src/types/security.ts` | Stable |
| `EvidenceItem` | `src/types/analysis.ts` | Stable |
| `AnalysisResult` | `src/types/analysis.ts` | Stable |
| `AnalysisSummary` | `src/types/analysis.ts` | Stable |
| `Case` | `src/data/case.ts` | Stable |
| `CaseEvent` | `src/data/case.ts` | Stable |
| `Entry` | `src/data/case.ts` | Legacy — frozen |
| `SearchItem` | `src/lib/search-index.ts` | Stable |

---

## Core Services

| Service | File | Role |
|---|---|---|
| Analyzers | `src/api/*.ts` | Produce `AnalysisResult` |
| Case Factory | `src/data/case-factory.ts` | `createCaseFromAnalysis()`, event builders |
| Case persistence | `src/data/case.ts` | `loadCases()` / `saveCases()` (localStorage) |
| Search Engine | `src/lib/search-engine.ts` | Shared Fuse instance, `useSearch()` hook |
| Search Index | `src/lib/search-index.ts` | `buildSearchIndex()` — typed `SearchItem[]` builder |
| Recents | `src/lib/recents.ts` | Route visit tracking |
| Timeline | `src/lib/timeline.ts` | App-wide activity (separate from Case events) |
| Locker | `src/lib/locker.tsx` | IOC locker context + persistence |
| Handoff | `src/lib/handoff.ts` | Cross-page send-to-case protocol |
| Reporting | `src/routes/report.$caseId.tsx` | Print/save case report |

---

## Stable Contracts

These types are consumed by multiple subsystems and must not change without updating all consumers:

- `AnalysisResult` — output of every analyzer
- `Case` — center of the investigation model
- `CaseEvent` — typed event stream
- `SearchItem` — unified search index entry
- `AnalysisSummary` — verdict/score/confidence
- `IOC` / `Finding` / `Artifact` — security primitives

---

## Frozen Components

These components are stable and should not be refactored without product justification:

- `InvestigationActivityFeed` — CaseEvent renderer
- `ExportPanel` — case export
- `ResultBanner` — analyzer verdict display
- `SendToRow` — cross-page handoff
- `EvidenceCard` — structured finding card
- `ToolShell` — analyzer page wrapper
- `IocLocker*` — IOC locker trigger/panel
- `CommandPalette` — ⌘K quick navigation
- `GlobalSearch` — ⌘⇧F investigation search
- `BulkActionBar` — reusable selection + bulk actions

---

## Architectural Rules

1. **AnalysisResult contract** — No analyzer may bypass `AnalysisResult`. Every analyzer output conforms to this shape.

2. **No string parsing for structured data** — No feature may parse serialized strings to recover structured information. All structured data (findings, IOCs, events) must be stored on the `Case` model as typed fields.

3. **Events on mutations** — All meaningful investigation mutations emit a `CaseEvent` via `addCaseEvent()` or event builders in `case-factory.ts`.

4. **Unified search index** — All searchable objects (cases, findings, IOCs, events, notes, artifacts, pages) enter `SearchIndex`. No subsystem maintains its own search.

5. **Dual-write for Entry compatibility** — Legacy `Entry[]` is populated alongside new structured fields. The `legacy-adapter.ts` bridge converts `Entry[]` → `CaseEvent[]` for the activity feed. No new code reads `Entry[]` directly.

6. **Architecture freeze** — No new core domain models, services, or abstractions unless a concrete product requirement cannot be satisfied with the current architecture. Every feature proposal must begin with an analyst problem, not a technical solution.

---

## Tech Debt

| Item | Impact | Notes |
|---|---|---|
| `useActiveCase` parallel hook | 3 components bypass event system | Documented, not blocking |
| `lib/case.ts` second implementation | Duplicates case data access | Consumed by ActiveCaseBar, AttachButton, AppSidebar |
| localStorage only | No migration path to server | Acceptable for local-first |
| `case.tsx` missing `useMemo` import | Build errors | Pre-existing, unrelated to architecture |
| No search param validation in routes | `as any` casts in navigation | Acceptable for current scale |
