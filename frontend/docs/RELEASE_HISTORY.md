# BeyondLabs Release History

Permanent record of every release, its benchmark results, and the decision for the next milestone.

---

## Template

```text
## vX.Y — Release Name

**Date:** YYYY-MM-DD
**Branch:** <branch>
**Commit:** <sha>

### Objective

One sentence describing what this release was trying to achieve.

### Architecture Changes

- Major architectural decisions or changes in this release.

### Product Changes

- Notable user-facing changes.

### Benchmark Results

| Metric | Value |
|--------|-------|
| Benchmark Version | |
| Verdict Accuracy | |
| Findings Coverage | |
| IOC Coverage | |
| MITRE Coverage | |
| Trust Score (avg) | |

### Workflow Metrics

| Metric | Value |
|--------|-------|
| Avg Investigation Time | |
| Avg Searches / Investigation | |
| Avg Context Switches | |

### Top 5 Improvements

1.
2.
3.
4.
5.

### Known Issues

- 

### Release Gates

- [ ] Functional — Build, typecheck, benchmark complete, no critical bugs
- [ ] Analytical — No regression in accuracy, coverage, or trust
- [ ] UX — Investigation time, searches, and context switches stable or improved

### Decision

Ready for next milestone:
```

---

## v0.8 — Platform Foundation

**Date:** 2026-07-26
**Branch:** `main`
**Commit:** N/A (initial release)

### Objective

Finish the architecture and establish the platform foundation.

### Architecture Changes

- Unified `AnalysisResult` contract across all analyzers
- `CaseFactory` and structured `Case` model with typed events, findings, IOCs, evidence
- `CaseEvent` system with typed event kinds, categories, importance levels, origin tracking
- Investigation Activity Feed
- Legacy parser removal
- Architecture freeze declared
- `PLATFORM_BASELINE.md` created as architecture snapshot

### Product Changes

- Unified navigation with sidebar groups
- Shared analyzer pipeline
- Structured findings, IOCs, evidence in case notebook
- Case persistence via localStorage
- IOC Locker
- Investigation Report generation

### Release Gates

- [x] Functional — Build passes, typecheck passes, no critical bugs
- [ ] Analytical — No benchmark existed at this point
- [ ] UX — No benchmark existed at this point

### Decision

**Ready for v0.9.** Architecture is stable enough to build search and workflow improvements.

---

## v0.9 — Search & Workflow

**Date:** 2026-07-27
**Branch:** `main`
**Commit:** current

### Objective

Make analysts faster without redesigning the UI.

### Architecture Changes

- `SearchItem` canonical discovery layer — unified Fuse index for cases, findings, IOCs, events, notes, artifacts, pages
- Shared `useSearch()` hook in `search-engine.ts` — module-level singleton, cache invalidation via DOM events
- Search query logger to localStorage for behavioral analysis
- Bulk selection engine (`useSelection` hook + `BulkActionBar`)
- Deep link support via URL search params (`?tab=ioc&highlight=0`)
- Architecture freeze maintained

### Product Changes

- GlobalSearch dialog (`⌘⇧F`) — cross-entity search with type-grouped results
- Enhanced CommandPalette — inline investigation results with shared ranking
- Bulk IOC actions — multi-select, add to locker, copy values, remove from case
- Deep links — search results navigate to specific tab/highlight in case view
- Benchmark suite (40 samples, 5 categories) with ground truth
- Analyst validation page (`/validation`) — per-sample metrics, export, analytics dashboard
- Benchmark versioning, coverage comparison, trust scoring

### Benchmark Results

| Metric | Value |
|--------|-------|
| Benchmark Version | 1.0 |
| Verdict Accuracy | N/A (not yet run) |
| Findings Coverage | N/A (not yet run) |
| IOC Coverage | N/A (not yet run) |
| MITRE Coverage | N/A (not yet run) |
| Trust Score (avg) | N/A (not yet run) |

### Workflow Metrics

| Metric | Value |
|--------|-------|
| Avg Investigation Time | N/A (not yet run) |
| Avg Searches / Investigation | N/A (not yet run) |
| Avg Context Switches | N/A (not yet run) |

### Top 5 Improvements

1. Cross-entity global search replaces page-by-page hunting
2. Bulk IOC actions reduce repetitive operations
3. Deep links eliminate manual tab navigation
4. Benchmark suite enables objective accuracy measurement
5. Validation framework captures UX metrics alongside correctness

### Known Issues

- `case.tsx` has 9 pre-existing TypeScript errors (missing `useMemo` import, `setAnnotatingEntry`)
- `useActiveCase` hook in `lib/case.ts` bypasses the event system — documented tech debt
- No benchmark results yet (campaign not conducted)

### Release Gates

- [x] Functional — Build and typecheck pass (pre-existing case.tsx errors excluded), benchmark suite defined, no critical bugs
- [ ] Analytical — No benchmark data collected yet
- [ ] UX — No benchmark baseline established yet

### Decision

**Entering validation phase.** Architecture is frozen, validation framework is built. Next step: run the benchmark campaign to establish baseline metrics before designing v0.10.

---

## v0.10 — Investigation Workspace (planned)

**Date:** TBD
**Branch:** TBD

Goal and success criteria defined in `PRODUCT_ROADMAP.md`. Evidence from Benchmark 1.0 campaign will determine the specific scope.

---

## v1.0 — Investigation Platform (planned)

Goal defined in `PRODUCT_ROADMAP.md`.

---

## v1.1 — Platform Enhancements (planned)

Goal defined in `PRODUCT_ROADMAP.md`.
