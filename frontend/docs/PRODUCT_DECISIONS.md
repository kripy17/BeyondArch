# BeyondLabs Product Decisions

Permanent record of major product decisions and their rationale. Read this before proposing changes that contradict established direction.

---

## Decision: Local-first architecture

**Context:** BeyondLabs could have been designed as a cloud platform with a backend, authentication, and shared state.

**Decision:** All data lives in the browser. No backend required. No authentication. No sync.

**Rationale:** SOC analysts need to work with sensitive data that cannot leave their environment. Local-first means zero data leaves the browser, zero setup cost, and zero dependency on external infrastructure. It also means the product works offline, on a plane, in a classified environment, or on a VM with no outbound access. This decision is the single most important constraint shaping every other design choice.

**Trade-off:** No collaboration, no persistence across devices, no server-side processing. These are acceptable because they can be added later as optional layers without changing the core experience.

**Status:** Frozen. Not changing unless a benchmark result demonstrates that the local-first constraint is the primary blocker to completing investigations.

---

## Decision: Investigation-centric workflow

**Context:** Analysts could work with raw artifacts directly without a case structure.

**Decision:** Every investigation is represented by a single `Case` object. All artifacts, findings, IOCs, events, evidence, and notes belong to a case.

**Rationale:** Without a case structure, evidence fragments across tools and pages. The Case model provides a single source of truth for any investigation. It also provides the natural boundary for export (reports), persistence (save/load), and analysis (cross-case correlation).

**Trade-off:** Cases introduce overhead for trivial lookups. Not every artifact interaction needs a case. The "quick look" workflow (look up a hash, close the tab) doesn't benefit from the case model.

**Status:** Stable. The `Case` interface in `src/data/case.ts` is the canonical data model. All consumers import from it.

---

## Decision: Structured over parsed

**Context:** Early versions serialized analysis results into markdown strings. Downstream consumers had to parse text to extract structured data.

**Decision:** Never serialize meaningful data into strings. Every domain object (Finding, IOC, Artifact, EvidenceItem, CaseEvent) has a typed interface with structured fields.

**Rationale:** Parsing strings is fragile, untyped, and makes it impossible to query or filter by field. Structured objects enable search indexing, type-safe access, and reliable serialization. The cost is slightly more code at definition time, but far less code at consumption time.

**Status:** Frozen. Any new domain object must follow the same pattern.

---

## Decision: Architecture freeze

**Context:** After v0.8, the platform had enough abstractions to support the product vision.

**Decision:** No new core models, no new architectural wrappers, no new abstractions unless a concrete product requirement (validated through dogfooding) demonstrates they are necessary.

**Rationale:** Premature architecture creates unused abstractions that become maintenance debt. Every new model, wrapper, or abstraction must earn its place by solving a real problem an analyst encounters during an investigation. The existing architecture is sufficient for the product roadmap through v1.0.

**Trade-off:** Some feature implementations may be uglier or require slightly more code than a clean-slate redesign would. That's acceptable — the cost of redesigning is higher than the cost of slightly inelegant code for a single feature.

**Status:** Active. Enforced from v0.8 onward. Violations require justification in a PR description.

---

## Decision: Search-first philosophy

**Context:** Analysts navigate by clicking through pages. As the number of cases, findings, and IOCs grows, page-based navigation becomes slow.

**Decision:** The search index (`SearchItem` in `search-engine.ts`) is the canonical discovery layer. All consumers use the shared `useSearch()` hook. No subsystem maintains its own Fuse instance.

**Rationale:** One search engine means one ranking algorithm, one cache, one query log. Ranking is consistent across GlobalSearch and CommandPalette. The search query log (`localStorage("ba.search.log")`) provides behavioral data that reveals indexing gaps, weighting errors, and missing metadata.

**Status:** Active. Search is the primary navigation method. Every new domain object must be indexed as a `SearchItem`.

---

## Decision: Event-driven investigation activity

**Context:** Investigations generate a trail of actions (analyzer runs, IOC extractions, findings, decisions).

**Decision:** Every meaningful action emits a `CaseEvent` with a structured type, category, importance, and origin. Events are rendered in the Activity Feed.

**Rationale:** A flat timeline of events enables the analyst to reconstruct what happened, when, and why. Structured event types enable filtering, searching, and cross-case correlation. Events also provide the foundation for future features (timeline replay, audit trails, investigation reports).

**Trade-off:** Events add write overhead for every action. Not every transient action (typing a note draft) should emit an event.

**Status:** Stable. `CaseEvent` kinds are defined in `src/data/case.ts:CaseEventKind`.

---

## Decision: localStorage persistence

**Context:** BeyondLabs needed a persistence layer that works without a backend.

**Decision:** All data persisted to `localStorage` with structured keys (`ba.*` prefix). No database, no IndexedDB, no SQLite.

**Rationale:** localStorage is synchronous, zero-setup, and sufficient for single-analyst use with moderate data volumes. It survives browser restarts and requires no migration scripts for simple schema changes.

**Trade-off:** Performance degrades beyond ~5MB of data. No cross-tab synchronization. No query capabilities. These are acceptable because the product is local-first and single-analyst. Storage abstraction is planned for v1.1 if needed.

**Status:** Temporary. Will be replaced by an abstracted storage layer when a benchmark demonstrates that localStorage is the bottleneck.

---

## Decision: No AI-generated summaries (yet)

**Context:** LLMs can generate investigation summaries automatically.

**Decision:** Do not build AI features until the benchmark demonstrates that analysts complete investigations correctly but struggle to write reports.

**Rationale:** AI features are expensive to build, expensive to run, and introduce non-determinism that conflicts with the "evidence-aware" product principle. They also create a trust problem — the analyst must verify the AI's output. Before investing in AI, BeyondLabs should prove that the manual workflow is correct and efficient.

**Status:** Explicitly deferred. Revisit after Benchmark 2.0 if report generation is the top friction point.

---

## Decision: No multi-user collaboration

**Context:** Most SOC platforms support team workflows.

**Decision:** BeyondLabs is single-user, local-only. No sharing, no assignments, no comments, no approvals.

**Rationale:** Multi-user features add authentication, authorization, conflict resolution, synchronization, and state management complexity. None of these help answer the question: "Can a single analyst complete investigations efficiently?" Until that answer is yes, multi-user is premature.

**Status:** Explicitly out of scope through v1.1. Revisit only after the single-analyst workflow is validated.

---

## Decision: Validation inside the product

**Context:** The benchmark suite could be maintained as a separate document or external tool.

**Decision:** The benchmark queue and investigation recorder live at `/validation` in the product itself. Results persist to localStorage, exportable as JSON and Markdown.

**Rationale:** Keeping validation inside the product means it evolves with the product. New analyzers automatically appear in the benchmark context. The export format is designed to produce `ANALYST_TEST_RESULTS.md` directly. A separate tool would drift out of sync.

**Status:** Active. `/validation` is in the Developer sidebar group — visible to developers, invisible to analysts.

---

## Decision: Deep links via URL search params

**Context:** Search results needed to navigate to specific tabs and items within a case.

**Decision:** Deep link state is encoded as URL search parameters (`?tab=ioc&highlight=0`). Parsed by `case.tsx` via `useSearch()`.

**Rationale:** URL search params are naturally serializable, bookmarkable, and survive page refreshes. They don't require a separate data structure or global state. This is the simplest thing that works for the current navigation depth.

**Status:** Acceptable as-is. If deep linking grows beyond tab + highlight (e.g., specific event, specific finding), consider a dedicated deep-link data structure.

---

## Decision: Shared sidebar + single workspace

**Context:** Different investigation types (phishing, malware, log analysis) could have different workspace layouts.

**Decision:** One sidebar for all tools. Groups categorize tools by function (SIEM, Investigation, Detection, Intelligence, Tools). Users can pin favorites, hide groups, and reorder.

**Rationale:** A unified workspace reduces context switching. Analysts don't need to "switch modes" — they use the same mental model for every investigation type. Pinning provides personalization without workspace complexity.

**Status:** Stable. Group definitions in `src/lib/workspaces.ts`.

---

## Decision: Frozen 40-sample benchmark as first release baseline

**Context:** The benchmark could start with 10 samples and grow organically.

**Decision:** Release Benchmark 1.0 with exactly 40 samples (10 phishing, 10 URLs, 10 logs, 5 PCAPs, 5 files) and documented ground truth for every sample.

**Rationale:** 40 samples provides statistical significance for accuracy and coverage metrics. The fixed set enables reproducible before/after comparisons across releases. The mix of benign, malicious, and suspicious samples prevents overfitting to any single verdict.

**Status:** Active. `BENCHMARK_VERSION = "1.0"` in `src/data/benchmark.ts`. Next version (1.1+ ) will be created based on gaps identified during the first campaign.

---

## Decision: Friction over features during dogfooding

**Context:** During the validation phase, analysts encounter bugs, friction, and missing capabilities.

**Decision:** Record everything. Fix bugs immediately. Record friction as data (do not fix during the investigation phase). Collect wishes but do not implement until the campaign is complete and the results inform v0.10 priorities.

**Rationale:** Fixing friction mid-campaign invalidates the metrics. If you fix navigation on sample 20, samples 1–19 and 21–40 were measured under different conditions. The whole point of the campaign is to measure the current state accurately. Improvements belong in the next release.

**Status:** Active rule during Benchmark 1.0 campaign.
