# BeyondLabs — Frontend Reconstruction Recommendations

## Baseline

The workflow is frozen at `v0.9-workflow-freeze`. These recommendations improve **presentation, navigation, and interaction quality** only — they do not add or change features.

---

## Priority 1: High Impact, Low Effort

### 1.1 Knowledge Bar for Intel Entities

**What OpenCTI does:** The Knowledge tab shows a permanent right-side drawer with categorized relationship counts (Entities: 12, Threats: 3, Arsenal: 8, Observations: 5). Clicking a category shows a filtered list in the content area.

**What BeyondLabs does:** Shows a flat list of relationships in a Panel.

**Recommendation:** Replace the flat Relationships panel with a categorized sidebar. Categories would be: Actors, Malware, Vulnerabilities, Hashes, TLS Fingerprints. Each shows a count. Clicking filters the results. This makes relationship exploration bidirectional and navigable.

**Adaptation:** Not a permanent drawer — embedded in the entity detail page as a panel on the right side (like OpenCTI's knowledge bar but without the permanent drawer). Two-column layout: left = overview + observables, right = knowledge bar + actions.

**Effort:** 1-2 days.

---

### 1.2 Composed Entity Overview

**What OpenCTI does:** The overview page is a configurable grid of widgets: StixDomainObjectOverview (basic info), EntityDetails (domain fields), SimpleStixCoreRelationships (recent), StixCoreObjectExternalReferences, StixCoreObjectLatestHistory, StixCoreObjectOrStixCoreRelationshipNotes.

**What BeyondLabs does:** A single Panel with a `buildOverview()` function that returns a list of `{ label, value }` pairs.

**Recommendation:** Split the overview into composed sub-panels:
- **Basic Information:** Type, score, confidence, last seen (current overview fields)
- **Entity Details:** Type-specific fields (CVSS, vendor, exploits for CVEs; origin, motivation, targets for actors)
- **Relationships Preview:** First 5 relationships with "View all" link
- **External References:** URLs, advisories, CVE links
- **Notes:** Any analyst notes attached to this entity

Each sub-panel is a reusable component. This makes the page feel structured rather than a single flat list.

**Effort:** 1-2 days.

---

### 1.3 Entity Header with Actions

**What OpenCTI does:** A consistent `StixDomainObjectHeader` with title (inline editable), entity type badge, confidence/reliability, and a consistent actions row (edit, relate, delete, share, export, enrich).

**What BeyondLabs does:** The entity title panel doubles as header and summary, with actions scattered below.

**Recommendation:** Create a dedicated entity header above the content area:
- Left: Entity type icon + title + confidence badge + score badge
- Right: Copy entity ID, Add to Locker, Export MD, Intel → Case actions
- Below: Tags as chips

Keep the summary text in a separate Panel below the header. The header should be sticky as the user scrolls the entity detail.

**Effort:** 1 day.

---

### 1.4 Consistent Empty/Loading States

**What OpenCTI does:** Every page has `Loader` during loading, `ErrorNotFound` for missing data, and contextual empty state messages.

**What BeyondLabs does:** `Empty` component exists and is used on most pages, but loading states are inconsistent and error states are rare.

**Recommendation:** Audit every page for:
- Loading state (skeleton or spinner) for async operations
- Empty state for each panel that can be empty
- Error state for corrupt or missing data

The UI Consistency Audit (`docs/UI_CONSISTENCY_AUDIT.md`) already has a per-page score. Bring every page above 8/12.

**Effort:** 2-3 days across all pages.

---

## Priority 2: Medium Impact, Medium Effort

### 2.1 Right-Side Drawers for Case Actions

**What OpenCTI does:** Entity creation and editing use right-side drawers (420px-960px) triggered by a FAB button. The user never navigates away from the current context.

**What BeyondLabs does:** Intel → Case handoff buttons trigger a toast and update data, but there's no intermediate UI to confirm or customize what's being created.

**Recommendation:** When the analyst clicks "Create Finding" or "Attach IOCs" on an Intel entity, open a right-side drawer that shows:
- A preview of the finding that will be created (title, severity, IOC count)
- A case selector (active case pre-selected, dropdown for other cases)
- Optional note field
- Confirm/Cancel buttons

This replaces the current fire-and-forget toast with a deliberate action that the analyst can review and customize.

**Effort:** 2-3 days.

---

### 2.2 Tabbed Entity Detail

**What OpenCTI does:** Every entity has tabs: Overview, Knowledge, Analyses, Sightings, Files, History. Each tab is a route, deep-linkable.

**What BeyondLabs does:** All entity information is in a single continuous scroll page.

**Recommendation:** Split the Intel entity detail into 3-4 tabs:
- **Overview:** Header + summary + basic info + type-specific details
- **Relationships:** Categorized knowledge bar + relationship list
- **Observables:** Table of all observables with bulk actions (copy, locker, export)
- **History:** Timeline of when this entity was viewed, linked to cases, or enriched

Tabs should be sticky and route-driven (via `?tab=` or sub-route). This makes entity detail pages navigable and deep-linkable.

**Effort:** 3-4 days.

---

### 2.3 DataTable Component

**What OpenCTI does:** `DataTable` with column definition system, sorting, filtering, multi-select, drag-reorder, pagination, CSV export. Used consistently across list pages.

**What BeyondLabs does:** Each page builds its own table with hand-rolled markup. The IOC table in the case page is the most structured, but it's not reusable.

**Recommendation:** Extract a lightweight `DataTable` component from the IOC table pattern:
- Column definitions: `{ id, label, width, render, sortable }`
- Sort state: `{ column, direction }` with URL persistence
- Selection: checkbox column, shift-click range
- Filter: search input + column-specific filters
- Supports empty state and loading state

Start with the IOC list and entity list. Don't force every table to use it — adopt where it reduces code duplication.

**Effort:** 2-3 days.

---

## Priority 3: Polish

### 3.1 Keyboard Shortcuts
- `J/K` or arrow keys for list navigation
- `Ctrl+Enter` to submit forms
- `Escape` consistently closes panels/dialogs
- Document shortcuts with `kbd` badges in the UI

### 3.2 Tab Deep-Linking
All tab states should survive page refresh via URL search params. Currently the case page does this (`?tab=findings`). Intel entity tabs should too.

### 3.3 Responsive Behavior
Minimum width of 1024px (not 1400px like OpenCTI). At narrower widths, collapse sidebar panels, stack grid columns, and show/hide less important columns. This makes BeyondLabs usable on smaller screens without a full responsive rebuild.

---

## Architectural Recommendations (Cross-Cutting, Pre-Sprint Foundation)

These are not UI features — they are infrastructure patterns that multiple UI features depend on. Consider implementing the **MESSAGING$ bus** and **usePaginationLocalStorage** before Sprint 1 if other features will use them.

### A.1 MESSAGING$ Notification Bus

**What OpenCTI does:** A single RxJS Subject (`MESSAGING$`) in `relay/environment.jsx` with `notifyError()`, `notifySuccess()`, etc. A consumer component (`Message.tsx`) renders MUI Snackbar. 500ms debounce. The `useApiMutation` hook auto-fires messages on success/error.

**What BeyondLabs does:** Ad-hoc toast calls scattered across components. No central notification bus.

**Recommendation:** Before any Sprint 1 work, create `src/lib/messaging.ts`:
- Simple EventTarget or custom event bus (no RxJS dependency)
- `notifySuccess(text)`, `notifyError(text)`, `notifyInfo(text)`
- A `<Toaster>` component subscribes and renders timed snackbar
- Auto-dismiss: 3s for success, 6s for errors
- 200ms debounce to coalesce rapid notifications

This is a prerequisite for right-side drawers (Sprint 2) and future form actions.

**Effort:** 0.5 days.

### A.2 usePaginationLocalStorage — Unified State Persistence

**What OpenCTI does:** `usePaginationLocalStorage(key, initialValue)` persists filter/sort/search/pagination to both localStorage and URL. URL params take priority on load. Cross-tab sync via BroadcastChannel. Filter state is a `FilterGroup` (mode + filters + filterGroups for AND/OR).

**What BeyondLabs does:** Some ad-hoc localStorage keys, some URL params (`?tab=` on case page). No unified pattern.

**Recommendation:** Create `src/hooks/usePaginationLocalStorage.ts`:
- Accepts a unique key and initial value
- Reads URL params on mount (priority), falls back to localStorage
- Writes changes to both URL (pushState, no navigation) and localStorage
- No BroadcastChannel sync needed yet (single-tab for now)
- Keep filter state simple (no FilterGroup) — flat key-value pairs are sufficient

**Effort:** 1 day.

### A.3 Error Boundary with Error-Code Routing

**What OpenCTI does:** `Error.jsx` class boundary with `getDerivedStateFromError` + error-code categorization. Auto-resets on route change. Frontend errors logged via mutation.

**What BeyondLabs does:** Some try/catch in individual components but no top-level error boundary.

**Recommendation:** Wrap each workspace route with an `ErrorBoundary` component that:
- Catches render errors
- Shows a contextual message (not found, forbidden, generic error)
- Auto-resets when the route changes
- Logs to console (no backend logging needed)

**Effort:** 0.5 days.

### A.4 Unified Entity Creation Form Pattern

**What OpenCTI does:** Every entity creation follows: `*Creation` wrapper (Drawer + FAB) → `*CreationForm` (Formik + Yup + shared field components) → `useApiMutation` (auto-notify, loading state).

**What BeyondLabs does:** No entity creation forms (Intel entities are mock data). Case creation is a simple dialog.

**Recommendation:** Not needed now — no real entity creation exists. But when it does (v1.x), use the Formik + Yup pattern with shared field components. For now, document the pattern in ARCHITECTURE.md so future work is consistent.

**Effort:** 0 days now (documentation only).

---

## Newly Discovered — Worth Noting for v1.x (Not Current Sprint)

### N.1 Investigation Graph Canvas

OpenCTI's "investigation" workspace is an interactive entity graph where analysts:
- Drag entities from search results onto a canvas
- Connect them by drawing edges (right-click drag)
- Annotate with notes
- Save/restore graph state
- Convert graph to a case/report with one click

This would fundamentally change BeyondLabs' investigation UX from entry-based to graph-based. Not for the current freeze cycle, but worth prototyping when v1.x begins.

**BeyondLabs adaptation:** Not a replacement for the case page, but an optional "Visualization" tab in the case that renders the case's entities and relationships as an interactive graph. The case entries/timeline become the metadata layer beneath the visual canvas.

### N.2 Rich Notes with Entity Linking

OpenCTI notes have: `attribute_abstract`, `content` (markdown), `note_types` (vocabulary), `likelihood`, `confidence`, `objects` (linked entities/relationships). Notes are created inline at the bottom of entity pages via an accordion.

**BeyondLabs adaptation:** Add inline note creation to Intel entity detail (bottom of page, expandable). Note types: "analysis", "enrichment", "context", "raw-data". Notes are linked to both the entity and the current case.

### N.3 Workflow State Machine

OpenCTI's `workflowEnabled` + `status template { name, color }` provides configurable entity lifecycle (e.g., New → Triage → Contained → Eradicated → Closed).

**BeyondLabs adaptation:** Replace binary active/closed case status with 4-5 states: Triage, Investigation, Remediation, Closed-Resolved, Closed-FalsePositive. Each with a color and transitions. The Progress checklist feeds into this — 100% progress suggests Ready-to-Close.

### N.4 "Origin of the Case" Display

OpenCTI prominently shows what triggered the case creation.

**BeyondLabs adaptation:** In the case header, show "Created from {analyzer type} — {artifact name}" with a link back to the original analysis. This is metadata already stored in `analysisSummary` but not surfaced visually.

### N.5 Field-Level Timeline Tracking

OpenCTI's audit logs record `changes: [{ field, old, new }]` for every update.

**BeyondLabs adaptation:** Add field-level detail to timeline events. When severity changes from "medium" to "high", the timeline should show "Severity: medium → high" rather than just "Finding updated".

### N.6 Observable Lifecycle

OpenCTI pipeline: raw data → observable → indicator → enrichment → decay.

**BeyondLabs adaptation:** Add status to IOCs: New → Enriching → Enriched → Investigated → Closed. Show enrichment status per IOC in the IOC table. This is a post-freeze data model change.

### N.7 MESSAGING$ Notification Bus

OpenCTI's RxJS Subject-based notification bus is simple and decoupled. Already covered in A.1 above — implement as pre-sprint infrastructure.

### N.8 usePaginationLocalStorage

OpenCTI's dual localStorage + URL persistence pattern. Already covered in A.2 above — implement as pre-sprint infrastructure.

### N.9 Investigation Undo Stack

OpenCTI's `useInvestigationState` uses sessionStorage for an operation stack (max 20) supporting undo/rollback via `getOpsUntilExpand()`.

**BeyondLabs adaptation:** Add undo support to the Investigation Progress checklist. When the analyst toggles "Findings Review" or "Ready for Handoff", push the previous state to a sessionStorage stack. A Ctrl+Z or undo button reverts the last action.

### N.10 Status Pipeline Visualization

OpenCTI's `ItemStatusTemplate` renders workflow statuses as colored tags separated by arrow icons, grouped by `order` field.

**BeyondLabs adaptation:** If workflow states are added (N.3), render the case lifecycle as a pipeline: `Triage → Investigation → Remediation → Closed`. Each state is a colored tag, connected by arrow icons. Active state is highlighted.

### N.11 PDF Export via pdfmake

OpenCTI converts HTML → PDF via `html-to-pdfmake` + `pdfmake`, supporting headers, footers, page breaks, tables, and image embedding.

**BeyondLabs adaptation:** Add a "Export as PDF" option to the case page. Convert case content (findings, IOCs, timeline, report) to styled PDF. The pipeline runs entirely in the browser — no server needed.

### N.12 Cross-Tab BroadcastChannel Sync

OpenCTI syncs list state across browser tabs via BroadcastChannel API.

**BeyondLabs adaptation:** When the user opens the same case in two tabs, changes in one tab should auto-reflect in the other. This is a nice-to-have — not needed until multi-case workflows are common.

---

## What We Should NOT Do (Rejections)

| Pattern | Reason for Rejection |
|---------|---------------------|
| OpenCTI's left nav with 20+ items | BeyondLabs' 7-workspace model is better for SOC workflows |
| GraphQL + Relay | Overkill for localStorage-based data |
| MUI component library | Tailwind is lighter, more controlled, and already established |
| Configurable overview layout per entity type | BeyondLabs has 5 entity types — hardcoding is fine |
| Collaborative editing | Single-analyst tool |
| Column drag-reorder in tables | Low value, high complexity |
| Virtualized lists (react-virtualized) | Data sizes are small enough for flat rendering |
| Infinite scroll | Pagination is simpler and sufficient |
| Entity type icons (150+) | BeyondLabs has 5 entity types — simple icon mapping is fine |
| Full graph visualization (force-graph-2d/3d) | Too complex for current scope — revisit in v1.x |
| Workflow state machine | Binary active/closed + checklist covers current needs |
| Dashboard widget system | No dashboards exist yet — design when dashboard is built |
| File management (import/export/storage) | Not needed until multi-case workflows |

---

## Decision Matrix

| Pattern | Adopt | Adapt | Skip | Reason |
|---------|:-----:|:-----:|:----:|--------|
| Messaging bus (MESSAGING$) | ✅ | | | Decouples notifications, pre-req for drawers |
| Error boundary with error-code routing | ✅ | | | Prevents one workspace from crashing another |
| Persistent filters/search (usePaginationLocalStorage) | ✅ | | | Shared hook removes duplicated state |
| Standardized empty/loading/error states | ✅ | | | Every page benefits, low effort per page |
| Common page action bar component | ✅ | | | Consistent header pattern across all workspaces |
| Entity header (identity left, actions right) | | ✅ | | Adapt to OpenCTI's pattern, not copy markup |
| Composed entity overview (sub-panels) | | ✅ | | Use reusable sub-panels, not widget grid |
| Knowledge bar (categorized relationships) | | ✅ | | Embed in page, not permanent drawer |
| Right-side drawer for creation/editing | | ✅ | | Adapt to analyzer → review → case pipeline |
| Tabbed entity detail | | ✅ | | Use OpenCTI's tab structure, not copy routes |
| Workflow status pipeline (arrows & tags) | | ✅ | | Use investigation stages (Intake → Analysis → etc.) |
| Investigation graph canvas | | ✅ | | Future v1.x feature — optional case visualization tab |
| Investigation undo stack (sessionStorage) | | ✅ | | Future — notebook edits, checklist toggles |
| Rich notes with entity linking | | ✅ | | Future — inline note creation on entity pages |
| PDF export via pdfmake | | ✅ | | Future — only if markdown reports are inadequate |
| Field-level timeline tracking | | ✅ | | Future — post-freeze data model change |
| Observables lifecycle (enrichment status) | | ✅ | | Future — post-freeze data model change |
| Origin of case display | | ✅ | | Future — surface existing metadata in case header |
| Drag-and-drop (`@hello-pangea/dnd`) | | | ✅ | Low value today — only needed for reorderable settings |
| CSV/image export enhancements | | | ✅ | Markdown export sufficient for now |
| STIX/TAXII | | | ✅ | Out of scope — no external intelligence sharing |
| Multi-tenancy | | | ✅ | Out of scope — single analyst |
| Connector framework | | | ✅ | Out of scope — no plugin system |
| GraphQL + Relay | | | ✅ | Overkill for localStorage-based data |
| MUI component library | | | ✅ | Tailwind is lighter and already established |
| Collaborative editing | | | ✅ | Single-analyst tool |
| Configurable widget grid per entity type | | | ✅ | 5 entity types — hardcoding is fine |
| Cross-tab BroadcastChannel sync | | | ✅ | Nice-to-have; not needed until multi-case workflows |
| Full force-graph-3d visualization | | | ✅ | Too complex for current scope; revisit in v1.x |
| Workflow state machine | | | ✅ | Binary active/closed + checklist covers current needs |
| Dashboard widget system | | | ✅ | No dashboards exist yet — design when dashboard is built |
| AI/NLQ search | | | ✅ | Future consideration — not now |

---

## OpenCTI Analysis Status

**No further OpenCTI analysis needed.** The reference is now saturated — all major architectural patterns, component patterns, interaction patterns, and data model patterns have been identified and categorized. Future OpenCTI references should be limited to concrete implementation questions (e.g., "how does OpenCTI render the knowledge bar layout?") rather than discovery analysis.

---

## Implementation Order

### Sprint 0 — Platform Infrastructure
No UI changes. Foundation that every future page benefits from.

1. **MESSAGING$ notification bus (A.1)** — `src/lib/messaging.ts` with `notify.success/error/warning/info` + `<Toaster>` consumer. Replaces ad-hoc toast calls.
2. **Error boundary per workspace (A.3)** — Wrap Intake, Investigation, Intel, Detection, SIEM, Operations. One workspace crash doesn't take down the rest.
3. **Shared persistence hook (A.2)** — `usePaginationLocalStorage(key, initialValue)`. Dual localStorage + URL sync. Start with Intel search and case filters.
4. **Standardized empty/loading/error states (1.4)** — Audit every workspace. `Empty`, `Loading`, and `ErrorPanel` variants that match.
5. **Common page action bar** — Extract the sticky header pattern shared across workspaces. Not Entity Header (that's Sprint 1) — the workspace-level action bar (search, create, filter).

### Sprint 1 — Visual Reconstruction: Intel Entity Detail
Pattern page — if Intel entity detail is right, other entity pages follow.

1. Entity header: identity left (type icon, title, score/confidence badges), actions right (copy, locker, export, case actions), tags below. Sticky.
2. Composed overview: sub-panels (BasicInfo, EntityDetails, RelationshipPreviews, ExternalReferences, Notes).
3. Knowledge bar: categorized relationship sidebar with counts. Embedded in page (not permanent drawer).

### Sprint 2 — Visual Reconstruction: Case + Intel Polish

1. Right-side drawer for Intel → Case handoff (uses MESSAGING$ for confirm/cancel feedback).
2. Tabbed entity detail: Overview | Relationships | Observables | History.
3. Loading/empty/error state audit across remaining workspaces.

### Sprint 3 — Cross-Cutting Polish

1. Investigaton Pipeline: visualize checklist stages as `Intake → Analysis → Findings → Intel → Report → Handoff` pipeline (ItemStatusTemplate inspiration, adapted to investigation stages).
2. DataTable component: extract from IOC table pattern, add sorting/selection/filtering.
3. Keyboard shortcuts: registry + cheat-sheet dialog.
4. Tab deep-linking audit: every tab survives refresh via URL params.
5. Responsive baseline: minimum 1024px.

### v1.x (Post-Freeze)

1. Investigation graph canvas (optional case visualization tab)
2. Rich notes with inline entity linking
3. PDF export via pdfmake (if needed)
4. Field-level timeline tracking
5. Undo stack for checklist toggles and notebook edits
