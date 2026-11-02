# OpenCTI Project Analysis

## Overview

OpenCTI is an open-source cyber threat intelligence platform designed for collaborative intelligence sharing and analysis. It is built around the STIX 2.1 standard and provides a complete CTI lifecycle: ingestion, enrichment, analysis, sharing, and reporting.

**Stack:** Nx monorepo · TypeScript backend (GraphQL) · React/Relay frontend · Python worker · Elasticsearch/OpenSearch · Redis · RabbitMQ · MinIO

---

## What OpenCTI Does Well

### 1. Entity-Centric Navigation

Every page is centered around an entity. The URL pattern is consistent:

```
/dashboard/{domain}/{entity_type}/{entity_id}/{tab}
```

Navigation flows naturally: list → entity → tab → related entity. The left sidebar provides a hierarchical menu of entity categories, and the breadcrumbs track the current location within that hierarchy.

### 2. Knowledge Graph as a First-Class UI

OpenCTI's "Knowledge" tab is the most powerful feature. It shows all relationships for an entity in a navigable sidebar organized by category (Entities, Threats, Arsenal, Techniques, Observations, Events). Each category shows a count of related items. Clicking a category opens a relationship listing filtered to that type. The knowledge bar is a permanent right-side drawer on knowledge pages — it never scrolls away.

### 3. Configurable Overview Layout

Each entity type has a configurable overview layout (`overview_layout_customization`) that lets admins choose which widgets appear and at what width. Widgets include: basic information, entity details, recent relationships, external references, recent history, notes, and recent containers. This means the overview page is tailored per entity type without hardcoding.

### 4. Consistent Tab System

Every entity detail page uses the same tab structure defined in `StixDomainObjectTabsBox`. Tabs appear/disappear based on relevance per entity type, but the tab bar always behaves the same: sticky, route-driven, with consistent spacing and typography.

### 5. Right-Side Drawers for Creation/Editing

Entity creation and editing use right-side drawers (MUI Drawer, `anchor="right"`), never separate pages or modals. Sizes are standardized: small (420px), medium (640px), large (960px), extra-large (90vw). This keeps the user in context — they never navigate away to edit.

### 6. Entity Header with Inline Actions

Every entity has a consistent header with: title (inline editable), aliases, sharing/export buttons, enrichment trigger, relationship creation, playbook enrollment, and quick subscription. Actions that change the entity are in the header; actions that leave the entity are in tabs.

### 7. Bulk Operations

Data tables support checkbox selection with shift-click range selection. Selected rows trigger a toolbar with bulk operations (delete, add to container, change status, export). The `DataTable` component handles selection state, column reordering, sorting, filtering, and pagination as a coherent system.

### 8. GraphQL + Relay for Data Management

The combination of GraphQL subscriptions for real-time updates and Relay's fragment co-location means each component declares its own data requirements. The data layer is invisible to components. Pagination uses Relay's cursor-based connections consistently.

---

## What OpenCTI Does NOT Do Well (for BeyondLabs)

### 1. Heavy Infrastructure

OpenCTI requires Elasticsearch, Redis, RabbitMQ, and MinIO. This is appropriate for a CTI platform but completely wrong for a local-first SOC workspace. BeyondLabs' localStorage approach is correct for its scope.

### 2. Overwhelming Navigation

The left sidebar has 20+ menu items across 6 sections. For a CTI analyst this makes sense (they need access to all entity types), but for a SOC analyst the workspace should be organized by job function, not entity type. BeyondLabs' 7-workspace model is more appropriate.

### 3. STIX Model Overhead

STIX 2.1 is comprehensive but heavy. Types like "StixDomainObject" apply to everything but add visual noise. BeyondLabs' flat discriminated union (IntelEntity with 5 variants) is simpler and sufficient for investigation-focused work.

### 4. MUI Component Overhead

OpenCTI uses MUI v6 with extensive customization. While consistent, this comes at a bundle size cost and requires deep MUI knowledge. BeyondLabs' custom Tailwind approach with `Panel`, `Chip`, `SectionBar`, and `SendToRow` is lighter and more controlled.

### 5. Collaborative Editing Overhead

OpenCTI supports multi-user editing with focus tracking, edit contexts, subscription avatars, and revision history. For a single-analyst tool, this adds complexity without value.

---

## Reusable Ideas for BeyondLabs

### 1. Knowledge Bar Pattern

The permanent right-side knowledge sidebar showing relationship counts is directly applicable to Intel entities. Currently BeyondLabs shows relationships inline — a persistent sidebar with category counts would improve navigation.

### 2. Entity Header Pattern

OpenCTI's entity header (title, inline edit, actions row, tags) is cleaner than BeyondLabs' current entity detail page header. The separation of identity (left) and actions (right) is worth adopting.

### 3. Overview Widget Grid

The configurable widget approach is overkill for BeyondLabs, but the concept of an overview page composed of reusable sub-components (BasicInfo, Details, RecentRelationships, ExternalReferences, Notes, History) is worth extracting.

### 4. Drawer Pattern for Creation/Editing

Right-side drawers for entity creation instead of full-page forms or modals. BeyondLabs currently has no structured creation flow for Intel entities (they're mock data). When real creation is needed, this pattern is ideal.

### 5. Relationship Navigation

The knowledge tab with categorized relationship types is directly applicable. OpenCTI's pattern of "show counts per category, click to see the list" is clean and well-proven.

### 6. Consistent Empty/Loading/Error States

OpenCTI renders `Loader` during loading, `ErrorNotFound` for missing entities, and configurable empty states in lists. BeyondLabs has `Empty` but inconsistent loading and error handling.

### 7. Investigation Graph Canvas (Newly discovered)

OpenCTI's "Investigation" workspace type is an interactive graph canvas where analysts place entities as nodes and draw edges to create relationships. Key features:
- Nodes are entities (actors, malware, CVEs, observables) dragged from search results
- Edges are created by right-click drag between nodes
- Graph positions are saved (`graph_data` JSON)
- Graph can be "turned into a container" (case/report) with all entities added as knowledge
- Supports 2D and 3D force-directed layouts, tree view, time-range filtering

**Relevance to BeyondLabs:** This is a potential replacement for the current case page's flat entry-based model. Instead of writing entries, the analyst places entities on a canvas and connects them visually. The entries/notes become annotations on the graph. This is an advanced feature — not for the current freeze cycle, but worth noting for v1.x.

### 8. Rich Notes System (Newly discovered)

OpenCTI notes are full STIX entities with: `attribute_abstract` (summary), `content` (markdown), `note_types` (vocabulary categorization), `likelihood`, `confidence`, and `objects` linking to entities/relationships. Notes appear as an inline widget on entity detail pages (not a separate tab), with an inline creation accordion at the bottom.

**Relevance to BeyondLabs:** The inline creation accordion on entity pages is directly applicable to BeyondLabs' Intel entity detail. Instead of navigating to the case notebook, the analyst could add a note directly on the Intel entity page. Note types (e.g., "analysis-note", "enrichment", "context") would help categorize findings.

### 9. Knowledge Graph Visualization (Newly discovered)

OpenCTI uses `react-force-graph-2d`/`3d` for interactive relationship visualization. Controls include:
- 2D/3D toggle, tree layout (vertical/horizontal)
- Force-directed layout (toggleable, fix positions on drag)
- Click node → expand (fetch and show connected entities)
- Right-click drag between nodes → create relationship
- Filter by entity type, author, marking, time range
- Search within graph
- Save/restore zoom and camera position

**Relevance to BeyondLabs:** A graph view for Intel entity relationships would be powerful. The current flat list of relationships is readable but not explorable. A lightweight graph component (2D only, no 3D) showing connected entities with click-to-expand would make relationship discovery much more natural. Not for the current freeze cycle.

### 10. Case Templates with Task Generation (Newly discovered)

OpenCTI has a `caseSetTemplate` mutation that auto-generates tasks from predefined templates. This is different from BeyondLabs' entry templates — it creates structured tasks with assignees, due dates, and independent workflow status.

**Relevance to BeyondLabs:** BeyondLabs' `CASE_TEMPLATES` (phishing triage, ransomware triage, suspicious login) generate entry skeletons, not tasks. Adding task-like items to the Investigation Progress checklist (e.g., "Check SPF record", "Scan attachment") would make templates more actionable.

### 11. Workflow State Machine (Newly discovered)

OpenCTI entities have `workflowEnabled` + `status { template { name, color } }` — a configurable state machine. For cases, this means custom statuses (e.g., New → Triage → Contained → Eradicated → Closed) with per-status colors, managed by admin settings.

**Relevance to BeyondLabs:** Currently cases are binary (active/closed). A configurable workflow with 3-5 statuses (Triage, Investigation, Remediation, Closed) would improve progress tracking. The Investigation Progress checklist is a lightweight alternative, but a formal status field would be cleaner for reporting.

### 12. Audit with Field-Level Change Tracking (Newly discovered)

OpenCTI's audit system goes beyond event logging — it tracks `changes: [{ field, changes_added, changes_removed }]` for every update, showing exactly what changed (e.g., "severity: medium → high"). The audit drawer shows a before/after table of all field changes in an update event.

**Relevance to BeyondLabs:** The current timeline events log actions ("finding created", "IOC attached") but don't show what changed. Field-level tracking (e.g., "severity changed from medium to high") would make the timeline more useful for post-incident reconstruction.

### 13. "Origin of the Case" Pattern (Newly discovered)

OpenCTI's case incident overview prominently shows an "Origin of the case" section displaying the entities/observations that triggered the case creation — linked via `ContainerStixObjectsOrStixRelationships` with types `['Incident', 'stix-sighting-relationship', 'Report']`.

**Relevance to BeyondLabs:** Cases store `analysisSummary` with the analyzer source, but this isn't displayed prominently. Showing "Created from Phishing Analysis — email@example.com" at the top of the case would remind the analyst where the case came from, similar to OpenCTI's origin section.

### 14. Observable Lifecycle (Newly discovered)

OpenCTI has a clear pipeline: raw artifact → observable → indicator (promote) → enrichment → decay scoring. Observables can be promoted to indicators, linked to containers, enriched with external sources, and scored for decay over time. The decay chart shows indicator score history.

**Relevance to BeyondLabs:** BeyondLabs has IOCs but no observable lifecycle. Adding enrichment status (pending/completed/failed), investigation status (new/investigated/closed), and a promote-to-indicator flow would close the observable lifecycle. However, this is a post-freeze enhancement — it changes the data model.

### 15. "Add to Container" Generic Pattern (Newly discovered)

OpenCTI has a universal `ContainerAddStixCoreObjects` component for linking any entity to any container (case, report, grouping). It provides a searchable entity picker, batch add, and inline remove.

**Relevance to BeyondLabs:** BeyondLabs' Intel → Case round-trip is a specialized version of this (add finding + IOCs from Intel entity to active case). A generic "Add to Case" flow with entity picker would allow adding any entity from any page to any case. This is the direction the Intel → Case actions should evolve toward.

---

### 16. Notifications via RxJS Subject Bus (Newly discovered — architectural)

OpenCTI uses a `MESSAGING$` RxJS Subject in `relay/environment.jsx` as a service bus for notifications. Components fire `MESSAGING$.notifyError()`, `MESSAGING$.notifySuccess()`, etc. A consumer component (`Message.tsx`) renders MUI Snackbar/Alert. The bus uses 500ms debounce. The `useApiMutation` hook auto-calls `MESSAGING$` on mutation success/error.

**Relevance to BeyondLabs:** Directly applicable. BeyondLabs uses ad-hoc toast calls. A central `MESSAGING$` Subject decouples notification producers from consumers, makes testing easier, and allows the UI to batch/coalesce notifications. This is a pure architectural improvement — no feature change.

### 17. usePaginationLocalStorage — Dual localStorage + URL Persistence (Newly discovered — architectural)

OpenCTI's `usePaginationLocalStorage` hook persists filter, sort, search, and pagination state to **both** localStorage **and** URL search params. On load, URL params take priority (enables deep-linking). State is also synced across browser tabs via `BroadcastChannel`. The filter state is structured as a `FilterGroup` object (mode, filters, filterGroups) supporting AND/OR logic.

**Relevance to BeyondLabs:** Highly applicable. BeyondLabs has some URL persistence (case `?tab=`) and some localStorage, but no unified pattern. Adopting `usePaginationLocalStorage` would make every table/list state survive refresh, be shareable via URL, and sync across tabs.

### 18. Standardized Form Pattern — Formik + Yup + useApiMutation (Newly discovered — architectural)

Every entity creation form in OpenCTI follows the same pattern:
1. `*Creation` wrapper: Drawer + FAB trigger + `useApiMutation`
2. `*CreationForm`: Formik form + Yup schema (built via `useDynamicSchemaCreationValidation` + `useIsMandatoryAttribute`)
3. `useApiMutation`: wraps Relay mutation, auto-fires notifications, handles loading state
4. Shared field components: `ConfidenceField`, `ObjectLabelField`, `ObjectMarkingField`, `ExternalReferencesField`, `StatusField`, etc.

**Relevance to BeyondLabs:** Applicable for v1.x when entity creation moves from mock data to real creation. The pattern of "wrapper + form + shared field components" keeps creation forms consistent across entity types. The dynamic validation based on mandatory attributes is a nice touch for admin-configurable forms.

### 19. Error Boundary with Error-Code Routing (Newly discovered — architectural)

OpenCTI's `Error.jsx` class component uses `getDerivedStateFromError` and categorizes errors by `extensions.code`: `COMPLEX_SEARCH_ERROR`, `IP_FORBIDDEN`, `FORBIDDEN_ACCESS`, `RESOURCE_NOT_FOUND`, `AUTH_REQUIRED`, unknown. Each has a dedicated display. The boundary auto-resets on route change (`componentDidUpdate` watching `location.pathname`). Frontend errors are logged to the backend via a `frontendErrorLog` mutation. Exported as `boundaryWrapper` HOC.

**Relevance to BeyondLabs:** Applicable. BeyondLabs has some error handling but no unified boundary. The error-code routing pattern is clean — one boundary handles all error types with specific displays. The `boundaryWrapper` HOC pattern is reusable.

### 20. PDF Export via pdfmake (Newly discovered)

OpenCTI's `htmlToPdf.ts` converts HTML to PDF via `html-to-pdfmake` + `pdfmake`. The `htmlToPdfReport()` variant generates styled reports with headers, footers, backgrounds, page breaks, image embedding, table layout, and CJK font detection. Also uses `react-csv` for CSV and `html2canvas` for image export.

**Relevance to BeyondLabs:** Partially applicable. BeyondLabs has Markdown export for cases. A PDF export option (Intelligence Report format) would be valuable for handoff/deliverables. The `html-to-pdfmake` pipeline avoids server-side PDF libraries entirely.

### 21. Investigation Undo Stack via sessionStorage (Newly discovered)

`useInvestigationState.ts` uses `sessionStorage` (not localStorage) to track an operation stack (`expand`, `add`, `remove`) with a max of 20 entries. Supports undo/rollback via `getOpsUntilExpand()`. This is separate from the graph state — it's a command history pattern for the investigation workspace.

**Relevance to BeyondLabs:** Applicable for the Investigation Progress checklist. An undo stack for checklist actions (mark findings reviewed, toggle ready for handoff) would allow the analyst to revert mistakes. sessionStorage is the right choice — undo history doesn't need to survive browser close.

### 22. Status Pipeline Visualization (Newly discovered)

`ItemStatusTemplate.tsx` renders workflow statuses as a pipeline: colored tags separated by arrow icons (`ArrowRightAltOutlined`), grouped by `order` field. `ItemStatus.tsx` renders a single status as a `<Tag>` component with the status template's color. The related `StatusField` form input uses `AutocompleteField` with colored avatars showing the status order number.

**Relevance to BeyondLabs:** Applicable for workflow status display. If BeyondLabs adds workflow states (Triage → Investigation → Remediation → Closed), the pipeline visualization is a clean pattern for showing the full lifecycle. Even without workflow states, this pattern could render the Investigation Progress checklist as a pipeline.

### 23. @hello-pangea/dnd for Reorderable Lists (Newly discovered)

OpenCTI uses `@hello-pangea/dnd` (the modern maintained fork of `react-beautiful-dnd`) in 5 places: DataTable column reorder, entity overview layout customization, widget column customization, and custom attributes input. The graph canvas uses `react-force-graph-2d` for its own drag handling (not dnd).

**Relevance to BeyondLabs:** Low priority but worth knowing. If BeyondLabs ever needs reorderable lists (e.g., customizable entity overview fields, reorderable case timeline events), `@hello-pangea/dnd` is the right library.

### 24. Theme System — Factory Function with MUI Augmentation (Newly discovered)

OpenCTI's `ThemeLight.ts` (726 lines) and `ThemeDark.ts` (724 lines) are factory functions accepting overrides for: `logo`, `logo_collapsed`, `background`, `paper`, `nav`, `primary`, `secondary`, `accent`, `text_color`. The extended MUI palette includes `border`, `gradient`, `ai`, `ee`, `severity`, `dangerZone`, `chip`. MUI's `Palette` and `PaletteOptions` types are augmented via `Theme.d.ts`. The theme management UI provides full color pickers for each slot.

**Relevance to BeyondLabs:** Partially applicable. BeyondLabs doesn't use MUI, but the factory function pattern (function taking overrides → returns theme tokens) is clean. The extended palette structure (especially `border`, `severity`, `chip` colors) should inform BeyondLabs' Tailwind config if dark mode or custom theming is added.

---

## What Does NOT Apply to BeyondLabs

| Concept | Reason |
|---------|--------|
| STIX/TAXII | Out of scope — no external intelligence sharing |
| Connector framework | Out of scope — no plugin system |
| Multi-tenancy | Out of scope — single analyst |
| Organizations/groups | Out of scope — no collaboration |
| Feeds/ingestion pipelines | Out of scope — manual intake |
| Reports as entities | BeyondLabs reports are case output, not entities |
| Workflow engine | Out of scope — no state machine needed |
| Draft/approval workflow | Out of scope — single analyst |
| Enrichment from external sources | Future consideration — not now |
| AI/NLQ search | Future consideration — not now |
