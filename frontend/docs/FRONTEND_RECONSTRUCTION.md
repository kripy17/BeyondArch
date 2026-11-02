# Frontend Reconstruction

## Goal

Transform BeyondLabs from a collection of tools into a cohesive analyst workspace. No architecture changes. One canonical page. Extract patterns only after repetition is observed.

---

## Canonical Page

The Case page (`/case`) is the reference implementation. Every future workspace page (Activity, Hunt, Incident, Evidence Review) derives its patterns from this page. The Report page remains independent — it is a print document, not a workspace.

---

## Reconstruction Checklist

### Header
- [ ] Investigation identity with editable title + inline save
- [ ] Status chip (active/closed)
- [ ] Severity badge (critical/high/medium/low) when available
- [ ] Tag editor (add/remove, inline input)
- [ ] Primary actions (close, delete, new) — visually distinct from secondary

### Overview
- [ ] Metrics grid (Findings, IOCs, Evidence, Decisions) — always visible, not conditional on verdict
- [ ] Verdict/score/confidence line when decision exists
- [ ] Case ID and creation date accessible without scrolling to page bottom

### Intake
- [ ] Quick-add entry bar (kind selector + textarea + append)
- [ ] Move below tab bar — output before input
- [ ] Kind selector defaults to auto-detect based on body text

### IOC Table
- [ ] Structured table with type/value/severity/source
- [ ] Checkbox selection with batch actions (add to locker, copy, remove)
- [ ] Source column links to filtered timeline (in-place, no tab switch)
- [ ] "All to locker" bulk action
- [ ] Remove regex fallback after legacy parse is consolidated

### Findings
- [ ] Severity-ordered list with left-border color coding
- [ ] Source attribution inline (clickable, filters timeline in-place)
- [ ] MITRE technique badge with link to `/mitre?technique=ID`
- [ ] Related IOCs shown per finding
- [ ] No separate rendering paths — single adapter produces structured Finding objects

### Timeline (Activity tab)
- [ ] Category filter bar (artifact, analysis, finding, IOC, case, detection, report, analyst)
- [ ] Date grouping with sticky headers
- [ ] Importance dots (critical/high/normal/low)
- [ ] Expand/collapse for long detail text (>120 chars)
- [ ] Reference chips linking to related entities
- [ ] Origin filter buttons (click to filter by source)
- [ ] Empty state with guidance

### Notebook
- [ ] Auto-populated templates (Findings Review, IOC Triage) populated from case data ✔
- [ ] Timeline Reconstruction template pre-filled from timeline events (grouped by phase)
- [ ] Template buttons section
- [ ] Markdown editor + live preview
- [ ] Preview handles tables, code blocks, bold/italic (use a library, not regex)

### Right Panel
- [ ] Case metadata (ID, opened, state, entries)
- [ ] Report — rendered markdown (not raw `<pre>`), toggle for raw view
- [ ] Export buttons (.md, .html, .json, .beyondcase) — labeled actions, not icon-only
- [ ] Import .beyondcase button
- [ ] Handoff Report — collapsed by default, expand to show structured L2/IR handoff
- [ ] SendToRow — link to Detection, MITRE Coverage, Logs

### SendToRow
- [ ] Sticky at viewport bottom or duplicated in sidebar — not hidden below scroll

### Polish
- [ ] Empty states for every panel (no findings, no IOCs, no events, empty notebook)
- [ ] Loading skeleton for InvestigationActivityFeed
- [ ] Error states (corrupt case data, failed import)
- [ ] Keyboard shortcuts documented in UI (⌘Enter to append, Escape to close)
- [ ] Tab deep-linking via URL `?tab=` parameter
- [ ] Responsive layout for narrow viewports

### Removals
- [ ] Remove legacy timeline panel (replaced by InvestigationActivityFeed)
- [ ] Remove annotation system (unused, adds complexity)
- [ ] Remove `entryFilter` (replaced by originFilter on activity feed)
- [ ] Remove `ResultBanner` (replaced by Investigation Overview panel)

---

## Do Not Extract Yet

- `InvestigationShell` — wait until at least two pages share the same layout
- `IntelShell` — no intel page exists yet
- `SIEMShell` — no SIEM page exists yet
- `DashboardShell` — no dashboard exists yet
- `InvestigationHeader` — extract after second consumer emerges
- `InvestigationMetrics` — extract after second consumer emerges
- `InvestigationTabs` — extract after second consumer emerges
- `InvestigationSidebar` — extract after second consumer emerges

Rule: **No reusable abstraction until at least two pages implement the same pattern.**

---

## Definition of Done

- A complete investigation can be performed end-to-end without confusion
- Information hierarchy is obvious (overview → findings → timeline → notebook)
- No duplicated UI patterns in the Case page
- All empty/loading/error states render meaningful content
- Keyboard shortcuts work consistently
- Tab state survives page refresh via URL
- No `"TBD"` or placeholder MITRE values
- Components extracted only after repetition is observed across pages
- Can switch from `case.tsx` to `report/$caseId.tsx` without mental model mismatch
