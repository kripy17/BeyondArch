# Investigation UX Audit

**Date:** 2026-07-28
**Scope:** Case page (`/case`), InvestigationActivityFeed, FindingsPanel, IOCTable, MitrePanel, TimelinePanel
**Method:** Code-level trace of the analyst investigation flow, visual hierarchy, friction points, empty states, and progressive disclosure.

---

## Critical

### C1. Intake panel precedes output — analyst sees input before results

The intake section (kind selector + textarea + append button) is positioned above the tab bar and all investigation content. An analyst opening an analysis-generated case must scroll past the intake panel, templates panel, and IOCs panel before reaching the Activity/Findings/Notebook tabs.

**Evidence:** `case.tsx` lines 744-773 (intake) appear before line 908 (tab bar).

**Impact:** Every case load requires vertical scroll to reach the primary content. For a fresh case with no IOCs, the analyst sees: title → overview (if verdict) → templates → intake → tab bar → content. The input surface competes with the output surface for above-the-fold real estate.

**Fix:** Move the intake section below the tab bar (inside the active tab area), or collapse it behind an "add entry" button. The tab content should be the primary visual focus.

---

### C2. Three separate rendering paths for the same domain concept

Findings/IOCs render through three parallel code paths:
1. Structured `active.findings` / `active.iocs` arrays (when populated by `createCaseFromAnalysis`)
2. Parsed `active.entries` with `kind === "evidence"` / `kind === "ioc"` (legacy path with `parseSeverity`, `parseSource`, `parseIocEntry`)
3. Regex-based extraction in the report and handoff generators (raw regex on entry body text)

**Evidence:** `case.tsx` lines 919-964 (structured findings), 966-1029 (parsed evidence entries), 888-903 (regex IOC extraction), 357-365 (handoff report regex extraction), 413-426 (markdown report regex extraction).

**Impact:** Inconsistencies between views are inevitable. A finding with a technique ID shows in the structured Findings tab but may not appear in the markdown report if the report uses regex on entry bodies rather than structured data. Maintenance burden: every new field must be added to three rendering paths.

**Fix:** Consolidate the legacy parsing and regex paths into a single adapter that produces structured `Finding`/`IOC` objects. All rendering paths consume structured data only. The parsing adapter runs once per case load.

---

## High

### H1. No entry detail view — full entry body is always visible

All entries in both the Activity feed and the legacy timeline render their full body text inline. There is no way to:
- View a condensed summary with expand-to-read
- See metadata (source, technique, tags) in a structured sidebar
- Navigate between findings sequentially (previous/next)

**Evidence:** Activity feed renders `ev.detail` inline with a 120-char line-clamp toggle (lines 241-252). Legacy entries render `e.body` directly (pre-refactor). There is no detail panel or modal.

**Impact:** Long IOC lists or detailed analysis output create very tall list items. The analyst cannot quickly scan through findings — they must read every line.

**Fix:** Add a detail panel (slide-over or modal) activated by clicking a finding/entry. Show full body, metadata, related IOCs, and cross-references in the panel. The list view shows title, severity, source, and technique only.

---

### H2. Source filter causes tab switch — loses context

Clicking "from: {source}" on a finding card switches the active tab from Findings to Activity AND sets the origin filter. The analyst loses their place in the findings list and must switch back to continue reviewing.

**Evidence:** `case.tsx` lines 932-937 (structured path) and 991-996 (legacy path): both call `setActiveTab("timeline")` + `setOriginFilter(source)`.

**Impact:** Every "where did this come from?" click is a context switch. To review findings from two different analyzers, the analyst tab-switches back and forth.

**Fix:** Add a source badge that filters IN-PLACE within the Findings tab rather than switching to Activity. Optionally show a tooltip/popover with source context. Only switch tabs when the analyst explicitly navigates to the timeline.

---

### H3. Report panel shows raw markdown, not rendered HTML

The Report panel renders `markdown` (auto-generated markdown string) inside a `<pre>` tag. The analyst must mentally parse markdown syntax to read the report. Export buttons produce rendered formats, but the in-page preview is raw text.

**Evidence:** `case.tsx` lines 1111-1112: `<pre className="max-h-80 overflow-auto ...">{markdown}</pre>`.

**Impact:** The report is not readable in-page. The analyst must export to .md or .html to get a formatted view. This breaks the "review before export" workflow.

**Fix:** Render the report markdown as formatted HTML in the panel (via a lightweight markdown renderer). Keep the raw `<pre>` as an optional toggle for editing.

---

### H4. Templates panel collapsed by default — guidance hidden

The Templates panel (Phishing Triage, Ransomware Triage, Suspicious Login) is collapsed on every page load. A new analyst creating their first manual case won't know structured templates exist.

**Evidence:** `case.tsx` line 724: `{templateOpen ? (...)` — default state is `false` (line 87: `const [templateOpen, setTemplateOpen] = useState(false)`).

**Impact:** Analysts who don't know about templates will start typing free-form entries. Inconsistent case structures across analysts.

**Fix:** Show the first-use template prompt or auto-expand the panel when the case has no structured entries. Add a "start with a template" prompt in the empty state.

---

## Medium

### M1. Investigation Overview metric grid only shows when verdict exists

The four-column metric grid (Findings, IOCs, Evidence, Decisions) is conditionally rendered only when `s && s.verdict` is truthy. Analyst-created cases or cases without a verdict show no overview metrics.

**Evidence:** `case.tsx` lines 699-713: `{s && s.verdict && (grid...)}`.

**Impact:** Inconsistent layout. Some cases have a rich overview, others show just the title. The analyst sees no aggregate counts until a decision entry is added.

**Fix:** Always show the metric grid. If no verdict exists, show the grid without the verdict/score/confidence line above it.

---

### M2. Timeline Reconstruction notebook template is always blank

The "Timeline Rec." notebook template is a static empty scaffold with phase headings. Unlike Findings Review and IOC Triage (which now auto-populate from case data), Timeline Reconstruction offers no data pre-fill.

**Evidence:** `case.tsx` line 176: `{ label: "Timeline Rec.", body: "# Timeline Reconstruction\n\n## Phase 1: Initial Access\n- \n..." }`.

**Impact:** Analyst must manually copy events from the Activity tab into the notebook to reconstruct phases. This duplicates work.

**Fix:** Auto-populate the Timeline Reconstruction template with entries grouped by MITRE tactic (if available) or by temporal clustering (e.g., events within 5-minute windows).

---

### M3. MITRE technique badge links to external site, not internal MITRE page

The technique badges link to `attack.mitre.org`. The app has a `/mitre` route with MITRE ATT&CK coverage tracking. The badge should link to the internal page for coverage-aware navigation.

**Evidence:** `case.tsx` lines 942-945, 1002-1005: `href="https://attack.mitre.org/techniques/${technique.replace(".", "/")}/"`.

**Impact:** Analyst navigates away from the app to learn about a technique. No coverage state (none/partial/full) is visible on the badge.

**Fix:** Link to `/mitre?technique=T1059.001` instead. Show coverage state as a dot indicator on the badge.

---

### M4. IOC table data source label inconsistent

The structured IOC table shows a clickable source button (navigating to Activity filter). The legacy IOC table shows source as text. The regex IOC summary shows no source at all. Source attribution is inconsistent across all three views.

**Evidence:** Lines 833-841 (structured table), 870-879 (legacy table), 888-903 (regex summary).

**Impact:** Analyst cannot trace where an IOC came from when viewing the regex-based summary (the fallback view).

**Fix:** Remove the regex summary path entirely once legacy IOC entries are parsed into structured objects. Or add source parsing to the regex path.

---

### M5. Report and Handoff Report are separate panels with overlapping content

The Report panel and Handoff Report panel both contain auto-generated markdown that overlaps significantly (summary, IOC list, timeline). The Handoff Report is collapsed with a one-line description; the Report is always visible as raw `<pre>` text.

**Evidence:** Lines 1085-1113 (Report) and 1115-1139 (Handoff Report). Both use the same entry data with different markdown templates.

**Impact:** The analyst has two separate "export my work" surfaces with no clear distinction between them. The Handoff Report is better structured but hidden behind a click.

**Fix:** Consolidate into a single Export panel with format selector (Report / Handoff / JSON). Default to rendered markdown preview. Keep collapsed behavior optional.

---

## Low

### L1. Auto-created empty case on first visit is confusing

When no cases exist, the app auto-creates one with a timestamp-based title. The first-time visitor sees "BA-20260728-1700 — Phishing Analysis" with no entries and no guidance. The page title/description says "Append-only timelines you build yourself. Nothing is pre-populated." — which now conflicts with the structured data features.

**Evidence:** `case.tsx` lines 108-111: auto-creates a bare `Case` with `entries: []`.

**Fix:** Show a welcome/onboarding state instead. Let the analyst choose to create a blank case, import one, or run an analyzer.

---

### L2. Notebook markdown preview is hand-rolled, fragile

The notebook preview uses a custom regex-based renderer (lines 1064-1071) that handles only `# h1`, `## h2`, `### h3`, `- li`, and `br`. Tables, code blocks, bold, italic, and links are not rendered.

**Evidence:** `case.tsx` lines 1064-1071.

**Impact:** The IOC Triage template renders a markdown table as raw text in the preview. The analyst must use the textarea view to read the table.

**Fix:** Use a lightweight markdown library (e.g., `marked` or `react-markdown`) for the preview.

---

### L3. SendToRow at the very bottom may be below the fold

The SendToRow (Detection, MITRE Coverage, Logs) is the last element in the main content column. On smaller screens or cases with many entries, it's invisible without scrolling.

**Evidence:** `case.tsx` lines 1141-1145.

**Fix:** Make the SendToRow sticky at the bottom of the viewport, or duplicate key navigation links in the sidebar.

---

### L4. Case metadata (ID, state, entry count) is at the bottom of the content column

The Case metadata panel (showing ID, Opened, State, Entries) is positioned below the tab content. The analyst must scroll past all investigation content to find the case ID for reference.

**Evidence:** `case.tsx` lines 1076-1083: positioned after the Notebook panel.

**Fix:** Move case ID and state into the top case title panel or the Investigation Overview.

---

### L5. "Activity" tab label uses generic "Activity" instead of "Timeline"

The tab label says "Activity" with an event count. The concept of a "timeline" is more familiar to SOC analysts. The old code used "Timeline" before the InvestigationActivityFeed refactor.

**Evidence:** Line 912: `tab === "timeline" ? `Activity (...)` : ...`.

**Fix:** Revert to "Timeline" for the tab label to match SOC terminology.

---

## Summary: Friction Count

For an analyst reviewing an analysis-generated case:

| Step | Clicks | Scrolls | Context switches |
|------|--------|---------|-----------------|
| Open case | 1 | to mid-page | 0 |
| Review findings | 0 | variable via tab | 1 (if scrolled) |
| Check IOC details | 1-2 | 0 | 1 (tab switch) |
| Add finding note | 3+ | 0 | 2 (tab switch) |
| View source context | 1 | 0 | 1 (tab switch + filter) |
| Generate report | 0 (auto) | to bottom | 0 |
| Export report | 1 | 0 | 0 |
| Hand off | 1 (click show) | 0 | 0 |

**Key insight:** The tab-based layout creates a context-switch tax on every cross-reference action. The "from: {source}" filter is the highest-friction single action — it combines a tab switch with a filter application, losing the analyst's place.

---

# Full-App UX · A11y Pass — 2026-08-29

**Scope:** All 27 nav routes in `frontend/src/lib/workspaces.ts` (+ `/developer.components`). Playwright-driven, sample-based WCAG 2.2 AA evaluation.
**Method:**
- Every route: HTTP 200, `#main` present, zero console errors, exactly one `h1`, heading levels do not skip.
- Contrast sampling (recurring text nodes against nearest solid background) at 4.5:1 body / 3:1 large-text thresholds, across all three themes: `dark`, `light`, `dark-hc`.
- All inputs/selects/textareas/buttons flagged if they lack an accessible name (aria-label / `label[for]` / wrapping `<label>` / `title` / visible text) unless `display:none`.
- Tabbing smoke on `/`; every stop has a visible focus indication (ring or outline).
- Horizontal-overflow check at 1024 / 768 / 390 px.

## Verified clean

- **Contrast: 0 failures** on any route in any of the three themes — token system is sound.
- **Console: 0 errors, 0 horizontal overflow** at 1024 and 768 px.
- **Keyboard:** skip link → nav → content; every focusable element shows a focus ring (incl. the high-contrast focus boost option).
- **Empty states:** no bare "No data" text anywhere; every empty panel ships copy + hint + icon.

## Fixed this pass

| # | Severity | Finding | Fix |
|---|----------|---------|-----|
| F1 | P1 | Scratchpad textarea, Attach-to-case textarea, and IOC-note input (all in `IocLocker.tsx`) had placeholder-only labels; present on every page | Added `aria-label` to each |
| F2 | P1 | **All 16** `/settings` switches had no accessible name (bare Radix `role="switch"`, label was a plain `div`) | Added `aria-label` matching each visible `Row` label |
| F3 | P1 | `/chef` copy-output icon button had no name | Added `title` + `aria-label="Copy output"` |
| F4 | P1 | `/siem` keyword-filter input, `/mitre` technique-ID input had no name | Added `aria-label` |
| F5 | P2 | `h1 → h3` heading skip: shared `Panel` always rendered `<h3>` titles | `soc/Panel.tsx` title is now `<h2>` |
| F6 | P2 | `h1 → h3` skip on `/diff`, `/regex-playground` (`EntitySection` at page level) and `/timeline` date-groups | `EntitySection`/`SectionBar` gained an opt-in `headingLevel="h2"`; applied at the 7 page-level sites |
| F7 | P2 | `h1 → h3` skip on `/` Command Deck sections and `/developer` card titles | Promoted to `h2` (`index.tsx` ×13 incl. `CaseLoadSection`, `developer.tsx`) |

## Known / intentionally not changed

- **Mobile (≤390 px):** horizontal overflow ~231–356 px — the shell is desktop-first; was previously excluded as out of scope. Flagged here so it is a tracked decision, not an accident.
- **10.6 px mono chrome labels** (`ba-text-3xs`) are a deliberate design token; the one exception **8.5 px "active"** on `/settings` is the smallest text in the app — candidate to bump to 10.6 if the settings panel is revisited.
- **Hidden file inputs** (`display:none`, triggered by titled "Upload file" buttons) on `/url`, `/attachment`, `/parser` are behind correct, named controls.
- `/developer.components` intentionally has no `#main` target and is not in nav (dev showcase).
- Decorative empty `<span>`s on `/file`, `/logs`, `/pcap`.

## Good news worth preserving

- The three-workstream nav + single-`h1` page shell gives a clean document outline on every route after the fixes above.
- Empty-state copy quality (icon + explanation + next action) is consistently high — flag standard for other products.

---

# Visual Layout Audit — Page-by-Page (2026-08-29)

**Scope:** All 31 screenshots at `/tmp/opencode/audit/*.png` (1440×900 dark theme, full-page captures). Reviewed for layout quality, visual hierarchy, typography, spacing, component consistency, empty states, and interactive affordances.

**Legend:** ✅ Good / ⚠️ Minor nit / 🔴 Should fix (with suggested change).

---

## Global Shell (sidebar + topbar + content)

| Item | Status | Notes |
|------|--------|-------|
| Sidebar nav | ✅ | Three-workstream grouping (Dashboard / Intake / Investigation / Intelligence / Detection / SIEM / Workspace) is clear. Group collapse with chevrons works. Badge counts for each sub-route are useful. |
| Topbar | ✅ | Case badge, workspace chip, search, local/online indicator — all present. The `Ctrl+K` / `Ctrl+Shift+F` / `Esc` shortcut bar at the bottom of most pages is a nice touch. |
| Content column | ✅ | Max-width feels right at 1440px. No horizontal bleed. Consistent `ba-panel` rounded containers throughout. |
| Sidebar theme toggle | ⚠️ | "Dark" toggle at bottom of sidebar uses a horizontal slider with `■` icons — functional but a bit visually noisy. Consider a single icon toggle (moon/sun) to save space. |
| "26 workspaces" footer | ⚠️ | Always shown at sidebar bottom. Correct count, but could be a subtle link to a workspace manager. Currently static. |
| Sidebar brand "BeyondLabs" | ✅ | Logo + name at top-left. Consistent across all routes. |
| Sidebar collapse | ✅ | Toggle button (sidebar-left icon) works to collapse/expand. |

---

## / — Command Deck (Dashboard)

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `h1: Command Deck` with breadcrumb `// workbench · session`. Clear. |
| Description | ✅ | `Pick up where you left off, start something new, or jump to any workspace.` — good onboarding copy. |
| Status bar | ✅ | `sessions ephemeral · mode offline-safe · timeline 13 events · recoverable 0 workspaces · last active none · ⊕ preferences` — dense but functional. |
| Case Load section | ✅ | Six stat tiles (5 cases / 5 active / 0 closed / 10 indicators / 3 findings / 3 evidence) with horizontal bar chart for severity. Visual hierarchy is clear. |
| Severity bar chart | ✅ | Critical (red), high (orange), medium (yellow), low (green), info (green). Color coding is standard. |
| Recent cases list | ✅ | Five cases with title, entry count, open date, and "active" badge. Clean list pattern. |
| Continue Investigation card | ✅ | Highlighted with arrow icon. Shows current triage context. "resume →" link is clear. |
| Today's Activity | ✅ | Three event rows with timestamp, source badge, action verb, and detail. Compact and scannable. |
| Quick Intake | ✅ | Six tile buttons (Email, URL, File, PCAP, Logs, Freeform) — good primary action surface. |
| Detection / Operations | ✅ | Detection shows empty state with "open detection editor →" link. Operations shows four tool cards (Parser, Chef, Regex, Diff). |
| Recent Alerts | ✅ | Four alert rows with source badge, title, date, time. Clean. |
| Pinned Investigations / Detections / Entities / Hunts | ✅ | Three-column grid, each with empty-state copy. Consistent pattern. |
| Scratch Notes | ✅ | "quick note — hashes, leads, reminders…" textarea with "note" button. Nice lightweight feature. |
| Recent Parser Inputs | ✅ | Shows a compact preview of recent inputs. |

**Suggestions:**
- 🔴 The Case Load section has a lot of vertical space above the fold. The six stat tiles + severity chart + recent cases list could use a more compact initial view. Consider collapsing "recent cases" behind a "show" toggle, or putting stats in a two-column grid instead of full-width.
- ⚠️ "open case notebook →" link is below the case list — feels disconnected from the "Continue Investigation" card above. Consider placing it adjacent to or inside that card.
- ⚠️ The four-column grid (Pinned Investigations / Pinned Detections / Pinned Entities / Pinned Hunts) is visually heavy for empty states. All three show "No pinned X — pin one from Y to keep it here." Consider a single "No pinned items" unified empty state instead of four identical empty panels.

---

## /triage — Triage Queue

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `// triage Triage Queue` — clear breadcrumb + title. |
| Stats bar | ✅ | `total 6 · open 4 · in review 0 · escalated 2 · dismissed 0 · high/critical 5` — useful overview strip. |
| Alert intake | ✅ | Textarea with placeholder "Paste an alert — beyondlabs.alert.v1, Sigma, Suricata EVE, or Sysmon XML…" — great format hint. |
| Intake toolbar | ✅ | `auto-detect` label + `ingest alert` button + sample loaders (BeyondLabs canonical, Sigma detection output, Suricata EVE alert, Sysmon XML). |
| Manual intake | ✅ | Title input + severity dropdown + description textarea + "add item" button. Clean. |
| Filter strip | ✅ | Status and severity filter chips with sort/view toggles. Functional. |
| Alert list | ✅ | Alert rows with icon, title, severity badge, status badge, description, timestamp, source badge, case link. Very information-dense but readable. |
| Severity distribution sidebar | ✅ | Donut chart showing Critical 2 / High 3 / Medium 1. Good visual summary. |
| Detail sidebar | ✅ | Selected alert detail with badges, case link, description, notes, and action buttons. |
| Case Handoff | ✅ | "send artifact to: Case & Report → / Detection → / SIEM →" — clean pivot links. |

**Suggestions:**
- ⚠️ The `unrecognized · 4 formats` badge next to "alert intake" is cryptic. What does "4 formats" mean? Is it the count of supported formats, or unrecognized alerts? Needs a tooltip or clearer label.
- ⚠️ The "Item title..." and "Description (optional)..." fields in the manual intake are not visually distinct from the textarea above. Consider a subtle card border or background tint to separate manual input from auto-ingest.
- ⚠️ The donut chart in the severity distribution sidebar is small and hard to read at this size. The text labels (Critical 2, High 3, Medium 1) carry the information; the chart is decorative. Consider whether the chart adds value.

---

## /case — Case Notebook

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `case / notebook Case Notebook` — clear. |
| Description | ✅ | `Append-only timelines you build yourself. Nothing is pre-populated.` + `cases 5 · active 5` count. |
| Case sidebar | ✅ | Search + case list with active badge, entry count, tags. Selected case highlighted. Good navigation pattern. |
| Case header | ✅ | Case title, tag chips (triage, manual, medium), edit/close/delete icons. |
| Tab bar | ✅ | Overview · Evidence (0) · Findings (0) · Observables (0) · Graph · Timeline (1) · Notebook · Reports · Detection · Activity (1) — ten tabs. Dense but functional. |
| Knowledge Graph (empty) | ✅ | `No provenance links yet. Run an analyzer on an artifact, add findings, or extract IOCs to build the graph.` — clear empty state. |
| Intake · new entry | ✅ | Tab selector (note/evidence/decision/action/ioc) + textarea + attach + append button. Clean. |
| Investigation Progress | ✅ | 13% progress bar + checklist (Intake Completed ✓, Analysis Completed, Findings Reviewed, IOCs Investigated, etc.). Nice workflow guidance. |
| Investigation Quality | ✅ | 60/100 score with "Missing evidence", "Analyst notebook not written", "No report generated", "Unresolved decisions" — each with "fix →" button. Excellent actionable quality feedback. |
| Recommendations | ✅ | "Analyse an artifact" card with "open →" and "dismiss" links. |
| Investigation assistant | ✅ | "summarize / missing evidence / related alerts / unresolved findings / explain ioc" quick-action chips + "Ask about this case..." input. Local-only answers — good privacy guarantee. |
| Correlation memory | ✅ | Workspace-wide match showing IP `203.0.113.9` with "confirmed" badge, seen-in-prior-case note, confirm/dismiss buttons. |
| Case Handoff | ✅ | "send artifact to: Case & Report → / Detection → / SIEM →" — consistent. |

**Suggestions:**
- 🔴 Ten tabs is a lot. The case detail page is the most information-dense page in the app. Consider grouping: Overview + Evidence + Findings + Observables could be a single "Summary" tab. Graph + Timeline could be one "Provenance" tab. This would cut to ~6 tabs.
- ⚠️ The Investigation Progress checklist (13%) and Investigation Quality score (60/100) overlap in purpose — both tell the analyst "you're not done." Consider consolidating into one progress indicator.
- ⚠️ The Correlation memory card at the bottom is easy to miss. It's the only workspace-wide cross-case feature visible. Consider surfacing it higher, or adding a "cross-case matches" badge to the case header.
- ⚠️ "Append-only timelines you build yourself. Nothing is pre-populated." — this description is slightly misleading now that the app supports auto-generated findings, structured entries, and graph-based provenance. Update to reflect current capabilities.

---

## /phishing — Phishing Triage

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `triage / phishing Phishing Triage` — clear. |
| Description | ✅ | `Static-only inspection of email envelope, auth results, body, and embedded indicators. No links followed.` — honest scope-setting. |
| Jump links | ✅ | `jump → URL Analysis · Detection` — useful cross-pivot. |
| Phishing Triage panel header | ✅ | Icon + title + description + filter + idle badge. |
| Intake panel | ✅ | "raw email source" label + "paste full source incl. headers" hint. Textarea with `[WAITING_FOR_INPUT]` + placeholder. |
| Email Source sub-panel | ✅ | Card with `✉️ Email Source` title — clear grouping. |
| Toolbar | ✅ | `sample` dropdown + `upload` / `copy` / `clear` / `analyse ⌘` buttons. Keyboard shortcut visible. |
| Run bar | ✅ | `run` + `analyse ⌘` + `clear ⌘` + "auto-runs on paste" — great for power users. |
| Output structure preview | ✅ | `Awaiting Analysis · expected output structure` — shows what will be populated: Sender Identity, Header Authentication, Extracted URLs, Lure Signals, Case Findings. Excellent forward-looking empty state. |

**Suggestions:**
- ⚠️ The "Email Source" card inside the intake panel is redundant — it's the only content. The card border adds visual noise without grouping anything. Consider removing it and letting the textarea be the direct child of the intake panel.
- ⚠️ The `[WAIT_FOR_INPUT]` placeholder in the textarea uses raw debug-style formatting. It's functional but reads like a log message rather than user-facing copy. Consider: "Paste raw email source including headers — or drop a .eml file."

---

## /url — Safe URL Analyzer

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `triage / safe url Safe URL Analyzer` — clear. |
| Description | ✅ | `Local parsing only — no headers fetched, no page rendered, no JavaScript executed.` — excellent security disclaimer. |
| Panel header | ✅ | `🔗 Safe URL Analyzer` + description + filter + idle badge. |
| Intake panel | ✅ | "candidate URL" label + "defanged or live" hint. URL Input sub-card with textarea. |
| URL Input sub-panel | ✅ | `🔗 URL Input` title + placeholder showing defanged URL format. |
| Toolbar | ✅ | `sample` dropdown + `upload` / `copy` / `clear` / `analyse ⌘` — consistent with Phishing. |
| Status bar | ✅ | `Chars 0 · Refanged no · Scheme — · Runs 0` — live metrics. |
| Backend enrichment checkbox | ✅ | `☐ backend enrichment` — clear opt-in. |
| Run bar | ✅ | Same pattern as Phishing — consistent. |
| Output empty state | ✅ | `No URL Loaded` + detailed explanation of what URL Analyzer does. |

**Suggestions:**
- ✅ This page is one of the cleanest in the app. No issues found.
- ⚠️ The "backend enrichment" checkbox label is bare. A tooltip explaining what backend enrichment does (e.g., "Send the URL to the backend for reputation lookup and redirect chain analysis") would help first-time users.

---

## /file — File Analysis

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `File Analysis` with breadcrumb `Intake > File`. |
| Description | ✅ | `Static analysis of files — detect suspicious patterns, embedded IOCs, and hidden payloads.` |
| Panel header | ✅ | `📄 File Analysis` + filter + empty badge. |
| File Input | ✅ | `Filename` label + `e.g. invoice.pdf` placeholder + `File content` label + textarea. Clear two-field layout. |
| Upload/Paste buttons | ✅ | Two buttons below textarea — good placement. |
| Samples list | ✅ | Four sample files (invoice_2024_05_15.pdf.exe, document.js, backup.sh, README_RECOVER.html) with char counts. Good for quick testing. |
| Run bar | ✅ | `analyse ⌘` + `clear ⌘` + "auto-runs on paste" — consistent. |
| Output structure preview | ✅ | Six-panel grid: File Metadata, Static Signals, Embedded IOCs, Risk Score, MITRE Mapping, Case Integration — each with description. |

**Suggestions:**
- ⚠️ The Filename field and File content textarea are not inside a card/panel border — they sit directly in the File Input section. Other pages wrap inputs in bordered cards. Consider adding a card border for visual consistency with Phishing/URL/SIEM intake panels.
- ⚠️ The six output panels at the bottom (File Metadata, Static Signals, etc.) are structurally identical to the Phishing "Awaiting Analysis" output grid — good reuse. But they're all full-width two-column. On a 1440px screen, some rows have only one item (e.g., MITRE Mapping alone). Consider a three-column grid to fill space more evenly.

---

## /logs — Log Analysis

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `Log Analysis` with breadcrumb `Intake > Logs`. |
| Description | ✅ | `Parse and analyze security logs — detect brute force, persistence, privilege escalation, and defense evasion.` |
| Panel header | ✅ | `📋 Log Analysis` + filter + empty badge. |
| Log Input | ✅ | `Raw log data` label + detailed placeholder listing supported detection rules (4625 failed login, 4103/4104 PowerShell, etc.). |
| Paste button | ✅ | Single "Paste" button — different from other pages which have upload/copy/clear/analyse. |
| Samples list | ✅ | Six sample files (RDP Brute Force, PowerShell Encoded, Priv Escalation, Persistence Chain, Log Tampering, Normal Baseline) with line counts. |
| Run bar | ✅ | `analyse ⌘` + `clear ⌘` + "auto-runs on paste" — consistent. |
| Output structure preview | ✅ | Six-panel grid: Log Parsing, Event Detection, IOC Extraction, MITRE Mapping, Timeline Reconstruction, Case Integration. |

**Suggestions:**
- ⚠️ The Log Input textarea is larger than other pages' textareas (looks ~250px tall vs ~150px on Phishing/URL). This is intentional (log data is verbose) but creates visual inconsistency. Consider standardizing textarea heights across all input pages, with a resizable handle.
- ⚠️ The "Paste" button below the Log Input is the only action button in the input panel. Other pages have upload/copy/clear/analyse. Consider adding the same toolbar for consistency, even if some buttons are disabled initially.

---

## /pcap — PCAP Analysis

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `PCAP Analysis` with breadcrumb `Intake > PCAP Analysis`. |
| Description | ✅ | `Upload a .pcap file for full Scapy-based analysis, or paste tcpdump/tshark output for quick triage.` |
| Panel header | ✅ | `🌐 PCAP Analysis` + filter + empty badge. |
| Input Mode | ✅ | `Upload .pcap` (selected, blue) + `Paste Output` toggle. Good tab-like selector. |
| File upload | ✅ | `Choose .pcap / .pcapng file` — clear file type hint. |
| Run bar | ✅ | `analyze ⌘` + `clear ⌘` + "auto-runs on paste" — consistent. Note: "analyze" (American) vs "analyse" (British) on other pages. |
| Output empty state | ✅ | `No capture loaded` + detailed description of what PCAP Analysis does. |

**Suggestions:**
- 🔴 Spelling inconsistency: "analyze" on PCAP vs "analyse" on every other page. Pick one and use it everywhere. The app uses British English in descriptions ("analyse event streams", "analyze new evidence"), so "analyse" is the intended form. Fix the PCAP run button.
- ⚠️ The PCAP input area is shorter than the Log input. The "No capture loaded" empty state with the network icon is good but appears quite far below the input area. Consider moving it closer (reducing the gap between the run bar and the output area).

---

## /attachment — Attachment Triage

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `Attachment Triage` with breadcrumb `Intake > Attachment`. |
| Description | ✅ | `Static review of file metadata, hashes, strings, and signals. Files are never executed.` — clear safety note. |
| Panel header | ✅ | `triage / attachment` breadcrumb + title. |
| Intake panel | ✅ | `Intake · file upload` label + "no file selected" hint. |
| Upload panel | ✅ | `✉️ Upload a file` card with `Choose file` button + "Supports any file type. Max 15 MB for MVP." |
| Hash Reputation Lookup | ✅ | `# Hash Reputation Lookup` section + `Paste a SHA-256, MD5, or SHA-1 hash..` input. |
| Reputation disclaimer | ✅ | `Reputation checks run on the Intel page and only fire after you opt in per query — nothing is sent from here.` — excellent privacy note. |
| Status bar | ✅ | `Status Idle · Detonation never · Upload none · Mode static review` — clear mode indicator. |
| Output empty state | ✅ | `No file loaded` + description of what File Triage does. |

**Suggestions:**
- ⚠️ The page has two distinct input surfaces (file upload + hash lookup) stacked vertically. This is fine but visually the hash input feels disconnected from the upload panel. Consider wrapping both in a single "Input" card to make the relationship clearer.
- ⚠️ "Max 15 MB for MVP" — the "for MVP" qualifier suggests this limit will change. Either remove it (the limit is just the limit) or make it a config setting in /settings.

---

## /siem — SIEM Workspace

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `siem / workspace SIEM Workspace` — clear. |
| Description | ✅ | `Query, filter, and analyse event streams — auto-classifies log format, counts entities, and lets you filter by them.` |
| Jump links | ✅ | `jump → Detection` — useful pivot. |
| Stats bar | ✅ | `0 / 0 events` — live count. |
| Hunt library | ✅ | `start a hunt` button + recent queries list with star icons + saved hunts section. Good hunt management surface. |
| Hunt presets | ✅ | Preset chips: Credential Access, PowerShell, Kerberoasting, Lateral Movement, Persistence, Living off the land — good quick-start options. |
| Intake panel | ✅ | `Intake · query + paste` label + "Paste raw events" card with JSONL/syslog/CSV hint. |
| Filter strip | ✅ | `Filter strip · 0 chip(s)` + keyword filter input + time range (15m / 1h / 24h / all) + "filters click any value to pin a filter" hint. |
| Status bar | ✅ | `Status Awaiting input · Sources 0 · High sev 0 · Window all` — clear. |
| Output panel | ✅ | `siem_summary` card with 0 events / 0 detection leads + four stat tiles (Events, Top src, Highest, Findings). |
| Incident timeline | ✅ | `Incident timeline · 0 step(s)` with empty state. |
| Event timeline | ✅ | `Event timeline · 0 bucket(s)` with empty state. |
| Events + Field summary | ✅ | Side-by-side: `Events · 0 rows` + `Field summary · top values per field` (src, dst, user, sig, sev). |
| Case Handoff | ✅ | "send artifact to: Detection → / MITRE Coverage → / Case Notebook →" — consistent. |

**Suggestions:**
- 🔴 The SIEM page is the longest scroll in the app — 8+ stacked panels (hunt library, presets, intake, filter, status, output summary, incident timeline, event timeline, events table, field summary, case handoff). This is overwhelming for a first visit. Consider:
  1. Collapsing the hunt library + presets behind a "hunts" toggle (most users paste events first).
  2. Moving the event timeline + incident timeline below the events table, or putting them in a tab.
  3. Making the field summary a collapsible sidebar instead of a full-width panel.
- ⚠️ The keyword filter input has the placeholder `keyword filter — a|b matches either · / to focus`. The "· / to focus" part is a keyboard shortcut hint. Good for power users, but the dot-separated format is inconsistent with other pages. Consider: `keyword filter (a|b matches either)  press / to focus`.
- ⚠️ The `siem_summary` card header uses the raw key name `siem_summary` instead of a human-readable label. Consider: "SIEM Summary" or just "Summary".

---

## /investigation — Investigation (Smart Parser)

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `investigation Investigation` — note: missing breadcrumb prefix (other pages show `ops / operations`). |
| Description | ✅ | `Analyze artifacts, extract IOCs, and enrich context — all from one workspace.` |
| Smart Parser heading | ✅ | `Smart Parser` as a sub-heading — clear. |
| Intake panel | ✅ | `Intake · raw artifact` label + `0 chars` count. |
| Input Terminal | ✅ | Collapsible panel with `[WAITING_FOR_INPUT]` + placeholder. Good progressive disclosure. |
| Toolbar | ✅ | `sample` dropdown + `upload` / `copy` / `parse ⌘` — consistent. |
| Recent inputs | ✅ | `recent timestamp,event,user...` + `clear` link — shows last input. |
| Status bar | ✅ | `Status Idle · Chars 0 · Lines 1 · IOCs 0 · Findings 0 · Mode session-only` — comprehensive. |
| Output panel | ✅ | `Output · detected` + `awaiting input` badge. |
| IOC families table | ✅ | Two-column grid: "What the parser recovers · 11 samples · 11 IOC families" + "How analysts use it · 3-step flow" (Paste anything → Inspect inventory → Pivot or hand off). |

**Suggestions:**
- ⚠️ The breadcrumb shows only `investigation` without a sub-breadcrumb. Other pages show `ops / operations / Parser`. This page should show `ops / operations / Parser` in the breadcrumb for consistency.
- ⚠️ The `[WAITING_FOR_INPUT]` placeholder text is in monospace and ALL-CAPS — reads like a terminal output rather than a user-friendly prompt. Other pages use sentence-case placeholders. Consider: "Paste raw artifact, log line, URL, hash, or rule — or drop a file." (which is already shown as secondary text — good, but the primary `[WAITING_FOR_INPUT]` is visually dominant).
- ⚠️ The "How analysts use it" panel on the right side of the output is a great 3-step guide. But it's only visible when the output area is empty. Consider showing it permanently (or until dismissed) so new users always see it.

---

## /intelligence — Intel Hub

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `intelligence / hub Intel Hub` — clear. |
| Description | ✅ | `Search CVEs, threat actors, malware, file hashes, and TLS fingerprints — unified.` |
| Unified lookup panel | ✅ | `Intelligence · unified lookup` label + "esc clear/close" hint. |
| Search input | ✅ | Large search bar with magnifying glass icon + placeholder `Search CVEs, threat actors, malware, hashes, JA3, IPs, domains...` — comprehensive. |
| Start working card | ✅ | `Search an observable` with `/intel →` link + description. |
| Recent Searches | ✅ | Two recent searches as clickable chips: `example.com`, `203.0.113.9`. |
| Keyboard shortcuts | ✅ | `Ctrl+K · Ctrl+Shift+F · Esc` shortcut bar. |

**Suggestions:**
- ✅ This page is clean and focused. The single search bar as the primary action is the right choice.
- ⚠️ The "Recent Searches" section shows only two items. If the user has searched more, where do they go? Consider a "View all recent searches" link or a expandable list.
- ⚠️ The page is quite empty below the fold for a first visit with no recent searches. Consider adding a "Suggested lookups" section (e.g., common CVEs, recent threat actors) to give new users something to click.

---

## /detection — Detection Editor

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `detection / rule editor Detection Editor` — clear. |
| Description | ✅ | `Compose Sigma · YARA · KQL detections, dry-run against events, map to MITRE ATT&CK, or generate Sigma rules from a description.` |
| Jump links | ✅ | `jump → SIEM · Investigation` — useful pivots. |
| Format selector | ✅ | Three format tabs: `sigma` (active, blue), `yara`, `kql` — each with icon and description. Plus `copy` / `sample` / `reset` buttons. |
| Generate tab | ✅ | `✦ generate · Sigma from description` — separate entry point for AI-assisted rule creation. |
| Toolbar | ✅ | `+ new rule` / `rule library` / `mitre` / `sigma tester` — good navigation strip. |
| Intake panel | ✅ | `Intake · format & rule body` + `1 lines · 0 chars` count + `rule library` / `dashboard` links. |
| Create from signal | ✅ | `Create rule · from finding / technique / IOC` + `3 findings loaded` + `create from signal · finding` card with finding/technique/ioc tabs + `select a finding...` dropdown. |
| Lifecycle | ✅ | `Lifecycle · state machine` + "no active rule" empty state. |
| Rule editor + Simulate | ✅ | Side-by-side: `rule · sigma · 1 ln` + `simulate · event · 1 ln` + `no match` badge. |
| Simulate corpus | ✅ | `simulate · corpus · sigma sample set` + `run corpus` button + `4 samples · sigma` count. |
| Conversion parity table | ✅ | `conversion parity · sigma ⊕ kql ⊕ yara · 10 constructs` — excellent reference table showing what each format can express. |
| Output verdict | ✅ | `Output · verdict & mapping` + "rule does not match" badge + "esc close" hint. |

**Suggestions:**
- 🔴 This page is extremely long — 8+ panels stacked vertically. The conversion parity table alone takes significant space. Consider:
  1. Moving the conversion parity table to a collapsible "Reference" section or a separate help modal.
  2. Putting the rule editor + simulate panels in a tabbed view (Edit / Simulate / Corpus / Reference).
  3. Collapsing the "Create from signal" panel behind a toggle until needed.
- ⚠️ The `1 lines · 0 chars` count on the intake panel is confusing when the textarea shows line `1` (empty). The count should either show `0 lines · 0 chars` or not show at all when empty.
- ⚠️ The format selector (sigma/yara/kql) and the generate tab are visually adjacent but functionally different. The format selector changes the rule editor mode; the generate tab is a separate workflow. Consider more visual separation between them.

---

## /mitre — MITRE ATT&CK Coverage

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `detection / mitre MITRE ATT&CK Coverage` — clear. |
| Description | ✅ | `Interactive coverage matrix — click techniques to cycle none → partial → full. Stored locally in your browser.` |
| Coverage summary | ✅ | `coverage` badge + `0% weighted coverage` + `0 full · 0 partial · 38 none` + four stat tiles (Tactics 14, Techniques 38, Full 0, Gaps 38). |
| Destructive alert | ✅ | Red-bordered `destructive · 38 techniques uncovered` card with Reason / Limitation / Action text. Good risk communication. |
| Technique Lookup | ✅ | `Technique Detection Lookup · TID → your local rule library` + search input + `Look up` button. |
| Kill-chain coverage | ✅ | Horizontal tactic bar: Recon → Resource Dev → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → C2. Each shows 0% coverage. |
| Matrix tabs | ✅ | `matrix` / `gaps (38)` / `notes (0)` — good filtering. |
| Coverage matrix grid | ✅ | Full MITRE matrix with technique IDs (T1595, T1583, etc.) and names. Each cell shows coverage badge (n = none). |
| Technique detail panel | ✅ | `Technique detail` — "Click any technique cell to cycle through coverage states (none → partial → full) or right-click to inspect." |
| Case Handoff | ✅ | "send artifact to: Detection Editor → / SOC Guide → / Case Notebook →" — consistent. |

**Suggestions:**
- ⚠️ The `0% weighted coverage` display is accurate but could be more motivating. Consider showing progress as "0/38 techniques covered" or "38 gaps remaining" to frame it as actionable.
- ⚠️ The kill-chain coverage bar shows all tactics at 0%. When coverage is 0%, the bar is just a row of labels. Consider collapsing it when coverage is 0% and expanding when coverage starts filling in.
- ⚠️ The coverage matrix grid shows only "n" (none) badges since coverage is 0%. The grid is dense but readable. Consider adding a "compact/detailed" toggle for users who want to see more techniques at once.
- ⚠️ The "destructive" alert card uses the word "destructive" which has a specific meaning in SOC contexts (destructive attacks). Here it means "38 uncovered techniques are risky." Consider: "⚠ coverage gap" or "high-risk gap" instead.

---

## /sigma-tester — YARA & Sigma Rule Tester

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `tools / rule tester YARA & Sigma Rule Tester` — clear. |
| Description | ✅ | `Paste a YARA or Sigma rule alongside your sample — see which conditions matched and which didn't, grouped by category.` |
| Format tabs | ✅ | `YARA` (active) + `Sigma` tabs + sample rules (Suspicious PowerShell Download, Base64 Encoded Data). |
| Side-by-side panels | ✅ | `Rule (YARA)` left + `Sample Data` right — correct layout for a tester. |
| Test Rule button | ✅ | `Test Rule` button + "paste a rule and sample to enable testing" hint. |
| Output empty state | ✅ | `Test a rule` + "Select a tab, load an example, or paste your own YARA/Sigma rule and sample data, then click Test Rule." |

**Suggestions:**
- ✅ This page is well-designed. The side-by-side layout is exactly right for a rule tester.
- ⚠️ The "Test Rule" button is at the bottom of the input panels. Consider placing it at the top (next to the format tabs) so it's visible without scrolling.
- ⚠️ The sample rule chips (Suspicious PowerShell Download, Base64 Encoded Data) are positioned below the format tabs but above the panels. This is a good location, but the chips look like they belong to the format selector rather than being independent samples. Consider labeling them: "Try: Suspicious PowerShell Download · Base64 Encoded Data".

---

## /operations — Tool Launcher

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `operations / home Tool Launcher` — clear. |
| Description | ✅ | `Supporting analyst utilities — parse, transform, compare.` |
| Start working card | ✅ | `Parse evidence` with `/parser →` link — good primary action. |
| Tools grid | ✅ | Five tool cards: Parser, CyberChef, Diff, Regex, Snippets — each with icon and one-line description. |
| Recent Tools | ✅ | `No tool runs yet — the launcher above will record what you use.` |
| Keyboard shortcuts | ✅ | `Ctrl+K · Ctrl+Shift+F · Esc` bar. |

**Suggestions:**
- ✅ Clean hub page. The five tool cards are well-organized.
- ⚠️ The page has a lot of empty space below the tool grid. Consider adding "What each tool does" descriptions or use-case examples to fill the space and help new users choose the right tool.
- ⚠️ The "Recent Tools" section is empty. Consider showing it only when there are recent tools, or combining it with the tool grid (e.g., "Parser · last used 2 min ago").

---

## /diff — Diff View

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `tools / diff Diff View` — clear. |
| Description | ✅ | `Side-by-side comparison for artifacts — pcap summaries, email headers, Sigma rules, JSON blobs. Highlights IOCs added or removed.` |
| Quick-load buttons | ✅ | `Nmap scans` / `Email headers` / `JSON reports` / `md` — good presets. |
| Side-by-side panels | ✅ | `Original` left + `Changed` right — correct diff layout. |
| Output empty state | ✅ | `Paste two versions of an artifact above` + "Or load a sample — see what changed between good and bad". |

**Suggestions:**
- ✅ Clean, focused page. The side-by-side layout is correct for a diff tool.
- ⚠️ The two textareas have different placeholder text (`Paste original content...` vs `Paste modified content...`) — good differentiation. But the textareas are quite tall (~200px each). For short diffs, this wastes space. Consider making them resizable or starting at a smaller height.
- ⚠️ The output area (showing "Paste two versions...") sits below the textareas. For long diffs, this would require scrolling. Consider a sticky output area or a split-pane layout.

---

## /timeline — Investigation Timeline

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `ops / timeline Investigation Timeline` — clear. |
| Description | ✅ | `Auto-captured history of every tool action across workspaces — no manual entry needed.` |
| Toolbar | ✅ | `md` export + `clear timeline` (red) — good action placement. |
| Event count | ✅ | `events 13` — live count. |
| Search + filters | ✅ | `search events...` input + filter chips (all, /parser, case, mitre, triage). |
| Timeline | ✅ | Two date groups: "Today · 8 events" and "August 25, 2026 · 5 events" — each with a colored DT badge. |
| Event rows | ✅ | Each row: timestamp + source badge + action verb + detail + `→` link. Very scannable. |

**Suggestions:**
- ✅ The timeline is one of the best-designed pages. The date-grouped event list with source badges and action verbs is exactly right for an investigation timeline.
- ⚠️ The "clear timeline" button is red and prominent. This is a destructive action — consider adding a confirmation dialog or at least a tooltip: "Clear all timeline events. This cannot be undone."
- ⚠️ The event rows show `triage → case opened` as a sub-line. The `→` arrow is used both as a link indicator (in the topbar) and as a directional indicator (in event details). Consider using a different symbol for one of these to avoid confusion.

---

## /snippets — Saved Queries & Snippets

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `library Saved Queries & Snippets` — clear. |
| Description | ✅ | `SIEM queries, Sigma rules, SOC regex, and investigation checklists — saved locally.` |
| Toolbar | ✅ | `import` / `export` / `+ new` — good CRUD surface. |
| Search + filter | ✅ | `search snippets...` input + type tabs (all, SIEM, Sigma, Regex, Notes). |
| Snippet cards | ✅ | Each card: title + type badge + tags + content preview. Very readable. |
| Card layout | ✅ | Two-column grid of cards. Each card shows full content preview (queries, rules, checklists). |

**Suggestions:**
- ✅ Excellent page. The snippet cards with full content preview are highly functional.
- ⚠️ The cards show full query/rule text in monospace. For long rules (e.g., PowerShell encoded command Sigma rule), the content is quite verbose. Consider a "show more/show less" toggle for long content, or a max-height with scroll.
- ⚠️ The Notes type badge is red while SIEM is teal, Sigma is blue, Regex is orange. The color coding is consistent but the "Notes" type feels less structured than the others. Consider a different badge style (e.g., outline) to differentiate notes from structured rules.

---

## /guide — SOC Playbook Guide

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `detection / guide SOC Playbook Guide` — clear. |
| Description | ✅ | `Bite-sized response playbooks — pick a scenario, work the steps, pivot into the right tool.` |
| Playbook count | ✅ | `14 bundled playbooks` — good aggregate. |
| Priority stats | ✅ | Four stat tiles: Total 14, P1 critical 6, P2 high 7, P3 medium 1. |
| Filter + search | ✅ | `Filter · pick a scenario` + search input + priority tabs (all, p1, p2, p3). |
| Playbook list | ✅ | Left column: playbook cards with icon, title, priority badge, category, time estimate, progress (0/7). |
| Playbook detail | ✅ | Right column: selected playbook with description, MITRE tags, step list with checkboxes and pivot links. |
| Always/Never panels | ✅ | Two side-by-side panels: "Always" (3 rules) + "Never" (3 rules) — good guardrails. |
| Case Handoff | ✅ | "send artifact to: MITRE Coverage → / Detection Editor → / Case Notebook →" — consistent. |

**Suggestions:**
- ✅ The playbook guide is one of the most polished pages. The master-detail layout (list + detail) is the right choice.
- ⚠️ The step list in the detail panel shows numbered steps with checkboxes and pivot links (e.g., "01 Pause any new inbox rules... Logs →"). The step numbers (01, 02, etc.) use leading zeros — this is visually clean but unnecessary for 7 steps. Consider dropping the leading zero for counts < 10.
- ⚠️ The "Always" and "Never" panels at the bottom are separated from the playbook detail by some vertical space. Consider making them collapsible or putting them in a "Guardrails" tab to keep them associated with the selected playbook.

---

## /validation — Analyst Validation

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `developer / validation Analyst Validation` — clear. |
| Description | ✅ | `Benchmark suite — run investigations through BeyondLabs, record metrics, and compare against ground truth.` |
| Progress banner | ✅ | `0/40 investigations completed` — good aggregate progress. |
| Stats grid | ✅ | Four stat tiles: Total 40, Phishing 0/10, URL 0/10, Log 0/10, File 0/5. |
| Sample queue | ✅ | Search + type filters (All, Phishing, URL, Log, PCAP, File) + status filters (Any, pending, in progress, completed). |
| Sample list | ✅ | Sample cards with ID (PH-001), difficulty (Easy/Medium), description, type, and verdict (Malicious/Benign). |
| Detail panel | ✅ | "Select a sample from the queue to begin" empty state. |

**Suggestions:**
- ✅ Well-structured benchmark page. The queue + detail layout is appropriate.
- ⚠️ The stat tiles show `0/10` for each category. The denominator (10, 10, 10, 5) is useful but the tile layout is uneven — File has 5 while others have 10. Consider a more balanced grid or grouping them differently.
- ⚠️ The sample list shows difficulty badges (Easy, Medium) with different colors. Consider adding a "Hard" tier to the color system for completeness, even if no hard samples exist yet.

---

## /settings — Workspace Settings

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `settings / workspace Workspace` — clear. |
| Description | ✅ | `brand, theme, fonts, layout, accessibility, shortcuts. Everything persists locally — no account, no sync.` |
| Tabs | ✅ | Extensive tab bar: Filter settings, Brand, Theme gallery, Density, Typography, Accessibility, Sidebar layout, Dashboard layout, Shortcuts, Data & Privacy. |
| Brand section | ✅ | Logo upload + name + icon grid — good customization surface. |
| Theme gallery | ✅ | Three themes: Dark (active), Light, Dark High Contrast — each with color preview chips. |
| Density & Radius | ✅ | Density slider + corner radius slider — good fine-tuning. |
| Typography | ✅ | Monospace ligatures toggle + font stack display (Inter, IBM Plex Mono, etc.) — excellent typography control. |
| Sidebar layout | ✅ | Full sidebar configuration with collapsible groups, drag handles, visibility toggles. Very powerful. |
| Accessibility | ✅ | Reduce motion, Reduced transparency, High contrast, Zebra rows, High-contrast focus, Open palette with /, Show topbar toggles. |
| Motion & UI | ✅ | Panel opacity slider, Show breadcrumb toggle. |
| Dashboard layout | ✅ | Toggle sections: Command strip, Case load, Continue row, Activity tracks, Workflow ribbon, Pinned rail, Recent inputs, Scratch notes. |
| Keyboard shortcuts | ✅ | Full shortcut reference table organized by category (Global, Navigation, Search & Filter, Panels & Tools). |
| Backend health | ✅ | `Backend URL http://localhost:8000` + Status badge (pong, v1.1.0, 79ms). |
| Data & Privacy | ✅ | Export/Restore workspace backup + Clear recents + Clear all local data + storage location info. |

**Suggestions:**
- ⚠️ The settings page is extremely long — 10+ sections. The tab bar at the top is essential for navigation. Ensure all tabs are reachable via keyboard (the tab bar should be scrollable if needed).
- ⚠️ The "8.5px active" text (mentioned in the earlier audit) is visible in the Settings section headers. This is the smallest text in the app and may be hard to read for users with low vision. Consider bumping to 10.6px.
- ⚠️ The "Storage" info at the bottom says "beyondlabs stores everything locally..." — this is good transparency. But the "Local Storage" badge could be a link to a storage management page.
- ⚠️ The sidebar layout section shows a full tree of all nav items with drag handles and visibility toggles. This is powerful but complex. Consider a simpler "Quick Layout" preset (e.g., "Default", "Minimal", "Full") alongside the detailed tree.

---

## /developer — Developer Hub

| Item | Status | Notes |
|------|--------|-------|
| Page title | ✅ | `dev Developer Hub` — clear. |
| Description | ✅ | `Internal tools, component inventory, and build notes for BeyondLabs frontend.` |
| Three cards | ✅ | `Component Showcase`, `Investigation Guide`, `Settings` — each with icon and description. |
| Design System v1.0 | ✅ | Highlighted card with `frontend/docs/DESIGN_SYSTEM.md` reference — good internal documentation link. |

**Suggestions:**
- ✅ Simple hub page. The three cards + design system reference are appropriate for a developer section.
- ⚠️ The page is mostly empty below the four cards. Consider adding build status, recent commits, or a changelog summary to fill the space.

---

## /developer.components — Component Showcase

| Item | Status | Notes |
|------|--------|-------|
| Terminal display | ✅ | `beyondlabs / terminal` + `$ navigate /wild-path` + `command not found: /wild-path` + route hint table. |
| Route hint table | ✅ | Lists all major routes with descriptions — good reference. |

**Suggestions:**
- ✅ This is a dev-only route with a terminal easter egg. Fun and functional.
- ⚠️ The route table lists only 8 routes. The app has 27+ routes. Consider expanding the table to be a complete route reference.

---

## Cross-Page Consistency Summary

| Pattern | Status | Notes |
|---------|--------|-------|
| Page title format | ✅ | `breadcrumb / Page Title` — consistent across all routes. |
| Description format | ✅ | One-line description below the title — consistent. |
| Panel borders | ✅ | `ba-panel` rounded containers — consistent across all pages. |
| Button styles | ✅ | Primary (blue fill), secondary (outline), destructive (red) — consistent. |
| Empty states | ✅ | Every empty panel has icon + title + copy + next action — excellent consistency. |
| Keyboard shortcuts | ✅ | `Ctrl+K · Ctrl+Shift+F · Esc` bar appears on most pages — consistent. |
| Case Handoff | ✅ | "send artifact to:" with pivot links — consistent across SIEM, Detection, MITRE, etc. |
| Status badges | ✅ | `idle` / `empty` / `no match` / `awaiting input` — consistent badge pattern. |
| Spelling | 🔴 | "analyze" (PCAP) vs "analyse" (everywhere else) — inconsistent. Pick one. |
| Textarea heights | ⚠️ | Vary across pages (Phishing ~150px, Log ~250px). Consider standardizing with resizable handles. |
| Sub-panel redundancy | ⚠️ | Some pages have redundant sub-panel cards inside intake panels (e.g., Phishing "Email Source" card, URL "URL Input" card). These single-child cards add visual noise. |

---

## Prioritized Visual Fixes (No Code Changes — Suggestions Only)

| # | Priority | Page | Finding | Suggested Change |
|---|----------|------|---------|------------------|
| V1 | P1 | Global | "analyze" vs "analyse" spelling inconsistency | Standardize to "analyse" across all pages |
| V2 | P1 | /siem | 8+ stacked panels create overwhelming first visit | Collapse hunt library/presets behind toggle; tab-ify timelines |
| V3 | P1 | /detection | 8+ stacked panels; conversion parity table takes excessive space | Move parity table to collapsible reference or modal |
| V4 | P1 | /case | Ten tabs is too many; progress/quality overlap | Group related tabs (Summary, Provenance); consolidate progress indicators |
| V5 | P2 | /siem | `siem_summary` raw key name shown as card header | Change to "SIEM Summary" or "Summary" |
| V6 | P2 | / | Case Load section too tall above the fold | Compact the stats/timeline grid; collapse recent cases |
| V7 | P2 | / | Four empty "Pinned" panels are repetitive | Unify into a single "No pinned items" empty state |
| V8 | P2 | /timeline | "clear timeline" is destructive with no confirmation | Add confirmation dialog or tooltip warning |
| V9 | P2 | /attachment | "Max 15 MB for MVP" qualifier is unnecessary | Remove "for MVP" or make it a configurable setting |
| V10 | P2 | /phishing | `[WAITING_FOR_INPUT]` placeholder is debug-style | Replace with user-friendly sentence-case copy |
| V11 | P2 | /investigation | Missing breadcrumb prefix (shows only "investigation") | Add full breadcrumb: `ops / operations / Parser` |
| V12 | P3 | /settings | 8.5px "active" text is smallest in the app | Bump to 10.6px (`ba-text-3xs`) for consistency |
| V13 | P3 | /pcap | Empty state sits far below input area | Reduce gap between run bar and output area |
| V14 | P3 | /mitre | "destructive" label is misleading (means coverage gap, not destructive attack) | Change to "coverage gap" or "high-risk gap" |
| V15 | P3 | /snippets | Long snippet content has no collapse mechanism | Add show more/show less toggle for long content |
| V16 | P3 | /intelligence | Empty page below fold for first visit | Add "Suggested lookups" section |
| V17 | P3 | Global | Sidebar theme toggle is visually noisy | Simplify to a single moon/sun icon toggle |
| V18 | P3 | /settings | Sidebar layout tree is complex for casual users | Add "Quick Layout" presets alongside detailed tree |
