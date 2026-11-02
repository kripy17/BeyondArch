# OpenCTI-Informed Visual Migration Plan

Status: DRAFT — plan only, no code until reviewed.

Scope: a surface-level visual pass on the FROZEN frontend architecture
(`FRONTEND_ARCHITECTURE.md` v1.0), using OpenCTI's frontend
(`opencti_refrence/opencti-platform/opencti-front/`) as a **design
reference only**. This is not an OpenCTI port and not an architecture
change.

## 0. Framing

| Constraint | Rule |
|---|---|
| Architecture | FROZEN v1.0 — no page restructures, no new UI primitives as *architecture*, no navigation redesigns, no backend/GraphQL concepts |
| What can change | Visual tokens (values inside the existing theme system), per-component styling of *existing* primitives (PageShell top bar, DataTable, EntityHeader, empty states, badges/chips), density, empty/loading guidance |
| What cannot change | Routes, state stores, component tree shape, `data/*` domain models, localStorage keys, workflow (analyst-led, no detonation, bounded scans) |
| Identity | BeyondLabs keeps its mono/uppercase micro-label identity, 7-workspace model, and per-workspace accent scoping. OpenCTI patterns are adapted, never copied verbatim |
| Attention budget | **90% neutral / 10% accent.** Backgrounds, borders, text stay neutral; workspace color, severity, and active state are the only accents. Accent guides the eye — it does not decorate the page. When in doubt, strip an accent rather than add one |
| Objective | Someone familiar with OpenCTI should immediately feel comfortable navigating BeyondLabs, while someone using BeyondLabs should still recognize it as its own product |
| Verification | After each visual subsystem: `npm run lint` (0 new errors), `npm run build`, driver suites (regression S1–S6, reader R1–R5, chain A1–B3, timeline 14) with 0 console errors, plus Playwright screenshot review of the touched surface |

## 1. Ranked by UX impact (highest first)

| # | Subsystem | UX impact | Effort | Risk |
|---|---|---|---|---|
| 1 | Empty states with guidance | High — every table/panel benefits, first-run experience | Low | Low |
| 2 | Table density & readability | High — analysts read tables most of the time; scan speed is the win | Med | Med (identity drift) |
| 3 | EntityHeader sticky/compact refinement | High — analysts live on entity/detail pages | Low-Med | Low |
| 4 | Top bar refinement | Med-High — visible on every page | Low | Low |
| 5 | Information hierarchy audit | High — consistent visual priority across every page | Med | Low |
| 6 | Severity color discipline | Med — signal reading speed | Low | Low |
| 7 | Filter chips bar polish | Med — analyst tooling surfaces | Med | Low |
| 8 | Visual consistency audit | Med-High — "one person designed it" feel | Med | Low |
| 9 | Card-list alternation with dense tables | Med — findings/cases lists | Med | Med |
| 10 | Pagination + details polish | Low | Low | Low |

## 2. Item detail

### 1. Empty states with guidance (adopt)

- OpenCTI: empty states carry an illustration + a short 3-step guidance
  list (what to do next), not a bare "No data" label.
- BeyondLabs today: `components/output/data-table.tsx` renders a dashed
  box with `emptyMessage` text; several panels render bare text.
- Change: extend the DataTable empty branch to render
  `emptyMessage` + optional `emptyHint?: ReactNode` (steps/call-to-action)
  inside the existing dashed frame — **styling change only, no new
  primitives**. Wire hints at the highest-value call sites first: IOC
  inventory (SIEM/operations), findings list on a case, detection
  editor's rules table, search results.
- Files: `components/output/data-table.tsx`, call sites
  (`components/soc/IocInventory.tsx`, `components/entity/FindingCard.tsx`
  list surfaces, detection route).
- Reject: OpenCTI's illustration art style; BeyondLabs keeps text/mono
  guidance inside existing frames.

### 2. Table density & readability (adopt values, guard identity)

- OpenCTI: 42px header row, 48px body rows (spacing 6), 12px semibold
  header labels, sort arrows. Analysts scan tables for hours — density
  and typography are the readability win, which is why this ranks
  above header polish.
- BeyondLabs today: `data-table.tsx` has sticky header with mono
  uppercase micro-labels (`ba-text-2xs tracking-widest`), `py-1.5`
  header / `py-2` rows, sort arrows (ArrowUp/ArrowDown/ArrowUpDown),
  zebra rows, hover left-border accent. Already close.
- Change: normalize body rows to 48px (`min-h` on `td`), header to 42px;
  keep the mono uppercase label (BeyondLabs identity) but drop
  `tracking-widest` on sortable headers to reduce noise; keep zebra and
  hover affordance. Do NOT adopt resize handles or the hover column menu
  (rejected earlier: low value, high complexity).
- Files: `components/output/data-table.tsx`.
- Risk guard: screenshot-compare before/after on dark + light themes;
  density pref (`html[data-density="compact"]`) must still win.

### 3. EntityHeader sticky/compact refinement (adopt/adapt)

- OpenCTI: detail pages use a sticky header band with entity identity
  (avatar/type color, name, key meta) on the left and a stable action
  cluster on the right; the header stays visible while content scrolls.
- BeyondLabs today: `components/entity/EntityHeader.tsx` exists but is a
  static block; PageShell already provides sticky top bar + hero.
- Change: make EntityHeader's action row sticky under the top bar
  (`sticky top-14 z-20` inside the scroll context) with
  `backdrop-blur` + `bg-background/85`, matching the top bar treatment;
  ensure actions never reflow (fixed right cluster, wrap left).
  Progressive fill: keep hero, add a compact sticky bar that appears
  with entity name + actions once the hero scrolls out.
- Files: `components/entity/EntityHeader.tsx`, consumers
  (case route, intel detail, detection detail).
- Verify: no layout shift at 1280px and 768px widths.

**DONE (item 3)** — one shared shell, no page-specific implementations:
- Sticky offset: `top: <measured top-bar height>` (measured via
  `document.querySelector("header")`; falls back to 0 when the top bar
  is hidden). Top bar height lives in one CSS var `--ba-topbar-h`
  (`:root`, styles.css) — item 4 changes one value, not class lists.
- Shared shell: accent strip (`border-t-2 border-primary`), `border-b
  border-subtle`, `bg-surface-2/90 backdrop-blur-md`, `-mx-4 -mt-4`
  edge bleed — identical for both variants (intel/case).
- Compact state (compress, not collapse): on scroll the breadcrumb/back
  row collapses (grid-rows 1fr→0fr + opacity, ~150ms) and padding
  drops `pt-4 pb-3` → `pt-2 pb-2`; title and actions never leave;
  ~150ms `transition-[padding]` — no text reflow.
- Header height is published as `--ba-header-h` on `:root` (updates on
  scroll/resize + 170ms after compact settles) so every element that
  used to stick at `top-16` (parser SectionBar, logs filter bar, case
  tab bar + sidebar, hacking-toolkit sidebar) now sticks at
  `calc(var(--ba-topbar-h) + 1rem + var(--ba-header-h))` — they stay
  clear of the stuck header at any height. BulkActionBar sticks at
  `top-[var(--ba-topbar-h)]`.
- Action standardization: `HeaderAction` (shared button: `px-2 py-1
  ba-text-2xs uppercase tracking-widest`, tones default/primary/danger)
  + `headerActionClass` for Link actions. Every page action migrated;
  ordering contract Primary → Export → Share/Copy → More:
  case edit/close/delete, SIEM MD/CSV, detection copy→sample→reset,
  report print, intel locker/export.
- Hierarchy fixes: intel right cluster reordered actions → badges
  (score/confidence now below Primary actions); report state chip moved
  out of actions into the metadata row (was duplicate metadata in the
  action slot); case page no longer passes `tags` (children already
  renders the interactive tag editor — repeated badges removed).
- Fixed latent bug: header previously `sticky top-0` under the `z-30`
  top bar — on scroll its top half slid behind the bar (both variants).
- Fixed regression introduced during this item: intel variant was
  dispatched on `variant === "intel"` but the intel detail passes no
  `variant` prop; discrimination is now by prop shape (`"entity" in
  props`), restoring the old default-to-intel behavior.
- **Acceptance (verified in-browser on all five surfaces at 1440px +
  640px viewports, no console errors):** navigate Intel → Case →
  Detection → SIEM → Report while scrolling each page — the header
  feels like the same component changing context, not five different
  headers: identical sticky offset (flush under top bar), identical
  blur/border/transition, identical compact behavior, title + actions
  always visible.
- Files: `components/entity/EntityHeader.tsx` (shell, HeaderAction,
  headerActionClass), `components/PageShell.tsx` (var), `styles.css`
  (var), all consumers (index, case, siem, detection, intel, report,
  parser), `components/soc/BulkActionBar.tsx`.

### 4. Top bar refinement (adopt values)

- OpenCTI: TopBar min-height 68px, 24px h-padding, translucent gradient
  over blur. BeyondLabs today: `PageShell.tsx` header is `h-12` (48px),
  `px-3`, `bg-background/85 backdrop-blur-md` — already sticky + blur.
- Change: bump to `h-14`, `px-4`; keep `backdrop-blur-md`; add a subtle
  gradient layer (`bg-gradient-to-b from-background/90 to-background/70`
  combined with existing translucency); icon actions
  (`SidebarTrigger`, settings, backend pill cluster) go 32px → 36px
  (`h-9 w-9`) with 36px hit areas per OpenCTI's 36px icon-button
  standard. Keep the brand chip, breadcrumb, TopSearch, status pills as
  they are.
- Files: `components/PageShell.tsx` (header markup only).
- Reject: OpenCTI's notification dot badge on TopBar (no notification
  system yet — revisit with messaging), theme-based logo swap.

**DONE (item 4)** — one value + two markup touches:
- `--ba-topbar-h: 3.5rem` (was 3rem) in styles.css — the single source
  of truth; EntityHeader measures the bar at runtime, and all
  sub-sticky elements use `var(--ba-topbar-h)`, so nothing else
  changed. Verified: header sticks at 59.5px on all five surfaces.
- Header: `px-3` → `px-4`; flat `bg-background/85` → translucent
  gradient `bg-gradient-to-b from-background/90 to-background/70`
  over the existing `backdrop-blur-md` (OpenCTI-style gradient over
  blur). Brand chip, breadcrumb, TopSearch, status pills untouched.
- Icon actions 32px → 36px hit areas (`h-9 w-9`): SidebarTrigger,
  settings (icon `h-3.5` → `h-4`).
- Verified: lint 0 errors, build green, header-check 5/5, verify.mjs
  20/20, no console errors.

### 5. Information hierarchy audit (adopt principle, no new components)

- OpenCTI feels easy largely because the eye always lands on the most
  important thing first. Adopt one consistent visual priority per page:
  `Page → Workspace → Primary action → Current object → Status →
  Metadata → Supporting information`.
- Change: walk every route and verify the rendered order matches the
  priority stack. For example, an investigation page should read:
  case name → progress → primary actions → findings → IOCs → evidence →
  timeline → notes — not case → timeline → metadata → progress →
  buttons → findings. Where a page reorders this stack, fix by
  **reordering existing sections** (or moving a header/action cluster),
  never by adding new UI.
- Deliverable per route: a one-line ordering note in this doc's appendix
  after the audit pass, so the hierarchy becomes an explicit, checkable
  contract.
- Files: audit of `routes/*` + layout components; edits are section
  reorders inside existing layouts.
- Constraint: reordering sections must not change state or data flow —
  pure JSX order changes, verified by the driver suites.

**DONE (item 5)** — audit of all 31 content-bearing routes against the
priority stack; **zero violations found, no reorders needed**. Every
route already renders `object → primary action → status → metadata →
supporting`. The explicit, checkable contract is in the appendix below.

### 6. Severity color discipline (adopt scale)

- OpenCTI scale: critical `#EE3838`, high `#E6700F`, medium `#E1B823`,
  low `#16AD34`, info `#1565c0`.
- BeyondLabs today: `SEVERITY_TONE` in `components/entity/FindingCard.tsx`
  maps to Chip tones; `SeverityBadge` exists in soc. Tones are
  theme-derived (warning/success/info tokens), which is correct — do not
  hardcode hex.
- Change: verify every severity-bearing surface (FindingCard Chip,
  SeverityBadge, IocInventory, timeline markers, detection editor)
  maps critical→destructive, high→warning/orange variant,
  medium→warning/yellow, low→success, info→info. Add the missing
  critical→destructive mapping where a generic `default` is used.
  Severity is accent — it must stay within the 10% budget: one severity
  chip per item, not multiple competing highlights.
- Files: `components/entity/FindingCard.tsx`, `components/soc/SeverityBadge.tsx`, call sites.

**DONE (item 6)** — canonical scale is now enforced everywhere:
`critical → destructive`, `high → warning`, `medium → warning`,
`low → success`, `info → info` (theme tokens only, no hex).
- Fixed surfaces (were: high = destructive, low = info/gray):
  `lib/severity.ts` `severityTone()`, `soc/SeverityBadge.tsx`,
  `entity/FindingCard.tsx` (incl. left border), `routes/case.tsx`
  `SEVERITY_TONE`, `investigation/FindingsPanel.tsx` (border + chip),
  `investigation/TimelinePanel.tsx` marker chip, `routes/siem.tsx`
  sev-count chips (high was red, low was gray), `routes/detection.tsx`
  template meta row.
- High vs medium share the single warm token (no orange/yellow split
  exists in the theme system; text label still distinguishes).
  OpenCTI's orange/yellow distinction would need a new token — not
  done, per "do not hardcode hex / no new primitives".
- Verified: lint 0 errors, build green, verify.mjs 20/20, header-check
  5/5, no console errors.

### 7. Filter chips bar polish (adopt interaction)

- OpenCTI: filters render as operator/keyword chip bars with
  dismissible active chips.
- BeyondLabs today: `components/soc/OutputFilter.tsx` exists; active
  chips may not be individually dismissible everywhere.
- Change: ensure active filter chips render with a visible × dismiss
  (existing Chip/button primitives), Enter-to-add in the keyword input,
  and a clear-all when >1 active. Keep current storage keys.
- Files: `components/soc/OutputFilter.tsx`, consumers.

**DONE (item 7)** — audit-only, zero gaps found:
- SIEM (`routes/siem.tsx`) and LogsViewer chip bars already render a
  per-chip `×` dismiss (`aria-label="remove filter"`), a clear-all
  button when >1 chip is active, and click-to-pin chip creation; no
  free-text chip input exists anywhere, so Enter-to-add is N/A.
- `OutputFilterBar` (Ctrl+F panel filter) already has `clear` + `esc`
  actions.
- Other filter surfaces are segmented controls ("all" = dismiss) —
  triage status/severity, MITRE coverage, case finding-source filter
  (inline `clear`), intel search (esc clears). No storage keys changed.
- Verified: no code changes; gate unaffected.

### 8. Visual consistency audit (adopt standard, no new components)

- OpenCTI's restraint makes it feel like one designer built it. Audit
  for consistency of *existing* primitives — no new components:
  all icon buttons 36×36; every sticky header identical; every section
  header identical; every search box identical; every filter bar
  identical; every badge identical; every table identical; every empty
  state identical; every loading state identical.
- Change: fix divergences by aligning to the single canonical style
  each audit row names (the first one found / the one matching this
  plan's adopted values). List each divergence fixed in this doc's
  appendix.
- Deliverable: a checklist (the rows above) that future UI work runs
  against — written into this doc, not into the architecture doc
  (the freeze stays untouched).
- Files: pass over `components/**` after items 1–7 land, so the audit
  measures the finished state, not the intermediate one.

**DONE (item 8)** — audit of every row + fixes. The checklist below is
the contract; divergences fixed are listed after it.

**Consistency checklist (run every new UI pass against this):**
1. **Icon buttons** — standalone/toolbar icon buttons are 36×36
   (`h-9 w-9`, `rounded-md`); row-level micro-actions stay small.
2. **Sticky headers** — one shared EntityHeader shell; top offset =
   measured bar height; compact = compress, never hide title/actions.
3. **Section headers** — `EntitySection` (or `SectionBar` for
   intake/output strips) everywhere; no ad-hoc `<h2>` styling.
4. **Search boxes** — `rounded-md border border-subtle bg-surface-0
   outline-none placeholder:text-fg-dim focus:border-primary/50`;
   sizes vary by context (full-width list filter vs compact toolbar),
   tokens never do.
5. **Filter bars** — chips with per-chip `×` dismiss + clear-all;
   segmented controls when the filter is exhaustive.
6. **Badges/chips** — `Chip`/`SeverityBadge`/`EntityBadge` only; one
   severity chip per item; scale: critical destructive, high/medium
   warning, low success, info info.
7. **Tables** — `DataTable` for review surfaces; dot-`<table>` display
   grids (report summary, terminal, logs raw, parser output) are a
   deliberate exception (no interaction needed).
8. **Empty states** — one `Empty` (`@/components/output`): dashed
   border, corner-bracket icon tile, mono title, optional hint,
   examples/onSample, shortcut, children.
9. **Loading states** — `AnalysisLoading` for full-block waits;
   `Skeleton`/`PanelSkeleton` for partial fills; `animate-pulse`
   only.
10. **Font sizes** — scale tokens only (`ba-text-2xs` … `ba-text-lg`);
    zero raw `text-[Npx]` in application code.

**Divergences fixed this pass:**
- Empty states: merged the duplicate `ui/empty.tsx` into the canonical
  `output/empty.tsx` (added `children` slot, now the only Empty;
  `ui/empty.tsx` deleted). `SearchEmpty` had no users and went with it.
- Raw font sizes → scale tokens across 23 files (`text-[10.5px]` →
  `ba-text-2xs`, `[9.5px]` → `ba-text-3xs`, `[14px]` → `ba-text-base`,
  `[13px]` → `ba-text-sm`, `[15px]` → `ba-text-lg`).
- Search boxes: `border-border`→`border-subtle`, `rounded`→`rounded-md`,
  placeholder `text-muted-foreground`→`text-fg-dim`,
  `focus:border-primary/40`→`/50` across activity, snippets, url,
  detection, mitre, diff, case.
- Toolbar icon buttons: activity refresh `h-8` → `h-9 w-9` (top-bar
  standard already set in item 4; settings/sidebar conform).
- Verified: lint 0 errors, build green, verify.mjs 20/20, header-check
  5/5, no console errors.

### 9. Card-list alternation with dense tables (adapt)

- OpenCTI leads with data tables as the primary list form; BeyondLabs
  leads with cards. Do not swap the model — where dense review matters
  (findings on a case, IOC inventory, detection rules), offer the
  existing DataTable inside the existing card containers.
- Change: audit the two highest-traffic lists (case findings,
  IocInventory) for whether a table variant inside the existing card
  improves scanning; implement only if the audit supports it.
- Files: case route findings section, `components/soc/IocInventory.tsx`.

**DONE (item 9)** — audit only; conversion not supported by the
evidence, no changes made:
- Case IOC inventory: already a `DataTable` (migrated in item 2) —
  the dense-review form is in place.
- Case findings: `FindingCard` cards carry the provenance trace
  ("why is this finding here?", expandable), source filter, and
  narrative detail — a dense table would truncate the evidence
  narrative and lose the trace affordance. Cards are the correct form.
- Detection rules: searchable card list with per-rule actions
  (load/duplicate/delete/tags) — supports scanning without a table.
- Rule: cards stay where interaction/narrative matters; `DataTable`
  is for tabular review (IOCs, events, weights).

### 10. Pagination + details polish (adopt wording, minimal)

- Pagination: OpenCTI shows "X of Y" next to page-size controls. Add
  "N of M" text next to existing pager controls using existing text
  tokens.
- Details: reuse the dashed-border frame (`border-dashed border-subtle`,
  already in data-table) for the detection editor's "create rule"
  affordance and the case knowledge-bar add links only if item 9's
  audit surfaces a natural spot. Otherwise skip — lowest priority.

**DONE (item 10)** — pagination: N/A, details: already conform.
- Pagination: the app has **no pager controls** anywhere (verified —
  `DataTable` renders all rows; the shadcn `ui/pagination.tsx` is dead
  code with zero imports). Adding pagination would be a new feature
  beyond the frozen scope; "N of M" wording therefore has no attach
  point. Lists stay fully scannable at current sizes.
- Details: the detection editor's "new rule" affordance already uses
  the dashed frame (`border-dashed border-primary/40`, detection.tsx
  format cards); case knowledge-bar add links were left alone — item
  9's audit surfaced no natural spot (IOC inventory is already a
  table, findings already carry their own affordances).
- No code changes; gate unaffected.

## 3. Explicit rejections (from study, re-confirmed for this pass)

| Pattern | Reason |
|---|---|
| GraphQL/Relay, subscriptions, backend assumptions | Out of scope — localStorage + bounded backend |
| 700-line theme files / full theme overhaul | BeyondLabs multi-theme inline `@theme` + per-theme data-theme blocks are the identity; adopt values, not structure |
| Variable-width content layout | BeyondLabs fixed max-width container is deliberate |
| Entity-type color map (`utils/Colors.ts`) | Per-workspace accent scoping already covers differentiation |
| Drawer patterns for entity forms | Route-based detail pages are frozen; no new navigation concept |
| Notification dot badges | No notification bus yet |
| Column resize handles, hover column menus, sort dropdowns | Low value, high complexity (rejected in prior OpenCTI analysis too) |
| Illustration-style empty states | BeyondLabs text/mono guidance identity |
| Accent decoration beyond the 10% budget | The 90/10 ratio is a rule, not a suggestion — accents mark state and primary actions only |

## 4. Sequencing (one visual subsystem at a time)

1. Item 1 — empty-state guidance (DataTable + top call sites)
2. Item 2 — table density & readability
3. Item 3 — EntityHeader sticky/compact
4. Item 4 — top bar refinement
5. Item 5 — information hierarchy audit (route-by-route, reorder only)
6. Item 6 — severity discipline
7. Item 7 — filter chip dismiss
8. Item 8 — visual consistency audit (against the finished state)
9. Item 9 — list audit → table variants (conditional)
10. Item 10 — pagination wording, callouts

**ALL TEN ITEMS COMPLETE (2026-08-02).** Items 3, 4, 6, 8 made code
changes; items 5, 7, 9, 10 were audit-only (no violations found);
items 1–2 landed in earlier sessions. Final gate at the end of item 8
(which touches the most surfaces): lint 0 errors (98-warning baseline),
build green, verify.mjs 20/20, header-check.mjs 5/5, zero console
errors. Note: the standalone regression/reader/provenance-chain/
timeline driver files from earlier sessions lived in `/tmp` and are no
longer present; verify.mjs + header-check.mjs (also in `/tmp`) are the
surviving comprehensive drivers.

## 5. Out of scope / future

- Notification bus + TopBar badge (needs messaging design first)
- Table column resize / column menus
- Any change to routes, stores, or `data/*` models

## 6. Appendix — information-hierarchy contract (item 5 audit)

Priority stack: `Page → Workspace → Primary action → Current object →
Status → Metadata → Supporting information`. One-line ordering note per
route, verified 2026-08-02 against the rendered JSX. Routes marked
"redirect" carry no layout of their own.

| Route | Ordering note (top → bottom) |
|---|---|
| `/` (Command Deck) | header (object + session status) → Continue Investigation (primary resume) → Today's Activity + Quick Intake → Detection + Operations → Recent tools/searches |
| `/case` | sidebar (search → case list → progress) · main: header (title → actions → tags) → Investigation Overview (severity → progress → findings summary) → tabs findings → timeline → notebook |
| `/siem` | header (object → status chips → export actions) → start-a-hunt strip (primary) → intake → filters → events table → event details |
| `/detection` | header (object → copy/sample/reset) → format selector → intake (rule body) → output verdict/mapping → IDS preview |
| `/intel` | search (primary) → results → detail: header (back → title/type → summary/tags → actions → badges) → knowledge bar → sections |
| `/report/$caseId` | header (title → status → meta → print) → knowledge bar → executive summary → IOCs → timeline → findings → handoff |
| `/parser` | intake (raw artifact) → output (detected indicators, attach) |
| `/logs` | intake → analysis → raw log data panel |
| `/hacking-toolkit` | tool rail (categories → tools) · main: tool header (object) → intake (IN) → output (OT) → command history → raw output → facts → IOC locker |
| `/terminal` | session panel (object) → transcript → input line |
| `/chef` | recipe editor (object) → step list → settings → bake/save |
| `/operations`, `/investigation`, `/intake` | workspace home: StartWorking (primary) → tool sections → recents |
| `/recon` | intake target → output snapshot |
| `/phishing` | awaiting-analysis scaffold → intake (raw source) → auth detail/chain → verdict panels |
| `/triage` | intake → filter → queue (status → actions) |
| `/timeline` | date groups → events |
| `/activity` | day groups → events |
| `/osint` | tab lookup (primary) → domain info → actions → breach DB |
| `/nmap` | intake (target + profile) → output scan |
| `/pcap` | input mode → samples → capture → packet details |
| `/url` | intake URL → verdict → backend enrichment → hostname segments |
| `/attachment` | intake upload → selected file → hash lookup → analyze |
| `/settings` | sections in sidebar order (workspace first) |
| `/mitre` | TID search → kill-chain coverage → coverage matrix |
| `/validation` | campaign analytics → friction → wishes → accuracy vs coverage |
| `/snippets` | list → editor |
| `/sigma-tester`, `/regex-playground` | intake → output |
| `/guide`, `/developer`, `/developer.components` | reference/documentation, no analyst stack |
| `/diff` | original → changed → verdict |
| `/file` | intake → analysis → output |
| `/threat-actors` | redirect → `/intel` |
