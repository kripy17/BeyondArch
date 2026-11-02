# Design System — Frontend Conventions

Status: LIVING · How the BeyondLabs frontend composes UI. Frontend
code must follow these tokens, components, and motion/a11y rules.

## 1. Theming

- Themes: `dark` (default), `light`, `dark-hc` — `lib/theme.tsx` `THEMES`.
- Mode: `auto | light | dark`; applied to `<html>` as `data-theme`,
  `data-mode`, and the `dark` class (`applyThemeAndMode`).
- Legacy pre-redesign theme ids migrate via `LEGACY_THEME_MAP` (never
  re-introduce "terminal-noir"-style themes).
- Preferences live in `lib/prefs.tsx` and reflect onto `<html>` data
  attributes: `data-density`, zebra stripes toggle, topbar toggle, motion
  level, focus boost, contrast. Settings UI is `/settings` (per-workspace
  panels).

## 2. Tokens & utilities

- Semantic tokens render through `styles.css` (`--color-primary`,
  `--color-destructive`, `--color-warning`, `--color-success`, `--color-info`,
  `--color-accent`, `--color-chart-1..3`, `--color-border`,
  `--color-muted-foreground`, surface tokens `surface-0/1`, `fg-dim`);
  components use Tailwind classes that reference these tokens —
  `bg-primary/10`, `text-warning`, `border-divider-soft`, etc.
- App-specific utilities: `ba-text-2xs / ba-text-3xs` (mono scale),
  `text-mono`, `bg-surface-0/1`, `border-subtle`, `text-fg-dim`,
  `font-mono` conventions. Tooltips, focus ring and reduced-motion
  handling live in `styles.css`.
- Icons: `lucide-react`, single set; semantic icons chosen per data kind
  (Siren = IOC, Crosshair = finding, Box = artifact, Radar = MITRE,
  ShieldCheck = detection).

## 3. Component inventory

UI primitives (`components/ui/` — shadcn-style, Radix-based where
interactive):

- dialog, alert-dialog, command (cmdk), dropdown-menu, popover,
  hover-card, tooltip, sheet, tabs, accordion, select, switch, slider,
  input, input-otp, button, badge, skeleton, table, scroll-area.

SOC surface components (`components/soc/`):

- `Chip` — status/severity pill (tone prop).
- `DataTable` — typed column table.
- `MetricGrid` / `MetricTile` — dimension cards.
- `Panel` / `SectionBar` / `Field` — workspace layout.
- `IocInventory`, `AnalysisLoading`, `TerminalOutput`, `SendToRow`,
  `WorkflowActions`, `BulkActionBar`, `IntakeCard`.

Investigation components (`components/investigation/`):

- `InvestigationAssistant`, `InvestigationRecommendations`,
  `InvestigationQuality`, `InvestigationActivityFeed`, `InvestigationGraph`
  (see `GRAPH_MODEL.md`), legacy adapter (`getUnifiedFindings/IOCs`).

Support components: `Skeleton` (loading), `ErrorBoundary`, `CopyButton`,
`ActiveCaseBar`, `GlobalSearch` (Ctrl+Shift+F), `CommandPalette` (Ctrl+K).

## 4. Composition rules

- New UI must reuse the inventory; do not re-style primitives per page.
- Sentence-case typography (sweep enforced); titles lowercase except
  proper nouns.
- Empty states explain what to do next (example text included); never a
  bare "No data".
- Honest degradation: capabilities not yet implemented state so
  explicitly ("ingestion is a future capability") rather than faking
  results.

## 5. Motion policy

From ROADMAP §Motion — only purposeful animation:

- panel expansion / collapse (slide-up),
- hover feedback (150ms color/border transitions),
- status pulse (glow-pulse on live badges),
- loading skeletons (shimmer),
- graph transitions (ReactFlow pan/zoom).

No decorative motion. `components/magic/` (Marquee, AnimatedGrid,
NumberTicker) was removed for violating this. `html[data-motion]` allows
reducing motion; `prefers-reduced-motion` disables it (see `styles.css`).

## 6. Accessibility conventions

- Keyboard-first: every page reachable by keyboard; case tabs support
  ArrowLeft/ArrowRight and digits 1-9; Ctrl+Shift+F search, Ctrl+K
  palette, `g`-prefix navigation.
- All dialogs carry an accessible name (`label` prop on `CommandDialog`
  forwards to `aria-label` on Radix content).
- Table headers use `scope="col"`; `<thead>` on every data table.
- Icon-only buttons must carry `aria-label`.
- Focus-visible ring enforced globally; `data-focus-boost` preference
  strengthens it.
- Screen reader + keyboard verification happens in browser (Playwright),
  not unit tests.

## 7. Related documents

- `ROADMAP.md` §Phase 4 (motion / accessibility / performance).
- `PAGE_SPECIFICATIONS.md` — per-page layout intent.
- `INVESTIGATION_UX_AUDIT.md` — investigation UX findings.