# Design System v1.0 — Frozen

## Primitive Inventory

| Component | Status | Used by |
|---|---|---|
| EntityHeader (variant=intel\|case) | Stable | Intel, Case, Report |
| KnowledgeBar | Stable | Intel, Report |
| ActionDock | Stable | Intel, Report |
| EntitySection | Stable | Intel, Case, Report |
| EntitySectionRow | Stable | Intel, Case, Report |
| EntityMetadata | Stable | Intel |
| ObservableList | Stable | Intel |
| RelationshipCard / RelationshipList | Stable | Intel |
| MetricGrid / MetricCard | Stable | Case, Report |
| FindingCard | Stable | Case, Report |
| EntityTypeBadge / EntityTypeIcon | Stable | Intel |
| ConfidenceBadge | Stable | Intel |
| ScoreBadge | Stable | Intel |
| PageShell | Stable | Every page |
| Empty | Stable | Every page (via `@/components/output`) |
| Loading | Available | `@/components/ui/loading.tsx` — spinner + label |
| AnalysisLoading | Stable | Intel, SIEM (via `@/components/output`) |
| ErrorState | Stable | 4 routes (intel, siem, detection, case) |
| Chip (tone=default\|primary\|warning\|destructive\|success\|info\|accent) | Stable | Every page (via `@/components/soc`) |
| SectionBar | Stable | Activity, Guide (via `@/components/soc`) |

## Import Paths

```
Entity primitives:   @/components/entity
Page shell:          @/components/PageShell
Output/state:        @/components/output
SOC/domain:          @/components/soc
UI primitives:       @/components/ui
Notifications:       @/lib/notify
Locker:              @/lib/locker
```

## Layout Rules

```
Every workspace page:

  PageShell (eyebrow, title, description, crumbs, meta?, jumps?, actions?)
    |-- EntityHeader (variant=case)
    |     |-- KnowledgeBar (optional — stats grid)
    |     |-- EntitySection(s)
    |           |-- EntitySectionRow (key-value pairs)
    |           |-- MetricGrid (metric cards)
    |           |-- FindingCard(s)
    |           |-- Any domain-specific inline content
    |           |-- ActionDock (optional — entity-level actions)
```

No custom shell/wrapper per page. No nested PageShells. PageShell is the only page container.

## Naming Rules

```
✅ EntityHeader        — domain-wide, variant picks intel vs case
❌ IntelHeader         — too narrow, creates drift when reused

✅ EntitySection       — generic section wrapper with title + border
❌ FindingsPanel       — too specific, encourages section reinvention

✅ FindingCard         — specific to domain concept
✅ MetricGrid          — generic metric layout

✅ useEntityPrimitives — hooks follow component names
```

**Rule**: Name for reuse. If it lives in `@/components/entity/`, it must work outside its origin page. If it's truly page-specific, keep it inline in the route file.

## Design Tokens

### Spacing
- Page content: `px-6 py-6` (PageShell main)
- Sections: `space-y-6` between EntitySections
- Section internals: `px-4 py-3` (EntitySection body), `px-4 py-2.5` (header)
- Primitive gaps: `gap-1.5` within rows, `gap-2` between inline elements
- Metric cards: `p-3`
- Grids: `grid-cols-2 sm:grid-cols-4` (MetricGrid), `gap-3`

### Sticky Behavior
- EntityHeader: `sticky top-0 z-20 -mx-4 -mt-4 bg-background/90 backdrop-blur-md px-4 pb-3 pt-4`
- PageShell topbar: `sticky top-0 z-30`

### Typography
- Page title (h1): `font-display gradient-text text-3xl font-bold tracking-tight text-[2.25rem]`
- Section title (h3): `font-mono text-[10px] uppercase tracking-[0.22em] text-muted-foreground`
- Body: `font-mono text-[12px] text-foreground/70`
- Small: `font-mono text-[10px]` or `text-[11px]`
- Micro: `font-mono text-[9px] uppercase tracking-widest`
- Ba utility classes used: `ba-text-sm`, `ba-text-2xs`, `ba-text-3xs`, `ba-hero-fx`, `ba-fade-in`
- Numbers: `tabular-nums` on all numeric values

### Borders & Cards
- Section: `rounded-md border border-border/50 bg-card/40`
- Cards/rows: `border border-border/60 bg-card/30 hover:bg-card/50`
- Active state: `border-primary/40 bg-primary/10`

### EntityHeader Height
- Intel variant: back button + title row + summary + tags + score/confidence + locker/export
- Case variant: back button + title + tags + actions + children
- Both: approximately 80-120px content, sticky, backdrop blur

### Color / Tone
- `destructive` — critical/high severity, blocking issues
- `warning` — medium severity, attention needed
- `info` — low severity, informational
- `success` — green, completed/confirmed
- `primary` — accent, interactive/call-to-action
- `default` — neutral
- `muted` — subdued, secondary info

## Anti-Patterns

```
❌ Raw Panel nesting — Panels are legacy. Use EntitySection.
❌ Page-specific card components — Use FindingCard, MetricCard, or inline.
❌ Duplicate metric grids — MetricGrid is the only metric layout.
❌ Custom headers — EntityHeader with variant is the only header.
❌ Custom section wrappers — Use EntitySection. Justify if you need something else.
❌ New Empty/Loading/ErrorState — Use @/components/output versions.
❌ toast() — Use notify.success/error/warning/info() from @/lib/notify.
```

If you think you need one of these, the bar is: "EntitySection/FindingCard/MetricGrid/EntityHeader cannot be adapted without breaking 2+ existing pages."

## Development Workflow

```
Adding a new primitive:
  1. Create component in @/components/entity/ (or appropriate directory)
  2. Add live example to /developer/components
  3. Update DESIGN_SYSTEM.md — inventory table + any new naming/layout rules
  4. Only then use in production routes
```

New primitives require justification. Existing primitives may evolve. No hidden components.

---

**Design System Version 1.0 — Frozen**  
All future pages must use these primitives unless compelling reason exists.  
Unfreeze only by consensus via DESIGN_SYSTEM.md amendment.
