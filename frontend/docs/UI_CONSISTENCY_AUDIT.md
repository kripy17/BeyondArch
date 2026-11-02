# UI Consistency Audit

Reference: `case.tsx` — canonical investigation workspace.
Goal: every workspace page scores the same rubric.

---

## Rubric

| # | Item | weight |
|---|------|--------|
| 1 | **PageShell wrapper** | must |
| 2 | **Sticky tab bar** (sub-navigation stays visible) | high |
| 3 | **SectionBar** used for intake/output dividers | medium |
| 4 | **Panel priority levels** correct (primary/secondary/raw) | medium |
| 5 | **Empty states** on all panels that can be empty | high |
| 6 | **Loading states** for async operations | high |
| 7 | **Sticky SendToRow** at viewport bottom | medium |
| 8 | **Keyboard shortcuts** documented in UI | high |
| 9 | **Button hierarchy** (primary/destructive/neutral visually distinct) | medium |
| 10 | **Color semantics** consistent (destructive=red, warning=amber, info=blue) | medium |
| 11 | **Table styling** consistent (header, hover, zebra) | low |
| 12 | **Export placement** consistent (bottom or panel actions) | low |

---

## Scores

| Page | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | Score |
|------|---|---|---|---|---|---|---|---|---|---|---|---|-------|
| **case** (ref) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🔶 | ✅ | ✅ | ✅ | ✅ | **11.5/12** |
| intel | ✅ | ❌ | ❌ | 🔶 | ✅ | ❌ | ❌ | ❌ | 🔶 | ✅ | ✅ | 🔶 | **5.5/12** |
| siem | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | 🔶 | ✅ | ✅ | 🔶 | **7.5/12** |
| parser | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ | **9/12** |
| logs | ✅ | ❌ | ❌ | 🔶 | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | **5.5/12** |
| triage | ✅ | ❌ | ✅ | 🔶 | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ❌ | 🔶 | **6.5/12** |
| detection | ✅ | ❌ | ✅ | ✅ | ✅ | 🔶 | ❌ | 🔶 | 🔶 | ✅ | ❌ | ✅ | **7/12** |
| activity | ✅ | ❌ | 🔶 | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | 🔶 | ❌ | ❌ | **3/12** |

✅ = full match · 🔶 = partial · ❌ = missing

---

## Findings by page

### case.tsx (11.5/12) — Reference

Missing: keyboard shortcuts not explicitly documented in the UI (Escape to dismiss handoff is the only wired one). Button hierarchy is correct with three tiers. All panels have priority levels. Sticky tab bar and sticky SendToRow both implemented.

### intel.tsx (5.5/12)

| Issue | Impact | Fix |
|-------|--------|-----|
| No SectionBar dividers | Page flows without visual zones | Add SectionBar between search and results |
| Tab bar not sticky | Tabs scroll away on long result lists | Add `sticky top-16 z-10 bg-background/95` to tab bar |
| No loading states | Sync data now, will break when real API hits | Add skeleton containers per tab |
| No documented keyboard shortcuts | Escape resets search but user can't know | Add hint text or kbd badges |
| SendToRow inline per tab | Inconsistent with case page | Single sticky SendToRow at bottom |
| Some panels at default priority that could be secondary | Visual noise | Downgrade utility panels |

### siem.tsx (7.5/12)

| Issue | Impact | Fix |
|-------|--------|-----|
| No sticky sub-navigation | Filter strip scrolls away | Make filter panel header sticky (already has sticky table header ✅) |
| No keyboard shortcut documentation | Escape collapses rows but hidden | Add shortcut hint |
| SendToRow not sticky | Bottom of long page | Wrap in sticky container |
| Some panels default priority that could be secondary | Visual weight competition | Audit panel priorities |

### parser.tsx (9/12) — Second-best

| Issue | Impact | Fix |
|-------|--------|-----|
| No sticky regions (tabs, export) | Tab bar and export panel scroll away | Sticky IOC kind tabs + bottom actions |
| Table uses div grid instead of table pattern | Misses table header/hover/zebra patterns | Already consistent within page — low priority |
| SendToRow in 2-col grid instead of sticky bottom | Inconsistent placement | Move to sticky bottom bar |

### logs.tsx (5.5/12)

| Issue | Impact | Fix |
|-------|--------|-----|
| Hand-rolled tab bar not sticky | Tabs scroll away | Make sticky |
| No SectionBar dividers | No intake/output visual zones | Add SectionBar |
| No keyboard shortcuts documented | Missing opportunity | Add hints |
| Button hierarchy subtle | Danger actions only show on hover | Explicit destructive button style |
| AnalyzerShell adds abstraction layer | Layout inconsistent with case page | Either adopt AnalyzerShell everywhere or drop it |

### triage.tsx (6.5/12)

| Issue | Impact | Fix |
|-------|--------|-----|
| No sticky header or SendToRow | List scrolls but controls scroll away | Sticky filter bar + bottom SendToRow |
| No loading states | Sync data currently, will need loading when async | Add skeleton list |
| Tab bar absent (uses filter chips) | Different navigation model from case page | Acceptable — triage is fundamentally a queue, not a workspace |

### detection.tsx (7/12)

| Issue | Impact | Fix |
|-------|--------|-----|
| No sticky sections | Long form scrolls without pinned reference | Sticky format selector or generator panel |
| No loading state for translation | Async call has no spinner | Add loading indicator on rule translate |
| Button hierarchy subtle in places | Some actions blend together | Audit danger vs neutral styling |

### activity.tsx (3/12)

| Issue | Impact | Fix |
|-------|--------|-----|
| No Panel components | Page uses SectionBar directly without Panel wrapping | Wrap grouped content in Panel (secondary/raw) |
| No SendToRow | Activity page is a read-only log | Add navigation to Case/Intel |
| No keyboard shortcuts | Navigation-only page | j/k navigation + Enter to open case |
| No sticky headers | Date groups scroll away | Make active SectionBar sticky as user scrolls |
| No button hierarchy | Only SectionBar actions exist | Add primary action (jump to case) |
| Color semantics minimal | Only category dots | Add severity/importance color to events |

---

## Priority recommendations

### Sprint 1 (high impact, low effort)

1. **Make tab bars sticky on all tabbed pages** (intel, parser, logs) — copy the `sticky top-16 z-10 bg-background/95 backdrop-blur` pattern from case.tsx
2. **Add SectionBar to intel.tsx** — intake/output dividers
3. **Add keyboard shortcut hints** to siem, intel, detection (they already wire Escape handlers but don't document them)
4. **Downgrade panel priorities on intel** — utility panels should be `priority="secondary"`

### Sprint 2 (medium impact, medium effort)

5. **Sticky SendToRow on siem, parser, intel** — wrap in same pattern as case.tsx
6. **Add loading states to intel** — skeleton containers per tab
7. **Activity page Panel wrapping** — wrap event groups in secondary panels
8. **Detection loading state** — spinner on rule translate

### Sprint 3 (lower impact, higher effort)

9. **Align table patterns** — create shared `DataTable` component or document the pattern
10. **AnalyzerShell inconsistency** — either standardize all analyzer routes or remove AnalyzerShell
11. **Full activity page rebuild** — adopt case page patterns (Panel, SectionBar, SendToRow)

---

## Design language rules (extracted from case.tsx)

```
Page wrapper:          PageShell
Section dividers:      SectionBar with id="IN"/"OT"
Content containers:    Panel (priority=primary/secondary/raw)
Empty state:           Empty component with icon + title + hint
Loading state:         Skeleton or AnalysisLoading
Sub-navigation:        Sticky tab bar with uppercase labels + count badges
Page-bottom bar:       Sticky SendToRow with border-top, backdrop-blur
Button tiers:          primary (border-primary/40 bg-primary/10 text-primary)
                       neutral (border-border text-muted-foreground hover:text-foreground)
                       destructive (border-destructive/50 bg-destructive/10 text-destructive)
Export placement:      Panel actions area or SendToRow area
Color mapping:         destructive → critical/high
                       warning → medium
                       info → low/info
                       success → clean/resolved
Tables:                w-full text-left + sticky header + uppercase header labels
                       + divide-y + hover:bg-card/30
```

---

## Next

After scoring all pages, the next step is to freeze the Case page as the reference and bring each page up to parity in priority order.
