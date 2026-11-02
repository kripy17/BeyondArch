# InvestigationShell Contract

## Scope

A behavioral shell for workspace-style investigation pages.

**Covers:** `case.tsx`, `activity.tsx`, future hunt/incident/evidence-review pages.
**Does not cover:** `report.$caseId.tsx` — that is a print-optimized document with its own layout.

---

## Regions

```
┌──────────────────────────────────────────────┐
│  TopBar (from PageShell)                      │
├──────────┬───────────────────────────────────┤
│          │  PageHeader                        │
│          │  ├─ title (editable or static)     │
│          │  ├─ status chip                    │
│          │  ├─ severity badge                 │
│          │  ├─ tags                           │
│          │  └─ actions (primary/secondary)    │
│ Sidebar  ├───────────────────────────────────┤
│ (list/   │  TabBar (optional)                 │
│  nav)    │  ├─ tabs defined by page           │
│          │  └─ deep-link sync                 │
│          ├───────────────────────────────────┤
│          │  MainContent                       │
│          │  ├─ renders active tab             │
│          │  └─ scrollable                     │
│          ├───────────────────────────────────┤
│          │  RightPanel (optional)             │
│          │  ├─ metadata                       │
│          │  ├─ export actions                 │
│          │  └─ send-to                       │
└──────────┴───────────────────────────────────┘
```

---

## Props

```typescript
type TabDef = {
  id: string;
  label: string;
  count?: number;
  icon?: LucideIcon;
  content: ReactNode;
};

type InvestigationShellProps = {
  // ── Identity ──
  title: string;
  onTitleChange?: (title: string) => void;
  status?: { label: string; tone?: ChipTone };
  severity?: string;
  tags?: { label: string; onRemove?: (tag: string) => void }[];
  onAddTag?: (tag: string) => void;

  // ── Navigation ──
  sidebar?: ReactNode;         // case list / nav tree
  actions?: ReactNode;         // primary action buttons

  // ── Content ──
  tabs?: TabDef[];             // if undefined, no tab bar — single content
  activeTab?: string;
  onTabChange?: (tab: string) => void;
  children?: ReactNode;        // rendered when no tabs

  // ── Right panel ──
  rightPanel?: ReactNode;      // metadata / export / send-to

  // ── States ──
  loading?: boolean;
  empty?: boolean;
  emptyTitle?: string;
  emptyHint?: string;
  error?: string | null;
};
```

---

## Shell Responsibilities

### Layout
- Two-column grid: sidebar (18rem) + main (1fr)
- Optional right panel as a third column or below content
- Sticky sidebar that scrolls independently
- Consistent spacing between regions

### Tab behavior
- Tab bar with active state, counts, optional icons
- Button-style tabs (not nav links)
- Tab state managed by the shell OR controlled externally
- Deep-link sync via URL search params (tab ID)

### States
- Loading: skeleton placeholder matching layout
- Empty: centered Empty component with title + hint
- Error: error banner above content
- Tab-specific empty states delegated to page

### Keyboard shortcuts
- `⌘K` — command palette (delegated to PageShell)
- `⌘N` — new (page-defined action)
- Escape — close panels, clear filters

### Deep linking
- Read `?tab=` from URL on mount
- Push `?tab=` on tab change (without full navigation)

---

## Page Responsibilities

- Provide all data, actions, and renderers
- Handle tag add/remove
- Handle title editing
- Handle tab content rendering
- Define tab structure (order, icons, counts)
- Supply sidebar content (case list, filters)
- Supply right panel content (metadata, export buttons)

---

## Extension Points

| Situation | Mechanism |
|-----------|-----------|
| Page needs custom layout per tab | Render inside tab content |
| Page needs extra header actions | Pass via `actions` slot |
| Page needs no sidebar | Omit `sidebar` prop (layout switches to single column) |
| Page needs no tabs | Omit `tabs` — use `children` instead |
| Page needs right panel | Pass via `rightPanel` |
| Page needs different empty state | Omit shell empty — use tab empty states |

---

## Migration Plan

### Phase 1: Build shell (no visual changes)
- Create `InvestigationShell` with all regions
- No consumers yet

### Phase 2: Migrate `case.tsx`
- Extract sidebar → `sidebar` prop
- Extract tab content → `tabs` prop
- Extract metadata/export → `rightPanel` prop
- Keep all behavior identical

### Phase 3: Migrate `activity.tsx`
- Wrap in InvestigationShell without sidebar
- Single content via `children`
- Uses PageHeader + empty state

### Phase 4: Validate
- Remove duplicate layout CSS
- Verify keyboard shortcuts work on both pages
- Check responsive behavior
