# OpenCTI Frontend Analysis

## Layout System

### Structure

OpenCTI uses a fixed left sidebar + fixed top bar + scrollable content area pattern:

```
┌─────────────────────────────────────────────────┐
│ SystemBanners (fixed, z-index: 2000)            │
├─────────────────────────────────────────────────┤
│ TopBanners (fixed, z-index: 1202)               │
├──────────┬──────────────────────────────────────┤
│          │ TopBar (fixed, z-index: drawer-1)    │
│ LeftBar  │  Search, AI, upload, notifications   │
│ (180px)  ├──────────────────────────────────────┤
│          │ Main Content (scrollable, px: 3)     │
│ MenuList │  Breadcrumbs                         │
│  Home    │  ---------------------------------   │
│  Cases   │  Entity Header                       │
│  Threats │  ---------------------------------   │
│  Arsenal │  Tab Bar                             │
│  ...     │  ---------------------------------   │
│          │  Overview Widget Grid                 │
│ Settings │   (details, relationships, notes)    │
│          │                                      │
│          │                                      │
└──────────┴──────────────────────────────────────┘
```

### Spacing & Typography

- **Horizontal padding:** Main content uses `px: 3` (24px via MUI spacing)
- **Vertical rhythm:** Content uses `gap: theme.spacing(3)` between sections
- **Fonts:** "Geologica" for headings (lowercase), "IBM Plex Sans" for body
- **Labels:** Uppercase, small (10-12px), with tracking for metadata fields
- **Card backgrounds:** Slightly differentiated (`background.secondary`), not pure white
- **Page min width:** 1400px — OpenCTI does not prioritize responsive/mobile

### Component System

**Page-level:**
- `PageContainer` — flex column container, optional right menu (200px padding)
- `Breadcrumbs` — horizontal separator layout with current-page bold styling
- `StixDomainObjectHeader` — entity title, inline edit, actions row, sharing, export

**Tabs:**
- `StixDomainObjectTabsBox` — sticky tab bar, route-driven, hides when single page
- Route-driven: each tab is a `<Route>` nested inside the entity detail

**Cards/Widgets:**
- `Card` — MUI Card wrapper, `fullHeight` by default, configurable padding
- Widgets render inside `<Grid item>` — overview page is a fluid grid

**Data Display:**
- `DataTable` — column-based table with sorting, filtering, selection, pagination
- `ListLines` — legacy list with virtualized scrolling
- `ItemIcon` — entity-type icon resolver (150+ types)
- `ItemEntityType` — type chip with color + icon

**Overlays:**
- `Drawer` — right-side drawer for creation/editing
- Standard sizes: 420px, 640px, 960px, 90vw
- Fab button triggers drawer open

## Interaction Patterns

### Search
- Global search in TopBar: keyword, bulk, or AI/NLQ modes
- Search results page with Knowledge/Files tabs
- Inline search on list pages via `SearchInput` variant

### Filtering
- `Filters` component: autocomplete + chip display + boolean logic
- Filters persisted to localStorage per page
- Filter state serialized to URL for sharing

### Selection
- Single click, shift-click range, select-all checkbox
- Bulk action toolbar replaces header when items selected

### Navigation
- Breadcrumbs track hierarchy
- Entity ID in URL for deep linking
- Tab state driven by URL sub-route
- Knowledge bar is a permanent right-side drawer on `/knowledge/*` routes

## Visual Design Attributes

### Color System
- 12 color families mapped to entity categories (analysis=green, cases=purple, threats=red, observations=orange)
- Severity: critical=red, high=orange, medium=yellow, low=blue, info=grey
- Marking definitions use specific chip colors
- Backgrounds use layered transparency for visual depth

### Information Density
- Lower than BeyondLabs — MUI components add whitespace
- Cards are preferred over flat lists
- Grids with 2-3 columns on overview pages
- More scroll, less cramming

### Empty/Loading States
- `Loader` — centered spinner during Suspense
- `ErrorNotFound` — "not found" card for missing data
- Empty lists show contextual empty state messages
- Loading skeletons in some DataTable variants

## Key Differences from BeyondLabs

| Aspect | OpenCTI | BeyondLabs |
|--------|---------|------------|
| Component library | MUI v6 | Custom Tailwind |
| Layout | Fixed sidebar + top bar + scroll content | PageShell + sticky tabs |
| Typography | Geologica + IBM Plex | Monospace (JetBrains Mono) |
| Information density | Medium — cards, whitespace | High — compact panels |
| Entity pages | Tabbed with widget grid | Continuous scroll with panels |
| Drawers | Right-side for edit/create | Not used |
| Loading states | Suspense + Loader everywhere | Inconsistent |
| Notifications | MESSAGING$ RxJS Subject → Snackbar | Ad-hoc toast calls |
| Error boundary | Error.jsx with error-code routing | None (per-component try/catch) |
| State persistence | usePaginationLocalStorage (localStorage + URL + BroadcastChannel) | Ad-hoc |
| Form creation | Formik + Yup + useApiMutation + shared field components | Simple dialogs |
| Export | pdfmake (PDF), react-csv (CSV), html2canvas (image) | Markdown only |
| Keyboard shortcuts | None found | Opportunity for BeyondLabs |
| Drag-and-drop | @hello-pangea/dnd for reorderable lists | Not used |
| Responsive | Desktop-only (1400px min) | Desktop-only |
