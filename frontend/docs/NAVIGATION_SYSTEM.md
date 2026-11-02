# Navigation System

Navigation architecture for BeyondLabs. Canonical spec for sidebar, breadcrumbs, keyboard nav, and workspace identity. V4.2 (Command Palette) and V4.3 (Workspace Identity) build on this.

---

## 1. Workspace Hierarchy

### Groups (top-level sections)

```
Dashboard
──────────
Intake
Investigation
Intelligence
Detection
SIEM
Operations
Knowledge
Developer
```

### Items per group

```
Dashboard
  Command Deck

Intake
  Triage
  Phishing
  URL Analysis
  File Analysis
  Attachment
  Logs
  PCAP Analysis
  Recon
  Nmap
  OSINT

Investigation
  Cases
  Activity
  Timeline

Intelligence
  Intel Hub

Detection
  Workspace
  MITRE ATT&CK
  Sigma Tester

SIEM
  Workspace

Operations
  Parser
  CyberChef
  Hacking Toolkit
  Diff
  Regex
  Snippets
  Terminal

Knowledge
  Guide

Developer
  Validation
  Settings (footer only)
```

### Rules

- System group (Settings) lives in the footer, not the content area.
- Order is user-reorderable via `prefs.sidebar.order`.
- Hidden groups are suppressed entirely (no empty section shown).
- Pinned items float above all groups in their own section.

---

## 2. Sidebar

### 2.1 States

| State | Width | Behavior |
|-------|-------|----------|
| Expanded | `16rem` | Full labels, pin buttons, group labels visible |
| Collapsed | `3rem` | Icons only, tooltips, no text |
| Mobile | Full-screen overlay | Slide-in sheet, backdrop |

Toggle via `Cmd+B` or the `SidebarTrigger` hamburger button.

### 2.2 Header

Brand mark + name in a fixed header strip. Non-scrolling. Shows active case chip below when one is loaded.

### 2.3 Group Block (collapsible)

- Click group header to toggle open/closed.
- State persisted in `localStorage` by group label.
- Chevron rotates: `▼` expanded → `›` collapsed.
- Count badge: `rounded-sm border border-sidebar-border/60 bg-sidebar-accent/40 px-1 ba-text-3xs tracking-widest text-sidebar-foreground/55`.
- In collapsed mode: groups render as a flat list of icons with no header row.

### 2.4 Row (nav item)

- Height: `h-8`.
- Left accent bar: `2px` wide, `rounded-r`. Active = `bg-primary shadow-[0_0_8px_var(--primary)]`. Inactive = `bg-transparent`, shows `bg-sidebar-border` on hover.
- Icon: `h-4 w-4`, primary color when active, scales to `110%` on hover.
- Label: truncates, `ba-text-base tracking-tight`.
- Pin button: visible on hover (inactive) or always (pinned). `h-5 w-5`.
- In collapsed mode: no label, no pin button, tooltip on hover.

### 2.5 Active Detection

Current logic (correct enough):
```
isActive = (url) => pathname === url || pathname.startsWith(url + "/")
```
Exception: root `/` matches only exact.

When a route is active:
- The item gets `bg-sidebar-accent text-sidebar-accent-foreground`.
- The workspace group is visually indicated (parent group's items include the active item).

### 2.6 Footer

- ThemeSwitcher (collapsed mode: icon only).
- Settings link with `⌘,` shortcut hint.
- Workspace count: `"{N} workspaces"` in `ba-text-3xs uppercase tracking-[0.22em] text-sidebar-foreground/35`.

---

## 3. Breadcrumbs

### 3.1 Pattern

Breadcrumbs should express **workflow**, not filesystem paths.

```
Workspace / Page / Sub-page
```

Examples:
```
Intake / URL Analysis

Investigation / Case / Intel Enrichment

Operations / Parser
```

### 3.2 Rules

- Breadcrumbs are **page-defined** (each route passes `crumbs` to `PageShell`).
- Convention: first crumb = workspace label, second crumb = page title, third = sub-context when needed.
- Maximum depth: 3 crumbs. 4+ is a signal the navigation hierarchy is too deep.
- Long labels truncate with `min-w-0 truncate`.
- Non-last crumbs are links (`href`). Last crumb is a `<span>` with `aria-current="page"`.
- Last crumb gets `rounded bg-primary/10 font-semibold text-primary`.
- Separator: `ChevronRight` icon at `h-3 w-3`.
- Container: `rounded-md border border-divider-strong bg-surface-1 px-1.5 py-1`.
- Hover effect on links: underline animation via `scale-x-0 → scale-x-100`.

### 3.3 Workspace-breadcrumb mapping

| Group | Breadcrumb label |
|-------|------------------|
| Dashboard | `Deck` |
| Intake | `Intake` |
| Investigation | `Investigation` |
| Intelligence | `Intelligence` |
| Detection | `Detection` |
| SIEM | `SIEM` |
| Operations | `Ops` |
| Knowledge | `Knowledge` |
| Developer | `Dev` |

---

## 4. Keyboard Navigation

### 4.1 Sidebar

| Key | Action |
|-----|--------|
| `Cmd+B` | Toggle sidebar collapse |
| `↑` / `↓` | Navigate between visible sidebar items |
| `Enter` | Activate focused item |
| `Escape` | Close sidebar (mobile overlay) |

### 4.2 Focus Rings

- All interactive nav elements must have visible focus rings.
- `focus-visible:ring-2 focus-visible:ring-sidebar-ring focus-visible:ring-offset-2 focus-visible:ring-offset-sidebar`.
- Tab order: sidebar header → pinned items → group items in display order → footer items.

### 4.3 Tab Order (page level)

1. Sidebar toggle (`SidebarTrigger`)
2. Breadcrumb links
3. TopSearch
4. Page header actions
5. Main content (in DOM order)
6. Footer

### 4.4 Global

| Key | Action |
|-----|--------|
| `Cmd+K` | Command palette (V4.2) |
| `Cmd+Shift+F` | Global search (already exists) |
| `Cmd+,` | Settings |

---

## 5. Collapse Behavior

### 5.1 Sidebar Collapse

- Toggle via `Cmd+B` or hamburger.
- State persisted in cookie (`sidebar_state`).
- Expanded → Collapsed: labels fade, pin buttons disappear, group headers disappear, tooltips appear.
- On collapse, the currently active group stays visually traceable via its active item's icon.

### 5.2 Group Collapse

- Per-group open/closed state persisted in `localStorage`.
- Key: `ba.sidebar.group.{label}`.
- Default open: Dashboard and SIEM (low item count).
- Default closed: Intake and Operations (high item count).
- When all groups in a section are closed: the section head is still visible.

---

## 6. Icon Rules

### 6.1 Workspace Icons

Each workspace item uses a single Lucide icon. These are consistent across sidebar, breadcrumbs (future), and command palette (future).

| Item | Icon |
|------|------|
| Command Deck | `LayoutDashboard` |
| Triage | `ListChecks` |
| Phishing | `MailWarning` |
| URL Analysis | `Link2` |
| File Analysis | `File` |
| Attachment | `Paperclip` |
| Logs | `ScrollText` |
| PCAP Analysis | `Globe` |
| Recon | `Radar` |
| Nmap | `Network` |
| OSINT | `User` |
| Cases | `FileText` |
| Activity | `Clock` |
| Timeline | `Clock` |
| Intel Hub | `Bug` |
| Detection Workspace | `ShieldCheck` |
| MITRE ATT&CK | `Target` |
| Sigma Tester | `FlaskConical` |
| SIEM Workspace | `Activity` |
| Parser | `Wand2` |
| CyberChef | `Wrench` |
| Hacking Toolkit | `Swords` |
| Diff | `Code2` |
| Regex | `Search` |
| Snippets | `Bookmark` |
| Terminal | `Terminal` |
| Guide | `BookOpen` |
| Validation | `FlaskConical` |

### 6.2 Icon Treatment

- Sidebar: `h-4 w-4`, primary color when active.
- Active icon: `text-primary`, subtle glow via `drop-shadow`.
- Inactive hover: `group-hover/row:scale-110` for tactile feel.

---

## 7. Active State Rules

### 7.1 Visual Indicators

| Element | Active | Inactive |
|---------|--------|----------|
| Row background | `bg-sidebar-accent text-sidebar-accent-foreground` | `text-sidebar-foreground/75 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground` |
| Left accent bar | `bg-primary shadow-[0_0_8px_var(--primary)]` | `bg-transparent hover:bg-sidebar-border` |
| Icon color | `text-primary` | Sidebar foreground (75% opacity) |
| Icon scale | 1.0 | 1.0, hover → `110%` |

### 7.2 Active Parent Group

When a child route is active, the parent group is not explicitly highlighted — the active item within it serves as the indicator. If we later add sub-routes, the group header should get a subtle active state (`font-semibold text-sidebar-foreground`).

---

## 8. Deep-Link Conventions

- All routes are single-level (e.g., `/siem`, `/case`, `/intel`). Except `/developer/components` and `/report/$caseId`.
- Sub-routes use a slash suffix: `/developer/components`.
- Parametrized routes use `$param`: `/report/$caseId`.
- There are no nested workspace layouts. All pages are direct children of root.
- Future workspace sub-pages should follow: `/{workspace}/{subpage}` or `/{workspace}/{entity}/{action}`.

---

## 9. Command Palette Integration (V4.2)

The command palette will mirror this navigation structure:

```
Go to {Item Title}
```

| Source | Items |
|--------|-------|
| All workspace items | 29 items |
| Recent pages | Last 10 visited routes |
| Active case | Quick-link to current case |
| Actions | Settings, Toggle Sidebar, Open Search |

The palette groups should mirror sidebar groups for visual consistency.

---

## 10. Implementation Boundaries

### Current (V4.1)

- [x] Sidebar hierarchy with collapsible groups
- [x] Pin/unpin items
- [x] Hide/show groups
- [x] Reorder groups
- [x] Expand/collapse sidebar
- [x] Breadcrumbs in PageShell
- [x] Active route detection
- [x] Keyboard shortcut: `Cmd+B`
- [ ] **Stronger workspace visual distinction** (section dividers, group header polish)
- [ ] **Consistent workspace breadcrumb labels** (map groups → crumb labels)
- [ ] **Sidebar keyboard nav** (arrow up/down, Enter)
- [ ] **Focus rings** on all nav elements
- [ ] **Collapse animation smoothness** (transition widths, not instant snap)

### Future (V4.2)

- [ ] Command palette matches navigation structure
- [ ] Recent pages tracking exposed in palette
- [ ] Fuzzy search over all items

### Future (V4.3)

- [ ] Workspace accents propagated to sidebar (active indicator, group header icons)
- [ ] Landing pages per workspace with identity
- [ ] Consistent "Where am I?" pattern per workspace

---

## 11. Component Architecture

```
<SidebarProvider>                    — context: open/closed, mobile
  <AppSidebar>                       — main sidebar
    <SidebarHeader>
      Brand link
      ActiveCase chip
    <SidebarContent>
      <GroupBlock label="Pinned">    — collapsible, localStorage-persisted
        <Row />                      — nav item with active state, pin button
      <GroupBlock label="Intake">
        <Row />
        <Row />
    <SidebarFooter>
      ThemeSwitcher
      Settings link
      Workspace count
  <SidebarInset>
    <PageShell>
      <header>                       — top bar
        SidebarTrigger
        Brand chip (sidebar collapsed)
        Breadcrumbs
        TopSearch
        Status cluster
        Settings link
      <hero>                         — title, description, jumps, meta
      <main>                         — route content
      <footer>
```
