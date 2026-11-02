# Page Framework v1

> BeyondLabs has 32 route files but only 6 page archetypes. Every page must belong to exactly one archetype. Pages of the same archetype must share the same layout, spacing, components, and behavior — only their content differs.

---

## The Archetypes

### 1. Analyzer

Input → analyze → findings → IOCs → export. The most common pattern.

**Pages (7):** phishing, url, file, logs, pcap, parser, attachment

**Canonical template:**
```
PageShell (eyebrow, title, description, crumbs, jumps)
  AnalyzerShell (icon, title, purpose, state, intake, output, ...)
    intake:
      SectionBar "Intake"
      IntakeCard + samples
    output:
      ResultBanner (verdict + metrics)
      SectionBar "Findings"
      Analysis panels
      SectionBar "IOCs"
      IocInventory
      ExportPanel
      SendToRow
```

**Enforced by:** `AnalyzerShell` component

**Shared patterns:** keyboard shortcuts (⌘↵ run, ⌘. clear, Esc reset), auto-runs on paste, state indicator, output filter, exports (JSON + MD), investigation creation, send-to targets.

---

### 2. Investigation Case

Evidence-centric workspace for active investigations.

**Pages (3):** case, timeline, activity

**Structure:**
```
PageShell
  CaseHeader (case title, tags, state)
  TabBar (Activity | Findings | Notebook)
  Panel sections per tab
  Attach evidence panel
```

**Unique patterns:** active case bar, event timeline, findings-to-IOC linking, notebook markdown, bulk IOC actions, deep-link tabs.

---

### 3. Scan / Recon

Configuration-heavy tools with authorization gates and progress tracking.

**Pages (4):** nmap, recon, hacking-toolkit

**Structure:**
```
PageShell
  Tool configuration (IntakeCard + Settings panels)
  Authorization gate
  StatusBar (current params)
  Execute (scan button + progress)
  Raw output
  Parsed results (ports, services, IPs, changes)
  Export
  SendToRow
  OutputFilter
```

**Unique patterns:** scan progress indicator, diff tracking, abort/cancel, authorization checkbox, timing/risk profiles.

---

### 4. Intelligence Hub

Reference data browsing — search, filter, detail.

**Pages (1):** intel (unified megapage)

**Structure:**
```
PageShell
  TabBar (CVE | Threat Actors | Hash Lookup | JA3 | User Agents)
  Filter/search bar
  DataTable / Card grid
  Detail panel (on select)
  SendToRow (per item)
```

**Note:** cve.tsx, hash-lookup.tsx, ja3-lookup.tsx exist as redirect-only shells. They are deleted when they have no traffic.

---

### 5. Tool / Utility

Standalone utilities — no analysis pipeline, no investigation integration.

**Pages (8):** chef, diff, terminal, sigma-tester, regex-playground, snippets, mitre, guide

**Structure:**
```
PageShell
  ToolHeader (title, purpose)
  Custom tool UI
  optional SendToRow
```

**No enforced template.** These are intentionally different from Analyzer pages.

---

### 6. Dashboard / System

Metrics, overviews, preferences.

**Pages (4):** index, settings, triage, osint

**Structure:**
```
PageShell
  Metrics / Overview
  Quick actions
  Preference sections
```

---

## Archetype Assignment

| Route | Archetype | Status |
|-------|-----------|--------|
| phishing | Analyzer | ✅ needs AnalyzerShell |
| url | Analyzer | ✅ needs AnalyzerShell |
| file | Analyzer | ⚠️ imports ToolShell, doesn't use it |
| logs | Analyzer | ⚠️ imports ToolShell, doesn't use it |
| pcap | Analyzer | ⚠️ imports ToolShell, doesn't use it |
| parser | Analyzer | ❌ raw PageShell |
| attachment | Analyzer | ❌ raw PageShell |
| case | Investigation | — |
| timeline | Investigation | — |
| activity | Investigation | — |
| nmap | Scan | — |
| recon | Scan | — |
| hacking-toolkit | Scan | — |
| intel | Intelligence | — |
| chef | Tool | — |
| diff | Tool | — |
| terminal | Tool | — |
| sigma-tester | Tool | — |
| regex-playground | Tool | — |
| snippets | Tool | — |
| mitre | Tool | — |
| guide | Tool | — |
| index | Dashboard | — |
| settings | Dashboard | — |
| triage | Dashboard | — |
| osint | Dashboard | — |
| cve | — | ❌ redirect to /intel |
| hash-lookup | — | ❌ redirect to /intel |
| ja3-lookup | — | ❌ redirect to /intel |
| siem | — | ❌ no clear archetype |
| detection | — | ❌ no clear archetype |

---

## Migration Plan

### Round 1 (this sprint): Analyzer Pages

1. Build `AnalyzerShell` component
2. Refactor phishing → AnalyzerShell (reference impl)
3. Refactor url → AnalyzerShell
4. Refactor file, logs, pcap → AnalyzerShell
5. Refactor parser, attachment → AnalyzerShell

### Round 2: Cleanup

6. Delete redirect-only pages (cve, hash-lookup, ja3-lookup)
7. Remove dead ToolShell imports
8. Add `SendToRow` to timeline, activity, snippets

### Round 3: Intel + SIEM

9. Revisit siem and detection archetype

---

## Page Review Rule

Every new page must answer:
1. Which archetype does this belong to?
2. Does it follow the canonical template?
3. If not, why does this page justify a new layout?

A page that introduces a new layout without a valid reason is rejected.
