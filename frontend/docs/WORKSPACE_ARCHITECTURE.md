# Workspace Architecture

## Current Problem

33 top-level routes. Most are islands. No natural flow between them. An analyst must know the tool name to navigate.

## Proposed: 7 Workspaces

```
Intake → Investigation → Intelligence → Detection → SIEM → Operations → Knowledge
```

Plus a hidden Developer section for product internals.

---

## Navigation Model

Three levels:

```
Workspace

↓

Object

↓

View
```

Examples:

```
Intelligence → APT29 → Relationships

Investigation → Case #42 → Findings

Detection → Sigma Rule → Coverage
```

This replaces the flat page list. Every workspace has a primary object, a primary action, and a natural exit.

---

## Object Hierarchy

The data pipeline connecting all workspaces:

```
Artifact (what the analyst brings in)
   ↓
Analysis (analyzer output)
   ↓
Observable (IP, hash, domain, URL…)
   ↓
Finding (something suspicious found)
   ↓
Evidence (context + proof)
   ↓
Investigation (case container)
   ↓
Intel Entity (enriched intelligence from observable)
   ↓
Report (final output)
```

Pages are views into this pipeline at different stages.

---

## 1. Intake Workspace

**Job:** Begin an investigation from any artifact type.

```
Analyze → Extract Findings → Create Investigation
```

**Primary object:** Artifact (email, URL, file, log, PCAP…)
**Primary action:** Analyze
**Expected output:** Findings + Observables
**Next:** Investigation (create case)

| Route | Notes |
|---|---|
| `/intake/email` | Was `/phishing` |
| `/intake/url` | Was `/url` |
| `/intake/file` | Was `/file` |
| `/intake/attachment` | Was `/attachment` |
| `/intake/logs` | Was `/logs` |
| `/intake/pcap` | Was `/pcap` |
| `/intake/recon` | Was `/recon` |
| `/intake/nmap` | Was `/nmap` |
| `/intake/osint` | Was `/osint` |
| `/intake/triage` | Was `/triage` |

**Layout:**
- Left: artifact type selector (tabs)
- Center: analyzer input + results
- Right: "Next Actions" panel (Create Investigation, Add to Locker, Open Intelligence)

**Rule:** Every analyzer result has "Create Investigation" as the primary action.

---

## 2. Investigation Workspace ⭐

**Job:** Manage a single investigation end-to-end.

**Primary object:** Case
**Primary action:** Document findings
**Expected output:** Report
**Next:** Intelligence (via IOC click), Detection (via MITRE link)

|

Route | Notes |
|---|---|
| `/investigations/{caseId}` | Was `/case` |

**No more separate routes** for timeline, activity, report. All are tabs inside a case.

### Investigation phases (tab order):

```
Overview → Evidence → Findings → Timeline → Intelligence → Notebook → Report
```

| Tab | Content | Source |
|---|---|---|
| Overview | Case header, metrics, status, tags | Case metadata |
| Evidence | Raw artifacts attached to the case | From Intake analyzers |
| Findings | Detection results, structured observations | From Intake + manual |
| Timeline | Chronological event log | System-generated + manual |
| **Intelligence** | Intel entities linked to this case's observables | Embedded Intel Hub |
| Notebook | Analyst notes, markdown | Manual |
| Report | Final export document | Auto-generated from case |

Key addition: **Intelligence tab** inside the investigation shows entities linked to the case's IOCs without leaving the case.

---

## 3. Intelligence Workspace

**Job:** Investigate observables and entities, discover relationships.

**Primary object:** Intel Entity (threat actor, vulnerability, malware, hash, TLS fingerprint)
**Primary action:** Search → Review → Relate
**Expected output:** Enriched context for an investigation
**Next:** Investigation (link entity to case), Detection (open MITRE)

**No tabs.** The workspace is a single continuous flow:

```
Search bar (auto-detect observable type)
   ↓
Results list (grouped by entity type)
   ↓
Entity detail (header, overview, relationships, MITRE, evidence, timeline)
   ↓
Actions (copy, locker, link to case, export, enrich)
```

| Route | Notes |
|---|---|
| `/intelligence/search?q=` | Unified search |
| `/intelligence/entity/{id}` | Entity detail |
| `/intelligence/mitre` | MITRE lookup (teaching mode) |

Intel entity detail also renders inline inside an Investigation tab — same component, different container.

---

## 4. Detection Workspace

**Job:** Build, test, and map detection rules. Blue-team engineering.

**Primary object:** Detection Rule (Sigma, YARA, KQL)
**Primary action:** Compose → Test → Map
**Expected output:** Working rule mapped to MITRE
**Next:** Investigation (send rule to case), SIEM (query events)

| Route | Notes |
|---|---|
| `/detection/editor` | Was `/detection + /sigma-tester` |
| `/detection/mitre` | MITRE mapping (engineering mode) |

**Not included:** SIEM. SIEM is a separate workspace (see below).

---

## 5. SIEM Workspace

**Job:** Event operations — search, filter, alert triage.

**Primary object:** Event
**Primary action:** Query → Filter → Analyze
**Expected output:** Findings + IOCs
**Next:** Investigation (create case), Intelligence (enrich IOC)

| Route | Notes |
|---|---|
| `/siem/workspace` | Was `/siem` |

SIEM and Detection serve different jobs:
- SIEM: "What happened?" (operational)
- Detection: "How do we catch it next time?" (engineering)

---

## 6. Operations Workspace

**Job:** Stateless utilities used while investigating.

```
Input → Process → Output → Done
```

**Primary object:** Tool output
**Primary action:** Transform
**Expected output:** Processed data (copy, send, export)
**Next:** Investigation (send result to case), Locker

| Route | Notes |
|---|---|
| `/operations/parser` | IOC extraction |
| `/operations/chef` | CyberChef — encoding, decoding, hashing |

**Merged into CyberChef:** Diff, Regex playground, Snippets, Terminal. These are CyberChef tabs, not separate routes. `/hacking-toolkit` splits into individual tools within Chef.

**Layout:** Minimal chrome — single column tool interface.

---

## 7. Knowledge Workspace

**Job:** Learn and reference.

**Primary object:** Document
**Primary action:** Browse → Read
**Expected output:** Applied knowledge

| Route | Notes |
|---|---|
| `/knowledge/guide` | SOC Guide |

**Not included:** Validation. That belongs to the Developer section.

---

## What stays independent

| Route | Reason |
|---|---|
| `/` | Landing / dashboard — aggregates across workspaces |
| `/settings` | System-wide configuration |

---

## Developer Section (hidden)

**Audience:** Product team (not analysts).

| Route | Notes |
|---|---|
| `/developer/validation` | Was `/validation` |
| `/developer/status` | Benchmarks, feature flags, experimental |

Hidden from main navigation. Accessed via `/developer` or a settings link.

---

## Navigation

```
Home
├── Intake         (email, url, file, logs, pcap, recon…)
├── Investigations  (case list + case detail)
├── Intelligence    (search, entities, mitre)
├── Detection       (rules, mitre)
├── SIEM            (events, alerts)
├── Operations      (parser, chef)
└── Knowledge       (guide)

Settings
```

7 top-level items. Everything else is a sub-tab or sub-route.

---

## Next Action System

| From | Action | To |
|---|---|---|
| Intake (any analyzer) | "Create Investigation" | Investigation |
| Intake (any result) | "Open Intelligence" | Intelligence |
| Investigation (IOC click) | Auto-search in Intelligence | Intelligence (inline tab or workspace) |
| Investigation (MITRE link) | "Open MITRE" | Detection |
| Intelligence (entity) | "Link to Investigation" | Investigation |
| Intelligence (MITRE) | "View in Detection" | Detection |
| Operations (any tool) | "Copy to Evidence" | Investigation |
| Detection (rule) | "Send to Investigation" | Investigation |
| SIEM (event) | "Create Case" | Investigation |

---

## Migration Path

### Phase 1 — Navigation only (no route changes)
- Update sidebar/nav to the 7-item structure
- Add workspace labels as section headers
- Existing pages work exactly as before

### Phase 2 — Intake unification
- Create `/intake` route as a shell with artifact type selector
- Move email/url/file/logs/pcap into sub-routes
- Add "Create Investigation" as primary exit

### Phase 3 — Investigation tab consolidation
- Merge Timeline, Activity, Report into case as tabs
- Add Intelligence tab to case
- Remove `/timeline`, `/activity`, `/report/$caseId` routes

### Phase 4 — Intelligence launch
- Replace `/intel` with new search → entity → detail layout
- Wire IOC clicks across app to Intelligence
- Mount IntelEntityDetail component inside case Intelligence tab

### Phase 5 — Operations simplification
- Create `/operations` shell
- Merge diff, regex, snippets, terminal into CyberChef tabs
- Parser stays separate (it's a different kind of tool)

### Phase 6 — Detection + SIEM separation
- Move `/sigma-tester` into detection editor
- SIEM stays at `/siem` (no change)
- Move `/mitre` to dual-route: `/detection/mitre` and `/intelligence/mitre`

### Phase 7 — Knowledge + Developer
- Move guide to `/knowledge/guide`
- Move validation to `/developer/validation`
- Hide developer section from nav

---

## Anti-patterns

1. **Tool island** — a page with no next action exit. Fix: every page has a visible "what's next."
2. **Split identity** — MITRE is in both Intelligence and Detection. That's fine as dual-route, but `/mitre` must not be the only route.
3. **Deep nesting** — max 2 levels of sub-route.
4. **Dashboard scope creep** — `/` is a landing page, not a workspace.
5. **Workspace overload** — if a workspace has more than 10 sub-routes, it needs splitting. Currently capped at 10.
