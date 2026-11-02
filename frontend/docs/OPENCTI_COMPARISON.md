# BeyondLabs vs OpenCTI — Comparison

---

## Intake Workspace

| Aspect | BeyondLabs | OpenCTI Approach | Gap | Recommendation | Priority | Effort |
|--------|------------|------------------|-----|---------------|----------|--------|
| Artifact types | 10 analyzers (email, URL, file, logs, PCAP, recon, nmap, OSINT, triage, attachment) | Reports & grouping containers as intake sources | No "intake shell" — each analyzer is a separate route | Create `/intake` shell with artifact type selector tabs (similar to OpenCTI's analysis categories) | P2 | Medium |
| Analyzer → Case flow | "Create Case" button on some analyzers, handoff via localStorage | Reports create cases via "add to container" | Inconsistent next-action placement | Standardize "Create Investigation" as the primary action on every analyzer result | P1 | Small |
| Result persistence | Per-analyzer, no unified Intake record | Containers store all analysis output | No shared intake history | Low priority — not blocking workflow | P3 | Large |

---

## Investigation Workspace

| Aspect | BeyondLabs | OpenCTI Approach | Gap | Recommendation | Priority | Effort |
|--------|------------|------------------|-----|---------------|----------|--------|
| Case header | Editable title, status chip, tags, primary actions | Entity header with title (inline edit), aliases, sharing, export, playbook actions | Actions are inconsistently placed (some in Panel, some in header) | Adopt OpenCTI's entity header pattern: identity on left, actions on right, tags below | P1 | Small |
| Case layout | Sidebar (case list) + content panel | Tab-driven with configurable widget grid | No sidebar case list in OpenCTI (they use entity list pages + breadcrumbs) | Keep the sidebar case list — this is better for multi-case workflow | — | — |
| Evidence → Finding → IOC linking | Parallel arrays, no cross-references | STIX relationships connect all entities | No provenance chain — "where did this finding come from?" is unanswerable | Post-freeze: migrate to linked model with formal relationship records | P2 | Large |
| Checklist | InvestigationProgress component with derivation | No equivalent (OpenCTI doesn't do investigation checklists) | — | Keep and improve. This is a BeyondLabs differentiator. | — | — |
| Notebook | Markdown entry + templates | Notes widget on overview | Notebook is a tab, not an overlay | Keep as tab — better for analysis focus | — | — |
| Timeline | InvestigationActivityFeed with category filters | History tab with audit log | BeyondLabs has better timeline UX | Keep. OpenCTI's history tab is inferior. | — | — |

---

## Intelligence Workspace

| Aspect | BeyondLabs | OpenCTI Approach | Gap | Recommendation | Priority | Effort |
|--------|------------|------------------|-----|---------------|----------|--------|
| Entity detail | Continuous scroll: overview, observables, relationships, actions | Tabbed: overview, knowledge, analyses, sightings, files, history | No tab system on entity detail | Tabbed entity detail would improve navigation for complex entities. Single entity type at a time. | P1 | Medium |
| Relationship navigation | Flat list in relationships panel | Knowledge bar: categorized right-side drawer with counts per type | Relationships are readable but not navigable | Adopt the knowledge bar pattern: right-side drawer with category counts, clicking shows filtered list | P1 | Medium |
| Entity header | Panel with title + summary | StixDomainObjectHeader with inline edit, sharing, export, enrichment | Minimal header, no inline actions | Add entity header with: CVE ID display, confidence, score, tags, and action buttons | P2 | Small |
| Search | Unified search with auto-detect observable type | Global search with keyword/bulk/AI modes, results page | Search input could be more polished (debounce, keyboard navigation) | Add search keyboard shortcuts, result count in search bar | P2 | Small |
| Overview | Panel with entity-specific fields | Configurable widget grid (details, info, relationships, references, notes, history) | Overview is a list of fields, not a composed layout | Compose entity overview from reusable sub-panels (BasicInformation, Details, Relationships, ExternalReferences, Notes) | P2 | Small |
| Intel → Case link | Structured finding creation + IOC attachment | Direct linking via STIX relationship "related-to" | BeyondLabs has stronger Intel → Case flow | Keep. This is better than OpenCTI for investigation workflow. | — | — |

---

## Detection Workspace

| Aspect | BeyondLabs | OpenCTI Approach | Gap | Recommendation | Priority | Effort |
|--------|------------|------------------|-----|---------------|----------|--------|
| Sigma editor | Editor + tester | No Sigma editor (rules are indicators) | Not directly comparable | Keep as-is. Different scope entirely. | — | — |
| MITRE mapping | Manual technique links | Attack patterns as entity type with kill chain | No structured technique picker | Add technique autocomplete on finding creation | P3 | Small |

---

## SIEM Workspace

| Aspect | BeyondLabs | OpenCTI Approach | Gap | Recommendation | Priority | Effort |
|--------|------------|------------------|-----|---------------|----------|--------|
| Event table | Flat table with filters | No SIEM (different product) | Not directly comparable | Keep as-is. | — | — |

---

## Operations Workspace

| Aspect | BeyondLabs | OpenCTI Approach | Gap | Recommendation | Priority | Effort |
|--------|------------|------------------|-----|---------------|----------|--------|
| CyberChef merge | Diff/regex/snippets/terminal → Chef tabs | No equivalent | Partially implemented | Complete Chef tab integration | P3 | Small |

---

## Cross-Cutting Patterns

| Aspect | BeyondLabs | OpenCTI Approach | Gap | Recommendation | Priority | Effort |
|--------|------------|------------------|-----|---------------|----------|--------|
| Layout | Top bar + sidebar + content | Fixed sidebar + fixed top bar + scroll content | BeyondLabs sidebar is a case list, not navigation | Keep BeyondLabs sidebar for case list — navigation is in the top bar | — | — |
| Drawers | Not used | Right-side drawers for creation/editing | Full-page editor patterns increase context switching | Add right-side drawer for Intel entity linking and case actions | P2 | Medium |
| Empty states | Empty component, inconsistent on some pages | Loader + ErrorNotFound + contextual empty | Some pages lack loading states | Audit loading states across all pages | P1 | Small |
| Data tables | Custom tables per page | DataTable with column system, sorting, filtering, selection | No shared table component | Extract DataTable component for IOC lists, entity lists | P3 | Medium |
| Keyboard shortcuts | Some Escape handlers documented | Not a strong pattern in OpenCTI | Inconsistent shortcut coverage | Add J/K navigation in lists, Ctrl+Enter submission, consistent Escape | P2 | Small |

---

## Summary

**BeyondLabs strengths (keep, don't change):**
- Investigation checklist and progress tracking
- Intel → Case structured round-trip
- Timeline with category filters
- Notebook with auto-populated templates
- 7-workspace navigation model
- Monospace UI identity

**OpenCTI patterns to adopt:**
1. Knowledge bar — categorized relationship sidebar with counts
2. Entity header — identity left, actions right, tags below
3. Tabbed entity detail — overview, relationships, analyses, history
4. Right-side drawers — for entity linking and creation
5. Composed overview — reusable sub-panels per entity type
6. Consistent loading/empty states
7. **MESSAGING$ notification bus** — RxJS Subject → Snackbar consumer (A.1)
8. **usePaginationLocalStorage** — dual localStorage + URL persistence (A.2)
9. **Error boundary with error-code routing** — category-based error display (A.3)
10. **Investigation undo stack via sessionStorage** — operation history (N.9)
11. **ItemStatus pipeline visualization** — arrow-separated workflow states (N.10)
12. **PDF export via pdfmake** — browser-based report generation (N.11)

**OpenCTI patterns to reject:**
- STIX model overhead
- Collaborative editing
- Multi-tenancy
- Connector framework
- Feed ingestion
- AI/NLQ search
- MUI component library
- GraphQL + Relay
- Configurable overview layout per entity type
- Full graph visualization (deferred to v1.x)
- Workflow state machine (binary + checklist is sufficient for now)
