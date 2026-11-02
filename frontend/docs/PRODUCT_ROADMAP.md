# BeyondLabs Product Roadmap

> A local-first Security Operations Platform enabling analysts to investigate artifacts, correlate evidence, produce detections, and generate investigation reports from a unified workspace.

---

## What BeyondLabs IS

- A local-first investigation platform
- An analyst workspace
- An evidence correlation system
- A case management platform
- A reporting tool
- A detection opportunity generator

## What BeyondLabs is NOT

- A SIEM
- An EDR
- A SOAR platform
- A vulnerability scanner
- A penetration testing framework
- A malware sandbox
- A network monitor
- A Sigma IDE
- A collaborative multi-user platform

---

## Design Principles

1. **Case-first** — All operational work revolves around an Investigation.
2. **Structured over parsed** — Never serialize important information into strings.
3. **Local-first** — Offline by default; optional integrations later.
4. **Analyst-centric** — Optimize for investigation speed and clarity.
5. **Composable** — New analyzers plug into the existing `AnalysisResult` pipeline.
6. **Event-driven** — Every meaningful investigation action emits a `CaseEvent`.
7. **Progressive enhancement** — Start with static analysis; add optional enrichment.
8. **Architecture stability** — Core domain models evolve only when a concrete product requirement demands it.

---

## v0.8 — Platform Foundation ✅

**Goal:** Finish the architecture. **Complete.**

- Unified navigation
- `AnalysisResult` contract
- Shared analyzers
- `CaseFactory` / structured `Case` model
- `CaseEvent` system + typed event kinds
- Investigation Activity Feed
- Structured findings, IOCs, evidence
- Case persistence
- Legacy parser removal
- Architecture freeze

### Success criteria

- Every analyzer produces the same contract.
- Every investigation is represented by one `Case`.
- Every meaningful action emits a `CaseEvent`.
- No UI depends on parsing strings.

---

## v0.9 — Search & Workflow

**Goal:** Make analysts faster without redesigning the UI.

### Features

- **Global investigation search** — search across findings, IOCs, events, notes, artifacts in one query
- **IOC search/filtering** — filter by type, severity, source, date
- **Better Command Palette** — ⌘K-style quick actions (open case, search IOCs, run analyzer, generate report)
- **Bulk IOC actions** — select multiple IOCs → enrich / export / delete / add to locker
- **Investigation templates v2** — parametrized templates (fill in blanks, not raw text)
- **Report polish** — styling improvements, collapsible sections, print layout fixes

### Out of scope

- Multi-user collaboration
- Cloud sync or authentication
- Live SIEM ingestion
- EDR or SOAR features
- AI agents or automation
- Threat feeds or enrichment pipelines
- New architectural abstractions

### Success criteria

- Search any IOC in <1 second on a local machine
- Complete a phishing triage without switching pages
- Reach any investigation within 3 clicks
- Create a report in under 30 seconds

---

## v0.10 — Investigation Workspace

**Goal:** Redesign the primary analyst experience (UI/UX release, not architectural).

### Features

- **Investigation Dashboard** — overview, recent activity, evidence, findings, IOC inventory, MITRE coverage, detection opportunities, notes, report status
- **Evidence relationships** — visual artifact→evidence→finding→IOC flow
- **Rich Activity Feed** — better cards with context, filtering, search
- **Rich Finding cards** — severity badges, technique mapping, linked IOCs, source attribution
- **Case navigation improvements** — tabs, back/forward, recently viewed

### Out of scope

- Multi-user
- Real-time collaboration
- Cloud sync
- Automation/playbooks
- Threat intelligence feeds

### Success criteria

- View all evidence related to any IOC in one place
- Navigate between artifacts, findings, and events without manual searching
- Understand the flow of an investigation at a glance

---

## v1.0 — Investigation Platform

**Goal:** BeyondLabs feels like a commercial SOC investigation platform.

### Features

- **Detection Opportunities** — map findings to MITRE techniques, suggest Sigma rules (not a full Sigma IDE)
- **Threat Intelligence** — IOC enrichment, threat actor/malware family mapping, CVE correlation, JA3 context, cross-investigation links
- **Investigation Graph** — visualize artifact→finding→IOC→threat actor→campaign→detection
- **Cross-case correlation** — "Has this IOC appeared before?", "Which investigations share infrastructure?"
- **Professional Reports** — executive summary, technical report, IOC appendix, MITRE summary, investigation timeline
- **Timeline Replay** — reconstruct an investigation chronologically

### Out of scope

- Real-time SIEM ingestion
- EDR sensor management
- SOAR playbook engine
- Multi-user/collaborative features
- Cloud-hosted version

### Success criteria

- Complete a phishing investigation in under 2 minutes
- Produce a professional report from one investigation in under 30 seconds
- View all evidence related to any IOC across all cases in one place
- Navigate between artifacts, findings, and events without manual searching

---

## v1.1 — Platform Enhancements

**Goal:** Improve quality of life and close remaining technical debt.

### Features

- **Automation** — investigation playbooks, automatic enrichment, IOC pipelines, report generation
- **Integrations** — optional external enrichment APIs, MISP/ThreatFox export, STIX/TAXII
- **Performance audit** — optimize localStorage usage, lazy-load investigations, paginate large case lists
- **Persistence improvements** — abstract storage layer behind an interface (localStorage today, IndexedDB or SQLite tomorrow)
- **Accessibility audit** — keyboard navigation, screen reader support, contrast compliance

### Platform maintenance (ongoing through all versions)

- Remove `useActiveCase` parallel hook
- Consolidate `lib/case.ts` `useActiveCase` implementation into the main case model
- Storage abstraction (replace direct `localStorage` calls)
- Accessibility improvements
- Performance optimization

---

---

## Benchmark Progression

BeyondLabs validates its platform through three benchmark stages. Each release runs against the current stage; stage transitions happen when all samples are recorded and metrics are stable.

### Stage 1 — Synthetic Suite (current)

**Label:** `Synthetic v1.0`

Handcrafted samples with known ground truth. Tests that the platform works — architecture, workflow, UX, pipeline integrity — not analyzer quality.

- 40 samples: 10 Phishing, 10 URL, 10 Log, 5 PCAP, 5 File
- Mix of malicious (28), benign (10), suspicious (2)
- Edge cases: quishing, thread hijacking, SIEM false positive, parked domains, LOLBins, VBA obfuscation

### Stage 2 — Real-World Suite

Curated real-world samples from public datasets. Tests analyzer quality — false positives, false negatives, detection quality, coverage.

Planned sources: public phishing datasets, malware traffic PCAPs, Windows Event Log samples, MITRE ATT&CK evaluation data, community threat reports.

### Stage 3 — Mixed Regression Suite

Runs both suites before every release. Prevents regressions as the product matures.

```
Benchmark/
  Synthetic v1.0/
  Real-World v1.0/
```

Every release must show no regression in synthetic accuracy while real-world metrics are tracked as directional indicators.

---

## Release Governance

Every release must satisfy three gates before shipping. Gates are evaluated against the current benchmark suite using the previous release as a baseline.

### Functional Gate

- Build passes (`vite build`)
- Typecheck passes (`tsc --noEmit`)
- Benchmark suite completes (all samples in queue have a recorded result)
- No critical bugs

### Analytical Gate

- Verdict accuracy does not regress
- Findings coverage does not regress (where measurable)
- IOC coverage does not regress
- MITRE coverage does not regress (where measurable)
- Average trust score stays the same or improves

### UX Gate

- Average investigation time stays the same or decreases
- Searches per investigation do not increase unexpectedly
- Context switches do not increase
- High-frequency friction points from the previous release are addressed
- No new recurring workflow blockers appear

### Directional KPIs

| KPI | Rule |
|-----|------|
| Verdict accuracy | Never regress |
| IOC coverage | Improve where possible |
| Findings coverage | Improve where possible |
| Trust | ≥ Previous release |
| Investigation time | ≤ Previous release |
| Searches / investigation | ≤ Previous release |
| Context switches | ≤ Previous release |
| Critical bugs | 0 |

---

## Checkpoint: Post-v0.9

After v0.9 ships, measure real usage before committing to v0.10:

- Is global search used daily?
- Are templates reducing investigation time?
- Are reports being generated?

If analysts aren't engaging with these features, investigate why before building the next major release. Features that don't get used are worse than features not yet built — they're maintenance debt.

---

## Future (no timeline)

Ideas that are explicitly deferred until the project moves beyond local-first or demonstrates clear demand:

- Collaborative investigations (comments, assignments, approvals)
- Team timelines and workspaces
- Multi-user server mode
- Role-based access control
- Audit logging for compliance
