# BeyondLabs Roadmap — Analyst Workbench (v3)

> **Superseded for forward work by `ROADMAP-v4.md` (2026-08-22).** v3 remains
> the canonical reference for frozen phases 1–4, the constitution, and the
> retained-items appendix below. New work is tracked in v4 tracks V4.1–V4.5.

> Source: product direction conversations (v1, v2, v3). **v3 is the canonical
> goal set.** It supersedes the earlier phase structures; any v1/v2 points not
> already folded in are preserved in the "Retained items" appendix at the end
> so nothing is lost. Treat this file as the reference for all future work.

## North star

One connected platform: every major object — artifacts, evidence, findings,
IOCs, entities, MITRE techniques, detections, simulations, deployments,
alerts, reports, and analyst decisions — exists within a single connected
knowledge graph. Each workspace offers a different perspective on the same
underlying data rather than maintaining isolated representations.

Constitution (frozen): `ROADMAP.md` + `PROVENANCE_MODEL.md` +
`DETECTION_LIFECYCLE.md` + `ANALYSIS_ENGINE.md` + `INVESTIGATION_OBJECTS.md`.
The platform is now a layered engine: Extraction → Analysis Engine →
Investigation Objects → Correlation → Knowledge Graph. Analyzers are
producers; workspaces are consumers; pages compute nothing (Analysis First,
Presentation Second).

The Knowledge Graph is the platform backbone:

```
Artifact
    │
Evidence
    │
Finding
    │
IOC
    │
Intel Entity
    │
MITRE
    │
Detection
    │
Simulation
    │
Deployment
    │
Alert
    │
Case
    │
Report
```

Every workspace becomes a **projection of this graph**, not an independent
representation.

Trajectory:
- **Today:** a polished collection of cybersecurity tools connected by investigations.
- **Next:** an integrated analyst workbench where every tool participates in a single investigation workflow.
- **Eventually:** a SOC investigation platform where provenance, relationships, detections, alerts, reports, and analyst decisions all become views of one knowledge graph.

No foundational redesign. Preserve the frozen architecture.

## Capability-driven phases

Each phase builds a capability, not a feature list — every task is evaluated
against the capability it serves:

```
Phase 1 → Investigation Platform
Phase 2 → Detection Platform
Phase 3 → Analyst Intelligence
Phase 4 → Product Maturity
```

## Release milestones

A checkpoint between major phases — not necessarily public releases, but
clear gates to freeze, dogfood, fix defects, and update documentation before
carrying unfinished work into the next phase:

```
Phase 1
    ↓
v1.0 Investigation Edition

Phase 2
    ↓
v1.5 Detection Edition

Phase 3
    ↓
v2.0 Analyst Edition

Phase 4
    ↓
v2.5 Platform Edition
```

> **v2.0 Analyst Edition gate: PASSED (2026-08-12).** Phase 3 froze with a full
> dogfood pass: a browser smoke run over demo data exercising case close-out,
> recommendation rules, detection coverage, report types, version saves, and
> NL search. One real defect found and fixed (GlobalSearch ignored the
> detected intent's scope term). Docs are current.
>
> **v2.5 Platform Edition gate: PASSED (2026-08-13).** Phase 4 closed with the
> screen-reader/contrast audit (see below) and a final browser smoke-test
> pass over all 31 routes: every route renders 200 with a single `h1`, zero
> unnamed icon-only buttons, skip-to-main is the first focusable element, and
> closed drawers never steal focus or appear in tab order (`inert`). Real
> defects found and fixed during the pass: light-theme `--warning` contrast
> (2.9:1 → 5.33:1), focus stolen by an always-mounted hidden scratchpad
> `autoFocus`, duplicate `h1`s on tool pages, and every remaining
> placeholder-only input/label-less control across all routes now has an
> accessible name (`aria-label`, `label[for]`, or wrapper label — verified
> zero unlabeled visible inputs on all 31 routes).

## The one principle

> Every new feature should either **deepen an existing workflow** or
> **connect two existing workflows**.

- URL → Intel ✔
- Intel → Case ✔
- Case → Detection ✔
- Detection → Alert ✔
- Alert → Investigation ✔

These improve platform cohesion. By contrast: a brand-new standalone analyzer
with no integration ✖, an isolated dashboard ✖, a separate mini-workflow ✖ —
those increase surface area without strengthening the platform.

---

# Phase 1 — Investigation Workspace 2.0 + Recovery (Highest Priority)

**Goal:** make Investigation the primary workspace where analysts spend most
of their time — the orchestration layer of the platform, not a page that
displays results.

## 1. Investigation becomes the command center

Everything flows through it; every stage is accessible directly from the
investigation:

```
Artifact → Analysis → Findings → IOC → Intel → MITRE → Detection → Report
```

## 2. Investigation tabs

Replace long scrolling pages with focused workspaces. Suggested tabs:

```
Overview | Evidence | Findings | Observables | Knowledge Graph | Timeline | Notes | Reports | Detection | Activity
```

No redesign needed — continue using existing primitives:

```
EntityHeader | EntitySection | MetricGrid | DataTable | FindingCard
```

The improvement is organization.

## 3. Investigation progress engine

Replace `38%` with meaningful, actionable progress. Each unfinished item links
directly to the required action:

```
Investigation Progress

✓ Evidence collected
✓ Findings reviewed
✓ IOC enrichment complete
✓ Timeline reviewed
○ Detection authored
○ Report generated
○ Investigation closed
```

The progress engine becomes actionable rather than informational.

## 4. Analyst notebook

Expand free-form notes into structured investigation reasoning. Each
hypothesis includes:

```
Hypothesis
Supporting Evidence
Contradicting Evidence
Confidence
Decision
Next Step
Status
```

Every decision remains attached to the case timeline.

## 5. Investigation recommendations (Analyst assistance)

No autonomous AI — only recommendations. Recommendations always explain *why*
they appear:

```
No IOC enrichment found.
Suggested action: → Open Intel Hub
```

```
Technique has no mapped detection.
Suggested action: → Create Sigma Rule
```

```
Artifact not attributed.
Suggested action: → Review evidence
```

**Status: DONE.** `InvestigationRecommendations` widget in
`frontend/src/components/investigation/InvestigationRecommendations.tsx`,
rendered in the `/case` sidebar below the progress engine. Derives up to 4
recommendations from unified findings/IOCs/artifacts: no-findings →
parser intake, unmapped-technique → /detection, no-enrichment → /intel,
unattributed-evidences → findings tab. Each row shows *why* it appears and an
`open →` deep link. Per-case dismiss persistence via localStorage
(`ba.case.recs.dismissed`).

## 6. Investigation quality engine

"Linting" an investigation. Checks include:

```
Missing evidence | Missing provenance | Missing MITRE mapping
Duplicate IOCs | Duplicate findings | No report | Missing notebook
Low confidence | No timeline | Unresolved decisions
```

Each issue links directly to its fix.

**Implemented: DONE.** `InvestigationQuality` widget in
`frontend/src/components/investigation/InvestigationQuality.tsx`, rendered in
the `/case` sidebar below progress. `checkCaseQuality(case, nav)` returns
`{ issues, score }` (100 − penalties per open check) and scores against:
missing/unattributed evidence, no analysis, unreviewed findings, un-enriched
IOCs, missing MITRE mapping, duplicate IOCs (by value), duplicate findings
(by title), no notebook notes, no report generated, no timeline events,
unresolved decisions with no follow-up action, low-confidence (unknown
severity) findings. Every issue row deep-links to its fix (tab or route);
score chip is color-coded (<60 destructive, <85 warning, else success).

## 7. Investigation Knowledge Graph

Already completed: provenance, MITRE, React Flow, search, filters, details.

Next additions:

### Graph modes

Same graph, different projections:

```
Relationship | Timeline | Detection | Infrastructure | Campaign
```

### Expand levels

```
1 hop | 2 hops | 3 hops
```

### Advanced filters

```
node type | edge type | confidence | source | workspace | date
```

### Search

Jump directly to:

```
IOC | Finding | Entity | Technique | Rule | Alert
```

### Explainability

Every node answers:

```
Why does this exist?
Where did it originate?
What evidence supports it?
What created it?
Where is it used?
```

**Implemented additions (this pass):**

- **Graph modes** — `Relationship | Timeline | Detection | Infrastructure | Campaign`
  chips above the graph. Each mode projects the same provenance store onto a
  different layer order + relation set: timeline sorts nodes chronologically
  within their layer (earliest incident edge `ts`), detection keeps the
  detection chain (`mapped-to/drives/validates/deploys/fires`), infrastructure
  isolates entities/observables, campaign keeps techniques/TTPs. Switching
  mode resets node positions and re-fits.
- **Expand levels** — `1 hop | 2 hops | 3 hops` buttons. Enabled once a node is
  focused (selected or hovered); prunes the visible graph to nodes within N
  undirected edges of the focus, keeping only edges between kept nodes. Click
  the active level again to clear.
- **Advanced filters (source, confidence):** `source:` select (distinct
  `edge.source` values) and `confidence ≥` thresholds intersect into the graph;
  extend the existing node-type / edge-type toggle chips. Reset clears all.
- **Explainability panel** — the node detail card now answers the five
  questions directly, derived from `explainNode` provenance walks:
  *why does this exist?* (origin artifact), *what created it?* (edge sources),
  *what evidence supports it?* (supports/validates edge count),
  *where is it used?* (downstream labels).
- Helpers exported from `InvestigationGraph.tsx`: `expandHops`, `nodeTime`,
  `modeRankOf`, and the `GRAPH_MODES` table (unit-testable, no UI deps).

---

# Recovery Items (finish before freezing Phase 1)

Complete remaining technical debt before moving into lifecycle work.

## File persistence

Results currently disappear after refresh. Implement lightweight recovery —
no permanent database required:

```
recent analyses
current artifact
last active analyzer
```

## Shared WorkflowActions primitive

Several pages implement action bars independently. Create one shared primitive
and use it everywhere:

```
Pivot to Intel | Create Investigation | Export | Copy | Share | Detection | Report
```

## Improve existing analyzers (depth before breadth)

### URL Analyzer — frozen (Recovery item 3)

```
redirect chain | canonical URL | WHOIS | certificate | ASN
related domains | extracted observables | related entities | passive DNS placeholder
```

Payload-depth signals landed 2026-08-14 (§4a deep list): named downloads
(path segment or `filename/file/download/dl` query argument), script download
cradles (bitsadmin/certutil/mshta/rundll32/regsvr32/wscript/cscript/
invoke-expression/iex/`-enc` markers → critical, T1059.001), and obfuscated
client-side script markers (`eval(`/`atob(`/`unescape(`/fromCharCode/
document.write/wshshell → medium, T1059.007). All pure token checks in
`data/url.ts` (`downloadFileName`, `urlPayloadMarkers`), surfaced as
findings + pathSignals + evidence via `composeSignals`.

### File Analyzer — frozen (Recovery item 4)

```
entropy | strings | imports | exports | PE metadata | archive inspection
Office metadata | YARA preview | hash relationships
```

### Phishing Analyzer — frozen (Recovery item 5)

Separate sections:

```
headers | authentication | URLs | attachments | language
brand impersonation | MITRE | indicators | recommendations
```

Language: script detection (latin/cyrillic/arabic/cjk…) with samples.
Brand impersonation: sender-domain vs official domain match, typosquatting
via edit distance, unrelated-domain claims. Recommendations: de-duplicated,
severity-ordered analyst actions.

### Parser — frozen

Support more evidence formats:

```
EVTX | Zeek | Suricata | Syslog | Apache | Nginx | CSV | JSON
```

Format-specific family detection, input-type chips, and signal generators
(Zeek conn-state anomalies, Nginx path probing / error codes, CSV row parsing)
added for Zeek conn.log, Nginx access log, and CSV IOC sheets; EVTX (Sysmon
XML), Suricata EVE JSON, Syslog/Unix (sshd), Apache combined, and free-form
JSON already covered.

PCAP adapter landed 2026-08-14 (ANALYSIS_ENGINE §4b acceptance: EVTX/PCAP/CSV
reach one `Observation` vocabulary): `PCAP_ADAPTER` in
`src/lib/extraction/adapters.ts` detects tcpdump (`HH:MM:SS.mmm IP a.b.c.d.port
> w.x.y.z.port`) and tshark (`# 1.234567 a.b.c.d → w.x.y.z PROTO …`) text and
extracts canonical IPs (port suffix stripped), DNS query names (tcpdump
`A?/AAAA?` and tshark `DNS Standard query …`), TLS SNI (`SNI=…`), and HTTP
paths into the shared Observation set, deduplicated with generic scanning.
Tests extend the acceptance suite to five formats with identical-value id
stability already asserted across EVTX/CSV.

Signal generators landed 2026-08-15: `ZEEK_ADAPTER` now records the measured
`conn_state` of each connection as a `zeek-conn-state` fact (state, src, dst,
uid in meta); `NGINX_ADAPTER` (new) parses combined log lines into
`http-request` facts (method, path, status, client). Verdicts stay in the
engine: `src/lib/analysis/zeek-rules.ts` maps anomalous states (REJ, S0,
RSTOS0, RSTRH, OTH, SH, …) to severity + MITRE (T1046), `web-rules.ts` maps
error-code bands (5xx/404/403/401) and probe paths (.env, .git, wp-admin,
phpMyAdmin, traversal, web shells, …) to findings; weighting floors and
reasoning rules consume the same tables. Extraction remains fact-only.

---

# Phase 2 — Detection Engineering Lifecycle

Follows the design document already written (DETECTION_LIFECYCLE.md).

## Detection state machine

```
Draft → Validated → Simulated → Approved → Deployed → Triggered → Retired
```

Detection becomes a managed object.

Implemented (2026-08-07): `SavedRule` carries lifecycle state (`draft → validated →
approved → deployed → retired`) via `transitionRule`/`canTransition` in
`data/detection.ts`, with the §4 forbidden-transition table enforced (draft→deployed,
draft→retired, validated→deployed, deployed→validated, approved→retired all rejected).
The editor shows a Lifecycle panel: current-state chip, transition actions (validate /
approve / deploy / retire / rollback / revise / reactivate), and an immutable deployment
history list. Every transition writes a `detection` timeline event.

## Detection provenance

Implement writers for (readers already support this; only writers remain):

```
Finding → Technique → Detection → Simulation → Deployment → Alert → Case
```

`mapped-to` (Finding → Technique) writer + legacy backfill landed with Phase 1 item 7's
provenance work (`backfillMitreEdges`, stamped `source: "backfill"`). `validates`
(Detection → Simulation) and `deploys` (Simulation → Deployment, plus `source: "rollback"`
stamped deployment nodes) landed 2026-08-07 with the lifecycle editor. Deterministic node
ids `det-*`/`sim-*`/`dep-*`/`al-*` via `lifecycleNodeId` in `lib/provenance.ts`;
`EVENT_NODE_KINDS` extends to detection/simulation/deployment/alert so the timeline
projection renders lifecycle chains. `drives` (Technique → Detection) landed with the
"create rule from finding / technique / IOC" surface (`ruleFromSignal` in
`data/detection.ts`, `Create rule · from finding` panel in the editor, stamping
`source: "detection-editor"`). `fires` writer landed 2026-08-12:
`recordAlert`/`alertNodeId` in `data/detection.ts` (deterministic
`al-<fnv1a(deploymentId|eventDigest)>`, idempotent via addEdge). The alert
*ingestion surface* landed 2026-08-14 with the Alert → Investigation → Graph
milestone: `lib/alerts/parse.ts` + `lib/alerts/ingest.ts` consume four formats
(BeyondLabs canonical `beyondlabs.alert.v1`, Sigma-style detection output,
Suricata EVE alert, Sysmon-derived XML), run the alert's observations through
the Analysis Engine + correlation, open a case, and write durable provenance
edges (`fires` when the alert resolves to a deployed rule — identity unifies
on the deployment-keyed `al-*` node — plus `creates` Alert → Case,
`produced`/`supports` Alert → Evidence → Finding, `extracts` Finding → IOC,
`mapped-to` Finding → Technique, and `enriched-by` IOC → Entity correlation
edges stamped `source: "correlation"`). Re-ingesting the same alert returns
the existing investigation via the `ba.alerts.v1` ledger — no duplicated
cases or edges. The ingestion UI landed 2026-08-15 as the "alert intake"
section of the triage queue (`/triage`): paste a raw alert (auto-detect or
four-format select), run `ingestAlert`, and read the outcome inline —
format/title/severity chips, new-case vs ledger-hit, `fires` rule chip when
the alert resolves to a deployed detection, edges written, and a link to the
opened case. Successful ingestion also auto-queues a triage item
(`source: "alert-ingest:<format>"`) so the intake queue mirrors the
pipeline; the four sample payloads live in `src/data/alert-samples.ts`.

## Simulation

Rules execute against sample data; display:

```
matches | misses | false positives | coverage
```

**Implemented (2026-08-15):** `runCorpus` + `SIM_CORPUS` in
`data/detection.ts` execute the format's keyword matcher over a fixed
per-format sample set (`found` / `partial` — expected matches; `benign` /
`benign-keyword` — expected non-matches) and classify each row as
tp/tn/fp/fn, deriving matches, misses, false positives, coverage (recall),
and precision. Corpus runs are deterministic: `corpusDigest` keys the
`simulationNodeId` so identical outcomes share a simulation node.
`recordCorpusSimulation` writes a `validates` Detection → Simulation edge
stamped `source: "detection-corpus"` (confidence by precision+coverage)
plus a `simulated` timeline event. The `/detection` editor renders a
"simulate · corpus" pane: run button, per-sample verdict table with hit
chips, metric grid (matches/misses/FPs/coverage/precision), and the record
action (requires a saved rule).

## MITRE coverage

```
Technique → Rules → Deployment → Coverage
```

Highlight gaps.

**Implemented (2026-08-12):** `computeMitreCoverage` in `data/detection.ts`
derives per-technique coverage from the rule library + provenance: `full`
(≥1 deployed rule), `partial` (rules exist, none deployed), `gap` (findings
`mapped-to` the technique but no rule targets it); techniques with neither
rules nor mapped findings are excluded. Techniques are read from the rule's
`technique` field, `attack.*` tags, and Sigma body references
(`ruleTechniques`). Rendered in the `/detection` dashboard panel: status
chips, rule/deployed counts, gaps first, `in findings` marker on gaps backed
by case findings.

## Rule library

Organize by:

```
Windows | Linux | Cloud | Identity | Email | Network | Web
```

**Implemented (2026-08-15):** `RULE_CATEGORIES` +
`ruleCategory` in `data/detection.ts` deterministically categorize every
saved rule — explicit `category` field wins, else the first keyword hit
from `CATEGORY_HINTS` scanned over the rule text (windows sysmon/4688,
linux auditd, cloud aws/azure, identity logon, email/smtp, network dns/tls,
web nginx/apache). The `/detection` editor groups the library by category
with counts per facet (`undefined` → unfiled) and offers the category
dropdown (explicit or `infer`).

## Rule templates

Create rule from:

```
Finding | IOC | Technique | Existing rule | Blank template
```

"Existing rule" (library load / duplicate) and "Blank" (new rule) already exist. Finding /
IOC / Technique templating drives the `drives` provenance writer (2026-08-07: `ruleFromSignal`
scaffolds a sigma rule from any of the three sources and stamps a `drives` edge when a
technique is present).

## Detection dashboard

```
draft rules | deployed rules | validation failures | simulations | recent alerts
```

**Implemented (2026-08-15):** the `/detection` dashboard panel renders all
five metrics: draft/deployed rule counts from the saved-rule states,
validation failures (rules whose last check logged errors, with an
`open` action), simulation count, and recent-alert count derived from
`fires` provenance edges. It also embeds the MITRE coverage list (gaps
first) and the five most recent corpus/validation simulations with
timestamps.

---

# Phase 3 — Analyst Assistance

After the lifecycle exists.

**Status: DONE (2026-08-12).** All five items below are implemented and
unit-tested; each is deterministic over local data with no trained models.

## Explain everything

Every object answers:

```
Why? | How? | Source? | Confidence? | Relationships?
```

## Recommendation engine

Always optional:

```
enrich IOC | create rule | generate report | attach evidence | add MITRE | close investigation
```

Implemented (2026-08-12): the full rule set above is covered by
`computeRecommendations` (pure function in
`frontend/src/components/investigation/InvestigationRecommendations.tsx`,
unit-tested):

- enrich IOC (`no-enrichment` when IOCs are local-only, no intel findings)
- create rule (`create-rule` when findings map to techniques with no rule in
  the library)
- generate report (`no-report` — findings without `report_generated` event)
- attach evidence (`unattributed` — artifacts without evidence entries)
- add MITRE (`unmapped-technique` — findings without technique attribution)
- close investigation (`close-investigation` once report + decision exist on
  an active case; closes the case in place)

All rules are deterministic over local data, explain why in the UI, cap at
four visible recommendations, and support per-case dismissal.

## Investigation assistant

Grounded entirely in local investigation data:

```
Summarize this case
Show missing evidence
Explain this IOC
Show related alerts
List unresolved findings
```

Implemented (2026-08-12): `InvestigationAssistant` in
`frontend/src/components/investigation/InvestigationAssistant.tsx` covers all
five intents — summary with severity-ranked top findings, evidence-gap scan
against attributed artifacts, live alert edge counts (alert ingestion now lands
the `al-*` nodes those counts read — `lib/alerts/ingest.ts`, 2026-08-14), unresolved-finding list, and `explain <ioc>` via the
explain-everything engine. Rendered on the case overview tab.

## Report assistance

Analyst reviews before export:

```
executive summary | technical summary | MITRE section | IOC appendix | timeline
```

Implemented (2026-08-12):

- Five report types — Executive, SOC, Incident Response, Technical, Customer —
  each with an audience-scoped section set (customer never shows provenance or
  analyst hypotheses; executive stays outcome-only).
- Report type selector on the report page (defaults to Technical, the full view).
- Analyst notebook hypotheses become a report section with status/confidence
  chips, decision and next-step detail.
- Markdown export (`copy md`) assembles the exact section set of the active
  type, with honest empty states (`_No IOCs on record._`, ...).

Scheduled exports landed 2026-08-13: `frontend/src/lib/report-schedule.tsx`
persists per-case report schedules under `ba.report-schedules.v1` (cadence
daily/weekly/monthly, report type, next-run time, missed-run counter). While
the workspace is open, a ticker in `PageShell` fires due schedules into the
same version history as manual saves (source-tagged `scheduled`, with the
originally scheduled time kept on the version); runs that fell due while the
app was closed are caught up once with a "generated N runs late" notice.
Schedules are created on the report page's "Report versions" section, which
now also shows a Source column (scheduled/manual) with a late indicator.

Print/PDF theming landed 2026-08-12: the report page carries a print-only
banner (report type, audience, case id/state/tags, included section list, and
timestamps) and hides interactive chrome (KnowledgeBar, version tooling,
action dock, send-to row) from printed output via `.no-print` wrappers, so
`print / Export PDF` produces a clean per-type document.

Delta views and attached versions landed 2026-08-12: `saveReportVersion` /
`loadReportHistory` / `snapshotFrom` / `deltaBetween` in
`frontend/src/lib/report-history.ts` persist up to 12 versions per case under
`ba.reports.v1` (deterministic id `<caseId>:<generatedAt>`, replace-on-same-id,
oldest dropped at cap). The report page saves the current snapshot
(`save current version`, writes a `report_generated` timeline event via the
idempotent `attachVersionEvent`) and shows *what changed since the last saved
version*: new findings, severity changes, new indicators, hypothesis
status/confidence flips, added MITRE techniques, and timeline growth. The
case Reports tab lists attached versions (Saved · Type · counts) with an
`open report` link.

Investigation Object sections landed 2026-08-14: reports now include
`Correlation Matches` (per-case projection of the `ba.correlation.v1` ledger —
dimension, confidence, status, seen count, sources; read-only, never mutates)
and `Analyst Decisions` (case entries of kind `decision`, verdict-extracted).
Wired via `correlationRows` / `decisionRows` in `src/lib/report.ts`, added to
the SOC / Incident Response / Technical section sets (kept out of Executive
and Customer), rendered as report page sections and in markdown export with
honest empty states (`_No correlation matches on record for this case._`).

## Analyzer → graph correlation projection (closes §9 end-to-end)

Landed 2026-08-14: analyzer surfaces advertise correlation relationships
"queued with origin=correlation for analyst review" — the ledger recorded them,
but only the alert path ever projected them into the provenance graph.
`createCaseFromAnalysis` now projects `correlationRelationships` as
`enriched-by` IOC → Entity edges via the shared `projectCorrelationEdges`
helper (same observation→ioc resolution as alert ingest), so case creation
from URL / Logs / Phishing / File / PCAP analyses writes the correlation
edges the surfaces promise. Skips matches with no resolvable ioc node;
`addEdge` stays deterministic and idempotent. Base `AnalysisResult` now
carries optional `observations` / `relationships` / `correlationRelationships`
engine output. Covered by `src/data/__tests__/case-factory.test.ts`
(projection, skip, idempotency, legacy results).

## Search improvements

Natural language queries, translated internally to structured search:

```
Show phishing investigations
Cases involving APT29
PowerShell detections
Recent credential theft
```

Implemented (2026-08-12): `detectIntent`/`applyIntent` in
`frontend/src/lib/search-intent.ts` translate the patterns above into scoped
queries (`recent X`, `X involving Y`, `Y detections`); GlobalSearch applies
the intent to every query and shows a scope note chip. Qualifiers remain the
structured form; v3 Phase 3 will extend the NL surface.

---

# Phase 4 — Platform Refinement

No major architecture changes. Focus on polish.

**Status: DONE (2026-08-13).** All four phases and both post-Phase-3 gates
closed; residuals tracked in the v2/v3 notes (see gate records above).

## Navigation

```
breadcrumbs | quick switching | keyboard navigation | recent work
```

Implemented: `PageShell` auto-prepends the workspace crumb and 20+ routes pass
section crumbs; ⌘K `CommandPalette` (navigation + actions, arrow/enter keys)
and ⌘K GlobalSearch cover quick switching; `WorkspaceHome` surfaces recent work
from `@/lib/recents`.

## Motion

Only purposeful animations: graph transitions, panel expansion, hover
feedback, loading skeletons. No decorative motion.

Implemented: hover transitions on graph nodes/edges, sections, and buttons
(`transition-colors/opacity duration-150`); `Skeleton` primitives for loading
states; graph fade/color transitions. No decorative animation; expansion is
instant to keep interaction snappy.

## Accessibility

```
keyboard navigation | focus visibility | screen reader support | contrast | table navigation
```

Implemented: semantic `<section>/<h2>/<h3>` structure, labeled dialogs
(`aria-label` on CommandDialog/DialogContent), `aria-label` on icon-only
buttons, global `:focus-visible` ring (plus `data-focus-boost` high-contrast
mode in settings), `scope`-attributed table headers, and a `data-zebra` table
row mode. Full screen-reader/contrast audit is part of the deferred browser
smoke-test pass.

### Screen-reader / contrast audit — DONE (2026-08-13)

Measured with a Playwright probe (canvas 2d readback for ground-truth oklch →
sRGB luminance; WCAG 2.1 ratio math):

- **Dark theme:** foreground/bg 16.32, muted/bg 6.0, muted/card 5.72,
  primary/bg 4.69, destructive/bg 5.86, warning/bg 10.55, success/bg 8.58,
  info/bg 8.27 — all content pairs pass AA. `--border` 1.37 is decorative.
- **Light theme:** foreground/bg 15.84, muted/bg 6.55, primary/bg 5.09,
  destructive/bg 4.94, success/bg 4.79, info/bg 4.8 — pass AA.
  **Defect found and fixed:** `--warning` oklch(0.66 0.15 80) was 2.9:1 on
  light bg → darkened to oklch(0.51 0.15 80) → 5.33:1 on bg, 4.65:1 on the
  `bg-warning/10` chip surfaces, 4.02:1 on `bg-warning/20` hover (transient).

Fixes applied in the same pass: skip-to-main link at root layout in `__root.tsx`
(first focusable, before the sidebar DOM), focusable `id="main"` target
(`tabIndex={-1}` + programmatic focus on activation; sidebar DOM precedes
`PageShell`, so the link was 19th in tab order when placed there), `inert` +
`aria-hidden` on the always-mounted IocLocker/InvestigationGraph drawers so
closed drawers no longer steal focus or sit in tab order (replaced their
unconditional `autoFocus` with focus-on-open, e.g. scratchpad/attach textareas
and graph close button), `aria-label` on all unnamed icon-only buttons found
(IocLocker scratchpad/attach/locker closes, InvestigationGraph closes,
ExplainThis close, case tag/entry delete, activity refresh, diff locker-add
chips), and labels on placeholder-only inputs (TopSearch/GlobalSearch/intel
filters already existed partially; OutputFilter + intel input labelled).
Follow-up pass (same day) labelled every remaining control across all
routes: intake textareas (`aria-label={title}` in `IntakeCard`), triage
title/description/note, file/log inputs (`label[for]`), pcap capture + CLI
input, detection rule/event editors, sigma-tester rule/sample, diff panes,
regex playground (pattern/flags/replace/test), settings filter/app
name/backend URL, activity/timeline/case/snippets/guide/mitre/validation/
chef/url search inputs, and severity/sort/select controls.

## Performance

```
graph rendering | virtualization | search indexing | memoization | lazy loading
```

Implemented: TanStack Router code-splits every route (code-splitter in build),
hot paths are memoized (`useMemo`/`useCallback`), search indexing is cached and
rebuilt on data change, and the provenance graph is small-scale SVG with
capped node rendering. Virtualization is not needed at current data scale —
revisit if cases exceed hundreds of nodes.

## Documentation

Expand developer documentation:

```
architecture | workflows | provenance | detection | graph | design system
```

Implemented: `docs/` covers ARCHITECTURE_DECISIONS, WORKFLOW_DESIGN,
PROVENANCE_MODEL, GRAPH_MODEL, DETECTION_LIFECYCLE, DESIGN_SYSTEM,
ANALYSIS_ENGINE, INVESTIGATION_OBJECTS, PAGE_SPECIFICATIONS, SOC_OPERATIONS,
plus this roadmap.

## Testing

Automate:

```
workflow drivers | graph validation | provenance validation | lifecycle validation | visual regression
```

Implemented: 30 vitest suites (383 tests) covering graph (`graph.test.ts`),
provenance (`provenance.test.ts`), detection lifecycle/simulation/coverage/
library, report generation, recommendation rules, search intents/qualifiers,
artifact analyzers, extraction format acceptance, and case pinning. Browser smoke pass (2026-08-13): all 31 routes load
200 with a single `h1` (tool-panel headers demoted to `h2` in
`ToolShell`/`AnalyzerShell`; nav hub routes only card-render at their root —
nested `/developer/*` pages render their own `PageShell`); only console noise
is the offline backend health probe (`localhost:8000`). Visual regression
now shipped (2026-08-13): `frontend/tests/visual-regression.spec.ts` holds
pixel baselines for all 31 routes + a seeded investigation graph (PNGs
committed under `tests/visual-regression.spec.ts-snapshots/`), asserting
zero page errors and zero horizontal overflow alongside each snapshot.
Run with `npm run test:e2e` (update with `test:e2e:update`). Determinism
measures from the live debug session: suites run against the production
build (`vite preview`, no HMR/transform scheduling), clock frozen via
`page.clock.install`, animations/transitions disabled, reduced motion,
grayscale font rendering flags, all declared fonts force-preloaded
(`allSettled`), viewport-only captures (fullPage stitch height jittered
±1px), per-test fresh context, `workers: 4`. CI hookup shipped (2026-08-13):
`.github/workflows/ci.yml` runs backend (ruff + compileall + pytest) and
frontend (lint, typecheck, build, vitest, Playwright **functional**
core-flow). The **visual baseline suite is intentionally local-only**: the
app renders system-font stacks, so committed PNGs are only comparable on
machines with identical fontconfig rendering — CI would produce false
diffs. Baselines remain the machine-portable artifact to wire into CI the
day a pinned-font image exists. Functional flows:
`frontend/tests/core-flow.spec.ts`
(parser→attach→case, multi-IOC extraction, SIEM pivot, hunt persistence).

---

# Cross-cutting Engineering Constraints

Apply to every future feature.

1. **Preserve the architecture freeze.** No new primitives. No duplicate
   models. No parallel systems. Everything composes existing building blocks.

2. **Provenance-first mindset.** Every write action asks: *should this emit
   an edge?* Readers should never require modification for new relationships.

3. **Investigation-centric design.** Features integrate into investigations.
   Avoid isolated tools.

4. **Honest UI.** Never fabricate information. If data is missing,
   `No provenance available` / `No enrichment found` / `No related detections`
   is preferable to inferred output.

5. **Deterministic identity.** All long-lived entities have stable IDs.
   Avoid random IDs for anything that participates in provenance.

6. **Explainability.** Every recommendation, graph connection, and lifecycle
   transition is traceable: *Why is this here? Where did it come from? What
   supports it? What depends on it?*

7. **Keyboard-first workflow.** Every major action reachable via command
   palette, keyboard shortcuts, search, and context actions — without deep
   navigation.

8. **Workflow before aesthetics.** Visual polish reinforces workflow. Avoid
   dashboards, charts, or decorative elements that do not help investigation
   tasks.

9. **Expand depth before breadth.** Improve existing analyzers and workflows
   before adding entirely new tools. A mature URL analyzer, file analyzer,
   phishing analyzer, parser, and SIEM workflow provide more value than many
   shallow utilities.

10. **One connected platform.** Every major object lives in a single
    connected knowledge graph; each workspace offers a different perspective
    on the same underlying data, not isolated representations.

11. **Deepen or connect.** Every new feature either deepens an existing
    workflow or connects two existing workflows. Standalone analyzers,
    isolated dashboards, and separate mini-workflows are rejected: they
    increase surface area without strengthening the platform.

The constraints answer the questions that keep the roadmap from drifting:

```
Should this create a new component?      → constraint 1
Should this create another data model?   → constraint 1
Should this action emit provenance?      → constraint 2
Does this feature integrate into investigations? → constraint 3
Is this recommendation explainable?      → constraint 6
Is this identifier deterministic?        → constraint 5
```

---

# Retained items from earlier roadmaps (v1/v2 — deferred unless folded into a phase)

Kept so no prior direction is lost. These are secondary to the v3 phases
unless they map onto Phase 1–4 work.

## Dashboard 2.0 (v2)

Operational home / analyst launcher — not metrics, not charts; nothing
decorative, everything launches work:

```
Continue Investigation | Recent Cases | Recent Searches | Recent Reports
Pinned Investigations | Recent Alerts | Detection Changes | Activity Feed | Quick Intake
```

**Implemented (2026-08-17 → 2026-08-19):** the launcher covers the full spec —
continue-investigation + active workspaces + recent assets, Recent Cases /
Searches / Entities / Parser Inputs, Today's Activity feed and Detection
changes (`index.tsx` + `WorkspaceHome`). **Recent Alerts** (top of the
`ba.alerts.v1` ledger with format + rule-key chips → case links) and
**Pinned Investigations** (new `lib/pins.ts` `ba.pins.v1` store, pin toggle
+ marker in the case notebook sidebar, pinned-first sort; dashboard panel)
landed 2026-08-17. Quick Intake and Operations grids launch work directly.

## Report Builder 2.0 (v2)

Analyst reports instead of data export:

```
Executive Summary | Investigation Timeline | Key Findings | Evidence | IOCs
MITRE Mapping | Threat Assessment | Detection Recommendations | Appendix
```

Report types: Executive | SOC | Incident Response | Technical | Customer.
Analyst notes become report sections automatically. (v3 Phase 3 report
assistance covers section generation; the builder/types remain.)

**Implemented (2026-08-19):** five report types (`REPORT_TYPES`), per-type
section sets (`REPORT_TYPE_SECTIONS`), notes-as-hypothesis-sections, report
route + markdown export + versions + cadence schedules (all pre-existing).
**Detection Recommendations** (critical/high findings → investigate-and-
validate rows + preserve-evidence guidance) and **Appendix** (raw case
record: counts + first-line entry bodies) sections added 2026-08-19 to
soc / incident-response / technical sets. Threat Assessment maps to MITRE
Coverage + Analyst Hypotheses; Key Findings → Findings; Evidence → IOCs /
Provenance. Section-set test extended.

## Global Search 2.0 (v2)

Scope: Cases | Reports | IOCs | Findings | MITRE | Rules | Alerts | Notes |
Evidence | Relationships. GitHub-style qualifiers:

```
type:ioc  severity:high  tag:lumma  state:open  actor:apt29  technique:t1059  report:credential
```

(v3 Phase 3 adds natural-language queries; qualifiers are the structured form.)

**Implemented (2026-08-17):** `parseQualifiers`/`matchesQualifier` in
`lib/search-engine.ts` whitelist `type severity tag state source technique
format ioctype kind category importance tactic entity confidence status
actor report` (whitelist keeps CVE/IPv6/URL colons as plain text);
GlobalSearch tokenizes the query, renders qualifier chips, and filters the
scoped index before the intent/text pass. Covered by
`lib/__tests__/search-qualifiers.test.ts` (extraction, multi-qualifier,
whitelist rejection, residual text) plus intent integration in
`search-intent.test.ts`; the search bar shows the supported qualifier set.

## SIEM 2.0 (v2)

Hunting console: saved hunts (Credential Access | PowerShell | Kerberoasting |
Lateral Movement | Persistence | Living off the land), search history
(Recent | Pinned | Favorites), IOC highlighting (IP red | Hash purple |
Domain blue | User green), MITRE overlay on event select (Technique →
Detection → Previous Cases → Related Alerts), one-click investigation pivot
(Event → Create Investigation → Case opened → Evidence attached). Hunt flow:
`hunt → interesting event → investigation → graph → report`. Timeline
generation: `09:11 Login / 09:14 PowerShell / 09:16 Service created /
09:18 Beacon / 09:20 C2`.

**Implemented (2026-08-18 → 2026-08-19):** hunt presets (Credential Access /
PowerShell / Kerberoasting / Lateral Movement / Persistence / Living off
the land — keyword + chips, one-click apply) + OR-aware `|` keyword filter;
IOC highlighting in the event table (IP red / hash purple / domain blue in
src+dst, user green); search-history favorites (star toggle + pinned row,
`beyondlabs.siem.favorites.v1`); incident timeline (HH:MM label strip,
signature-classified, severity-toned); MITRE overlay drill-down (technique
chips → detection rules / previous cases / related alerts). Saved hunts
(pinned-first), Recent queries, one-click event→investigation pivot,
timeline charts, CSV/markdown export pre-existed.

## Intelligence 2.0 (v2)

IOC search result hierarchy (Summary → relationships → actors → campaigns →
infrastructure → malware → reports → MITRE → suggested detections); full
entity pages (Overview | Aliases | Countries | Objectives | Known malware |
Infrastructure | Campaigns | MITRE | Observed IOCs | Related reports |
Timeline | Relationships); IOC pages (Seen In, associated malware/actors,
MITRE, detection coverage, confidence, last observed); rich intelligence
cards (APT28: campaigns 12 · malware 8 · infrastructure 52 · IOCs 430 · last
seen 2 days ago); relationship explorer (`APT29 → Campaign → Malware → IOC →
Victim`); confidence High/Med/Low with source attribution; every assertion
`Source | Reason | Date | Confidence`; enrichment sources Manual | MISP |
VirusTotal | Shodan | OTX | Internal (opt-in; source, method, confidence,
limitations, collection time always shown).

**Implemented (2026-08-19):** entity pages (Overview incl. aliases /
campaigns / tools / targets / techniques, Observables, Relationships,
KnowledgeBar, finding-create / attach-IOCs, markdown export) pre-existed;
IOC **seen-in** panel (per observable type/source/timestamp/confidence +
case-coverage chip over `ba.cases.v2`), relationship **attribution**
(Source · Reason under each row), and the **relationship explorer**
(2-hop chains `entity → relation → target → first IOC`) landed 2026-08-19,
satisfying Seen In / confidence / `Source | Reason | Confidence` (the
model has no per-assertion date — omitted honestly). Enrichment stays
Manual/local; external sources are documented pointers.
Timeline | Relationships); IOC pages (Seen In, associated malware/actors,
MITRE, detection coverage, confidence, last observed); rich intelligence
cards (APT28: campaigns 12 · malware 8 · infrastructure 52 · IOCs 430 · last
seen 2 days ago); relationship explorer (`APT29 → Campaign → Malware → IOC →
Victim`); confidence High/Med/Low with source attribution; every assertion
`Source | Reason | Date | Confidence`; enrichment sources Manual | MISP |
VirusTotal | Shodan | OTX | Internal (opt-in; source, method, confidence,
limitations, collection time always shown).

## UI evolution (v2, OpenCTI-leaning)

- Single primary dark theme first; additional themes optional, not core.
- Denser information layout: tables and split panes over cards.
- Tabbed workspaces and resizable panels replace long scrolling pages.
- Standardize every toolbar, search box, filter row, and table across workspaces.
- Consistent layout: left navigation + top action bar + central work area.
- Investigation Knowledge Graph as a first-class, always-accessible view.

## Analyst experience (v1)

- Command palette evolution: recent commands, macros, workflow shortcuts,
  saved searches, pinned actions.
- Keyboard-first: Cmd+K, `/`, Arrow, Enter, Ctrl+Enter, Ctrl+Shift+P.
- Bulk operations across tables: Select | Enrich | Export | Create case |
  Attach | Delete | Label.
- Session recovery: open investigations, filters, tabs, graph position,
  recent work (recovery items in Phase 1 cover the lightweight start).
- Personal workspace: pinned investigations/entities/hunts/detections,
  scratch notes, recent activity.

**Progress (2026-08-19):** palette recent commands landed
(`lib/palette/recent.ts`, `ba.palette.recent.v1`, capped 8, deduped to
front; recording wraps every `onSelect` so navigation/search/intake/
detection invocations all count). Saved searches are covered by the
existing query stores (SIEM favorites `beyondlabs.siem.favorites.v1`,
GlobalSearch `getSearchLog`), pinned investigations by
`lib/pins.ts` (`ba.pins.v1`) and pinned hunts by the SIEM hunt store.

**Progress (2026-08-22):** remaining v1 analyst-experience items landed.
- Macros: `lib/palette/macros.ts` (`ba.palette.macros.v1`, max 8 steps,
  deterministic ids via fnv1a); "macro <name>" in the palette saves the
  recent-command ledger as a replayable macro, "Run macro" re-resolves
  each step against live providers and reports unresolvable steps
  honestly instead of skipping silently.
- Session-recovery depth: graph controls (mode, hop limit, source,
  confidence, kind/relation filters) persist per case via
  `lib/session-view.ts` (`ba.session.view.v1`, 7-day TTL, validated on
  hydration against the NodeKind/ProvenanceRelation unions); case sidebar
  search + origin/finding filters persist under the same store; case tab
  persistence already existed (`ba.case.tab.v1`).
- Bulk table operations: case observables gained Enrich (intel lookup →
  `enriched-by` edges + honest per-selection summary) and Create case
  (structured IOCs carried over with provenance note); triage gained a
  bulk Label action via a new inline `extra` slot on BulkActionBar.
- Personal workspace: namespaced pins (`ba.pins.v2`, detection/entity/
  hunt buckets, id-keyed so renames survive) with pin toggles in the
  detection library and intel entity header; dashboard gained Pinned
  Detections, Pinned Entities, and local-only Scratch Notes panels
  (`lib/scratchpad.ts`, `ba.scratch.v1`).

---

## Cross-cutting notes (architecture)

- "Extending the system by adding data, not modifying algorithms" — add
  vocabulary, kinds, edges, and writers, not new engines.
- Graph UX finishes before new writers: writers (detection → `drives`,
  Sigma validation → `validates`, deployment → `deploys`, alert from triage →
  `fires`) come after the workspace is first-class.
- No automation that decides for the analyst: recommendations and guidance
  only; opt-in external enrichment only, with source, method, confidence,
  limitations, and collection time always shown.
