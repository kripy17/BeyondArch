# BeyondLabs Roadmap v4 — The Investigation System

> Supersedes v3 for all forward work. v3 (`ROADMAP.md`) remains the reference
> for frozen phases and the retained-items appendix. v4 does **not** continue
> v3 phase numbering and does **not** rebuild anything the v3 constitution
> froze (Analysis Engine, provenance spine, analyzer contracts).

## North star

BeyondLabs stops being a collection of security tools that share a graph, and
becomes one investigation system: a single case spine that every workspace
feeds and reads from. Alerts open cases, analyzers deepen cases, detections
defend what cases learned, reports prove what cases concluded. If a proposed
feature does not make an existing investigation stronger or connect two
existing workflows, it does not belong in v4.

Constitution (unchanged): `ROADMAP.md` + `PROVENANCE_MODEL.md` +
`DETECTION_LIFECYCLE.md` + `ANALYSIS_ENGINE.md` + `INVESTIGATION_OBJECTS.md`.
Layered engine stays: Extraction → Analysis Engine → Investigation Objects →
Correlation → Knowledge Graph. Analyzers produce; workspaces consume; pages
compute nothing.

## Entry state (2026-08-22)

- Phases 1–4 frozen; v2.5 Platform Edition gate passed.
- Analyst experience v1 shipped (macros, session-view persistence,
  namespaced pins, scratch notes, bulk operations).
- Dogfood pass (2026-08-22) found and fixed one honesty violation:
  fabricated redirect waterfall removed; waterfall now renders only measured
  hops from opt-in live Safe Fetch.

### Known defects to clear before or during V4.1

1. **P2** Graph viewport restore races mount-time `fitView`
   (`InvestigationGraph.tsx`) — restore in `onInit`, guard the fit effect.
2. **P2** Global Investigation Graph drawer never resolves the active case
   while other drawers do.
3. **P2** Backend CORS defaults break when Vite falls back from port 5173;
   "Backend offline" badge gives no hint. Widen default origins or explain
   in the badge.

---

## V4.1 — Alert → Investigation

**Capability:** an alert is the beginning of an investigation, not the end of triage.

The intake spine is currently the weakest link: alerts ingest into triage but
the handoff into a case is manual. Close that gap without automating judgment.

- One-click alert → case creation carrying structured IOCs, mapped fields,
  and a provenance edge from alert artifact to case.
- Alert cluster view before escalation: group by entity / signature /
  technique so one incident is not five alerts.
- Case links back to its originating alert(s); triage states (new → triaged →
  escalated → closed) visible in the case graph.
- Bulk escalate selected alerts to new or existing cases with honest counts.
- Constraint: no auto-verdicts. Heuristics label, analyst decides.

**Progress:** escalation path landed (`lib/alerts/escalate.ts`): single and
bulk escalate create structured cases carrying extracted IOCs, write the
alert → case provenance edge when an alert node id exists, link items that
already have a case instead of duplicating, and report honest per-action
counts. Items ingested via `ingestAlert` now carry their case id and alert
node id on the triage item. The cluster view (`lib/alerts/clusters.ts`)
groups open and in-review items by shared IOC value or MITRE technique,
with an explicit unclustered bucket, and offers escalate-all per cluster.
Still open: nothing — V4.1 is complete. Triage origin and state are now
visible on the case node in the investigation graph
(`triage escalation · active|closed`), derived from the case's triage tag or
escalation event, never invented for cases without that origin.

## V4.2 — Graph Memory

**Capability:** the knowledge graph remembers across sessions, cases, and time.

Session-view persistence landed in v3; v4 makes memory analytical.

- Surface cross-case correlation: when a new analysis touches entities seen
  in prior cases, show "seen before" cards linking to those cases. Correlation
  memory exists — expose it where analysts work.
- Named, restorable graph views per case (focus node, filters, viewport saved
  together under a name such as "lateral movement").
- Graph snapshot → notebook: export current annotated graph state as a
  case evidence entry.
- Entity timeline: unified per-entity appearance history across cases,
  alerts, hunts, and analyses.
- Constraint unchanged: correlation is remembered for review only and never
  re-ranks raw analysis.

**Progress:** named, restorable graph views landed (`lib/graph-views.ts`):
filters, focus node, and viewport save together under an analyst-chosen
name per case (`ba.graph.views.v1`), with apply/delete chips in the graph
toolbar and validation on read so junk entries degrade instead of breaking.
"Seen before" cards landed on the case overview: observables shared with
other cases are listed with links into those prior cases, derived at render
time from the cases store using the same value normalization as the
correlation engine — review only, never an input to analysis. Graph
snapshot → notebook landed (`lib/graph/snapshot.ts`): a toolbar action files
the current filter state, focus, and visible counts as a note entry in the
case activity log, explicitly labeled a filter-state record rather than an
image or analysis claim. Entity timeline landed
(`lib/timeline/entity-timeline.ts`): expanding an observable in a case shows
its unified appearance history across cases and triaged alerts — the two
stores that persist values with timestamps — newest first, with links into
each source; hunts and one-off analyses are honestly excluded because their
results are never persisted with values attached. Nothing left open — V4.2
is complete.

## V4.3 — Analyzer Depth

**Capability:** deeper measured facts from the producers we already have. No
new standalone analyzers; architectural freeze intact.

- URL analyzer: ✅ DONE — polish opt-in live Safe Fetch UX (effect-loop fix,
  allow_live_fetch follows the checkbox); TLS/certificate summary rendered
  with measured/derived separation and validity line; measured redirect hops
  wired into findings honestly (provenance-labeled rows; waterfall fix
  already landed). PRs #13, #14.
- Phishing analyzer: ✅ DONE — attachment filenames deep-link into the File
  Analyzer via artifact handoff (filename carried, content not — stated in
  UI); multi-header Authentication-Results parsed with per-family conflict
  flagging; verdicts sourced from last evaluating hop (RFC 8601). PR #15.
- Parser: ✅ DONE — format-detection confidence (level + matched anchors
  shown on the intake chip); mapping-review UI for src/dst/user/sig/sev with
  corrections persisted per detected source format (ba.parser.mappings.v1);
  corrections win over auto-guesses. PR #16.
- SIEM: ✅ DONE — keyword query input in the filter strip (| OR syntax,
  / focus, Escape clear, live match count); local-only re-run reminders for
  saved hunts via lastRunAt + stale badge with snapshot-honesty tooltip.
  PR #17.
- Detection editor: ✅ DONE — expanded quality lints (Sigma hygiene fields +
  condition↔detection cross-check with wildcard prefixes; YARA brace/meta/
  string-reference checks; KQL balance + search/projection warnings) and a
  published Sigma ↔ KQL ↔ YARA conversion parity table (10 constructs,
  honest partial/no cells with loss notes). PR #18.

V4.3 complete: all five analyzer bullets shipped (#13–#18).

## V4.4 — Reproducible Reports

**Capability:** a report is reproducible evidence, not a summary.

Report versions exist; v4 makes them defensible.

- Diff view between saved report versions: ✅ DONE — side-by-side diff of any
  two saved report versions with changed-line highlighting.
  PR #19.
- Every generated report embeds its inputs: ✅ DONE — reproducibility stamps
  (input values hash, analyzer versions, generation timestamp) rendered into
  every saved report so a reader can reproduce it. PR #19.
- Export bundle: ✅ DONE — one-click `.beyondcase` zip assembling case JSON,
  markdown + HTML report, raw artifacts, and a fingerprinted MANIFEST.txt
  (dependency-free deterministic zip writer; fixed timestamps for byte-stable
  output). PR #20.
- Deterministic report templates: ✅ DONE — L2 handoff, IR handoff, executive
  summary, and IOC-only annex assembled from stored case data with all
  timestamps rendered from recorded ISO strings (identical inputs produce
  byte-identical reports). PR #21.
- Provenance appendix: ✅ DONE — claim → evidence appendix in the IR handoff
  template walking each finding/IOC back through its recorded provenance
  spine to source artifacts, honestly marking unlinked claims as not yet
  linked. PR #21.

V4.4 complete: reports are now reproducible evidence — stamps, diffs,
bundles, deterministic templates, and provenance appendices shipped
(#19–#21).

## V4.5 — Evidence Expansion

**Capability:** more of the world becomes first-class, honest evidence — same
rules for everything.

- File attachments (screenshots, notes) on any case entry: ✅ DONE —
  attachment chips on intake and activity rows with payload storage kept
  separate from case data, deterministic content-hashed ids for dedupe,
  honest per-file/total size caps, and inclusion in export bundles.
  PR #22.
- Opt-in external enrichment adapters (WHOIS, DNS, hash lookup) behind the
  same gate as Safe Fetch: ✅ DONE — nothing leaves the machine without an
  explicit per-query consent click; every record always shows source,
  method, confidence, limitations, and collection time, and successful
  lookups land as `enriched-by` provenance edges on matching IOCs.
  PR #23.
- Timeline import: CSV/JSONL event import into a case timeline through the
  parser's mapping review: ✅ DONE — ts/title/detail columns guessed and
  correctable per source format beside log field mapping; timestamps must
  actually parse or rows are reported skipped (never fabricated), and
  deterministic event ids make re-imports dedupe instead of duplicating
  history. PR #24.
- Everything lands as vocabulary and edges per PROVENANCE_MODEL.md — data,
  not algorithms.

V4.5 complete: the evidence surface now spans attached files, opt-in
external enrichment, and imported timelines — all local-first, all
labeled (#22–#24).

---

## Release gates

```
V4.1 + defect list cleared    →  v3.0 Investigation Edition
V4.2                          →  v3.1 Memory Edition
V4.3 + V4.4                   →  v3.5 Depth Edition
V4.5                          →  v4.0 Evidence Edition
```

Each gate: freeze, dogfood pass (browser-driven, defect-list driven, no
visual-opinion items), fix P0–P2, update docs.

> **v3.5 Depth Edition gate: PASSED (2026-08-25).** One comprehensive
> browser-driven dogfood pass covered the V4.3/V4.4 surface plus carry-over
> checks. Diff-and-stamp provenance, all six deterministic report templates
> (including the IOC Annex), the claim → evidence appendix, and the
> reproducible export bundle (manifest fingerprints, attachment bytes
> verified identical on download) behaved as specified. The three known
> pre-V4.1 P2 defects were verified fixed: graph viewport restore race
> (guarded fit effect), global graph drawer resolving the active case with
> an honest empty state, and CORS (resolved by configuration —
> `BEYONDLABS_CORS_ORIGINS` documented in `.env.example` and
> docker-compose, not by a badge hint).
>
> **v4.0 Evidence Edition gate: PASSED (2026-08-25).** The same pass
> exercised the V4.5 evidence surface end-to-end: alert ingest auto-created
> a case with IOCs and a `creates` edge; entry attachments round-tripped
> (pending chips → persisted payload → byte-identical download); opt-in
> enrichment honored the per-query consent gate, rendered source/method/
> confidence/limitations/collection time on every record, and answered
> unresolvable targets with honest `no-data`; CSV timeline import went
> through the mapping review, skipped an unparseable row loudly, deduped a
> full re-import, and persisted mapping corrections across reloads. One
> real defect found and fixed during the pass: `enriched-by` edges were
> recorded but enrichment nodes never rendered in the investigation graph
> (missing label branch) — fixed and verified live. Residual observation:
> timeline title columns are not auto-guessed from generic names like
> `event` (the review dropdown exists precisely for this); accepted as-is.
>
> **v3.0 Investigation Edition gate: PASSED (2026-08-29).** A browser-driven
> pass walked the full triage → investigation escalation chain. Ingest in
> triage auto-created a case per alert (with its `creates` edges; a
> re-ingested identical alert hit the ledger — "ledger hit · 0 edges
> written" — and reused the existing investigation instead of duplicating).
> Cluster view grouped items by shared IOC (one cluster per address plus an
> honest "no shared entity or technique" bucket), each with an escalate
> action. Single and bulk escalation produced correct counts and behavior:
> a case-less manual item created one new case carrying the `triage` tag
> and a `triage-escalation` case_created event; an already-cased alert item
> linked to its existing case with no duplicate. The case node in the
> investigation graph renders `triage escalation · <state>` when the
> escalated case has provenance edges (verified at the logic and data
> layers); case-less manual items with zero observables render an honest
> empty graph, so the badge is reachable via case-less alert items from
> triage.txt. The three pre-V4.1 P2 defects remain verified fixed (see the
> v3.5 record).
>
> **v3.1 Memory Edition gate: PASSED (2026-08-29).** Correlation memory
> behaved as specified and honestly: with no shared observables across
> cases it rendered "workspace-wide · 0 matches"; after a Sysmon alert
> shared an observable with a prior case, the panel showed one match with
> the prior-case reference, confidence, and seen count, and confirm/dismiss
> transitions on the record persist without ever re-ranking raw analysis.
> The Observables tab showed each entity's timeline ("History · 1
> appearance across case stores · newest first") with a link to its source
> case. Named graph views saved filters/focus/viewport under an applied
> name, restored on click, deleted cleanly, and survived reloads (junk
> storage entries are filtered on read). The graph snapshot button filed
> the current filter state as a case notebook entry on the case Timeline —
> explicitly labeled a filter-state record, not an image or an analysis
> claim.

## Standing constraints (carried forward)

- Extend by adding data — kinds, edges, writers — never by adding engines.
- No automation that decides for the analyst.
- No fabricated results, ever: if nothing was measured, say nothing was
  measured.
- External enrichment opt-in only, clearly labeled.
- Honesty about limitations beats impressive-looking output.
