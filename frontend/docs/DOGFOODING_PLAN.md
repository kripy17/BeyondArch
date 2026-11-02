# Dogfooding Plan

> Validate the platform with real investigations before building v0.10.
> 40–50 investigations across 5 categories.
> Duration: ~3 sessions.

---

## Categories & Samples

| Category | Count | Sources |
|---|---|---|
| Phishing emails | 10 | .eml files from previous cases, test fixtures |
| Malicious URLs | 10 | Known phishing/malware URLs (VT, urlscan) |
| Windows logs | 10 | Security.evtx, Sysmon, PowerShell logs |
| PCAPs | 5 | Malware traffic, C2, exfiltration samples |
| Suspicious files | 5 | Documents, scripts, binaries (known-safe test files) |

---

## Investigation Script

For each sample, follow this workflow:

1. **Create investigation** — start from `/parser` or `/phishing` or `/attachment`
2. **Run analyzers** — default pipeline, note any errors
3. **Review findings** — structured findings, severity, source
4. **Review IOCs** — verify IOCs extracted, type detection, locker integration
5. **Check timeline** — events captured with correct categories
6. **Search** — find IOCs, findings, cases via ⌘⇧F and ⌘K
7. **Navigate** — deep link from search to case tab
8. **Generate report** — print / save report page
9. **Add notes** — record observations as case entries
10. **Close case** — toggle state

---

## Per-Investigation Record

| Field | Value |
|---|---|
| Sample type | phishing / url / log / pcap / file |
| Sample ID | unique identifier |
| Time to complete | mm:ss |
| Searches performed | count |
| Tabs / pages visited | list |
| Page switches | count |
| Actions repeated | list of repeated actions |
| Search queries | actual query strings typed |
| Missing feature | what was needed but didn't exist |
| Confusing UI | what was unclear or hard to find |
| Error / crash | any runtime issues |
| Friction rating | 1 (smooth) – 5 (blocked) |

---

## What to Record

### Search queries (critical)

Write down every query typed in ⌘⇧F and ⌘K:

```
"evil-host.ru"
"powershell"
"case BA-20260727"
"sha256:abcd"
```

These queries are the most valuable output — they reveal:
- What analysts expect to search by
- What search weighting should prioritize
- Whether search indexing has gaps

### Friction points

For each investigation, note every moment you:

- Had to switch pages to find something
- Couldn't find a related IOC or finding
- Had to re-type or copy-paste manually
- Wanted a keyboard shortcut that doesn't exist
- Found the UI confusing or unresponsive
- Expected a relationship that wasn't visible

### Context switches

Count the number of distinct pages/tabs visited during one investigation. Each switch is a cost. A well-designed investigation workspace should keep this ≤ 3.

---

## Post-Dogfooding Deliverable

After all investigations, produce:

```
ANALYST_TEST_RESULTS.md
```

### Structure

```
# Analyst Test Results

## Summary
- Total investigations: 45
- Average time: X:XX
- Average page switches: X
- Most common search queries: [...]
- Most frequent friction: [...]

## By Category

### Phishing (10)
- Avg time: X:XX
- Friction score: X.X
- Key issues: [...]

### URLs (10)
...

## Top 10 Pain Points
Ranked by frequency × severity.

1. ...
2. ...

## Recommended v0.10 Priorities
Based on observed analyst behavior, not assumptions.

1. ...
2. ...
3. ...
```

---

## Success Criteria

Before starting v0.10, these must be true:

- [ ] Search index covers all investigation objects
- [ ] ⌘⇧F returns IOC/finding/event results in <1s
- [ ] Deep links navigate to correct tab
- [ ] No crashes during standard investigation workflow
- [ ] Baseline completion time established for each category
- [ ] Top 5 friction points identified and documented
