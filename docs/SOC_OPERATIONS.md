# SOC Operations Manual

How analysts use BeyondLabs — journeys, expectations, and cross-page data flows.

---

## Section 1 — Analyst Journeys

### Journey 1: Suspicious Email Investigation

**Trigger:** User reports suspicious email.

```
Dashboard
    │
    ▼
Phishing Analysis (/phishing)
    │  paste .eml → backend parses headers, auth, URLs, body
    │
    ├── Findings (SPF fail, brand impersonation, malicious links)
    ├── IOCs (sender domain, URLs, attachment hashes)
    │
    ▼
Actions:
    ├── Add IOCs to Locker
    ├── File Analysis (/attachment) — scan attachments for malware
    ├── URL Analysis (/url) — inspect redirect chain
    ├── Create Case (/case) — escalate with evidence + findings
    └── Timeline (/activity) — event recorded automatically
```

**Existing coverage:**
- `/phishing` — fully implemented with auth tiles, URL extraction, attachment detection, body signals
- `/attachment` — can upload extracted files independently
- `/url` — can analyze extracted URLs independently
- `/case` — entries can be created from phishing output
- `/intel` — hash/domain enrichment after extraction
- **Gap:** No one-click "Send to File Analysis" or "Send to URL Analysis" from Phishing results
- **Gap:** Phishing outputs aren't structured as `Finding[]` — just displayed text

---

### Journey 2: SIEM Alert Triage

**Trigger:** SIEM alert fires.

```
SIEM Workspace (/siem)
    │  paste log text or upload
    │
    ├── Event timeline (severity BarChart)
    ├── Event list with filters
    ├── Event detail modal
    ├── Extracted IOCs
    └── MITRE mapping view
    │
    ▼
Actions:
    ├── Create Triage item (/triage)
    ├── Create Case (/case)
    └── Investigate in Detection (/detection)
```

**Existing coverage:**
- `/siem` — log paste, event list, severity histogram, IOCs, MITRE mapping, narratives
- `/triage` — queue for manual triage items
- `/case` — can receive SIEM findings
- **Gap:** No one-button "Escalate to Triage" from SIEM events
- **Gap:** SIEM "synthetic data" for event parsing — no real backend integration
- **Gap:** `/logs` route exists with no actual log ingestion

---

### Journey 3: Suspicious File Analysis

**Trigger:** User downloaded a suspicious file (`invoice.exe`).

```
File Analysis (/attachment)
    │  upload file → backend returns hashes, strings, findings
    │
    ├── Hashes (MD5, SHA1, SHA256)
    ├── Entropy analysis
    ├── Suspicious strings
    ├── YARA match hints
    └── Risk summary
    │
    ▼
Actions:
    ├── Hash Lookup → /intel
    ├── Add to Locker
    ├── Add Evidence to Case (/case)
    └── Create Finding → /detection
```

**Existing coverage:**
- `/attachment` — file upload, backend analysis, hash extraction, entropy, suspicious strings, risk scoring
- `/intel` — hash enrichment (synthetic)
- `/case` — evidence can be added
- **Gap:** No one-click "Create Sigma rule" from file finding
- **Gap:** File findings not structured as `Finding` type — displayed inline only

---

### Journey 4: Network Traffic Investigation

**Trigger:** Suspicious outbound connections detected.

```
PCAP Analysis (/pcap)
    │  upload .pcap or paste tcpdump output
    │
    ├── Summary (packets, IPs, protocols, duration)
    ├── Conversations (IP pairs, ports)
    ├── DNS queries
    ├── HTTP requests
    ├── TLS SNI
    ├── Alive hosts
    └── CLI mode for custom tshark/tcpdump commands
    │
    ▼
Actions:
    ├── Extract IOCs (IPs, domains, URLs) → Locker
    ├── Add PCAP as Evidence → Case (/case)
    ├── Timeline events → (/activity)
    └── Copy report
```

**Existing coverage:**
- `/pcap` — file/text input, backend analysis, CLI mode, IOC extraction, case integration
- `/case` — evidence timeline
- **Gap:** No MITRE mapping from PCAP findings (e.g., DNS tunneling → T1572)
- **Gap:** PCAP outputs not structured as reusable `Evidence` type

---

### Journey 5: IOC Enrichment & Threat Intel

**Trigger:** Analyst needs context on an IP/domain/hash.

```
IOC Search (/intel)
    │  enter IP, domain, hash, CVE, JA3, threat actor
    │
    ├── Threat actor profile
    ├── CVE details (CVSS, description, related)
    ├── Hash reputation
    ├── JA3 fingerprint details
    └── User-agent analysis
    │
    ▼
Actions:
    ├── Copy to clipboard
    ├── Add to Case
    └── Navigate to Threat Actors / CVE / JA3
```

**Existing coverage:**
- `/intel` — unified search, CVE cards, threat actor profiles, hash rep, JA3, UA analysis
- `/threat-actors`, `/cve`, `/ja3-lookup` — redirects to `/intel` with hash anchor
- **Gap:** `/threat-actors`, `/cve`, `/ja3-lookup` are nav dead ends — should scroll to section on `/intel`
- **Gap:** No "Add to Locker" from intel results
- **Gap:** Intel results are synthetic — waiting on real backend

---

### Journey 6: Finding → Detection Rule

**Trigger:** Investigation identifies a malicious pattern.

```
Detection Workspace (/detection)
    │
    ├── Generate Sigma rule from description
    ├── Map finding to MITRE technique
    ├── Test Sigma rule against samples
    └── Save rule
    │
    ▼
Sigma Tester (/sigma-tester)
    │  paste rule + sample log → match results
    │
    ▼
MITRE (/mitre)
    │  browse techniques, check coverage
    │
    ▼
Case (/case) updated with detection rule + MITRE mapping
```

**Existing coverage:**
- `/detection` — rule generation from description, Sigma templates, MITRE mapping, testing
- `/sigma-tester` — separate route for testing Sigma against samples
- `/mitre` — technique browser with coverage indicators
- `/case` — can receive detection output
- **Gap:** No automatic "Push detection to Case" — manual copy
- **Gap:** Sigma Tester is a separate route (should be a panel in Detection Workspace)
- **Gap:** No saved rules repository — rules disappear on refresh

---

### Journey 7: Tool-Assisted Recon (Ad-Hoc)

**Trigger:** Analyst needs to gather intel on a target domain.

```
OSINT (/osint) → email/username/domain/phone lookup
    │
Recon (/recon) → subdomains, certs, cloud surface
    │
Nmap (/nmap) → port scan target
    │
Terminal (/terminal) → run custom tool commands
    │
Hacking Toolkit (/hacking-toolkit) → build command strings
    │
    ▼
Results are manual copy — no automatic case integration
```

**Existing coverage:**
- All tools exist as separate routes with functional UIs
- **Gap:** Tools produce no structured output — results are display-only
- **Gap:** No "Send to Case" for tool results (except manual copy)
- **Gap:** Some tools are aspirational vs operational (Nmap, Terminal depend on local tooling)

---

## Section 2 — Analyst Expectations

### Phishing Analysis

Analyst expects:
- ✅ Upload/paste `.eml`
- ✅ View sender, auth results (SPF, DKIM, DMARC)
- ✅ View body text
- ✅ Extract URLs + attachments
- ✅ Generate findings with verdict
- ⬜ One-click "Analyze extracted URL" → `/url`
- ⬜ One-click "Scan attachment" → `/attachment`
- ⬜ Structured findings as `Finding[]` type

### File Analysis

Analyst expects:
- ✅ Upload file
- ✅ Get hashes (MD5, SHA1, SHA256)
- ✅ View metadata, type, strings
- ✅ View suspicious findings
- ✅ One-click hash lookup → `/intel`
- ⬜ Add findings directly to case

### PCAP Analysis

Analyst expects:
- ✅ Upload .pcap
- ✅ View summary, conversations, DNS, HTTP, TLS
- ✅ Extract IOCs
- ✅ CLI mode for advanced analysis
- ⬜ MITRE technique mapping from traffic patterns
- ⬜ Structured evidence type

### Case Notebook

Analyst expects:
- ✅ Append entries (note, evidence, decision, action, IOC)
- ✅ View chronological timeline
- ✅ Tags and search
- ✅ Export as markdown, HTML, JSON
- ✅ Handoff report
- ⬜ Structured Evidence view (separate from timeline)
- ⬜ Structured Findings view
- ⬜ MITRE technique mapping per finding
- ⬜ Detection rule attachments

### Intel Search

Analyst expects:
- ✅ Search by IP, domain, hash, CVE, JA3
- ✅ View CVE details
- ✅ View threat actor profiles
- ✅ View hash reputation
- ⬜ Add intel results to locker
- ⬜ Add intel results to case

---

## Section 3 — Cross-Page Actions

| Page | Can produce | Can send to | Actions missing |
|------|------------|-------------|----------------|
| Phishing | `Finding[]`, `IOC[]`, `Artifact` | Case, Locker, Timeline | URL Analysis, File Analysis |
| File Analysis | `Evidence`, `IOC[]`, `Finding[]` | Locker, Intel, Case | Detection |
| URL Analysis | `IOC[]`, `Finding[]` | Locker, Case, Intel | — |
| PCAP | `Evidence`, `IOC[]`, `Finding[]` | Locker, Case, Timeline | MITRE |
| SIEM | `Finding[]`, `IOC[]` | Case | Triage, Detection |
| Triage | `Case` | Case (escalation) | Detection |
| Detection | `Rule` | Case | — |
| Intel | `Intel` | (none) | Locker, Case |
| Tools | (display only) | (none) | Case |

---

## Section 4 — Gap Audit

### Dead / Redundant Pages

| Page | Verdict | Reason |
|------|---------|--------|
| `/logs` | **REDUNDANT** | SIEM Workspace already has log viewer + event list. Log Explorer adds nothing unique. Merge into SIEM or remove. |
| `/sigma-tester` | **WEAK** | Should be a panel inside Detection Workspace, not a separate route. Entry in sidebar is confusing. |
| `/threat-actors` | **REDUNDANT** | Redirects to `/intel`. Remove from sidebar. |
| `/cve` | **REDUNDANT** | Redirects to `/intel`. Remove from sidebar. |
| `/ja3-lookup` | **REDUNDANT** | Redirects to `/intel`. Remove from sidebar. |
| `/hash-lookup` | **DEAD** | Removed from nav but route may still exist. Remove entirely. |

### Pages Missing Core Functionality

| Page | Missing |
|------|---------|
| `/siem` | Real backend integration (synthetic data only) |
| `/logs` | Real backend integration (synthetic data only) |
| `/intel` | Real backend integration (synthetic data only) |
| `/nmap` | Runtime error, no real scanning |
| `/terminal` | No real shell execution |

### Missing Feature: Shared Data Types

No page produces structured types that another page can consume. Every page:
- Writes freeform text to Case entries
- Pushes unstructured strings to Timeline
- Sends plain text to Locker

This prevents:
- Case from showing a dedicated Evidence view (no `Evidence` type)
- Detection from reading Findings from Case
- Intel from enriching IOCs inline (no `IOC` type with enrichment slot)
- Any automated workflow between pages

---

## Section 5 — Integration Contracts (What Types Page A Expects From Page B)

### Phishing → Case

```
Finding {
  id: string
  severity: "info" | "low" | "medium" | "high" | "critical"
  title: string
  detail: string
  source: string          // "spf", "dkim", "dmarc", "url", "attachment", "body_signal"
  technique?: string      // MITRE ID
}

IOC {
  value: string
  type: "ip" | "domain" | "url" | "hash_md5" | "hash_sha1" | "hash_sha256"
  context: string
  source: string
}

Artifact {
  id: string
  kind: "email" | "file" | "pcap" | "log"
  raw: string
  metadata: Record<string, string>
}
```

### Case → Report

```
Case {
  id: string
  title: string
  state: "active" | "closed"
  tags: string[]
  entries: Entry[]
  createdAt: string
}

Entry {
  id: string
  ts: string
  kind: "note" | "evidence" | "decision" | "action" | "ioc"
  body: string
}

Report → markdown with IOC summary, decisions, timeline, MITRE mapping
```

### SIEM → Case / Detection

```
SIEMFinding {
  severity: Severity
  title: string
  detail: string
  timestamp: string
  source_log: string
  extracted_iocs: IOC[]
  mitre_techniques: string[]
}
```

---

## Section 6 — Recommended Actions (Priority)

### P0 — Do Now

1. **Remove dead nav entries:** `/threat-actors`, `/cve`, `/ja3-lookup` from sidebar (keep routes as redirects)
2. **Merge `/sigma-tester`** into Detection Workspace as a panel, remove sidebar entry
3. **Fix `/nmap` runtime error** or hide it behind a "needs local tooling" warning

### P1 — Before New Features

4. **Define shared types** (`Finding`, `IOC`, `Evidence`, `Artifact`) in `types/security.ts`
5. **Refactor Phishing** to output `Finding[]` instead of inline DOM text
6. **Refactor File Analysis** to output `Evidence` + `Finding[]`

### P2 — Workflow Completion

7. Add "Send to URL Analysis" / "Scan Attachment" buttons from Phishing results
8. Add "Send to Triage" button from SIEM events
9. Add MITRE technique picker to PCAP findings
10. Add "Push to Case" to Intel results

### P3 — Identity / Polish

11. Design system: standardize page headers, cards, badges, empty states
12. Logo + color system (currently default shadcn)
