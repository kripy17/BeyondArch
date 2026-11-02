# Intel Domain Model

## Four Concepts

The Intelligence Hub operates across four distinct layers:

| Layer | Purpose | Examples | Lifecycle |
|---|---|---|---|
| **Observable** | Raw indicator observed in an investigation | IP, domain, hash, URL, email, process, mutex, registry key | Created by analyzers, consumed by Intel |
| **Intel Entity** | Object with accumulated intelligence and relationships | Threat Actor, Malware, CVE, JA3, known-bad hash | Persists, grows context over time |
| **Lookup Utility** | Stateless decoder / reference tool | User-Agent parser, hash calculator, base64, ASN, WHOIS | Answer a question, done |
| **Enrichment Source** | External provider that adds context to observables/entities | VirusTotal, AbuseIPDB, Shodan, AlienVault | Stateless per call, results attached |

Design principle: if a thing can become the center of an investigation, it is an Intel Entity. If it answers one question and you move on, it is a Lookup Utility.

### Ownership

| Layer | Owned by | Examples |
|---|---|---|
| Observable | Data producers (analyzers, tools, manual IOC entry) | `{ type: "sha256", value: "abc..." }` from log analyzer |
| Intel Entity | Intel Hub (persistent knowledge base) | Threat Actor, CVE, Malware with relationships |
| Lookup Utility | Intel module (stateless helpers) | UA decoder, hash calculator |
| Enrichment | External providers (stateless per call) | VirusTotal, AbuseIPDB, Shodan |
| Investigation | Case workspace | Findings, Timeline, Report |

---

## 1. Existing Sources Audit (Reclassified)

| Source | Former role | Correct classification | Rationale |
|---|---|---|---|
| CVE | Intel tab | Intel Entity | Becomes investigation center: patch priority, exploit chains, vendor context |
| Threat Actor | Intel tab | Intel Entity | Relationships, campaigns, tools, MITRE — rich context over time |
| Hash (known malicious) | Intel tab | Intel Entity | Linked to malware, campaigns, actors |
| Hash (unknown) | Intel tab | Observable + Lookup | Raw IOC; lookup returns "no matches" |
| JA3/JA4 | Intel tab | Intel Entity | Maps to malware family → C2 → campaigns → actor |
| User-Agent | Intel tab | Lookup Utility | Decode browser/OS/bot, answer question, done |

### CVE — Vulnerability (Intel Entity)

| Field | Type | Example |
|---|---|---|
| `id` | `string` | `"CVE-2024-1708"` |
| `description` | `string` | `"Path traversal in ScreenConnect"` |
| `cvss` | `number` (0–10) | `9.8` |
| `epss` | `number` (0–1) | `0.97` |
| `kev` | `boolean` | `true` |
| `exploit.metasploit` | `boolean` | |
| `exploit.nuclei` | `boolean` | |
| `exploit.exploitDb` | `boolean` | |
| `vendor` | `string` | `"ConnectWise"` |
| `published` | `string` (date) | `"2024-02-19"` |
| `affected` | `string` | `"ScreenConnect < 23.9.8"` |
| **Record count** | | 28 |

### Actor — Threat Actor (Intel Entity)

| Field | Type | Example |
|---|---|---|
| `name` | `string` | `"APT29"` |
| `aliases` | `string[]` | `["Cozy Bear", "The Dukes"]` |
| `origin` | `string` | `"Russia"` |
| `motivation` | `string` | `"Espionage"` |
| `firstSeen` | `string` (year) | `"2010"` |
| `techniques` | `string[]` | `["T1566", "T1059"]` |
| `campaigns` | `string[]` | `["SolarWinds", "Hammered"]` |
| `tools` | `string[]` | `["Cobalt Strike", "Beacon"]` |
| `targets` | `string[]` | `["Government", "Think Tanks"]` |
| **Record count** | | 24 |

### Hash — File (multi-role)

Hash spans all four layers depending on context:

- **Observable**: raw hash from an IOC list or analyzer output
- **Intel Entity**: known malicious hash with verdict, AV detections, malware family, relationships
- **Lookup**: unknown hash → query sources → "no matches" or "found"
- **Enrichment**: VirusTotal/AbuseIPDB lookup on a hash

| Field | Type | Example |
|---|---|---|
| `hash` | `string` (hex) | `d41d8cd98f00b204e9800998ecf8427e` |
| `type` | `"MD5" \| "SHA1" \| "SHA256" \| "SHA512"` | `"MD5"` |
| `verdict` | `"malicious" \| "suspicious" \| "clean" \| "unknown"` | `"malicious"` |
| `avDetections` | `number` (0–62) | `18` |
| `avTotal` | `number` (62) | `62` |
| `firstSeen` | `string` (date) | `"2023-11-14"` |
| `malware` | `string` | `"Cobalt Strike"` |
| **Data source** | Generated at lookup | ~15 malware families |

### JA3 / JA4 — TLS Fingerprint (Intel Entity)

JA3 becomes investigative: a suspicious fingerprint → malware family → C2 infrastructure → campaigns → actor → MITRE.

| Field | Type | Example |
|---|---|---|
| `hash` | `string` | `6734f37431670b3ab4292b8f60f29984` |
| `type` | `"JA3" \| "JA4"` | `"JA3"` |
| `malware` | `string` | `"Cobalt Strike"` |
| `firstSeen` | `string` (date) | `"2022-03-15"` |
| `lastSeen` | `string` (date) | `"2024-01-20"` |
| **Record count** | | 24 (20 JA3, 4 JA4) |

### UA — User-Agent (Lookup Utility)

Decoded, displayed, done. No reputation, no relationships, no investigation.

| Field | Type | Example |
|---|---|---|
| `ua` | `string` | `"Mozilla/5.0 ..."` |
| `type` | `string` | `"Browser"`, `"Bot"`, `"Scanner"` |
| `os` | `string` | `"Windows 10"` |
| `freq` | `"Very High" \| "High" \| "Medium" \| "Low"` | `"Very High"` |
| **Record count** | | 21 |

---

### Cross-Source Overlaps

| Shared value | Appears in |
|---|---|
| `"Cobalt Strike"` | Actor.tools, Hash.malware, JA3.malware |
| `"Emotet"` | Hash.malware, JA3.malware |
| `"TrickBot"` / `"Qakbot"` / `"Dridex"` etc. | Hash.malware, JA3.malware |
| MITRE ATT&CK IDs (e.g., `T1566`) | Actor.techniques |

No formal foreign keys exist. All cross-references are string-level overlaps.

---

## 2. Domain Model

### Observable

```typescript
interface Observable {
  id: string;
  type: "ipv4" | "ipv6" | "domain" | "url" | "email" | "sha256" | "sha1" | "md5" | "sha512"
       | "ja3" | "ja4" | "registry-key" | "process" | "mutex" | "file" | "text" | "unknown";
  value: string;
  source: string;          // which analyzer or tool produced this
  timestamp: string;
  context?: string;         // surrounding log entry or note
}
```

Observables are the output of analyzers and tools. They flow into the Intel Hub for enrichment. Multiple observables can map to the same Intel Entity.

### Intel Entity

```typescript
interface IntelEntityBase {
  id: string;
  label: string;
  summary: string;
  entityType: IntelEntityType;
  score: number;            // 0–100 relevance/severity
  confidence: "high" | "medium" | "low" | "unknown";
  tags: string[];
  lastSeen?: string;
  sourceCount: number;      // number of confirming sources
  observables: Observable[]; // derived IOCs that map to this entity
}

type IntelEntityType =
  | "vulnerability"
  | "threat-actor"
  | "malware"
  | "file-hash"
  | "tls-fingerprint";

// ── Vulnerability ──
interface VulnerabilityEntity extends IntelEntityBase {
  entityType: "vulnerability";
  cvss: number;
  epss: number;
  kev: boolean;
  exploits: { metasploit: boolean; nuclei: boolean; exploitDb: boolean };
  vendor: string;
  published: string;
  affected: string;
}

// ── Threat Actor ──
interface ThreatActorEntity extends IntelEntityBase {
  entityType: "threat-actor";
  aliases: string[];
  origin: string;
  motivation: string;
  firstSeen: string;
  techniques: string[];
  campaigns: string[];
  tools: string[];
  targets: string[];
}

// ── Malware (future) ──
interface MalwareEntity extends IntelEntityBase {
  entityType: "malware";
  aliases: string[];
  category: "ransomware" | "trojan" | "worm" | "loader" | "infostealer" | "rat" | "botnet" | "rootkit";
  platforms: string[];
  firstSeen: string;
  capabilities: string[];
}

// ── File Hash (known malicious) ──
interface FileHashEntity extends IntelEntityBase {
  entityType: "file-hash";
  hashType: "MD5" | "SHA1" | "SHA256" | "SHA512";
  hash: string;
  verdict: "malicious" | "suspicious";
  avDetections: number;
  avTotal: number;
  malware: string;          // malware family name
  firstSeen: string;
}

// ── TLS Fingerprint ──
interface TlsFingerprintEntity extends IntelEntityBase {
  entityType: "tls-fingerprint";
  hashType: "JA3" | "JA4";
  hash: string;
  malware: string;
  firstSeen: string;
  lastSeen: string;
}

type IntelEntity =
  | VulnerabilityEntity
  | ThreatActorEntity
  | MalwareEntity
  | FileHashEntity
  | TlsFingerprintEntity;
```

### Entity Detail

The detail view for any selected entity:

```typescript
interface IntelEntityDetail {
  entity: IntelEntity;
  overview: { label: string; value: string }[];
  observables: Observable[];    // derived IOCs linked to this entity
  relationships: IntelRelationship[];
  mitre: { id: string; name: string }[];
  evidence: { source: string; label: string; value: string }[];
  timeline: { time: string; event: string }[];
  externalSources: { name: string; url: string }[];
  actions: IntelAction[];
}

interface IntelRelationship {
  targetId: string;
  targetType: IntelEntityType;
  label: string;
  confidence: "high" | "medium" | "low";
}

type IntelAction =
  | { kind: "copy"; label: string; value: string }
  | { kind: "locker"; observable: Observable }
  | { kind: "export"; format: "md" | "csv" | "json" }
  | { kind: "send-to"; page: string; label: string; icon: LucideIcon }
  | { kind: "external-link"; label: string; url: string }
  | { kind: "enrich"; source: string };   // trigger enrichment
```

### Search Result Shape

```typescript
interface IntelSearchResult {
  query: string;
  detectedType?: Observable["type"];  // if query matches an observable pattern
  totalHits: number;
  entities: IntelEntityGroup[];
  lookups: LookupResult[];            // stateless lookup results inline
}

interface IntelEntityGroup {
  entityType: IntelEntityType;
  label: string;
  icon: LucideIcon;
  count: number;
  entities: IntelEntity[];
}
```

### Lookup Utility

```typescript
interface LookupTool {
  id: string;
  label: string;
  icon: LucideIcon;
  description: string;
  detect: (input: string) => boolean;   // does this input look like it?
  execute: (input: string) => LookupResult;
}

interface LookupResult {
  toolId: string;
  input: string;
  parsed: { label: string; value: string }[];
  done: boolean;  // true = answer complete, no further enrichment
}
```

Current lookup tools: User-Agent decoder.

Future: hash calculator, base64, ASN lookup, WHOIS, CIDR.

---

## 3. Relationship Graph

```
Observable (IOC from analyzer)
     |
     v
Intel Entity
     |
     ├── Vulnerability ←→ Exploit
     │
     ├── Threat Actor ──→ Malware ←── File Hash
     │       │               │
     │       │               └──── TLS Fingerprint
     │       │
     │       ├── Technique (MITRE ATT&CK)
     │       ├── Campaign
     │       └── Tool/Malware
     │
     ├── Malware ←── File Hash
     │       │
     │       └──── TLS Fingerprint
     │
     └── TLS Fingerprint ←── Malware
```

**Implicit relationships to surface:**

| From | To | Via | Confidence |
|---|---|---|---|
| Actor | Hash (malware) | Shared tool name `"Cobalt Strike"` | medium |
| Actor | JA3 | Shared malware `"Cobalt Strike"` | medium |
| Hash | JA3 | Shared malware family | medium |
| Actor | Actor | Shared technique, campaign, tool | high |
| Actor | CVE | Technique used maps to exploit | low (needs mapping) |

**Planned relationship types:**
- `"uses-tool"` — actor to malware
- `"associated-with"` — entity to campaign
- `"linked-to"` — hash to malware family
- `"implements"` — actor technique to MITRE ATT&CK
- `"resolves-to"` — domain/IP (future)
- `"originates-from"` — origin attribution

---

## 4. Search Pipeline

```
Raw query
   ↓
Type detection (auto-classify query):
   ├── CVE pattern (CVE-YYYY-NNNNN) → search vulnerability source
   ├── Hash pattern (hex, 32-128 chars) → search hash source
   ├── JA3 pattern (hex, 32 chars) → search TLS fingerprint source
   └── Free text → search ALL entity sources
   ↓
Parallel search across applicable sources
   ↓
Score + rank results
   ↓
Group by entityType
   ↓
Return IntelSearchResult
```

Type detection keeps search fast: if the query is a known pattern, only search relevant sources.

Implementation: unify into `src/data/intel/search.ts` with an in-memory index built at module init.

---

## 5. Supported Analyst Workflows

### Primary: "I have an indicator"

```
Analyst has an IOC from an investigation
   │
   ▼
Paste/type in Intel Hub search bar
   │
   ▼
Auto-detect type, search all sources
   │
   ▼
Results list grouped by entity type
   │
   ▼
Select result → detail panel
   │
   ├── Overview (summary, score, tags)
   ├── Observables (derived IOCs)
   ├── Relationships (linked entities)
   ├── MITRE (techniques)
   ├── Evidence (sources, reports)
   ├── Timeline (history)
   └── Actions (copy, locker, export, send-to, enrich)
```

### Secondary: "Browse known threats"

```
Land on Intel Hub
   │
   ▼
Default view shows recent/high-value entities across all types
   │
   ▼
Filter by entity type, score range, date range, tags
   │
   ▼
Scroll cards, expand for detail
```

### Tertiary: "Who uses this technique?"

```
Search MITRE ATT&CK ID (e.g., T1566)
   │
   ▼
See all actors using that technique
   │
   ▼
See CVEs related to that technique (future)
   │
   ▼
Follow actor → malware → JA3 → hash graph
```

---

## 6. Required UI Components

### New for Intel Hub

| Component | Purpose |
|---|---|
| `IntelSearchBar` | Unified search with type detection + results count |
| `IntelResultsList` | Heterogeneous results grouped by entity type |
| `IntelEntityCard` | Compact card per entity (type badge, label, summary, score) |
| `IntelDetailPanel` | Full entity detail with sections (slide-over or right pane) |
| `IntelRelationshipList` | Linked entities with confidence indicators |
| `IntelTimeline` | Chronological event history for an entity |

### Existing (reusable as-is)

| Component | Used as |
|---|---|
| `SectionBar` | Zone markers (Search → Results → Detail) |
| `SendToRow` | Action bar in detail panel |
| `Chip` | Entity type badges, severity, confidence |
| `Empty` | No-results state |
| `Panel` | Section containers within detail |

### Future

| Component | Purpose |
|---|---|
| `IntelRelationshipGraph` | Visual graph of entity relationships |
| `IntelEnrichmentPanel` | Trigger and view enrichment results |

---

## 7. Page Layout

Rough sketch of how the Intel Hub page is organized:

```
┌─────────────────────────────────────────────────────────┐
│  Intel Hub                         [lookup ▾] [enrich ▾]│
│  Search bar___________________________________________  │
│                                                         │
│  SectionBar — Intelligence                              │
│                                                         │
│  Results list (grouped by entity type):                 │
│                                                         │
│  [Vulnerabilities] 3 results                            │
│  ┌────────────────────────────────────────────────────┐ │
│  │ CVE-2024-1708  ScreenConnect Path Traversal   9.8  │ │
│  │ KEV · Metasploit · ConnectWise · 2024-02-19       │ │
│  └────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────┐ │
│  │ CVE-2023-3519  Citrix RCE                     9.8  │ │
│  │ KEV · Nuclei · Citrix · 2023-07-11                │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│  [Threat Actors] 2 results                              │
│  ┌────────────────────────────────────────────────────┐ │
│  │ APT29 / Cozy Bear  Russia · Espionage  ⚑ 10 tools │ │
│  │ T1566 T1059 T1078 · SolarWinds Hammered            │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│  ... (or if a single entity is selected, show detail)   │
│                                                         │
│  SectionBar — Detail                                    │
│  ┌────────────────────────────────────────────────────┐ │
│  │ APT29 / Cozy Bear / The Dukes                      │ │
│  │ Russia · Espionage · since 2010                     │ │
│  │                                                     │ │
│  │ Overview   Relationships   MITRE   Evidence         │ │
│  │                                                     │ │
│  │ T1566 Phishing           linked to 3 campaigns      │ │
│  │ T1059 Command & Script   linked to Cobalt Strike    │ │
│  │ T1078 Valid Accounts     linked to SolarWinds       │ │
│  │                                                     │ │
│  │ Related: Cobalt Strike (malware)  ▸                 │ │
│  │          SolarWinds (campaign)    ▸                 │ │
│  │          JA3: 6734f37...         ▸                 │ │
│  │                                                     │ │
│  │ [Copy] [Locker] [Export MD] [Send to ▸] [Enrich ▸]  │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│  SectionBar — Lookup (collapsible)                      │
│  User-Agent: [paste UA] → Decode                        │
│  Browser: Chrome 122 · OS: Windows 10 · Type: Browser   │
│                                                         │
│  SectionBar — Actions                                   │
│  [Send to Case] [Send to Detection] [Send to SIEM]      │
└─────────────────────────────────────────────────────────┘
```

Layout principles:
- Results list and Detail panel are mutually exclusive views of the same content zone
- Lookup section is collapsible, below intelligence results
- Actions bar is sticky at the bottom
- Typed-detection runs before search to scope the query

---

## 8. Migration Strategy

### Phase 0 — Extract lookup tools (no UI change)
- Move UA decoder into `src/data/intel/lookups.ts`
- Create `LookupTool` interface
- UA still renders in existing Ja3Tab but backed by new tool system

### Phase 1 — Search unification (no UI change)
- Create `src/data/intel/search.ts` with unified `searchIntel()`
- Index all entity sources at module init
- Back existing tabs with unified search internally

### Phase 2 — New Intel Hub layout
- Replace 4-tab layout with: search bar → results list → detail panel
- Remove `CveTab`, `ActorsTab`, `HashTab`, `Ja3Tab` components
- UA moves to collapsible lookup section at bottom
- Keyboard shortcuts: j/k navigate, esc close, y copy

### Phase 3 — Detail panel + relationships
- Click result → detail slide-over or right pane
- Relationship discovery (cross-source string matching)
- MITRE technique resolution
- Timeline events for entity views/actions

### Phase 4 — Enrichment
- Observable→IntelEntity mapping from incoming IOCs
- External enrichment source integration (VirusTotal, etc.)
- Bulk enrichment from search results

---

## 9. Open Questions

1. **Should the detail panel be a route (`/intel/:id`) or a slide-over?** Route enables linkability and sharing. Slide-over preserves search context. Solution: both — nested route renders a slide-over panel over the search results page.

2. **When a hash is pasted, should we auto-lookup or require a button press?** Auto-lookup gives instant feedback but could trigger slow enrichment. Rule: local sources auto-lookup (within 50ms), external enrichment requires explicit action.

3. **What happens when search matches 100+ results?** 28 CVEs + 24 actors + 24 JA3s = 76 max with current data. Hash is the only unbounded source. Cap hash results at top 25, show "more results available" banner.

4. **Where does Malware entity data come from?** Currently no malware source exists — only string references in Actor.tools, Hash.malware, and JA3.malware. A Malware entity type is defined but needs its own data source (future).

5. **How do observables from analyzers reach the Intel Hub?** They need a handoff mechanism similar to `sendArtifact` — an `ingestArtifact` function that accepts an `Observable`, searches for matching entities, and optionally creates a session context. This is deferred.

6. **Should the Intel Hub track search/view history?** Yes — timeline events for searches and entity views enable session continuity and the "recently viewed" starting state.

7. **What is the migration impact on existing locker and timeline events?** Timeline events currently reference `source: "/intel"` with verb/detail. After migration, entity type should be encoded in the detail field for cross-referencing. Locker items remain unchanged (they already use typed values).
