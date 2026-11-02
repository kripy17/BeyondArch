# AnalysisResult Specification

## Purpose

`AnalysisResult` is the universal output contract for every analyzer in BeyondLabs.
Every analyzer — Phishing, URL, File, Logs, PCAP, and any future analyzer — must
return an object that structurally satisfies this contract.

This document defines the contract field by field so that consumers
(the Case Factory, Investigation Workspace, Report Generator, etc.) can rely on
semantically equivalent data regardless of which analyzer produced it.

---

## The Contract

Defined in `types/analysis.ts`:

```ts
interface AnalysisResult {
  id: string;
  analyzer: string;
  artifact: Artifact;
  raw: string;
  findings: Finding[];
  iocs: IOC[];
  evidenceItems: EvidenceItem[];
  summary: AnalysisSummary;
  generatedAt: string;
}
```

---

## Fields

### `id`

| | |
|---|---|
| **Type** | `string` |
| **Required** | yes |
| **Format** | UUID v4 via `crypto.randomUUID()` |
| **Meaning** | Unique identifier for this analysis result instance |
| **Invariant** | Must be unique per invocation |

---

### `analyzer`

| | |
|---|---|
| **Type** | `string` |
| **Required** | yes |
| **Allowed values** | `"phishing"`, `"url"`, `"file"`, `"logs"`, `"pcap"` |
| **Meaning** | Identifies which analyzer produced this result |

---

### `artifact`

| | |
|---|---|
| **Type** | `Artifact` (from `types/security.ts`) |
| **Required** | yes |
| **Meaning** | The subject of the analysis — what was analyzed |

**`Artifact` shape:**

```ts
{
  id: string;                // UUID v4
  kind: "email" | "url" | "file" | "log" | "pcap";
  title: string;             // Human-readable label
  metadata: Record<string, string>;  // Analyzer-specific properties
  created: string;           // ISO 8601 timestamp
}
```

**Invariants:**
- `metadata` values are always strings (cast with `String()` if needed)
- `metadata` field names use camelCase consistently

---

### `raw`

| | |
|---|---|
| **Type** | `string` |
| **Required** | yes |
| **Meaning** | The original raw input provided to the analyzer |

**Per analyzer:**
- phishing: full email source text
- url: the raw URL string (not refanged)
- file: file content only (filename is in `artifact.title` and page-specific fields)
- logs: full log text

---

### `findings`

| | |
|---|---|
| **Type** | `Finding[]` (from `types/security.ts`) |
| **Required** | yes |
| **Meaning** | Structured findings produced by the analyzer |

**`Finding` shape:**

```ts
{
  id: string;                    // UUID v4
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;                 // Short human-readable name
  detail: string;                // Explanation of the finding
  source: string;                // Analyzer identifier or sub-component
  technique?: string;            // MITRE ATT&CK ID (optional, but should be populated when applicable)
}
```

**Invariants:**
- `severity` MUST use the canonical `Severity` type — never UI tone values (`"destructive"`, `"warning"`, `"success"`)
- `technique` SHOULD be populated when a relevant MITRE technique exists
- `technique` MUST correlate to the specific finding, not the first MITRE entry globally

---

### `iocs`

| | |
|---|---|
| **Type** | `IOC[]` (from `types/security.ts`) |
| **Required** | yes |
| **Meaning** | Indicators of Compromise extracted during analysis |

**`IOC` shape:**

```ts
{
  value: string;     // The indicator value (IP, domain, hash, URL, email, etc.)
  type: IocType;     // "ipv4" | "domain" | "url" | "email" | "sha256" | "md5" | "sha1" | "cve" | "unknown"
  context: string;   // How the IOC was found
  source: string;    // Path of the analyzer (e.g., "/phishing", "/url")
  severity: Severity; // "critical" | "high" | "medium" | "low" | "info"
}
```

**Invariants:**
- `severity` MUST derive from the overall analysis verdict or associated finding severity — never hardcoded to `"info"`
  - `verdict === "malicious"` → `severity = "high"`
  - `verdict === "suspicious"` → `severity = "medium"`
  - `verdict === "clean"` → `severity = "info"`

---

### `evidenceItems`

| | |
|---|---|
| **Type** | `EvidenceItem[]` (from `types/analysis.ts`) |
| **Required** | yes |
| **Meaning** | Lightweight evidence entries for the Case workspace |

**`EvidenceItem` shape:**

```ts
{
  type: "finding" | "secret" | "log_match" | string;
  title: string;
  detail: string;
  source: string;
}
```

**Invariants:**
- `type` should be descriptive but consistent — prefer `"finding"` for general findings, `"secret"` for credential exposure
- `source` should be the analyzer name (e.g., `"phishing"`, `"url"`, `"file"`, `"logs"`)

---

### `summary`

| | |
|---|---|
| **Type** | `AnalysisSummary` (from `types/analysis.ts`) |
| **Required** | yes |

**`AnalysisSummary` shape:**

```ts
{
  verdict: "clean" | "suspicious" | "malicious" | "inconclusive";
  score: number;       // 0–100
  confidence: number;  // 0–1 (represented as 0–100 in future)
}
```

---

### `generatedAt`

| | |
|---|---|
| **Type** | `string` |
| **Required** | yes |
| **Format** | ISO 8601 via `new Date().toISOString()` |
| **Meaning** | Timestamp when the analysis was performed |

---

## Verdict Definitions

| Verdict | Meaning | Example thresholds |
|---|---|---|
| `"clean"` | No suspicious signals detected | 0 findings, score ≈ 0 |
| `"suspicious"` | Some low/medium risk signals present | medium findings > 0, no critical |
| `"malicious"` | Critical or high-confidence signals present | critical findings > 0 |
| `"inconclusive"` | Insufficient data to determine | Phishing-specific: no auth signals |

---

## Scoring Formula

All analyzers use the same weighted formula:

```
score = min(100, critical_count * 25 + high_count * 12 + medium_count * 5)
```

Where:
- `critical_count` = number of findings with `severity === "critical"`
- `high_count` = number of findings with `severity === "high"`
- `medium_count` = number of findings with `severity === "medium"`

Score is clamped to 0–100.

---

## Confidence Formula

All analyzers use the same tiered formula:

| Condition | Confidence |
|---|---|
| At least one critical finding | 0.85 |
| At least one high finding | 0.65 |
| At least one medium finding | 0.35 |
| At least one low/info finding | 0.15 |
| No findings at all | 0.05 |

Confidence is 0–1.

---

## Severity Values

Canonical severity type for `Finding.severity` and `IOC.severity`:

```ts
type Severity = "critical" | "high" | "medium" | "low" | "info";
```

UI components are responsible for mapping severity to display tones
(`"destructive"`, `"warning"`, `"success"`, etc.). The data layer never uses
UI tone values.

---

## MITRE ATT&CK Mapping

Each finding SHOULD be associated with its relevant MITRE ATT&CK technique.

### Rules

- `Finding.technique` MUST reference the technique relevant to THAT specific finding
- `Finding.technique` MUST NOT be set to the first MITRE entry in the analyzer's global array
- Each analyzer SHOULD maintain a title-to-technique mapping for correct correlation

**Preferred pattern:**

```ts
const FINDING_TECHNIQUE: Record<string, string | undefined> = {
  "Finding Title": "TXXXX",
};

findings: Finding[] = displayFindings.map(f => ({
  ...
  technique: FINDING_TECHNIQUE[f.title],
}));
```

---

## Page-Specific Fields

Analyzers may return additional fields beyond the `AnalysisResult` contract
for page-specific rendering. These fields:

- MUST NOT duplicate information already present in `AnalysisResult` fields
- MUST NOT be used by cross-analyzer consumers (Case Factory, Report Generator)
- SHOULD be prefixed or named clearly to indicate their domain specificity

---

## Compliance Checklist

Every analyzer must pass before being accepted:

```
□ Produces valid AnalysisResult (all required fields present)
□ summary.verdict is one of: "clean", "suspicious", "malicious", "inconclusive"
□ Finding.severity uses canonical Severity values only
□ Finding.technique is correctly correlated (not always first MITRE entry)
□ IOC.severity derives from verdict, not hardcoded
□ score uses the standard formula (25/12/5 weights)
□ confidence uses the standard tiered formula
□ Can create a Case via createCaseFromAnalysis()
□ Export produces valid JSON
```

---

## Changelog

| Date | Change |
|---|---|
| 2026-07-15 | Initial specification — standardizes verdicts, severity, scoring, confidence, IOC severity, MITRE mapping |
