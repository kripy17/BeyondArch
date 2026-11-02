import { objectId } from "@/lib/ids";
import { analyzeAndCorrelate, type CorrelationHistory, type CorrelationMatch } from "@/lib/correlation";
import type { MitreMapping } from "@/lib/analysis";
import { LOG_RULES, type LogRule } from "@/lib/analysis/log-rules";
import { normalizeObservations, makeObservation } from "@/lib/extraction";
import type { AnalysisQuality, DetectionOpportunity, Finding, Observation, Recommendation, Relationship } from "@/types/objects";
import type { AnalysisSummary, EvidenceItem } from "@/types/analysis";
import type { Artifact, IOC } from "@/types/security";
import type { Severity } from "@/lib/severity";

/**
 * Logs orchestrator: raw log text → canonical Observation set (extraction
 * facts + log-event facts) → Analysis Engine → correlation. The page consumes
 * this output; it never computes findings, MITRE, recommendations, or
 * relationships itself (ANALYSIS_ENGINE §4c, P11). Replaces the retired
 * data/analyzers/logs.ts legacy analyzer.
 */

export interface LogsAnalysisInput {
  logData: string;
  committed: boolean;
}

export interface LogsAnalysisOptions {
  source?: string;
  ts?: string;
  history?: CorrelationHistory;
}

export interface LogMatch {
  rule: LogRule;
  line: number;
  context: string;
}

export interface LogSummary {
  totalLines: number;
  matchedLines: number;
  uniqueEventIds: string[];
  uniqueUsers: string[];
  uniqueIPs: string[];
  uniqueHosts: string[];
  uniqueProcesses: string[];
  timeline: { line: number; label: string; severity: Severity }[];
}

export interface DisplayFinding {
  severity: Severity;
  title: string;
  reason: string;
  action: string;
  technique?: string;
  confidence?: Finding["confidence"];
}

export interface LogsAnalysisResult {
  id: string;
  analyzer: "logs";
  artifact: Artifact;
  raw: string;
  findings: Finding[];
  iocs: IOC[];
  evidenceItems: EvidenceItem[];
  summary: AnalysisSummary;
  generatedAt: string;
  matches: LogMatch[];
  logSummary: LogSummary;
  mitre: MitreMapping[];
  displayFindings: DisplayFinding[];
  // analysis-engine sections
  observations: Observation[];
  relationships: Relationship[];
  recommendations: Recommendation[];
  opportunities: DetectionOpportunity[];
  quality: AnalysisQuality;
  correlation: CorrelationMatch[];
  correlationRelationships: Relationship[];
}

const LOLBIN_LIST = [
  "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
  "regsvr32.exe", "rundll32.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe",
  "msiexec.exe", "scrcons.exe", "schtasks.exe", "net.exe", "net1.exe",
  "nslookup.exe", "ping.exe", "arp.exe", "tracert.exe",
];

const AMSI_KEYWORDS = ["amsiutils", "amsiinitfailed", "system.management.automation.amsiutils", "amsi"];
const SUSPICIOUS_USER_AGENTS = ["sqlmap", "nmap", "nikto", "python-requests", "curl/", "wget/", "go-http-client"];
const RX_IPV4_INLINE = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
const RX_BASE64_INLINE = /[A-Za-z0-9+/]{40,}={0,2}/;

function extractIPs(text: string): string[] {
  return [...new Set(text.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) ?? [])];
}

function extractUsers(text: string): string[] {
  const userRx = /\b(?:User|Account|AccountName):\s*(\S+)\b|\\\\\w+\\(\w+)\b/g;
  const users = [...text.matchAll(userRx)].map((m) => m[1] || m[2]).filter(Boolean);
  return [...new Set(users)];
}

function extractHosts(text: string): string[] {
  const hostRx = /\b(?:Computer|ComputerName|Workstation|Host):\s*(\S+)\b|(?:\w+\\)(\w+(?:\.\w+)+)\b/g;
  const hosts = [...text.matchAll(hostRx)].map((m) => m[1] || m[2]).filter(Boolean);
  return [...new Set(hosts)];
}

function extractProcesses(text: string): string[] {
  const procRx = /\b(?:Process|Image|ProcessName):\s*(\\\\(?:[^\\]+\\)*)?(\S+\.\w+)\b/gi;
  const procs = [...text.matchAll(procRx)].map((m) => m[2] || m[1]).filter(Boolean);
  return [...new Set(procs)];
}

function scanLine(line: string): LogRule[] {
  const matched: LogRule[] = [];
  const upper = line.toUpperCase();

  for (const rule of LOG_RULES) {
    const eid = rule.eventId;

    if (eid === "encoded_cmd" && RX_BASE64_INLINE.test(line) &&
        (upper.includes("POWERSHELL") || upper.includes("-ENCODEDCOMMAND") || upper.includes("-ENC "))) {
      matched.push(rule);
      continue;
    }

    if (eid === "lolbin_exec") {
      if (LOLBIN_LIST.some((lb) => upper.includes(lb.toUpperCase()))) {
        if (!matched.some((m) => m.eventId === "lolbin_exec")) matched.push(rule);
      }
      continue;
    }

    if (eid === "amsi_bypass") {
      if (AMSI_KEYWORDS.some((a) => upper.includes(a.toUpperCase()))) {
        matched.push(rule);
        continue;
      }
    }

    if (eid === "brute_force") {
      if ((upper.includes("4625") || upper.includes("FAILED LOGIN") || upper.includes("AUTH FAILURE")) && RX_IPV4_INLINE.test(line)) {
        matched.push(rule);
        continue;
      }
    }

    if (eid === "suspicious_reg_run") {
      if (/\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce)/i.test(line) &&
          (upper.includes("4657") || upper.includes("REG ADD") || upper.includes("REG IMPORT"))) {
        matched.push(rule);
        continue;
      }
    }

    if (eid === "suspicious_user_agent") {
      if (upper.includes("USER-AGENT") || upper.includes("USER_AGENT")) {
        if (SUSPICIOUS_USER_AGENTS.some((ua) => upper.includes(ua.toUpperCase()))) {
          matched.push(rule);
          continue;
        }
      }
    }

    if (eid === "wmi_persistence") {
      if ((upper.includes("WMI") || upper.includes("ROOT\\SUBSCRIPTION")) &&
          (upper.includes("__EVENTFILTER") || upper.includes("__FILTERTOCONSUMERBINDING"))) {
        matched.push(rule);
        continue;
      }
    }

    if (eid === "5156" || eid === "5158") {
      if (upper.includes(eid) && RX_IPV4_INLINE.test(line)) {
        matched.push(rule);
        continue;
      }
    }

    if (upper.includes(eid)) {
      matched.push(rule);
    }
  }

  return matched;
}

function dedupObservations(obs: Observation[]): Observation[] {
  const seen = new Set<string>();
  return obs.filter((o) => {
    if (seen.has(o.id)) return false;
    seen.add(o.id);
    return true;
  });
}

function summaryFrom(findings: Finding[]): AnalysisSummary {
  const crit = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const med = findings.filter((f) => f.severity === "medium").length;
  const score = Math.min(100, crit * 25 + high * 12 + med * 5);
  const verdict = crit > 0 ? "malicious" : high > 0 ? "suspicious" : med > 0 ? "suspicious" : "clean";
  const confidence = findings.some((f) => f.confidence?.level === "high")
    ? 0.85
    : findings.some((f) => f.confidence?.level === "medium")
      ? 0.65
      : findings.length > 0
        ? 0.35
        : 0.15;
  return { verdict, score, confidence };
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "info"];

/**
 * Logs orchestrator: same input → same ids and findings. Null when the input
 * is not committed or empty. Matches / evidence stay 1:1 with the retired
 * legacy analyzer so page behavior is unchanged.
 */
export function analyzeLogArtifact(input: LogsAnalysisInput, opts: LogsAnalysisOptions = {}): LogsAnalysisResult | null {
  const { logData, committed } = input;
  if (!committed || !logData.trim()) return null;

  const source = opts.source ?? "logs";
  const ts = opts.ts;
  const lines = logData.split("\n");
  const totalLines = lines.length;
  const generatedAt = new Date().toISOString();

  /* ── extraction facts: raw match sweep (never infers intent) ── */
  const matches: LogMatch[] = [];
  for (let i = 0; i < totalLines; i++) {
    for (const rule of scanLine(lines[i])) {
      matches.push({ rule, line: i + 1, context: lines[i].trim().slice(0, 120) });
    }
  }

  const uniqueEventIds = [...new Set(matches.map((m) => m.rule.eventId))];
  const uniqueUsers = extractUsers(logData);
  const uniqueIPs = extractIPs(logData);
  const uniqueHosts = extractHosts(logData);
  const uniqueProcesses = extractProcesses(logData);
  const matchedLines = new Set(matches.map((m) => m.line)).size;

  const timeline = matches
    .filter((m, idx, arr) => arr.findIndex((a) => a.line === m.line) === idx)
    .map((m) => ({ line: m.line, label: m.rule.title, severity: m.rule.severity }));

  const dedupedMatches: LogMatch[] = [];
  const seen = new Set<string>();
  for (const m of matches) {
    const key = `${m.rule.eventId}:${m.line}`;
    if (!seen.has(key)) {
      seen.add(key);
      dedupedMatches.push(m);
    }
  }

  /* ── canonical Observation set via extraction (§4b facade) ── */
  const norm = normalizeObservations(logData, { source, ts });
  const eventObs = dedupedMatches.map((m) =>
    makeObservation({
      kind: "string",
      value: `[${m.rule.eventId}] line ${m.line}: ${m.context}`,
      source,
      meta: {
        attr: "log-event",
        eventId: m.rule.eventId,
        rule: m.rule.title,
        line: String(m.line),
        severity: m.rule.severity,
      },
      ts,
    }),
  );
  const observations = dedupObservations([...norm.observations, ...eventObs]);

  /* ── Analysis Engine + correlation (post-analysis, local history) ── */
  const engine = analyzeAndCorrelate(observations, opts.history ?? {}, { source, ts });

  /* ── presentation mapping (engine conclusions + extraction facts) ── */
  const summary = summaryFrom(engine.findings);
  const findingByTitle = new Map(engine.findings.map((f) => [f.title, f]));

  const ruleCounts = new Map<string, number>();
  for (const m of dedupedMatches) {
    const id = m.rule.eventId;
    ruleCounts.set(id, (ruleCounts.get(id) || 0) + 1);
  }

  const displayFindings: DisplayFinding[] = [];
  for (const rule of LOG_RULES) {
    const count = ruleCounts.get(rule.eventId);
    if (!count) continue;
    const f = findingByTitle.get(rule.title);
    displayFindings.push({
      severity: rule.severity,
      title: rule.title,
      reason: `${count} occurrence${count > 1 ? "s" : ""} — ${rule.reason}`,
      action: rule.action,
      technique: f?.technique ?? rule.mitre.id,
      confidence: f?.confidence,
    });
  }
  displayFindings.sort(
    (a, b) =>
      Math.max(SEVERITY_ORDER.indexOf(a.severity), 0) - Math.max(SEVERITY_ORDER.indexOf(b.severity), 0),
  );

  const iocSeverity: Severity = summary.verdict === "malicious" ? "high" : summary.verdict === "suspicious" ? "medium" : "info";

  const iocs: IOC[] = [
    ...uniqueIPs.map((ip) => ({ value: ip, type: "ipv4" as const, context: "Extracted from log data", source: "/logs", severity: iocSeverity })),
    ...uniqueHosts.map((h) => ({ value: h, type: "domain" as const, context: "Host extracted from log data", source: "/logs", severity: iocSeverity })),
  ];

  const artifact: Artifact = {
    id: objectId("artifact", "log", source, String(totalLines), uniqueEventIds.join("|")),
    kind: "log",
    title: `Log Analysis — ${totalLines} lines`,
    metadata: {
      totalLines: String(totalLines),
      matchedLines: String(matchedLines),
      uniqueEventIds: uniqueEventIds.join(", "),
      uniqueIPs: String(uniqueIPs.length),
    },
    created: generatedAt,
  };

  const evidenceItems: EvidenceItem[] = dedupedMatches
    .filter((_, i) => i < 50)
    .map((m) => ({
      type: "log_match",
      title: `[${m.rule.severity.toUpperCase()}] ${m.rule.title}`,
      detail: `Line ${m.line}: ${m.context}`,
      source,
    }));

  const logSummary: LogSummary = {
    totalLines,
    matchedLines,
    uniqueEventIds,
    uniqueUsers,
    uniqueIPs,
    uniqueHosts,
    uniqueProcesses,
    timeline,
  };

  return {
    id: objectId("analysis", "logs", String(totalLines), uniqueEventIds.join("|")),
    analyzer: "logs",
    artifact,
    raw: logData,
    findings: engine.findings,
    iocs,
    evidenceItems,
    summary,
    generatedAt,
    matches: dedupedMatches,
    logSummary,
    mitre: engine.mitre,
    displayFindings,
    observations,
    relationships: [...engine.relationships, ...engine.correlationRelationships],
    recommendations: engine.recommendations,
    opportunities: engine.opportunities,
    quality: engine.quality,
    correlation: engine.correlation,
    correlationRelationships: engine.correlationRelationships,
  };
}