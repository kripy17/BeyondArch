import { objectId } from "@/lib/ids";
import { analyzeAndCorrelate, type CorrelationHistory, type CorrelationMatch } from "@/lib/correlation";
import type { MitreMapping } from "@/lib/analysis";
import { normalizeObservations, makeObservation } from "@/lib/extraction";
import { parsePcapText, type PcapBackendResult, type ParsedText, type Finding as PcapFinding } from "@/data/pcap";
import type { AnalysisQuality, DetectionOpportunity, Finding, Observation, Recommendation, Relationship } from "@/types/objects";
import type { AnalysisSummary, EvidenceItem } from "@/types/analysis";
import type { Artifact, IOC } from "@/types/security";
import type { Severity } from "@/lib/severity";
import type {
  ZeekConn,
  ZeekDns,
  ZeekHttp,
  ZeekSsl,
  CredentialFinding,
  ExtractedFile,
} from "@/lib/pcap/zeek-models";
import { extractZeekFromText } from "@/lib/pcap/zeek-models";
import { generateRulesetFromPcap } from "@/lib/pcap/suricata-generator";

/**
 * PCAP orchestrator: capture analysis output (backend result or parsed
 * tcpdump/tshark text) → canonical Observation set (detection facts +
 * extraction facts) → Analysis Engine → correlation. The page consumes this
 * output; it never computes findings, MITRE, recommendations, or relationships
 * itself (ANALYSIS_ENGINE §4c, P11). Replaces the retired legacy pcap analyzer.
 */

export interface PcapAnalysisOptions {
  source?: string;
  ts?: string;
  history?: CorrelationHistory;
}

export interface PcapDisplayFinding {
  severity: Severity;
  title: string;
  reason: string;
  action: string;
  technique?: string;
  confidence?: Finding["confidence"];
}

export interface PcapAnalysisResult {
  id: string;
  analyzer: "pcap";
  artifact: Artifact;
  raw: string;
  findings: Finding[];
  iocs: IOC[];
  evidenceItems: EvidenceItem[];
  summary: AnalysisSummary;
  generatedAt: string;
  // page-specific fields
  backendResult?: PcapBackendResult;
  textAnalysis?: ParsedText;
  inputMode: "file" | "text";
  fileName?: string;
  totalPackets: number;
  uniqueIPs: number;
  findings2: PcapFinding[];
  displayFindings: PcapDisplayFinding[];
  mitre: MitreMapping[];
  // Zeek NSM protocol models & detections
  zeek_conn?: ZeekConn[];
  zeek_dns?: ZeekDns[];
  zeek_http?: ZeekHttp[];
  zeek_ssl?: ZeekSsl[];
  credentials?: CredentialFinding[];
  extracted_files?: ExtractedFile[];
  suricata_rules?: string[];
  // analysis-engine sections
  observations: Observation[];
  relationships: Relationship[];
  recommendations: Recommendation[];
  opportunities: DetectionOpportunity[];
  quality: AnalysisQuality;
  correlation: CorrelationMatch[];
  correlationRelationships: Relationship[];
}

const DEFAULT_TEXT_RECOMMENDATION = "Review connection against threat intelligence feeds and block if confirmed malicious.";
const DEFAULT_NO_SUSPICIOUS_TITLE = "No suspicious indicators detected";
const DEFAULT_NO_SUSPICIOUS_DETAIL = "Traffic patterns appear normal based on regex analysis.";
const DEFAULT_NO_SUSPICIOUS_ACTION = "Monitor for any unusual outbound connections.";
const T1071_FALLBACK: MitreMapping = {
  technique: "T1071",
  name: "Application Layer Protocol",
  tactic: "Command and Control",
  evidenceRefs: [],
  confidence: { level: "unknown", contributors: [] },
  source: "mitre-mapper",
};

function matchTechnique(title: string, detail: string): string | undefined {
  const t = title.toLowerCase();
  const d = detail.toLowerCase();
  if (t.includes("beaconing") || t.includes("c2")) return "T1071.001";
  if (d.includes("dns") || t.includes("dns_query")) return "T1572";
  if (d.includes("encrypted") || t.includes("tls")) return "T1573.001";
  if (t.includes("suspicious") || t.includes("malicious")) return "T1105";
  if (d.includes("http")) return "T1071.001";
  return undefined;
}

function detectionObservation(input: { title: string; detail: string; severity: Severity; occurrence: number }, source: string, ts?: string): Observation {
  const technique = matchTechnique(input.title, input.detail);
  const meta: Record<string, string> = {
    attr: "pcap-detection",
    severity: input.severity,
    title: input.title,
  };
  if (technique) meta.technique = technique;
  return makeObservation({
    kind: "string",
    value: `[${input.occurrence}] ${input.title}`,
    source,
    meta,
    ts,
  });
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

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function hashIocType(value: string): IOC["type"] {
  if (value.length === 32) return "md5";
  if (value.length === 40) return "sha1";
  return "sha256";
}

function toIocs(input: { ips: string[]; domains: string[]; urls?: string[]; hashes?: string[] }, source: string, verdict: string): IOC[] {
  const iocSev: Severity = verdict === "malicious" ? "high" : verdict === "suspicious" ? "medium" : "info";
  const result: IOC[] = [];
  for (const ip of input.ips) {
    result.push({ value: ip, type: "ipv4", context: "PCAP traffic", source, severity: iocSev });
  }
  for (const d of input.domains) {
    result.push({ value: d, type: "domain", context: "DNS query", source, severity: iocSev });
  }
  for (const u of input.urls ?? []) {
    result.push({ value: u, type: "url", context: "HTTP request", source, severity: iocSev });
  }
  for (const h of input.hashes ?? []) {
    result.push({ value: h, type: hashIocType(h), context: "PCAP payload", source, severity: iocSev });
  }
  return result;
}

function compose(opts: {
  mode: "file" | "text";
  title: string;
  raw: string;
  artifactId: string;
  analysisId: string;
  metadata: Record<string, string>;
  observations: Observation[];
  findings2: PcapFinding[];
  actionByTitle: Map<string, string>;
  totalPackets: number;
  uniqueIPs: number;
  fileName?: string;
  backendResult?: PcapBackendResult;
  textAnalysis?: ParsedText;
  zeek_conn?: ZeekConn[];
  zeek_dns?: ZeekDns[];
  zeek_http?: ZeekHttp[];
  zeek_ssl?: ZeekSsl[];
  credentials?: CredentialFinding[];
  extracted_files?: ExtractedFile[];
  suricata_rules?: string[];
  source: string;
  ts?: string;
  history?: CorrelationHistory;
  generatedAt: string;
}): PcapAnalysisResult {
  const { observations, actionByTitle } = opts;
  const engine = analyzeAndCorrelate(observations, opts.history ?? {}, { source: opts.source, ts: opts.ts });

  const displayFindings: PcapDisplayFinding[] = engine.findings.map((f) => ({
    severity: f.severity,
    title: f.title,
    reason: f.detail,
    action: actionByTitle.get(f.title) ?? DEFAULT_TEXT_RECOMMENDATION,
    technique: f.technique,
    confidence: f.confidence,
  }));
  displayFindings.sort(
    (a, b) =>
      Math.max(SEVERITY_ORDER.indexOf(a.severity), 0) - Math.max(SEVERITY_ORDER.indexOf(b.severity), 0),
  );

  const summary = summaryFrom(engine.findings);
  const iocs = toIocs(
    {
      ips: opts.backendResult ? opts.backendResult.iocs.ips : (opts.textAnalysis?.ips ?? []),
      domains: opts.backendResult ? opts.backendResult.iocs.domains : (opts.textAnalysis?.dnsQueries ?? []),
      urls: opts.backendResult?.iocs.urls,
      hashes: opts.backendResult?.iocs.hashes,
    },
    "/pcap",
    summary.verdict,
  );

  const mitre: MitreMapping[] = engine.mitre.length > 0 ? engine.mitre : [T1071_FALLBACK];

  const artifact: Artifact = {
    id: opts.artifactId,
    kind: "pcap",
    title: opts.title,
    metadata: opts.metadata,
    created: opts.generatedAt,
  };

  return {
    id: opts.analysisId,
    analyzer: "pcap",
    artifact,
    raw: opts.raw,
    findings: engine.findings,
    iocs,
    evidenceItems: [],
    summary,
    generatedAt: opts.generatedAt,
    backendResult: opts.backendResult,
    textAnalysis: opts.textAnalysis,
    inputMode: opts.mode,
    fileName: opts.fileName,
    totalPackets: opts.totalPackets,
    uniqueIPs: opts.uniqueIPs,
    findings2: opts.findings2,
    displayFindings,
    mitre,
    zeek_conn: opts.zeek_conn ?? opts.backendResult?.zeek_conn,
    zeek_dns: opts.zeek_dns ?? opts.backendResult?.zeek_dns,
    zeek_http: opts.zeek_http ?? opts.backendResult?.zeek_http,
    zeek_ssl: opts.zeek_ssl ?? opts.backendResult?.zeek_ssl,
    credentials: opts.credentials ?? opts.backendResult?.credentials,
    extracted_files: opts.extracted_files ?? opts.backendResult?.extracted_files,
    suricata_rules: opts.suricata_rules ?? opts.backendResult?.suricata_rules,
    observations,
    relationships: [...engine.relationships, ...engine.correlationRelationships],
    recommendations: engine.recommendations,
    opportunities: engine.opportunities,
    quality: engine.quality,
    correlation: engine.correlation,
    correlationRelationships: engine.correlationRelationships,
  };
}

/**
 * Backend-mode orchestrator: a PcapBackendResult from uploadPcap is a
 * measured detection record; each finding becomes a pcap-detection fact the
 * engine reasons over, and traffic facts (IPs, DNS queries, TLS SNI, URLs)
 * become observations.
 */
export function analyzePcapBackend(r: PcapBackendResult, opts: PcapAnalysisOptions = {}): PcapAnalysisResult {
  const source = opts.source ?? "pcap";
  const ts = opts.ts;
  const generatedAt = new Date().toISOString();

  const detectionObs = r.findings.map((f, i) => detectionObservation({ title: f.title, detail: f.detail, severity: f.severity, occurrence: i }, source, ts));

  const ipSet = new Set<string>([...r.iocs.ips, ...r.top_ips.map((t) => t.ip)]);
  const domainSet = new Set<string>([...r.iocs.domains, ...r.dns_queries, ...r.tls_server_names]);
  const trafficObs: Observation[] = [
    ...[...ipSet].map((ip) => makeObservation({ kind: "ip", value: ip, source, ts })),
    ...[...domainSet].map((d) => makeObservation({ kind: "domain", value: d, source, ts })),
    ...r.iocs.urls.map((u) => makeObservation({ kind: "url", value: u, source, ts })),
  ];

  const observations = dedupObservations([...trafficObs, ...detectionObs]);
  const actionByTitle = new Map(r.findings.map((f) => [f.title, f.recommendation]));

  const raw = JSON.stringify(r);
  const artifactId = objectId("artifact", "pcap", r.sha256, r.filename);
  return compose({
    mode: "file",
    title: r.filename,
    raw,
    artifactId,
    analysisId: objectId("analysis", "pcap", r.sha256),
    metadata: { packets: String(r.summary.packets), sha256: r.sha256 },
    observations,
    findings2: r.findings,
    actionByTitle,
    totalPackets: r.summary.packets,
    uniqueIPs: r.summary.unique_ips,
    fileName: r.filename,
    backendResult: r,
    zeek_conn: r.zeek_conn,
    zeek_dns: r.zeek_dns,
    zeek_http: r.zeek_http,
    zeek_ssl: r.zeek_ssl,
    credentials: r.credentials,
    extracted_files: r.extracted_files,
    suricata_rules: r.suricata_rules,
    source,
    ts,
    history: opts.history,
    generatedAt,
  });
}

/**
 * Text-mode orchestrator: pasted tcpdump/tshark output is parsed
 * deterministically (parsePcapText); the parsed suspicious indicators become
 * pcap-detection facts and extraction pulls canonical IPs/domains/URLs from
 * the raw text. Deterministic for identical input.
 */
export function analyzePcapText(text: string, opts: PcapAnalysisOptions = {}): PcapAnalysisResult {
  const source = opts.source ?? "pcap";
  const ts = opts.ts;
  const generatedAt = new Date().toISOString();
  const parsed = parsePcapText(text);
  const blank = !parsed || parsed.totalPackets === 0;
  const totalPackets = parsed?.totalPackets ?? 0;
  const uniqueIPs = parsed?.ips.length ?? 0;
  const raw = text;

  const detectionObs: Observation[] = blank
    ? []
    : parsed.suspicious.map((s, i) => detectionObservation({ title: s.indicator, detail: s.detail, severity: s.severity, occurrence: i }, source, ts));
  if (!blank && detectionObs.length === 0) {
    detectionObs.push(
      detectionObservation(
        { title: DEFAULT_NO_SUSPICIOUS_TITLE, detail: DEFAULT_NO_SUSPICIOUS_DETAIL, severity: "low", occurrence: 0 },
        source,
        ts,
      ),
    );
  }

  const norm = normalizeObservations(text, { source, ts });
  const observations = dedupObservations([...norm.observations, ...detectionObs]);

  const findings2: PcapFinding[] = blank
    ? []
    : parsed.suspicious.map((s) => ({
        severity: s.severity,
        title: s.indicator,
        detail: s.detail,
        recommendation: DEFAULT_TEXT_RECOMMENDATION,
      }));
  if (!blank && findings2.length === 0) {
    findings2.push({
      severity: "low",
      title: DEFAULT_NO_SUSPICIOUS_TITLE,
      detail: DEFAULT_NO_SUSPICIOUS_DETAIL,
      recommendation: DEFAULT_NO_SUSPICIOUS_ACTION,
    });
  }

  const actionByTitle = new Map(findings2.map((f) => [f.title, f.recommendation]));

  const zeekText = extractZeekFromText(text);
  const suricataRules = generateRulesetFromPcap(
    findings2,
    parsed?.topTalkers.map((t) => ({ src: t.ip, dst: "target", packets: t.packets })) ?? [],
    parsed?.dnsQueries ?? [],
    zeekText.http
  ).split("\n").filter((l) => l.startsWith("alert"));

  return compose({
    mode: "text",
    title: "Pasted output",
    raw,
    artifactId: objectId("artifact", "pcap", "text", String(totalPackets), String(uniqueIPs)),
    analysisId: objectId("analysis", "pcap", "text", String(totalPackets), String(uniqueIPs)),
    metadata: { packets: String(totalPackets), ips: String(uniqueIPs) },
    observations,
    findings2,
    actionByTitle,
    totalPackets,
    uniqueIPs,
    textAnalysis: parsed ?? undefined,
    zeek_conn: zeekText.conns,
    zeek_dns: zeekText.dns,
    zeek_http: zeekText.http,
    credentials: zeekText.creds,
    suricata_rules: suricataRules,
    source,
    ts,
    history: opts.history,
    generatedAt,
  });
}
