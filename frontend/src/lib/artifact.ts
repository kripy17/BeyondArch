import { RX, RX_MAC, RX_B64, scanCmdLines, type CmdFinding } from "@/data/parser";
import { SHORTENERS, SUSPICIOUS_TLDS, entropy, refang, scanSecrets, isAuthParamToken, type Secret } from "@/lib/ioc-patterns";
import { extractCommandLines, normalizeObservations, observationsFromIocs } from "@/lib/extraction";
import { runAnalysis, type MitreMapping } from "@/lib/analysis";
import { analyzeAndCorrelate, type CorrelationHistory, type CorrelationMatch } from "@/lib/correlation";
import type { AnalysisQuality, DetectionOpportunity, Finding, Observation, Recommendation, Relationship } from "@/types/objects";
import { MODERN_PATTERNS } from "@/lib/parser-engine";

/**
 * Parser orchestrator (ANALYSIS_ENGINE §4c pipeline). One entry point for the
 * parser surface: raw artifact → canonical Observation set via extraction →
 * Analysis Engine → Correlation. The page consumes this output; it never
 * computes findings, MITRE, recommendations, or relationships itself.
 *
 * Legacy regex IOC grouping, secrets, and command-line findings are kept as
 * presentation of extraction facts for the existing UI sections.
 */

export interface UrlAnalysisRow {
  value: string;
  host: string;
  tld?: string;
  ipBased: boolean;
  shortener: boolean;
  suspiciousTld: boolean;
  hasCreds: boolean;
  pathEntropy: number;
}

export interface ArtifactAnalysis {
  family: string;
  primary: string;
  reasons: string[];
  lines: number;
  total: number;
  iocs: Record<string, string[]>;
  secrets: Secret[];
  cmds: CmdFinding[];
  urlAnalysis: UrlAnalysisRow[];
  format: string;
  observations: Observation[];
  findings: Finding[];
  relationships: Relationship[];
  mitre: MitreMapping[];
  opportunities: DetectionOpportunity[];
  recommendations: Recommendation[];
  quality: AnalysisQuality;
  correlation: CorrelationMatch[];
  correlationRelationships: Relationship[];
}

export interface ArtifactOptions {
  source?: string;
  ts?: string;
  history?: CorrelationHistory;
}

function dedupObservations(obs: Observation[]): Observation[] {
  const seen = new Set<string>();
  return obs.filter((o) => {
    if (seen.has(o.id)) return false;
    seen.add(o.id);
    return true;
  });
}

export function analyzeArtifact(raw: string, opts: ArtifactOptions = {}): ArtifactAnalysis {
  const t = raw.trim();
  const source = opts.source ?? "parser";
  const ts = opts.ts;

  /* ── extraction facts (legacy regex regrouped for the UI) ── */
  const find = (re: RegExp) => Array.from(new Set(t.match(re) ?? []));
  const emails = find(RX.Email);
  const iocs: Record<string, string[]> = {
    URL: find(RX.URL),
    Domain: find(RX.Domain).filter(
      (d) => !isAuthParamToken(d) && !emails.some((e) => e.toLowerCase().includes(d.toLowerCase())),
    ),
    CIDR: find(MODERN_PATTERNS.CIDR),
    IPv4: find(RX.IPv4).filter((v) => v.split(/[.\[\]]/).every((x) => !x || +x <= 255)),
    MD5: find(RX.MD5).filter((h) => h.length === 32),
    SHA1: find(MODERN_PATTERNS.SHA1),
    SHA256: find(RX.SHA256),
    Email: find(RX.Email),
    Crypto: Array.from(new Set([
      ...find(MODERN_PATTERNS.CryptoBTC),
      ...find(MODERN_PATTERNS.CryptoXMR),
      ...find(MODERN_PATTERNS.CryptoETH),
    ])),
    Registry: find(MODERN_PATTERNS.RegistryKey),
    UNC: find(MODERN_PATTERNS.UNCPath),
    "AWS-ARN": find(MODERN_PATTERNS.AWSArn),
    JWT: find(MODERN_PATTERNS.JWT),
    CVE: find(RX.CVE),
    ATTACK: find(RX.ATTACK),
    MAC: Array.from(new Set(t.match(RX_MAC) ?? [])),
    Base64: Array.from(new Set((t.match(RX_B64) ?? []).filter((s) => s.length % 4 === 0 && !/^[a-f0-9]{32,64}$/i.test(s)))),
  };
  const lines = t.split("\n").length;
  const total = Object.values(iocs).reduce((a, b) => a + b.length, 0);

  let family = "Unknown / Notes";
  let primary = "Unknown Artifact";
  const reasons: string[] = [];
  if (/encrypted.*(?:aes|rsa|decrypt|wallet|btc|xmr)|ransom|all your files/i.test(t)) { family = "Ransomware / Extortion"; primary = "Ransom Note"; reasons.push("Extortion and ransom indicators present"); }
  else if (/eventSource.*amazonaws|userIdentity.*arn:aws/i.test(t)) { family = "Cloud / Audit Log"; primary = "AWS CloudTrail Event"; reasons.push("CloudTrail JSON structure detected"); }
  else if (/From:|Subject:|Authentication-Results/i.test(t)) { family = "Email / Phishing"; primary = "Suspicious Email"; reasons.push("Email envelope headers detected"); }
  else if (/Event ID:|sshd\[/.test(t)) { family = "Log / Endpoint"; primary = "Endpoint Log Event"; reasons.push("Log event grammar matched"); }
  else if (/event_type.*alert|signature/.test(t)) { family = "Network / Sensor"; primary = "Sensor Alert"; reasons.push("Suricata EVE JSON detected"); }
  else if (/^title:|detection:|condition:/m.test(t)) { family = "Detection Rule"; primary = "Sigma-like Rule"; reasons.push("Sigma keys present"); }
  else if (/^GET |^POST |^HTTP\/|sqlmap|User-Agent/i.test(t) && /HTTP\/\d\.\d/.test(t)) { family = "Web / Proxy Log"; primary = "HTTP Request Log"; reasons.push("Web log grammar detected"); }
  else if (/#fields\s+ts\s+uid|#path\s+conn\b|id\.orig_h\s+id\.resp_h/i.test(t)) { family = "Network / Zeek"; primary = "Zeek Connection Log"; reasons.push("Zeek TSV log grammar detected"); }
  else if (/^\s*type,\s*value,\s*source/i.test(t) && /,\s*[^,]+,\s*[^,]+,\s*/m.test(t) && /ipv4|sha256|domain/i.test(t)) { family = "Structured / CSV"; primary = "CSV IOC Sheet"; reasons.push("CSV header with IOC columns"); }
  else if (/^GET |^POST |^HTTP\/2\.\d/i.test(t) && /\[\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} \+0000\]/.test(t) && !/GET \/.*HTTP\/1\.\d/i.test(t)) { family = "Web / Proxy Log"; primary = "Nginx Access Log"; reasons.push("Combined log format (Nginx)"); }
  if (iocs.SHA256.length || iocs.MD5.length) reasons.push("File hashes recovered");
  if (iocs.URL.length) reasons.push("URLs extracted for safe review");

  const secrets = scanSecrets(t);
  const cmds = scanCmdLines(t);

  const urlAnalysis: UrlAnalysisRow[] = iocs.URL.flatMap((u) => {
    try {
      const parsed = new URL(refang(u));
      const host = parsed.hostname;
      const tld = host.split(".").pop()?.toLowerCase();
      return [{
        value: u, host, tld, ipBased: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host), shortener: SHORTENERS.has(host.replace(/^www\./, "")), suspiciousTld: tld ? SUSPICIOUS_TLDS.has(tld) : false, hasCreds: !!(parsed.username || parsed.password), pathEntropy: entropy(parsed.pathname + parsed.search),
      }];
    } catch { return []; }
  });

  /* ── canonical Observation set via extraction (§4b facade) ── */
  const norm = normalizeObservations(t, { source, ts });
  const bridged = observationsFromIocs(iocs, source, "legacy-parser", ts);
  const commands = norm.format === "text" ? extractCommandLines(t, source, ts) : [];
  const observations = dedupObservations([...norm.observations, ...bridged, ...commands]);

  /* ── Analysis Engine + correlation (post-analysis, local history) ── */
  const engine = analyzeAndCorrelate(observations, opts.history ?? {}, { source, ts });

  return {
    lines,
    total,
    iocs,
    secrets,
    cmds,
    urlAnalysis,
    format: norm.format,
    family,
    primary,
    reasons,
    observations,
    findings: engine.findings,
    relationships: [...engine.relationships, ...engine.correlationRelationships],
    mitre: engine.mitre,
    opportunities: engine.opportunities,
    recommendations: engine.recommendations,
    quality: engine.quality,
    correlation: engine.correlation,
    correlationRelationships: engine.correlationRelationships,
  };
}

/** Run analysis alone (no correlation) for pure reasoning checks. */
export function reasonArtifact(raw: string, opts: { source?: string; ts?: string } = {}): {
  observations: Observation[];
  findings: Finding[];
  mitre: MitreMapping[];
} {
  const { observations } = analyzeArtifact(raw, opts);
  const result = runAnalysis(observations, { source: opts.source ?? "parser", ts: opts.ts });
  return { observations, findings: result.findings, mitre: result.mitre };
}