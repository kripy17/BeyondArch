import { objectId } from "@/lib/ids";
import { analyzeAndCorrelate, type CorrelationHistory, type CorrelationMatch } from "@/lib/correlation";
import { normalizeObservations, makeObservation } from "@/lib/extraction";
import { refang, entropy, domainEntropy, scanSecrets, SUSPICIOUS_TLDS, SHORTENERS } from "@/lib/ioc-patterns";
import { URL_SIGNAL_MAP } from "@/lib/analysis/url-rules";
import type { AnalysisQuality, DetectionOpportunity, Finding as EngineFinding, Observation, Recommendation, Relationship } from "@/types/objects";
import type { AnalysisSummary, EvidenceItem } from "@/types/analysis";
import type { Artifact, IOC } from "@/types/security";
import type { Finding } from "@/types/security";
import type { UrlAnalysisResult, UrlKnowledge } from "@/types/url";
import type { Severity } from "@/lib/severity";
import {
  buildUrlKnowledge, downloadFileName, urlPayloadMarkers, FILE_EXT_RX, NUMERIC_IP_RX,
  SUSPICIOUS_PATHS, SUSPICIOUS_PORT_WARN, TRACKING_PARAMS, BASE64_PATH_RX,
} from "@/data/url";

/**
 * URL orchestrator: refanged input URL → measured URL facts (extraction
 * observations + url-detection signals) → Analysis Engine → correlation.
 * The page consumes this output; it never computes findings, MITRE, or
 * recommendations itself (ANALYSIS_ENGINE §4c, P11). Replaces the retired
 * legacy url analyzer. Deterministic for identical input (objectId ids, no
 * crypto.randomUUID()).
 */

export interface UrlArtifactOptions {
  source?: string;
  ts?: string;
  history?: CorrelationHistory;
}

export interface UrlArtifactResult extends UrlAnalysisResult {
  // analysis-engine sections
  observations: Observation[];
  relationships: Relationship[];
  recommendations: Recommendation[];
  opportunities: DetectionOpportunity[];
  quality: AnalysisQuality;
  correlation: CorrelationMatch[];
  correlationRelationships: Relationship[];
}

type UrlSeverity = "destructive" | "warning" | "info";

interface Signal {
  severity: UrlSeverity;
  title: string;
  reason: string;
  action: string;
  technique?: string;
}

const HOST_SIGNALS = ["Punycode host", "Excessive subdomain depth", "Suspicious TLD", "Direct IP address as hostname", "URL shortener"];

function summaryFrom(findings: EngineFinding[]): AnalysisSummary {
  const crit = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const med = findings.filter((f) => f.severity === "medium").length;
  const score = Math.min(100, crit * 25 + high * 12 + med * 5);
  const verdict = crit > 0 ? "malicious" : high > 0 || med > 0 ? "suspicious" : "clean";
  const confidence = findings.some((f) => f.confidence?.level === "high")
    ? 0.85
    : findings.some((f) => f.confidence?.level === "medium")
      ? 0.65
      : findings.length > 0
        ? 0.35
        : 0.15;
  return { verdict, score, confidence };
}

/** Map legacy display tone → engine severity band (url-rules). */
function engineSeverity(display: UrlSeverity): Severity {
  return display === "destructive" ? "critical" : display === "warning" ? "medium" : "info";
}

/**
 * Compute deterministic signals for a parsed URL, mirroring the legacy url
 * analyzer's rule table (titles, reasons, actions, and technique mapping) so
 * the page UI is unchanged. Dynamic fragments (TLD, file extension, port,
 * matched paths, entropy, tracking params) are embedded at composition time.
 */
function composeSignals(ctx: {
  isHttp: boolean;
  punycode: boolean;
  subdomainAbuse: boolean;
  longPath: boolean;
  isShortener: boolean;
  defangedOriginal: boolean;
  fileExt: string | null;
  hasEmbeddedCreds: boolean;
  hasPathTraversal: boolean;
  isNumericDomain: boolean;
  isSuspiciousTLD: boolean;
  hasNonStandardPort: boolean;
  suspiciousPaths: string[];
  domainEnt: number;
  trackingParams: [string, string][];
  tld: string;
  portNum: string;
  portReason: string | null;
  downloadName: string | null;
  cradleMarkers: string[];
  obfuscatedMarkers: string[];
}): Signal[] {
  const signals: Signal[] = [];
  const push = (signal: string, severity: UrlSeverity, title: string, reason: string, action: string, technique?: string) => {
    signals.push({ severity, title, reason, action, technique: technique ?? URL_SIGNAL_MAP[signal]?.technique });
  };

  if (ctx.isHttp) push("http", "warning", "Plain HTTP destination", "No TLS — traffic and credentials would be in clear.", "Treat as untrusted.");
  if (ctx.punycode) push("punycode", "destructive", "Punycode host (IDN homograph risk)", "Lookalike domain encoded in xn-- form.", "Decode and compare against known brand.");
  if (ctx.subdomainAbuse) push("subdomain-abuse", "warning", "Excessive subdomain depth", "Brand-in-subdomain trick is common in phishing.", "Identify the registrable domain, not the prefix.");
  if (ctx.longPath) push("long-path", "info", "Unusually long path", "May carry tracking, session, or payload identifiers.", "Inspect query parameters before any pivot.");
  if (ctx.isShortener) push("shortener", "warning", "URL shortener", "Destination is hidden until expanded.", "Expand statically before review.");
  if (ctx.defangedOriginal) push("defanged", "info", "Originally defanged", "Indicator was sanitised by submitter.", "Continue to keep refanged version internal-only.");
  if (ctx.fileExt) push("file-ext", "warning", `Direct file download (.${ctx.fileExt})`, "URL points to an executable or document.", "Do not open; triage via attachment scanner.");
  if (ctx.downloadName) push("download-filename", "warning", `Named download: ${ctx.downloadName}`, "URL names a file payload directly.", "Do not open; triage via attachment scanner.");
  if (ctx.cradleMarkers.length > 0) push("download-cradle", "destructive", "Script download cradle", `URL carries execution markers: ${ctx.cradleMarkers.join(", ")}.`, "Detonate only in an isolated VM; preserve the full URL for static review.");
  if (ctx.obfuscatedMarkers.length > 0) push("obfuscated-script", "warning", "Obfuscated script markers in URL", `Client-side execution markers visible: ${ctx.obfuscatedMarkers.join(", ")}.`, "Fetch the script statically and analyse strings offline.");
  if (ctx.hasEmbeddedCreds) push("embedded-creds", "destructive", "Embedded credentials in URL", "Username/password in URL violates security best practices.", "Inspect for credential reuse or leakage.");
  if (ctx.hasPathTraversal) push("path-traversal", "destructive", "Path traversal pattern", "../ or encoded variants suggest directory escape.", "Test for LFI/read access in lab environment.");
  if (ctx.isNumericDomain) push("numeric-host", "warning", "Direct IP address as hostname", "No domain name — bypasses brand trust entirely.", "Resolve ASN and check hosting org.");
  if (ctx.isSuspiciousTLD) push("suspicious-tld", "warning", `Suspicious TLD (.${ctx.tld})`, "TLD associated with low-cost bulk registration.", "Check WHOIS age and registrant pattern.");
  if (ctx.hasNonStandardPort) push("nonstandard-port", "info", `Non-standard port ${ctx.portNum}`, ctx.portReason ? `Port ${ctx.portNum}: ${ctx.portReason}.` : "Unusual port for HTTP/S traffic.", "Verify intended service.");
  if (ctx.suspiciousPaths.length > 0) push("suspicious-path", "warning", `Suspicious path segment${ctx.suspiciousPaths.length > 1 ? "s" : ""}`, `Path references: ${ctx.suspiciousPaths.join(", ")}.`, "Common phishing path keywords detected.");
  if (ctx.domainEnt > 4.0) push("high-entropy", "info", "High domain entropy", `Domain character entropy: ${ctx.domainEnt.toFixed(2)} bits — suggests random/auto-generated domain.`, "Check domain registration age.");
  if (ctx.trackingParams.length > 0) push("tracking", "info", "Tracking parameters present", `Common tracking parameter${ctx.trackingParams.length > 1 ? "s" : ""}: ${ctx.trackingParams.map(([k]) => k).join(", ")}.`, "Identify tracking service and verify data handling practices.");

  return signals;
}

function toObservations(input: { url: string; host: string; signals: Signal[] }, source: string, ts?: string): Observation[] {
  const extraction = normalizeObservations(input.url, { source, ts });
  const hostLower = input.host.toLowerCase();

  // Dedupe by observation id; skip url observations for the analyzed URL
  // itself and domain/ip observations for its own host (no self-references).
  const obs: Observation[] = [];
  const push = (o: Observation) => {
    if (obs.some((x) => x.id === o.id)) return;
    obs.push(o);
  };

  for (const o of extraction.observations) {
    if (o.kind === "url") continue;
    if ((o.kind === "domain" || o.kind === "ip") && o.value.toLowerCase() === hostLower) continue;
    push(o);
  }

  input.signals.forEach((s, occurrence) => {
    const meta: Record<string, string> = {
      attr: "url-detection",
      severity: engineSeverity(s.severity),
      title: s.title,
      detail: s.reason,
    };
    if (s.technique) meta.technique = s.technique;
    push(makeObservation({ kind: "string", value: `[${occurrence}] ${s.title}`, source, meta, ts }));
  });

  return obs;
}

/**
 * Validity of a measured TLS certificate relative to now, derived from the
 * notAfter timestamp returned by backend Safe Fetch. Returns null when no
 * parseable date is present — never guesses.
 */
export function tlsValidity(notAfter: string, now: Date = new Date()): { label: "expired" | "expiring soon" | "valid"; days: number } | null {
  if (!notAfter) return null;
  const t = Date.parse(notAfter);
  if (Number.isNaN(t)) return null;
  const days = Math.floor((t - now.getTime()) / 86_400_000);
  if (days < 0) return { label: "expired", days };
  if (days <= 30) return { label: "expiring soon", days };
  return { label: "valid", days };
}


/**
 * Analyze a single URL. Returns null when the input is blank or unparseable so
 * the page can show its "could not parse" state. Deterministic for identical
 * input.
 */
export function analyzeUrl(input: { raw: string; committed: boolean }, opts: UrlArtifactOptions = {}): UrlArtifactResult | null {
  const { raw, committed } = input;
  const trimmed = raw.trim();
  const has = trimmed.length > 0;
  if (!committed || !has) return null;

  const url = refang(trimmed);
  let parsed: URL | null = null;
  try { parsed = new URL(url); } catch { parsed = null; }
  if (!parsed) return null;

  const source = opts.source ?? "url";
  const ts = opts.ts;
  const generatedAt = new Date().toISOString();

  const host = parsed.hostname;
  const path = parsed.pathname;
  const isHttp = parsed.protocol === "http:";
  const punycode = host.includes("xn--");
  const longPath = path.length > 40;
  const subdomainAbuse = host.split(".").length > 3;
  const isShortener = SHORTENERS.has(host.replace(/^www\./, ""));
  const defangedOriginal = /\[\.\]|hxxps?:\/\//i.test(raw);
  const fileExt = path.match(FILE_EXT_RX)?.[1] ?? null;
  const hasEmbeddedCreds = !!(parsed.username || parsed.password);
  const hasPathTraversal = /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c/i.test(path);
  const isNumericDomain = !!(NUMERIC_IP_RX.test(host) || /^0x[0-9a-f]+\.|\d+\.\d+\.\d+\.\d+/i.test(host));
  const hasNonStandardPort = !!(parsed.port && parsed.port !== "80" && parsed.port !== "443");
  const domainEnt = domainEntropy(host);
  const tld = host.split(".").pop() ?? "";
  const isSuspiciousTLD = SUSPICIOUS_TLDS.has(tld);

  const suspiciousPaths = SUSPICIOUS_PATHS.filter((p) => path.toLowerCase().includes("/" + p));

  const suspiciousChars: { char: string; pos: number }[] = [];
  const nonAscii = path.match(/[^\x20-\x7f]/g);
  if (nonAscii) {
    for (const c of new Set(nonAscii)) {
      const pos = path.indexOf(c);
      if (pos >= 0) suspiciousChars.push({ char: c, pos });
    }
  }
  const atInPath = path.indexOf("@");
  if (atInPath >= 0) suspiciousChars.push({ char: "@", pos: atInPath });
  const controlInPath = path.match(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/);
  if (controlInPath && controlInPath.index !== undefined) suspiciousChars.push({ char: `0x${controlInPath[0].charCodeAt(0).toString(16)}`, pos: controlInPath.index });
  const doubleDecode = /%25[0-9a-f]{2}/i.test(path);
  if (doubleDecode) suspiciousChars.push({ char: "%25 (double-encode)", pos: path.indexOf("%25") });

  const downloadName = downloadFileName(parsed, fileExt);
  const { cradle: cradleMarkers, obfuscated: obfuscatedMarkers } = urlPayloadMarkers(parsed.href);

  const pathSignals: string[] = [];
  if (fileExt) pathSignals.push(`File download: .${fileExt}`);
  if (hasPathTraversal) pathSignals.push("Path traversal pattern detected");
  if (suspiciousPaths.length) pathSignals.push(`Suspicious path segment${suspiciousPaths.length > 1 ? "s" : ""}: ${suspiciousPaths.join(", ")}`);
  const pathBase64 = path.split("/").filter(Boolean).some((seg) => (seg.match(BASE64_PATH_RX) ?? []).length > 0 && entropy(seg) > 4.0);
  if (pathBase64) pathSignals.push("Base64-like content in path segment");
  if (downloadName) pathSignals.push(`Named download: ${downloadName}`);
  if (cradleMarkers.length) pathSignals.push(`Script download cradle markers: ${cradleMarkers.join(", ")}`);
  if (obfuscatedMarkers.length) pathSignals.push(`Obfuscated script markers: ${obfuscatedMarkers.join(", ")}`);
  if (suspiciousChars.length) pathSignals.push(`Suspicious character${suspiciousChars.length > 1 ? "s" : ""} in path`);
  if (hasEmbeddedCreds) pathSignals.push("Embedded credentials in URL");
  if (isNumericDomain) pathSignals.push("Direct IP address as hostname");
  if (hasNonStandardPort) pathSignals.push(`Non-standard port: ${parsed.port}`);
  if (isSuspiciousTLD) pathSignals.push(`Suspicious TLD: .${tld}`);

  const secrets = scanSecrets(parsed.href);
  const trackingParams = Array.from(parsed.searchParams.entries()).filter(([k]) => TRACKING_PARAMS.has(k.toLowerCase()));

  const portNum = parsed.port;
  const portReason = hasNonStandardPort && portNum ? SUSPICIOUS_PORT_WARN[portNum] ?? "non-standard" : null;

  const signals = composeSignals({
    isHttp, punycode, subdomainAbuse, longPath, isShortener, defangedOriginal, fileExt,
    hasEmbeddedCreds, hasPathTraversal, isNumericDomain, isSuspiciousTLD, hasNonStandardPort,
    suspiciousPaths, domainEnt, trackingParams, tld, portNum, portReason,
    downloadName, cradleMarkers, obfuscatedMarkers,
  });

  const observations = toObservations({ url, host, signals }, source, ts);

  const engine = analyzeAndCorrelate(observations, opts.history ?? {}, { source, ts });

  const summary = summaryFrom(engine.findings);
  const iocSeverity: Severity = summary.verdict === "malicious" ? "high" : summary.verdict === "suspicious" ? "medium" : "info";

  const iocs: IOC[] = [
    { type: "url", value: parsed.href, source: "/url", context: "analyzed URL", severity: iocSeverity },
    { type: "domain", value: host, source: "/url", context: "URL hostname", severity: iocSeverity },
    ...(isNumericDomain ? [{ type: "ipv4" as const, value: host, source: "/url" as const, context: "direct IP host", severity: iocSeverity }] : []),
  ];

  const hostnameIoc = iocs.find((i) => i.context === "URL hostname");
  const ipIoc = iocs.find((i) => i.context === "direct IP host");

  const findings: Finding[] = engine.findings.map((f) => {
    const linked: IOC[] = [];
    if (HOST_SIGNALS.some((s) => f.title.startsWith(s))) {
      if (hostnameIoc) linked.push(hostnameIoc);
      if (f.title.startsWith("Direct IP address") && ipIoc) linked.push(ipIoc);
    }
    return {
      id: f.id,
      severity: f.severity,
      title: f.title,
      detail: f.detail,
      source: "url-analyzer",
      ...(f.technique ? { technique: f.technique } : {}),
      ...(linked.length ? { iocs: linked } : {}),
    };
  });

  const mitre = engine.mitre.map((m) => ({ id: m.technique, name: m.name }));

  const knowledge: UrlKnowledge = buildUrlKnowledge(parsed, { isNumericDomain, tld, punycode, isShortener, fileExt, isSuspiciousTLD });

  const artifact: Artifact = {
    id: objectId("artifact", "url", url),
    kind: "url",
    title: `URL: ${host}`,
    metadata: { host, scheme: parsed.protocol.replace(":", ""), tld },
    created: generatedAt,
  };

  const evidenceItems: EvidenceItem[] = [
    ...signals.map((s) => ({ type: "finding" as const, title: s.title, detail: s.reason, source: "url" })),
    ...secrets.map((s) => ({ type: "secret" as const, title: s.type, detail: s.value, source: "url" })),
  ];

  return {
    id: objectId("analysis", "url", url),
    analyzer: "url",
    artifact,
    raw: input.raw,
    parsed,
    findings,
    iocs,
    evidence: [],
    summary,
    evidenceItems,
    generatedAt,
    displayFindings: signals.map((s) => ({ severity: s.severity, title: s.title, reason: s.reason, action: s.action })),
    suspiciousPaths,
    pathSignals,
    trackingParams,
    suspiciousChars,
    secrets,
    mitre,
    domainEnt,
    tld,
    portNum,
    portReason,
    isHttp,
    punycode,
    isShortener,
    defangedOriginal,
    fileExt,
    downloadName,
    hasEmbeddedCreds,
    hasPathTraversal,
    isNumericDomain,
    isSuspiciousTLD,
    hasNonStandardPort,
    knowledge,
    observations,
    relationships: [...engine.relationships, ...engine.correlationRelationships],
    recommendations: engine.recommendations,
    opportunities: engine.opportunities,
    quality: engine.quality,
    correlation: engine.correlation,
    correlationRelationships: engine.correlationRelationships,
  };
}

export interface MeasuredRedirectSignal {
  severity: UrlSeverity;
  title: string;
  reason: string;
  action: string;
}

/**
 * Findings derived from MEASURED redirect-chain data (opt-in Safe Fetch),
 * not from URL-string heuristics. Registrable-domain comparison uses the
 * same last-two-labels convention as the rest of the UI (heuristic, no PSL).
 */
export function measuredRedirectSignals(chain: unknown[]): MeasuredRedirectSignal[] {
  const hops = chain.filter((h): h is Record<string, unknown> => !!h && typeof h === "object");
  if (hops.length === 0) return [];
  const hostOf = (h: Record<string, unknown>) => String(h.host ?? "").toLowerCase();
  const reg = (host: string) => host.split(".").slice(-2).join(".");
  const first = hostOf(hops[0]);
  const last = hostOf(hops[hops.length - 1]);
  const out: MeasuredRedirectSignal[] = [];
  const n = hops.length;
  if (first && last && reg(first) !== reg(last)) {
    out.push({
      severity: "destructive",
      title: `Redirect chain leaves origin domain (${n} hop${n === 1 ? "" : "s"}, measured)`,
      reason: `Measured via opt-in Safe Fetch: final destination ${last} differs from origin registrable domain ${reg(first)}.`,
      action: "Analyse the final destination as its own artifact before trusting the original link.",
    });
  } else if (n > 1) {
    out.push({
      severity: "info",
      title: `Multi-hop redirect on same domain (${n} hops, measured)`,
      reason: `Measured via opt-in Safe Fetch: chain stays within ${reg(last)}.`,
      action: "No domain hand-off observed; verify final URL parameters.",
    });
  }
  if (hops.some((h) => h.set_cookie_present === true)) {
    out.push({
      severity: "warning",
      title: "Set-Cookie during redirect chain (measured)",
      reason: "At least one measured hop issued a cookie during the redirect sequence.",
      action: "Review cookies for session fixation or tracking before reuse.",
    });
  }
  return out;
}