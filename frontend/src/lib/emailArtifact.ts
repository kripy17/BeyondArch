import { objectId } from "@/lib/ids";
import { techniqueInfo } from "@/lib/analysis/mitre";
import { normalizeObservations, makeObservation, classifyIoc } from "@/lib/extraction";
import { analyzeAndCorrelate, type CorrelationHistory, type CorrelationMatch } from "@/lib/correlation";
import { refang, defang, scanSecrets, isAuthParamToken } from "@/lib/ioc-patterns";
import { type Severity } from "@/lib/severity";
import { type Finding, type IOC, type IocType, type Artifact, type Evidence } from "@/types/security";
import type { AnalysisSummary, EvidenceItem } from "@/types/analysis";
import type { AnalysisQuality, DetectionOpportunity, Observation, Recommendation, Relationship } from "@/types/objects";
import {
  type AuthState, detectAuth, getDomain, extractBody, extractHeaders,
  detectAttachments, detectLookalike, detectDisplaySpoof, type DisplaySpoof, analyzeUrls, genBodySignals,
  detectLanguage, computeBrandClaims, buildRecommendations, buildFromApi, RX, SENDER_TLDS, BRAND_KEYWORDS,
  parseAuthResults, extractAttachmentFilenames, parseRawMail,
} from "@/data/phishing";
import type { LanguageDetection } from "@/data/phishing";
import type {
  PhishingAnalysisResult, PhishingFindingDisplay, PhishingBreakdownItem,
  PhishingMitreItem, PhishingHopItem,
} from "@/types/phishing";

/**
 * Email orchestrator: raw email source → measured email facts (SPF/DKIM/DMARC,
 * envelope, body signals) → Analysis Engine → correlation. The page consumes
 * this output; it never computes findings, MITRE, or recommendations itself
 * (ANALYSIS_ENGINE §4c, P11). Replaces the retired legacy phishing analyzer.
 * Deterministic for identical input (objectId ids, no crypto.randomUUID()).
 * The optional apiResult enrichment keeps its legacy opt-in shape: when the
 * backend service responds, its measured findings are merged in alongside
 * the local engine findings.
 */

export interface EmailArtifactOptions {
  source?: string;
  ts?: string;
  history?: CorrelationHistory;
}

export interface EmailArtifactResult extends PhishingAnalysisResult {
  observations: Observation[];
  relationships: Relationship[];
  engineRecommendations: Recommendation[];
  opportunities: DetectionOpportunity[];
  quality: AnalysisQuality;
  correlation: CorrelationMatch[];
  correlationRelationships: Relationship[];
}

type EmailSeverity = "destructive" | "warning" | "info";

function mapSev(sev: EmailSeverity): Severity {
  return sev === "destructive" ? "critical" : sev === "warning" ? "medium" : "info";
}

const emailUniq = <T,>(a: T[]): T[] => Array.from(new Set(a));

function guessIocType(value: string): IocType {
  const t = classifyIoc(value);
  return t === "unknown" ? "unknown" : t;
}

interface EmailSignal {
  sev: EmailSeverity;
  t: string;
  r: string;
  a: string;
  s: string;
  technique?: string;
}

/**
 * Deterministic signal table mirroring the legacy phishing analyzer's rule
 * list (titles, reasons, actions, source slugs verbatim). Techniques come
 * from the MITRE corpus (data/mitre.ts) and are attached per signal where
 * the legacy logic mapped them (auth failures, forms, attachments, CVE).
 */
function composeSignals(input: {
  spf: AuthState;
  dkim: AuthState;
  dmarc: AuthState;
  replyMismatch: boolean;
  defangedUrl: boolean;
  urgency: boolean;
  hasForm: boolean;
  hasPasswordField: boolean;
  hasAttachment: { hasAttachments: boolean; detail: string[] };
  fromDomain: string | undefined;
  envelopeFlags: string[];
  brandMatch: string | undefined;
  language: LanguageDetection | null;
  typosquat: { brand: string; claim: string }[];
  bodySignals: { sev: EmailSeverity; t: string; r: string; a: string }[];
  hasCve: boolean;
  attack: string[];
  displaySpoofs: DisplaySpoof[];
  urlTrustHits: number;
}): EmailSignal[] {
  const signals: EmailSignal[] = [];
  const push = (s: string, sev: EmailSeverity, t: string, r: string, a: string, technique?: string) => {
    signals.push({ sev, t, r, a, s, ...(technique ? { technique } : {}) });
  };

  if (input.spf === "fail") push("spf", "destructive", "SPF authentication failed", "Sender server is not authorised for the domain.", "Treat the From: address as untrusted.", "T1566");
  if (input.spf === "softfail") push("spf", "warning", "SPF soft-fail", "Sending IP is not in the SPF record but policy is permissive (~all).", "Tighten SPF policy and inspect originating IP.");
  if (input.dmarc === "fail") push("dmarc", "destructive", "DMARC alignment failed", "Sender policy denies delivery — likely spoof.", "Quarantine similar messages at the gateway.", "T1566");
  if (input.dkim === "fail") push("dkim", "warning", "DKIM signature not validated", "Body integrity not guaranteed.", "Pivot on Received: hops for true source.");
  if (input.dkim === "softfail") push("dkim", "info", "DKIM soft-fail / neutral", "Selector responded but signature did not cleanly verify.", "Confirm key rotation on the sending domain.");
  if (input.replyMismatch) push("envelope", "warning", "Reply-To masquerades as sender", "Reply traffic diverts to a different lookalike domain.", "Block both domains and notify the user.");
  if (input.defangedUrl) push("ioc", "info", "Defanged URL detected", "Indicator was sanitised by the submitter.", "Re-fang in Safe URL Analyzer, never click directly.");
  if (input.urgency) push("body_signal", "info", "Urgency / coercion language", "Social-engineering pressure tactic.", "Include in user training and report draft.");
  if (input.hasForm) push("body_signal", "destructive", "HTML form in email body", "Email contains a form — credential harvesting risk.", "Verify form action URL and inspect in Phishing Triage.", "T1566");
  if (input.hasPasswordField) push("body_signal", "destructive", "Password field in email", "Body contains password input — likely credential harvesting.", "Escalate; do not submit credentials.", "T1566");
  if (input.hasAttachment.hasAttachments) push("attachment", "warning", "Email carries attachments", input.hasAttachment.detail.length ? input.hasAttachment.detail.join("; ") : "Multipart content detected.", "Submit to Attachment Triage before opening.", "T1204");
  if (input.fromDomain && SENDER_TLDS.has(input.fromDomain.split(".").pop() ?? "")) push("envelope", "warning", "Sender TLD is high-risk", `Sender domain uses suspicious TLD .${input.fromDomain.split(".").pop()}`, "Investigate domain registration in OSINT.");
  if (input.envelopeFlags.length) push("envelope", "warning", "Envelope domain mismatch", input.envelopeFlags.join("; "), "Verify sender identity out-of-band.");
  if (input.brandMatch && input.spf === "fail") push("brand", "destructive", `Brand impersonation: ${input.brandMatch}`, `Message references '${input.brandMatch}' while authentication fails.`, "Verify sender out-of-band.", "T1566");
  if (input.brandMatch && input.spf !== "fail") push("brand", "warning", `Brand reference: ${input.brandMatch}`, `Message references '${input.brandMatch}' in body or subject.`, "Verify legitimacy with sender.");
  if (input.language && input.language.script !== "latin") push("language", "info", `Non-Latin script body (${input.language.label})`, input.language.samples.length ? `Body uses ${input.language.label} script — sample: ${input.language.samples.slice(0, 3).join(", ")}.` : `Body uses ${input.language.label} script.`, "Localise analysis — cross-check lures against language-specific campaigns.");
  for (const c of input.typosquat) push("brand", "destructive", `Typosquat domain: ${c.brand}`, c.claim, "Block the domain; add an exact-match watch rule.", "T1566");
  for (const d of input.displaySpoofs) {
    if (d.kind === "brand") push("envelope", "destructive", `Display-name brand spoof${d.brand ? `: ${d.brand}` : ""}`, d.detail, "Verify sender out-of-band; display names are free text.", "T1566");
    else push("envelope", "warning", "Possible BEC impersonation", d.detail, "Confirm the request with the supposed sender out-of-band.");
  }
  if (input.urlTrustHits > 0) push("ioc", "warning", "Redirect / abused-host URLs", `${input.urlTrustHits} link(s) hide behind open-redirect parameters or trusted-service hosts.`, "Expand redirects statically; treat the final host as the real indicator.");
  for (const s of input.bodySignals) push("body_signal", s.sev, s.t, s.r, s.a);
  if (input.hasCve) push("ioc", "warning", "CVE identifiers present in email", "Message references a known vulnerability identifier.", "Index against exposure context.", "T1190");
  for (const a of input.attack) push("ioc", "info", `ATT&CK technique referenced: ${a}`, "Message body references a known technique identifier.", "Match against detection coverage.", a);

  return signals;
}

function mapMitre(id: string): string {
  return techniqueInfo(id).name;
}

/** Legacy auth-state → page display tone. */
function toneFromSignals(signals: EmailSignal[], spf: AuthState, dmarc: AuthState): "destructive" | "warning" | "success" {
  const destructive = signals.some((s) => s.sev === "destructive") || (spf === "fail" && dmarc === "fail");
  if (destructive) return "destructive";
  if (signals.some((s) => s.sev === "warning")) return "warning";
  return "success";
}

function labelFromTone(tone: "destructive" | "warning" | "success"): string {
  return tone === "destructive" ? "Likely Phishing" : tone === "warning" ? "Suspicious" : "Inconclusive";
}

function standardVerdict(tone: "destructive" | "warning" | "success"): string {
  return tone === "destructive" ? "malicious" : tone === "warning" ? "suspicious" : "inconclusive";
}

function summaryFromEngine(engineFindings: Array<{ severity: Severity }>, signals: EmailSignal[]): AnalysisSummary {
  const destructive = signals.filter((s) => s.sev === "destructive").length;
  const warning = signals.filter((s) => s.sev === "warning").length;
  const crit = engineFindings.filter((f) => f.severity === "critical").length;
  const high = engineFindings.filter((f) => f.severity === "high").length;
  const med = engineFindings.filter((f) => f.severity === "medium").length;
  return {
    verdict: standardVerdict(crit > 0 ? "destructive" : high > 0 || med > 0 ? "warning" : "success"),
    score: Math.min(100, crit * 25 + high * 12 + med * 5),
    confidence: destructive > 0 ? 0.85 : warning > 0 ? 0.65 : 0.15,
  };
}

function buildBreakdown(input: {
  spf: AuthState; dmarc: AuthState; dkim: AuthState; replyMismatch: boolean;
  defangedUrl: boolean; urgency: boolean; hasForm: boolean; hasPasswordField: boolean;
  hasAttachment: { hasAttachments: boolean }; fromDomain: string | undefined; hasLookalike: boolean; brandMatch: string | undefined;
  displaySpoofs: DisplaySpoof[]; urlTrustHits: number;
}): PhishingBreakdownItem[] {
  return [
    { signal: "SPF", weight: input.spf === "fail" ? 30 : input.spf === "softfail" ? 12 : 0, state: input.spf },
    { signal: "DMARC", weight: input.dmarc === "fail" ? 30 : input.dmarc === "softfail" ? 10 : 0, state: input.dmarc },
    { signal: "DKIM", weight: input.dkim === "fail" ? 10 : input.dkim === "softfail" ? 4 : 0, state: input.dkim },
    { signal: "Reply-To mismatch", weight: input.replyMismatch ? 15 : 0, state: input.replyMismatch ? "fail" : "pass" },
    { signal: "Defanged URL", weight: input.defangedUrl ? 10 : 0, state: input.defangedUrl ? "fail" : "pass" },
    { signal: "Urgency / coercion", weight: input.urgency ? 10 : 0, state: input.urgency ? "fail" : "pass" },
    { signal: "HTML form", weight: input.hasForm ? 25 : 0, state: input.hasForm ? "fail" : "pass" },
    { signal: "Password field", weight: input.hasPasswordField ? 25 : 0, state: input.hasPasswordField ? "fail" : "pass" },
    { signal: "Attachments", weight: input.hasAttachment.hasAttachments ? 10 : 0, state: input.hasAttachment.hasAttachments ? "fail" : "pass" },
    { signal: "Sender TLD risk", weight: input.fromDomain && SENDER_TLDS.has(input.fromDomain.split(".").pop() || "") ? 10 : 0, state: "fail" },
    { signal: "Envelope mismatch", weight: input.hasLookalike ? 15 : 0, state: input.hasLookalike ? "fail" : "pass" },
    { signal: "Brand impersonation", weight: input.brandMatch && (input.spf === "fail" || input.dmarc === "fail") ? 30 : 0, state: "fail" },
    { signal: "Display-name spoof", weight: input.displaySpoofs.some((d) => d.kind === "brand") ? 25 : input.displaySpoofs.length ? 15 : 0, state: input.displaySpoofs.length ? "fail" : "pass" },
    { signal: "URL redirect / abused host", weight: input.urlTrustHits > 0 ? 10 : 0, state: input.urlTrustHits > 0 ? "fail" : "pass" },
  ];
}

function extractHops(input: string): PhishingHopItem[] {
  return Array.from(input.matchAll(/Received:\s*from\s+(\S+)\s*(?:\(([^)]+)\))?(?:\s+by\s+(\S+))?(?:\s+with\s+(\S+))?/gi)).map((m) => ({
    from: m[1], ip: m[2] ?? "", by: m[3] ?? "", protocol: m[4] ?? "",
  }));
}

/**
 * Analyze an email. Returns null for blank input. Deterministic for identical
 * input (objectId ids). The optional backend `apiResult` enrichment merges
 * machine-measured findings alongside the email-derived engine findings.
 */
export function analyzePhishing(input: string, apiResult?: Record<string, any> | null, opts: EmailArtifactOptions = {}): EmailArtifactResult | null {
  if (!input.trim()) return null;

  const source = opts.source ?? "phishing";
  const ts = opts.ts;
  const generatedAt = new Date().toISOString();

  // -- measured facts (pure derivations from the raw email source) --
  // Raw .eml is MIME: decode it first so lure scans read text, not base64.
  const mail = parseRawMail(input);
  const hdr = (n: string) => (mail.headers[n] ?? "").trim();
  // IOC scans run on headers + decoded text + href targets for MIME mail so
  // transfer-encoded blobs and boundaries can't mint phantom indicators.
  const scanSource = mail.isMime
    ? [Object.values(mail.headers).join("\n"), mail.textBody, ...mail.linkUrls].join("\n")
    : input;
  const refanged = refang(input);
  const scoped = mail.isMime ? refang(scanSource) : refanged;
  const spf = detectAuth(input, "spf");
  const dkim = detectAuth(input, "dkim");
  const dmarc = detectAuth(input, "dmarc");
  const fromLine = hdr("from") || (input.match(/From:\s*(.+)/i)?.[1] ?? "").trim();
  const replyLine = hdr("reply-to") || (input.match(/Reply-To:\s*(.+)/i)?.[1] ?? "").trim();
  const pathLine = hdr("return-path") || (input.match(/Return-Path:\s*(.+)/i)?.[1] ?? "").trim();
  const fromDomain = getDomain(fromLine);
  const replyDomain = getDomain(replyLine);
  const replyMismatch = !!(fromDomain && replyDomain && fromDomain !== replyDomain);
  const defangedUrl = /hxxps?:\/\/|\[\.\]/i.test(input);

  const body = mail.textBody || extractBody(input);
  const bodyHtml = mail.htmlBody;
  const htmlSource = bodyHtml || body;
  const headers = extractHeaders(input);
  const bodyLower = body.toLowerCase();
  const subject = (hdr("subject") || (input.match(/Subject:\s*(.+)/i)?.[1] ?? "")).toLowerCase();
  const urgency = /urgent|immediately|within \d+h|suspend|today|asap|before my flight/i.test(mail.isMime ? `${body}\n${subject}` : input);
  const brandMatch = BRAND_KEYWORDS.find((b) => bodyLower.includes(b) || subject.includes(b));

  const hasForm = /<form/i.test(htmlSource) || /<input.*type=["']?(?:text|password|email)["' ]/i.test(htmlSource);
  const hasPasswordField = /<input.*type=["']?password["' ]/i.test(htmlSource) || /password/i.test(bodyLower);
  const hasHtmlForm = /<form\s/i.test(htmlSource);
  const hasAttachment = mail.attachments.length
    ? { hasAttachments: true, detail: mail.attachments.map((a) => `Attachment: ${a.filename} (${a.mime}, ${a.size} chars decoded)`) }
    : detectAttachments(input);
  const envelopeFlags = detectLookalike(fromLine, replyLine, pathLine);
  const hasLookalike = envelopeFlags.length > 0;

  const language = detectLanguage(body);
  const brandClaims = computeBrandClaims(fromDomain, fromLine, body, subject);
  const typosquat = brandClaims.filter((c) => c.typosquat);

  const rawIocs = (() => {
    const urls = emailUniq((scoped.match(RX.URL) ?? []).map((u: string) => defang(u)));
    const emails = emailUniq(scoped.match(RX.Email) ?? []);
    const ips = emailUniq(scoped.match(RX.IPv4) ?? []);
    const md5 = emailUniq(scoped.match(RX.MD5)?.filter((h: string) => h.length === 32) ?? []);
    const sha256 = emailUniq(scoped.match(RX.SHA256) ?? []);
    const cve = emailUniq(scoped.match(RX.CVE) ?? []);
    const attack = emailUniq(scoped.match(RX.ATTACK) ?? []);
    const domains = emailUniq(
      (refanged.match(RX.Domain) ?? [])
        .filter((d: string) => !isAuthParamToken(d) && !ips.includes(d) && !emails.some((e: string) => e.toLowerCase().includes(d.toLowerCase())))
        .map((d: string) => defang(d)),
    );
    return { urls, domains, ips, hashes: [...md5, ...sha256], emails, cve, attack };
  })();

  const secrets = scanSecrets(body || input);
  const urlAnalysis = rawIocs.urls.length ? analyzeUrls(rawIocs.urls) : [];
  const urlTrustHits = urlAnalysis.filter((u) => u.badges.some((b) => b.label === "open redirect" || b.label === "abused host")).length;
  const displaySpoofs = detectDisplaySpoof(fromLine, fromDomain);
  const hops = extractHops(input);

  // ------------------------------------------------------------------
  // Local engine path: compose deterministic signals → analyze engine.
  // ------------------------------------------------------------------
  const signals = composeSignals({
    spf, dkim, dmarc, replyMismatch, defangedUrl, urgency,
    hasForm, hasPasswordField, hasAttachment, fromDomain, envelopeFlags,
    brandMatch, language, typosquat,
    bodySignals: genBodySignals(body, rawIocs),
    hasCve: rawIocs.cve.length > 0,
    attack: rawIocs.attack,
    displaySpoofs,
    urlTrustHits,
  });

  // -- optional backend enrichment (opt-in, additive) --
  const apiData = apiResult ? buildFromApi(apiResult, input, true) : null;
  if (apiData) {
    for (const f of apiData.findings) {
      const sev: EmailSeverity = f.sev === "destructive" ? "destructive" : f.sev === "warning" ? "warning" : "info";
      signals.push({ sev, t: f.t, r: f.r, a: f.a, s: "api" });
    }
  }

  // -- engine sections --
  const extraction = normalizeObservations(refanged, { source, ts });
  const observations: Observation[] = [...extraction.observations];
  signals.forEach((s, occurrence) => {
    observations.push(makeObservation({
      kind: "string",
      value: `[${occurrence}] ${s.t}`,
      source,
      meta: { attr: "email-detection", severity: mapSev(s.sev), detail: s.r, ...(s.technique ? { technique: s.technique } : {}) },
      ts,
    }));
  });

  const engine = analyzeAndCorrelate(observations, opts.history ?? {}, { source, ts });

  const findings: Finding[] = engine.findings.map((f) => ({
    id: f.id,
    severity: f.severity,
    title: f.title,
    detail: f.detail,
    source: "phishing",
    ...(f.technique ? { technique: f.technique } : {}),
  }));

  const displayFindings: PhishingFindingDisplay[] = signals.map((s) => ({ severity: s.sev, title: s.t, reason: s.r, action: s.a, source: s.s }));
  const tone = toneFromSignals(signals, spf, dmarc);
  const verdict = { label: labelFromTone(tone), tone };

  const breakdown = buildBreakdown({ spf, dmarc, dkim, replyMismatch, defangedUrl, urgency, hasForm, hasPasswordField, hasAttachment, fromDomain, hasLookalike, brandMatch, displaySpoofs, urlTrustHits });

  const mitre: PhishingMitreItem[] = [];
  const seen = new Set<string>();
  for (const s of signals) {
    if (!s.technique || seen.has(s.technique)) continue;
    seen.add(s.technique);
    mitre.push({ id: s.technique, name: mapMitre(s.technique), source: s.s });
  }
  if (rawIocs.attack.length) for (const a of rawIocs.attack) { if (!seen.has(a)) { seen.add(a); mitre.push({ id: a, name: mapMitre(a), source: "ioc" }); } }

  const iocs: IOC[] = [];
  const iocsByCategory: Record<string, string[]> = {};
  for (const [cat, values] of Object.entries(rawIocs) as [string, string[]][]) {
    iocsByCategory[cat] = values;
    for (const v of values) {
      iocs.push({
        value: v,
        type: guessIocType(v),
        context: `Extracted from email ${cat}`,
        source: "/phishing",
        severity: tone === "destructive" ? "critical" : tone === "warning" ? "medium" : "info",
      });
    }
  }

  const artifact: Artifact = {
    id: objectId("artifact", "email", input),
    kind: "email",
    title: `Email from ${fromLine || "unknown sender"}`,
    metadata: { from: fromLine, reply_to: replyLine, return_path: pathLine, verdict: verdict.label, spf, dkim, dmarc },
    created: generatedAt,
  };

  const evidence: Evidence = {
    id: objectId("evidence", "email", input),
    artifact,
    findings,
    iocs,
    notes: `Phishing analysis: ${verdict.label}`,
    created: generatedAt,
  };

  const evidenceItems: EvidenceItem[] = [
    ...signals.map((s) => ({ type: "finding", title: s.t, detail: s.r, source: s.s })),
    ...secrets.map((s) => ({ type: "secret", title: s.type, detail: s.value, source: "phishing" })),
  ];

  return {
    id: objectId("analysis", "email", input),
    analyzer: "phishing",
    raw: input,
    artifact, findings, iocs, evidence,
    summary: summaryFromEngine(engine.findings, signals),
    evidenceItems, generatedAt,
    auth: { spf, dkim, dmarc },
    verdict,
    breakdown,
    mitre,
    urlAnalysis,
    body, headers, fromLine, replyLine, pathLine, fromDomain,
    brandMatch, replyMismatch, defangedUrl, urgency,
    hasForm, hasPasswordField, hasHtmlForm, hasLookalike, envelopeFlags,
    hasAttachment, displaySpoofs,
    authResults: parseAuthResults(input),
    attachmentFiles: extractAttachmentFilenames(input),
    displayFindings,
    secrets,
    hops,
    iocsByCategory,
    language, brandClaims,
    recommendations: buildRecommendations(signals),
    observations,
    relationships: [...engine.relationships, ...engine.correlationRelationships],
    engineRecommendations: engine.recommendations,
    opportunities: engine.opportunities,
    quality: engine.quality,
    correlation: engine.correlation,
    correlationRelationships: engine.correlationRelationships,
  };
}