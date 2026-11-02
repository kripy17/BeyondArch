import type { Severity } from "@/lib/severity";
import { LOG_SEVERITY_FLOOR } from "./log-rules";

/**
 * URL detection rule data (migrated from the retired legacy url analyzer).
 * Each signal is a deterministic, measurable property of the parsed URL.
 * Severity floors reuse the log pipeline's band table — evidence weight is
 * attribute-driven, never a verdict (ANALYSIS_ENGINE §4c module 1).
 */

export const URL_SEVERITY_FLOOR: Record<Severity, number> = LOG_SEVERITY_FLOOR;

export type UrlSignal = "punycode" | "http" | "subdomain-abuse" | "long-path" | "shortener" | "defanged" | "file-ext" | "download-filename" | "embedded-creds" | "path-traversal" | "numeric-host" | "suspicious-tld" | "nonstandard-port" | "suspicious-path" | "high-entropy" | "tracking" | "download-cradle" | "obfuscated-script" | "secrets";

export interface UrlRule {
  signal: string;
  /** Engine finding severity emitted for this signal. */
  severity: Severity;
  /** MITRE ATT&CK technique id */
  technique?: string;
  title: string;
  detail: string;
  action: string;
  /** Optional resolved suffixes appended once per analysis (dynamic context). */
  titleSuffix?: (ctx: UrlRuleContext) => string;
  detailSuffix?: (ctx: UrlRuleContext) => string;
  actionSuffix?: (ctx: UrlRuleContext) => string;
}

export interface UrlRuleContext {
  host: string;
  tld: string;
  fileExt: string;
  port: string;
  portReason: string;
  paths: string[];
  params: string[];
  entropy: string;
}

export const URL_SIGNALS: UrlRule[] = [
  {
    signal: "http",
    severity: "medium",
    technique: "T1573",
    title: "Plain HTTP destination",
    detail: "No TLS — traffic and credentials would be in clear.",
    action: "Treat as untrusted.",
  },
  {
    signal: "punycode",
    severity: "critical",
    technique: "T1566",
    title: "Punycode host (IDN homograph risk)",

    detail: "Lookalike domain encoded in xn-- form.",
    action: "Decode and compare against known brand.",
  },
  {
    signal: "subdomain-abuse",
    severity: "medium",
    technique: "T1566",
    title: "Excessive subdomain depth",
    detail: "Brand-in-subdomain trick is common in phishing.",
    action: "Identify the registrable domain, not the prefix.",
  },
  {
    signal: "long-path",
    severity: "info",
    title: "Unusually long path",
    detail: "May carry tracking, session, or payload identifiers.",
    action: "Inspect query parameters before any pivot.",
  },
  {
    signal: "shortener",
    severity: "medium",
    technique: "T1566",
    title: "URL shortener",
    detail: "Destination is hidden until expanded.",
    action: "Expand statically before review.",
  },
  {
    signal: "defanged",
    severity: "info",
    title: "Originally defanged",
    detail: "Indicator was sanitised by submitter.",
    action: "Continue to keep refanged version internal-only.",
  },
  {
    signal: "file-ext",
    severity: "medium",
    technique: "T1105",
    title: "Direct file download",
    detail: "URL points to an executable or document.",
    action: "Do not open; triage via attachment scanner.",
  },
  {
    signal: "download-filename",
    severity: "medium",
    technique: "T1105",
    title: "Named file download",
    detail: "URL names a file payload directly (path segment or download argument).",
    action: "Do not open; triage via attachment scanner.",
  },
  {
    signal: "download-cradle",
    severity: "critical",
    technique: "T1059.001",
    title: "Script download cradle",
    detail: "URL carries execution-verb markers (bitsadmin/certutil/mshta/rundll32/…) used to fetch and run payloads.",
    action: "Detonate only in an isolated VM; preserve the full URL for static review.",
  },
  {
    signal: "obfuscated-script",
    severity: "medium",
    technique: "T1059.007",
    title: "Obfuscated script markers in URL",
    detail: "eval/atob/fromCharCode-style calls visible in the URL — typical of client-side payload staging.",
    action: "Fetch the script statically and analyse strings offline.",
  },
  {
    signal: "embedded-creds",
    severity: "critical",
    technique: "T1078",
    title: "Embedded credentials in URL",
    detail: "Username/password in URL violates security best practices.",
    action: "Inspect for credential reuse or leakage.",
  },
  {
    signal: "path-traversal",
    severity: "critical",
    technique: "T1190",
    title: "Path traversal pattern",
    detail: "../ or encoded variants suggest directory escape.",
    action: "Test for LFI/read access in lab environment.",
  },
  {
    signal: "numeric-host",
    severity: "medium",
    technique: "T1071",
    title: "Direct IP address as hostname",
    detail: "No domain name — bypasses brand trust entirely.",
    action: "Resolve ASN and check hosting org.",
  },
  {
    signal: "suspicious-tld",
    severity: "medium",
    technique: "T1583.001",
    title: "Suspicious TLD",
    detail: "TLD associated with low-cost bulk registration.",
    action: "Check WHOIS age and registrant pattern.",
  },
  {
    signal: "nonstandard-port",
    severity: "info",
    technique: "T1571",
    title: "Non-standard port",
    detail: "Unusual port for HTTP/S traffic.",
    action: "Verify intended service.",
  },
  {
    signal: "suspicious-path",
    severity: "medium",
    technique: "T1204",
    title: "Suspicious path segment",
    detail: "Path references suspicious keywords.",
    action: "Inspect path — common phishing keywords detected.",
  },
  {
    signal: "high-entropy",
    severity: "info",
    technique: "T1027",
    title: "High domain entropy",
    detail: "Domain character entropy exceeds normal text thresholds.",
    action: "Check domain registration age.",
  },
  {
    signal: "tracking",
    severity: "info",
    title: "Tracking parameters present",
    detail: "Common tracking parameters in query string.",
    action: "Identify tracking service and verify data handling practices.",
  },
  {
    signal: "secrets",
    severity: "info",
    technique: "T1552",
    title: "Potential secrets in URL",
    detail: "Credential-like material present in URL path or query.",
    action: "Rotate and revoke if real.",
  },
];

export const URL_SIGNAL_MAP: Record<string, UrlRule> = Object.fromEntries(
  URL_SIGNALS.map((s) => [s.signal, s]),
);