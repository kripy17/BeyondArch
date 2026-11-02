import { AMSI_BYPASS_PATTERNS, DOWNLOAD_CRADLES, LOLBINS, SUSPICIOUS_TLDS, SHORTENERS, domainEntropy } from "@/lib/ioc-patterns";
import type { Observation } from "@/types/objects";
import type { Severity } from "@/lib/severity";
import { LOG_SEVERITY_FLOOR } from "./log-rules";
import { PCAP_SEVERITY_FLOOR } from "./pcap-rules";
import { URL_SEVERITY_FLOOR } from "./url-rules";
import { EMAIL_SEVERITY_FLOOR } from "./email-rules";
import { ZEEK_STATE_RULES, ZEEK_SEVERITY_FLOOR } from "./zeek-rules";
import { matchWebProbe, matchWebStatus, WEB_SEVERITY_FLOOR } from "./web-rules";

/**
 * Evidence Weighting (ANALYSIS_ENGINE §4c module 1).
 * Deterministic per-observation score + rationale. Replaces ad-hoc +20/+10/+15.
 * Scores are signal strength only — never verdicts (facts stay in extraction).
 */

export interface WeightedObservation {
  observation: Observation;
  score: number;
  rationale: string[];
}

export const STRONG = 0.8;
export const MEDIUM = 0.5;
export const WEAK = 0.25;

export function weightObservation(o: Observation): WeightedObservation {
  const rationale: string[] = [];
  let score = 0;
  const v = o.value.toLowerCase();
  const meta = o.meta;

  if (o.kind === "command") {
    if (AMSI_BYPASS_PATTERNS.some((p) => v.includes(p))) {
      score = Math.max(score, 0.95);
      rationale.push("AMSI bypass pattern");
    }
    if (DOWNLOAD_CRADLES.some((c) => v.includes(c.toLowerCase()))) {
      score = Math.max(score, 0.91);
      rationale.push("Remote download cradle");
    }
    if (/-enc(?:odedcommand)?\b|-\s*e\s+[a-z0-9+/=]{20,}/i.test(o.value)) {
      score = Math.max(score, 0.88);
      rationale.push("Encoded PowerShell");
    }
    if (/-windowstyle\s+(hidden|minimized)|-w\s+(hidden|minimized)/i.test(o.value)) {
      score = Math.max(score, 0.7);
      rationale.push("Hidden execution");
    }
    if (/-(?:nop|noprofile)|\-executionpolicy\s+bypass/i.test(o.value)) {
      score = Math.max(score, 0.7);
      rationale.push("Reduced restriction flags");
    }
    if (LOLBINS.some((b) => v.includes(b))) {
      score = Math.max(score, 0.6);
      rationale.push("Living-off-the-land binary");
    }
  }

  if (o.kind === "url") {
    const authority = (o.value.split("://")[1] ?? "").split(/[/?#]/)[0] ?? "";
    if (authority.includes("@")) {
      score = Math.max(score, 0.9);
      rationale.push("Credentials embedded in URL");
    }
    if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(authority.split("@").pop() ?? "")) {
      score = Math.max(score, 0.55);
      rationale.push("IP-literal URL");
    }
    const tld = authority.split(".").pop()?.toLowerCase();
    if (tld && SUSPICIOUS_TLDS.has(tld)) {
      score = Math.max(score, 0.55);
      rationale.push(`High-risk TLD .${tld}`);
    }
    const host = meta.host ?? "";
    if (host && SHORTENERS.has(host.replace(/^www\./, ""))) {
      score = Math.max(score, 0.6);
      rationale.push("URL shortener");
    }
    const path = meta.path ?? "";
    if (path.length > 20 && domainEntropy(path) > 2.2) {
      score = Math.max(score, 0.5);
      rationale.push("High-entropy URL path");
    }
  }

  if (o.kind === "domain") {
    const tld = o.value.split(".").pop();
    if (tld && SUSPICIOUS_TLDS.has(tld)) {
      score = Math.max(score, 0.5);
      rationale.push(`High-risk TLD .${tld}`);
    }
    if (domainEntropy(o.value) > 5) {
      score = Math.max(score, 0.45);
      rationale.push("High-entropy domain");
    }
  }

  if (o.kind === "email") {
    const domain = o.value.split("@")[1] ?? "";
    const tld = domain.split(".").pop();
    if (tld && SUSPICIOUS_TLDS.has(tld)) {
      score = Math.max(score, 0.5);
      rationale.push(`Sender domain on high-risk TLD .${tld}`);
    }
  }

  if (o.kind === "hash") {
    score = Math.max(score, 0.35);
    rationale.push("File hash present");
  }

  if (o.kind === "ip") {
    score = Math.max(score, 0.25);
    rationale.push("Network indicator");
  }

  if (o.kind === "file") {
    const m = o.meta;
    if (m.doubleExt === "true") {
      score = Math.max(score, 0.9);
      rationale.push("Double-extension masquerade");
    }
    if (m.suspiciousExt === "true") {
      score = Math.max(score, 0.8);
      rationale.push("Suspicious file extension");
    }
    if (m.hiddenExt === "true") {
      score = Math.max(score, 0.75);
      rationale.push("Hidden extension characters");
    }
    if (m.magicMismatch === "true") {
      score = Math.max(score, 0.85);
      rationale.push("File type / extension mismatch");
    }
    if (m.highEntropy === "true") {
      score = Math.max(score, 0.65);
      rationale.push("High-entropy content");
    }
    if (m.largeFile === "true") {
      score = Math.max(score, 0.3);
      rationale.push("Unusually large file");
    }
    if (m.longName === "true") {
      score = Math.max(score, 0.3);
      rationale.push("Unusually long filename");
    }
  }

  if (o.kind === "macro") {
    score = Math.max(score, 0.9);
    rationale.push("Macro-enabled document");
  }

  if (o.kind === "string" && meta.secretType != null) {
    score = Math.max(score, 0.85);
    rationale.push(`Exposed ${meta.secretType} credential`);
  }

  if (o.kind === "string" && meta.attr === "log-event") {
    score = Math.max(score, LOG_SEVERITY_FLOOR[meta.severity as Severity] ?? 0.5);
    rationale.push(`Log event matched: ${meta.rule}`);
  }

  if (o.kind === "string" && meta.attr === "pcap-detection") {
    score = Math.max(score, PCAP_SEVERITY_FLOOR[meta.severity as Severity] ?? 0.5);
    rationale.push("PCAP detection signal");
  }

  if (o.kind === "string" && meta.attr === "zeek-conn-state") {
    const state = ZEEK_STATE_RULES.find((r) => r.state === meta.state);
    if (state) {
      score = Math.max(score, ZEEK_SEVERITY_FLOOR[state.severity]);
      rationale.push(`Zeek ${meta.state} connection state signal`);
    }
  }

  if (o.kind === "string" && meta.attr === "http-request") {
    const status = matchWebStatus(meta.status ?? "");
    const probe = matchWebProbe(meta.path ?? "");
    if (status) {
      score = Math.max(score, WEB_SEVERITY_FLOOR[status.severity]);
      rationale.push(`HTTP ${meta.status} error signal`);
    }
    if (probe) {
      score = Math.max(score, WEB_SEVERITY_FLOOR[probe.severity]);
      rationale.push("HTTP probing path signal");
    }
  }

  if (o.kind === "string" && meta.attr === "url-detection") {
    score = Math.max(score, URL_SEVERITY_FLOOR[meta.severity as Severity] ?? 0.5);
    rationale.push("URL detection signal");
  }

  if (o.kind === "string" && meta.attr === "email-detection") {
    score = Math.max(score, EMAIL_SEVERITY_FLOOR[meta.severity as Severity] ?? 0.5);
    rationale.push("Email detection signal");
  }

  if (score === 0) {
    score = 0.1;
    rationale.push("Recorded fact");
  }

  return { observation: o, score, rationale };
}

export function weightObservations(observations: Observation[]): WeightedObservation[] {
  return observations.map(weightObservation);
}