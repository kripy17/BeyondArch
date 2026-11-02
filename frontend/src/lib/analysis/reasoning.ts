import { SUSPICIOUS_TLDS } from "@/lib/ioc-patterns";
import { objectId } from "@/lib/ids";
import type { Finding, Observation } from "@/types/objects";
import { INVESTIGATION_OBJECTS_V1 } from "@/types/objects";
import { LOG_RULES, LOG_SEVERITY_FLOOR, type LogRule } from "./log-rules";
import { PCAP_SEVERITY_FLOOR } from "./pcap-rules";
import { URL_SEVERITY_FLOOR } from "./url-rules";
import { EMAIL_SEVERITY_FLOOR } from "./email-rules";
import { ZEEK_STATE_RULES, ZEEK_SEVERITY_FLOOR, type ZeekStateRule } from "./zeek-rules";
import { WEB_STATUS_RULES, WEB_PROBE_RULES, WEB_SEVERITY_FLOOR, matchWebProbe, matchWebStatus, type WebStatusRule, type WebProbeRule } from "./web-rules";
import type { WeightedObservation } from "./weighting";

/**
 * Threat Reasoning (ANALYSIS_ENGINE §4c module 4).
 * Hypothesis-style conclusions, each backed by observation refs, never verdict
 * strings. Findings carry confidence: "unknown" until the Confidence module fills
 * them (module 5). Deterministic rule list — ordered, most specific first.
 */

const BAD_TLDS = SUSPICIOUS_TLDS;

export interface ReasoningRule {
  id: string;
  title: string;
  detail: string;
  technique?: string;
  severity: Finding["severity"];
  minScore: number;
  kinds: Observation["kind"][];
  match: (w: WeightedObservation[]) => boolean;
  /** Overrides the kinds + minScore filter when selecting supporting observations. */
  matchObs?: (w: WeightedObservation) => boolean;
  /**
   * Per-observation findings (one finding per matched observation). The
   * observation's value/meta drive the finding's title/detail/technique —
   * used for external-detection signals (e.g. PCAP findings) where the
   * observation is the record of a measured detection.
   */
  render?: (w: WeightedObservation) => { severity: Finding["severity"]; title: string; detail: string; technique?: string };
}

function commandValues(w: WeightedObservation[]): string[] {
  return w.filter((x) => x.observation.kind === "command").map((x) => x.observation.value);
}

function urlValues(w: WeightedObservation[]): string[] {
  return w.filter((x) => x.observation.kind === "url").map((x) => x.observation.value);
}

function hasAny(values: string[], re: RegExp): boolean {
  return values.some((v) => re.test(v));
}

function fileMeta(w: WeightedObservation[], key: string): boolean {
  return w.some((x) => x.observation.kind === "file" && x.observation.meta[key] === "true");
}

function pcapDetection(severity: Finding["severity"]): (w: WeightedObservation) => boolean {
  return (w) =>
    w.observation.kind === "string" && w.observation.meta.attr === "pcap-detection" && w.observation.meta.severity === severity;
}

function pcapDetectionRule(severity: Finding["severity"]): ReasoningRule {
  const is = pcapDetection(severity);
  return {
    id: `pcap-detection-${severity}`,
    title: "Network detection",
    detail: "A detection signal recorded from network capture analysis.",
    severity,
    minScore: PCAP_SEVERITY_FLOOR[severity],
    kinds: ["string"],
    match: (w) => w.some(is),
    matchObs: is,
    render: (w) => ({
      severity,
      title: (w.observation.meta.title as string | undefined) ?? w.observation.value,
      detail: (w.observation.meta.detail as string | undefined) ?? w.observation.value,
      technique: (w.observation.meta.technique as string | undefined) ?? undefined,
    }),
  };
}

const PCAP_DETECTION_RULES: ReasoningRule[] = (["critical", "high", "medium", "low"] as const).map(pcapDetectionRule);

function urlDetection(severity: Finding["severity"]): (w: WeightedObservation) => boolean {
  return (w) =>
    w.observation.kind === "string" && w.observation.meta.attr === "url-detection" && w.observation.meta.severity === severity;
}

function urlDetectionRule(severity: Finding["severity"]): ReasoningRule {
  const is = urlDetection(severity);
  return {
    id: `url-detection-${severity}`,
    title: "URL detection signal",
    detail: "A measured signal recorded from a URL structure analysis.",
    severity,
    minScore: URL_SEVERITY_FLOOR[severity],
    kinds: ["string"],
    match: (w) => w.some(is),
    matchObs: is,
    render: (w) => ({
      severity,
      title: (w.observation.meta.title as string | undefined) ?? w.observation.value,
      detail: (w.observation.meta.detail as string | undefined) ?? w.observation.value,
      technique: (w.observation.meta.technique as string | undefined) ?? undefined,
    }),
  };
}

const URL_DETECTION_RULES: ReasoningRule[] = (["critical", "medium", "info"] as const).map(urlDetectionRule);

function emailDetection(severity: Finding["severity"]): (w: WeightedObservation) => boolean {
  return (w) =>
    w.observation.kind === "string" &&
    w.observation.meta.attr === "email-detection" &&
    w.observation.meta.severity === severity;
}

function emailDetectionRule(severity: Finding["severity"]): ReasoningRule {
  const is = emailDetection(severity);
  return {
    id: `email-detection-${severity}`,
    title: "Email detection signal",
    detail: "A measured signal recorded from an email envelope or body analysis.",
    severity,
    minScore: EMAIL_SEVERITY_FLOOR[severity],
    kinds: ["string"],
    match: (w) => w.some(is),
    matchObs: is,
    render: (w) => ({
      severity,
      title: (w.observation.meta.title as string | undefined) ?? w.observation.value,
      detail: (w.observation.meta.detail as string | undefined) ?? w.observation.value,
      technique: (w.observation.meta.technique as string | undefined) ?? undefined,
    }),
  };
}

const EMAIL_DETECTION_RULES: ReasoningRule[] = (["critical", "medium", "info"] as const).map(emailDetectionRule);

export const REASONING_RULES: ReasoningRule[] = [
  {
    id: "amsi-bypass",
    title: "AMSI bypass evasion",
    detail: "Command line contains an AMSI bypass pattern — likely disabling script-memory scanning.",
    technique: "T1562.001",
    severity: "critical",
    minScore: 0.5,
    kinds: ["command"],
    match: (w) => hasAny(commandValues(w), /amsiutils|amsiinitfailed|amsi\b/i),
  },
  {
    id: "encoded-download-remote",
    title: "Initial payload retrieval",
    detail: "Encoded PowerShell command combined with a remote download cradle and a reachable URL — consistent with initial payload retrieval.",
    technique: "T1105",
    severity: "high",
    minScore: 0.5,
    kinds: ["command", "url"],
    match: (w) => {
      const cmds = commandValues(w);
      return (
        hasAny(cmds, /-enc(?:odedcommand)?\b/i) &&
        hasAny(cmds, /invoke-webrequest|downloadstring|downloadfile|webclient/i) &&
        urlValues(w).length > 0
      );
    },
  },
  {
    id: "encoded-command",
    title: "Encoded PowerShell command",
    detail: "PowerShell launched with an encoded command — commonly used to hide instructions.",
    technique: "T1059.001",
    severity: "high",
    minScore: 0.5,
    kinds: ["command"],
    match: (w) => hasAny(commandValues(w), /-enc(?:odedcommand)?\b|-\s*e\s+[a-z0-9+/=]{20,}/i),
  },
  {
    id: "download-cradle",
    title: "Remote payload retrieval",
    detail: "Download cradle pattern observed — likely staging or retrieving payload from a remote host.",
    technique: "T1105",
    severity: "high",
    minScore: 0.5,
    kinds: ["command", "url"],
    match: (w) => hasAny(commandValues(w), /invoke-webrequest|downloadstring|webclient|bitsadmin\s+\/transfer/i),
  },
  {
    id: "embedded-creds",
    title: "Credentials embedded in URL",
    detail: "URL authority embeds user:pass@ credentials.",
    technique: "T1078",
    severity: "high",
    minScore: 0.5,
    kinds: ["url"],
    match: (w) => urlValues(w).some((u) => (u.split("://")[1] ?? "").split(/[/?#]/)[0].includes("@")),
  },
  {
    id: "hidden-execution",
    title: "Hidden process execution",
    detail: "Command configured to run without a visible window.",
    technique: "T1564",
    severity: "medium",
    minScore: 0.5,
    kinds: ["command"],
    match: (w) => hasAny(commandValues(w), /-windowstyle\s+(hidden|minimized)|-w\s+hidden/i),
  },
  {
    id: "high-risk-tld-url",
    title: "High-risk TLD in URL",
    detail: "URL uses a low-reputation TLD — commonly abused for phishing or staging",
    technique: "T1566",
    severity: "medium",
    minScore: 0.5,
    kinds: ["url"],
    match: (w) =>
      urlValues(w).some((u) => {
        const host = (u.split("://")[1] ?? "").split(/[/?#]/)[0];
        return BAD_TLDS.has(host.split(".").pop()?.toLowerCase() ?? "");
      }),
  },
  {
    id: "suspicious-sender-domain",
    title: "Suspicious sender domain",
    detail: "Email sender domain uses a high-risk TLD — often seen in phishing campaigns.",
    technique: "T1566",
    severity: "medium",
    minScore: 0.25,
    kinds: ["email"],
    match: (w) =>
      w
        .filter((x) => x.observation.kind === "email")
        .some((x) => {
          const t = x.observation.value.split("@")[1]?.split(".").pop()?.toLowerCase();
          return !!t && BAD_TLDS.has(t);
        }),
  },
  {
    id: "double-extension",
    title: "Double extension masquerade",
    detail: "Filename presents a second, hidden extension — commonly used to disguise executable files.",
    technique: "T1204",
    severity: "critical",
    minScore: 0.25,
    kinds: ["file"],
    match: (w) => fileMeta(w, "doubleExt"),
  },
  {
    id: "suspicious-file-extension",
    title: "Suspicious file extension",
    detail: "File extension is commonly used to distribute malware or active content.",
    technique: "T1204",
    severity: "high",
    minScore: 0.25,
    kinds: ["file"],
    match: (w) => fileMeta(w, "suspiciousExt"),
  },
  {
    id: "hidden-extension-chars",
    title: "Hidden extension characters",
    detail: "Filename contains Unicode control or encoded characters designed to hide the real extension.",
    severity: "high",
    minScore: 0.25,
    kinds: ["file"],
    match: (w) => fileMeta(w, "hiddenExt"),
  },
  {
    id: "file-type-mismatch",
    title: "File type / extension mismatch",
    detail: "File content does not match the extension's expected magic bytes — possible renamed artifact.",
    technique: "T1027",
    severity: "high",
    minScore: 0.25,
    kinds: ["file"],
    match: (w) => fileMeta(w, "magicMismatch"),
  },
  {
    id: "high-entropy-content",
    title: "High entropy content",
    detail: "Content entropy exceeds normal text thresholds — possible packing, encryption, or encoded payload.",
    technique: "T1027",
    severity: "medium",
    minScore: 0.25,
    kinds: ["file"],
    match: (w) => fileMeta(w, "highEntropy"),
  },
  {
    id: "large-file",
    title: "Large file",
    detail: "File is unusually large for its type — may conceal embedded payloads.",
    severity: "low",
    minScore: 0.25,
    kinds: ["file"],
    match: (w) => fileMeta(w, "largeFile"),
  },
  {
    id: "unusually-long-filename",
    title: "Unusually long filename",
    detail: "Filename is long — a pattern often seen in auto-generated or obfuscated samples.",
    severity: "low",
    minScore: 0.25,
    kinds: ["file"],
    match: (w) => fileMeta(w, "longName"),
  },
  {
    id: "macro-enabled",
    title: "Macro-enabled document",
    detail: "Document carries an embedded macro project — a common initial-access carrier.",
    technique: "T1204",
    severity: "high",
    minScore: 0.25,
    kinds: ["macro"],
    match: (w) => w.some((x) => x.observation.kind === "macro"),
  },
  {
    id: "exposed-secret",
    title: "Potential secrets exposed",
    detail: "Credential-like material present in file content — rotate if real.",
    technique: "T1552",
    severity: "high",
    minScore: 0.25,
    kinds: ["string"],
    match: (w) => w.some((x) => x.observation.kind === "string" && x.observation.meta.secretType != null),
  },
  ...LOG_RULES.map(logEventRule),
  ...PCAP_DETECTION_RULES,
  ...URL_DETECTION_RULES,
  ...EMAIL_DETECTION_RULES,
  ...ZEEK_STATE_RULES.map(zeekStateRule),
  ...WEB_PROBE_RULES.map(webProbeRule),
  ...WEB_STATUS_RULES.map(webStatusRule),
];

function logEventRule(rule: LogRule): ReasoningRule {
  return {
    id: `log-${rule.eventId}`,
    title: rule.title,
    detail: rule.reason,
    technique: rule.mitre.id,
    severity: rule.severity,
    minScore: LOG_SEVERITY_FLOOR[rule.severity],
    kinds: ["string"],
    match: (w) =>
      w.some(
        (x) => x.observation.kind === "string" && x.observation.meta.attr === "log-event" && x.observation.meta.eventId === rule.eventId,
      ),
    matchObs: (w) => w.observation.kind === "string" && w.observation.meta.attr === "log-event" && w.observation.meta.eventId === rule.eventId,
  };
}

function zeekStateRule(rule: ZeekStateRule): ReasoningRule {
  const is = (w: WeightedObservation) =>
    w.observation.kind === "string" && w.observation.meta.attr === "zeek-conn-state" && w.observation.meta.state === rule.state;
  return {
    id: `zeek-${rule.state}`,
    title: rule.title,
    detail: rule.reason,
    technique: rule.mitre.id,
    severity: rule.severity,
    minScore: ZEEK_SEVERITY_FLOOR[rule.severity],
    kinds: ["string"],
    match: (w) => w.some(is),
    matchObs: is,
    render: (w) => ({
      severity: rule.severity,
      title: rule.title,
      detail: `${rule.reason} Connection: ${w.observation.meta.src ?? "?"} → ${w.observation.meta.dst ?? "?"} (state ${rule.state}).`,
      technique: rule.mitre.id,
    }),
  };
}

function webStatusRule(rule: WebStatusRule): ReasoningRule {
  const is = (w: WeightedObservation) =>
    w.observation.kind === "string" &&
    w.observation.meta.attr === "http-request" &&
    (matchWebStatus(w.observation.meta.status ?? "")?.status ?? null) === rule.status;
  return {
    id: `http-${rule.status}`,
    title: rule.title,
    detail: rule.reason,
    technique: rule.mitre.id,
    severity: rule.severity,
    minScore: WEB_SEVERITY_FLOOR[rule.severity],
    kinds: ["string"],
    match: (w) => w.some(is),
    matchObs: is,
    render: (w) => ({
      severity: rule.severity,
      title: rule.title,
      detail: `${rule.reason} Request: ${w.observation.value} (status ${w.observation.meta.status ?? "?"}).`,
      technique: rule.mitre.id,
    }),
  };
}

function webProbeRule(rule: WebProbeRule): ReasoningRule {
  const is = (w: WeightedObservation) =>
    w.observation.kind === "string" &&
    w.observation.meta.attr === "http-request" &&
    (matchWebProbe(w.observation.meta.path ?? "")?.path.source ?? "") === rule.path.source;
  return {
    id: `web-probe-${rule.path.source}`,
    title: rule.title,
    detail: rule.reason,
    technique: rule.mitre.id,
    severity: rule.severity,
    minScore: WEB_SEVERITY_FLOOR[rule.severity],
    kinds: ["string"],
    match: (w) => w.some(is),
    matchObs: is,
    render: (w) => ({
      severity: rule.severity,
      title: rule.title,
      detail: `${rule.reason} Path: ${w.observation.meta.path ?? "?"} (client ${w.observation.meta.client ?? "?"}).`,
      technique: rule.mitre.id,
    }),
  };
}

export function reason(weighted: WeightedObservation[], source = "threat-reasoner"): Finding[] {
  const out: Finding[] = [];
  for (const rule of REASONING_RULES) {
    if (!rule.match(weighted)) continue;
    if (rule.render) {
      const matched = weighted.filter((w) => rule.matchObs?.(w) ?? false);
      for (const w of matched) {
        const r = rule.render(w);
        out.push({
          id: objectId("finding", source, rule.id, w.observation.id),
          severity: r.severity,
          title: r.title,
          detail: r.detail,
          source,
          technique: r.technique,
          observations: [w.observation],
          confidence: { level: "unknown", contributors: [] },
          schemaVersion: INVESTIGATION_OBJECTS_V1,
        });
      }
      continue;
    }
    const supporting = weighted.filter((w) =>
      rule.matchObs ? rule.matchObs(w) : rule.kinds.includes(w.observation.kind) && w.score >= rule.minScore,
    );
    out.push({
      id: objectId("finding", source, rule.id),
      severity: rule.severity,
      title: rule.title,
      detail: rule.detail,
      source,
      technique: rule.technique,
      observations: supporting.map((w) => w.observation),
      confidence: { level: "unknown", contributors: [] },
      schemaVersion: INVESTIGATION_OBJECTS_V1,
    });
  }
  return out;
}