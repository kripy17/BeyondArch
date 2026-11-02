import type { Severity } from "@/lib/severity";
import type { Observation, ObservationKind } from "@/types/objects";
import { extractObservations, extractCommandLines, makeObservation } from "@/lib/extraction";
import { normalizeIp, normalizeDomain, normalizeEmail, normalizeHash, normalizeUrl, classifyIoc } from "@/lib/extraction/normalize";
import { refang } from "@/lib/ioc-patterns";

export type AlertFormat =
  | "beyondlabs"
  | "sigma"
  | "suricata"
  | "sysmon"
  | "crowdstrike"
  | "defender"
  | "guardduty"
  | "elastic";

export interface ParsedAlert {
  format: AlertFormat;
  title: string;
  summary: string;
  /** Severity declared by the producer (beyondlabs/sigma/suricata) or documented static mapping (sysmon event types). */
  severity: Severity;
  observedAt?: string;
  /** Detection name the alert carries (sigma title / canonical rule_ref) — resolved against saved rules at ingest. */
  ruleName?: string;
  observations: Observation[];
  raw: string;
}

function jsonObject(raw: string): Record<string, unknown> | null {
  try {
    const j = JSON.parse(raw.trim());
    return j && typeof j === "object" && !Array.isArray(j) ? (j as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/* ── BeyondLabs canonical alert (beyondlabs.alert.v1) ─────── */

function canonicalObservations(values: string[], source: string, ts: string): Observation[] {
  const out: Observation[] = [];
  for (const v of values) {
    const value = refang(v).trim();
    if (!value) continue;
    const t = classifyIoc(value);
    if (t === "ipv4" || t === "ipv6") out.push(makeObservation({ kind: "ip", value: normalizeIp(value) ?? value, source, ts }));
    else if (t === "email") out.push(makeObservation({ kind: "email", value: normalizeEmail(value) ?? value, source, ts }));
    else if (t === "url") out.push(makeObservation({ kind: "url", value: normalizeUrl(value) ?? value, source, ts }));
    else if (t === "domain") out.push(makeObservation({ kind: "domain", value: normalizeDomain(value) ?? value, source, ts }));
    else if (t === "md5" || t === "sha1" || t === "sha256") {
      const h = normalizeHash(value);
      if (h) out.push(makeObservation({ kind: "hash", value: h.value, source, meta: { hashType: h.type }, ts }));
    }
  }
  return out;
}

function canonicalAlert(obj: Record<string, unknown>): ParsedAlert | null {
  if (obj["schema"] !== "beyondlabs.alert.v1") return null;
  const title = typeof obj["title"] === "string" ? obj["title"] : "";
  if (!title) return null;
  const sev = String(obj["severity"] ?? "medium");
  const severity: Severity = ["info", "low", "medium", "high", "critical"].includes(sev) ? (sev as Severity) : "medium";
  const summary = typeof obj["summary"] === "string" ? obj["summary"] : "";
  const observedAt = typeof obj["observed_at"] === "string" ? obj["observed_at"] : undefined;
  const ruleName = typeof obj["rule_ref"] === "string" ? obj["rule_ref"] : undefined;
  const body = typeof obj["body"] === "string" ? obj["body"] : "";
  const raw = JSON.stringify(obj, null, 2);
  const source = `beyondlabs-alert:${title}`;
  const ts = observedAt ?? new Date().toISOString();
  const observables = Array.isArray(obj["observables"])
    ? (obj["observables"] as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const observations = observables.length
    ? canonicalObservations(observables, source, ts)
    : extractObservations(body || raw, source, ts).observations;
  return { format: "beyondlabs", title, summary, severity, observedAt, ruleName, observations, raw };
}

/* ── Sigma-style detection output ─────────────────────────── */

function sigmaAlert(raw: string): ParsedAlert | null {
  const title = raw.match(/^\s*title\s*:\s*(.+)$/m)?.[1]?.trim();
  if (!title) return null;
  const level = raw.match(/^\s*level\s*:\s*(.+)$/m)?.[1]?.trim().toLowerCase() ?? "";
  const severity: Severity =
    level === "critical" ? "critical" :
    level === "high" ? "high" :
    level === "medium" ? "medium" :
    level === "low" || level === "informational" ? "low" : "medium";
  const desc = raw.match(/^\s*(?:description|details?)\s*:\s*(.+)$/m)?.[1]?.trim() ?? "";
  const source = `sigma-alert:${title}`;
  const ts = new Date().toISOString();
  const observations = [
    ...extractObservations(raw, source, ts).observations,
    ...extractCommandLines(raw, source, ts),
  ];
  return { format: "sigma", title, summary: desc, severity, ruleName: title, observations, raw };
}

/* ── Suricata alert (EVE JSON, event_type: alert) ─────────── */

const SURICATA_SEVERITY: Record<number, Severity> = { 1: "critical", 2: "high", 3: "medium", 4: "low" };

function suricataAlert(obj: Record<string, unknown>): ParsedAlert | null {
  if (obj["event_type"] !== "alert") return null;
  const alertObj = obj["alert"];
  const alert = alertObj && typeof alertObj === "object" ? (alertObj as Record<string, unknown>) : {};
  const signature = typeof alert["signature"] === "string" ? alert["signature"] : "Suricata alert";
  const sevNum = typeof alert["severity"] === "number" ? alert["severity"] : undefined;
  const severity = (sevNum !== undefined && SURICATA_SEVERITY[sevNum]) ? SURICATA_SEVERITY[sevNum] : "medium";
  const src = typeof obj["src_ip"] === "string" ? obj["src_ip"] : undefined;
  const dst = typeof obj["dest_ip"] === "string" ? obj["dest_ip"] : undefined;
  const observedAt = typeof obj["timestamp"] === "string" ? obj["timestamp"] : undefined;
  const raw = JSON.stringify(obj, null, 2);
  const source = `suricata-alert:${signature}`;
  const ts = observedAt ?? new Date().toISOString();
  const observations: Observation[] = [];
  for (const ip of [src, dst]) {
    if (!ip) continue;
    const v = normalizeIp(ip);
    if (v) observations.push(makeObservation({ kind: "ip", value: v, source, ts, meta: { role: ip === src ? "src" : "dst" } }));
  }
  observations.push(...extractCommandLines(raw, source, ts));
  const summary = src && dst ? `src ${src} → dst ${dst}` : `${signature}`;
  return { format: "suricata", title: signature, summary, severity, observedAt, observations, raw };
}

/* ── Sysmon-derived alert (XML <Event>) ───────────────────── */

const SYSMON_EVENTID_SEVERITY: Record<number, Severity> = {
  3: "high",   // network connection
  1: "medium", // process create
  7: "medium", // image load
  22: "low",   // dns query
  11: "low",   // file create
};

function xmlFields(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /<Data\s+Name="([^"]+)">\s*([^<]*?)\s*<\/Data>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) if (m[1] && m[2]) out[m[1]] = m[2];
  return out;
}

function basename(p: string): string {
  return p.split(/[\\/]/).pop() ?? p;
}

function sysmonAlert(raw: string): ParsedAlert | null {
  if (!/<Event\b/.test(raw)) return null;
  const eventId = Number(raw.match(/<EventID[^>]*>\s*(\d+)\s*<\/EventID>/)?.[1] ?? 0);
  const fields = xmlFields(raw);
  const commandLine = fields["CommandLine"] ?? "";
  const image = fields["Image"] ?? "";
  const target = fields["TargetFilename"] ?? "";
  const src = fields["DestinationIp"] ?? undefined;
  const dst = fields["SourceIp"] ?? undefined;
  const title = commandLine
    ? `Sysmon EventID ${eventId}: ${commandLine.slice(0, 120)}`
    : `Sysmon EventID ${eventId}: ${basename(image || target || "event")}`;
  const severity = SYSMON_EVENTID_SEVERITY[eventId] ?? "medium";
  const source = `sysmon-alert:${eventId}`;
  const ts = new Date().toISOString();
  const observations: Observation[] = [];
  if (commandLine) {
    observations.push(
      makeObservation({
        kind: "command",
        value: commandLine.slice(0, 512),
        source,
        ts,
        meta: { process: basename(image).replace(/\.exe$/i, ""), context: "sysmon-e1" },
      }),
    );
  }
  for (const ip of [src, dst]) {
    if (!ip) continue;
    const v = normalizeIp(ip);
    if (v) observations.push(makeObservation({ kind: "ip", value: v, source, ts, meta: { role: ip === src ? "dst" : "src" } }));
  }
  const scanned = extractObservations(raw, source, ts);
  observations.push(...scanned.observations.filter((o) => o.kind !== "command"));
  const summary = commandLine ? `command: ${commandLine.slice(0, 160)}` : `image: ${image || target}`;
  return { format: "sysmon", title, summary, severity, observations, raw };
}

/* ── CrowdStrike Falcon Detection ─────────────────────────── */

function crowdstrikeAlert(obj: Record<string, unknown>): ParsedAlert | null {
  const isCs =
    Boolean(obj["DetectId"] || obj["CompositeId"] || obj["FalconHost"]) ||
    obj["event_type"] === "DetectionSummaryEvent" ||
    (Boolean(obj["ComputerName"]) && Boolean(obj["Tactic"] || obj["Technique"]));
  if (!isCs) return null;

  const title =
    (typeof obj["Technique"] === "string" && obj["Technique"]) ||
    (typeof obj["Tactic"] === "string" && `CrowdStrike: ${obj["Tactic"]}`) ||
    (typeof obj["Description"] === "string" && obj["Description"]) ||
    "CrowdStrike Falcon Detection";

  let severity: Severity = "medium";
  const rawSev = obj["Severity"] ?? obj["severity"];
  if (typeof rawSev === "number") {
    if (rawSev >= 4) severity = "critical";
    else if (rawSev === 3) severity = "high";
    else if (rawSev === 2) severity = "medium";
    else severity = "low";
  } else if (typeof rawSev === "string") {
    const s = rawSev.toLowerCase();
    if (s === "critical") severity = "critical";
    else if (s === "high") severity = "high";
    else if (s === "medium") severity = "medium";
    else severity = "low";
  }

  const host = typeof obj["ComputerName"] === "string" ? obj["ComputerName"] : undefined;
  const user = typeof obj["UserName"] === "string" ? obj["UserName"] : undefined;
  const cmd = typeof obj["CommandLine"] === "string" ? obj["CommandLine"] : undefined;
  const summary = [
    host ? `host: ${host}` : "",
    user ? `user: ${user}` : "",
    cmd ? `cmd: ${cmd.slice(0, 120)}` : "",
  ].filter(Boolean).join(" | ") || (typeof obj["Description"] === "string" ? obj["Description"] : title);

  const raw = JSON.stringify(obj, null, 2);
  const source = `crowdstrike:${host ?? "endpoint"}`;
  const ts = typeof obj["ProcessStartTime"] === "string" ? obj["ProcessStartTime"] : new Date().toISOString();
  const observations: Observation[] = [];

  if (cmd) {
    observations.push(
      makeObservation({
        kind: "command",
        value: cmd.slice(0, 512),
        source,
        ts,
        meta: { process: String(obj["FileName"] ?? "powershell"), context: "crowdstrike-cmd" },
      }),
    );
  }

  const scanned = extractObservations(raw, source, ts);
  observations.push(...scanned.observations.filter((o) => o.kind !== "command"));

  return { format: "crowdstrike", title, summary, severity, observations, raw, ruleName: title };
}

/* ── Microsoft Defender 365 Alert ─────────────────────────── */

function defenderAlert(obj: Record<string, unknown>): ParsedAlert | null {
  const isDefender =
    Boolean(obj["alertId"] && (obj["detectorId"] || obj["serviceSource"])) ||
    (Boolean(obj["incidentId"]) && Array.isArray(obj["evidence"])) ||
    (Boolean(obj["category"]) && Array.isArray(obj["evidence"]) && Boolean(obj["alertCreationTime"]));
  if (!isDefender) return null;

  const title =
    (typeof obj["title"] === "string" && obj["title"]) ||
    (typeof obj["alertName"] === "string" && obj["alertName"]) ||
    "Microsoft Defender 365 Alert";

  let severity: Severity = "medium";
  const s = String(obj["severity"] ?? "Medium").toLowerCase();
  if (s === "critical" || s === "high") severity = "high";
  else if (s === "low" || s === "informational") severity = "low";
  else severity = "medium";

  const desc = typeof obj["description"] === "string" ? obj["description"] : String(obj["category"] ?? "");
  const summary = desc.slice(0, 200) || title;
  const raw = JSON.stringify(obj, null, 2);
  const source = `defender:${String(obj["alertId"] ?? obj["incidentId"] ?? "alert")}`;
  const ts = typeof obj["alertCreationTime"] === "string" ? obj["alertCreationTime"] : new Date().toISOString();
  const observations: Observation[] = [];

  if (Array.isArray(obj["evidence"])) {
    for (const ev of obj["evidence"]) {
      if (ev && typeof ev === "object") {
        const evObj = ev as Record<string, unknown>;
        if (typeof evObj["ipAddress"] === "string") {
          const v = normalizeIp(evObj["ipAddress"]);
          if (v) observations.push(makeObservation({ kind: "ip", value: v, source, ts }));
        }
        if (typeof evObj["sha256"] === "string") {
          const h = normalizeHash(evObj["sha256"]);
          if (h) observations.push(makeObservation({ kind: "hash", value: h.value, source, meta: { hashType: "sha256" }, ts }));
        }
        if (typeof evObj["url"] === "string") {
          const u = normalizeUrl(evObj["url"]);
          if (u) observations.push(makeObservation({ kind: "url", value: u, source, ts }));
        }
      }
    }
  }

  const scanned = extractObservations(raw, source, ts);
  for (const obs of scanned.observations) {
    if (!observations.some((o) => o.value === obs.value)) {
      observations.push(obs);
    }
  }

  return { format: "defender", title, summary, severity, observations, raw, ruleName: title };
}

/* ── AWS GuardDuty Finding ────────────────────────────────── */

function guarddutyAlert(obj: Record<string, unknown>): ParsedAlert | null {
  const isGd = Boolean(obj["service"] && obj["schemaVersion"] && typeof obj["type"] === "string");
  if (!isGd) return null;

  const type = String(obj["type"]);
  const title = typeof obj["title"] === "string" ? obj["title"] : `GuardDuty: ${type}`;
  let severity: Severity = "medium";
  const num = typeof obj["severity"] === "number" ? obj["severity"] : 5;
  if (num >= 7) severity = "high";
  else if (num >= 4) severity = "medium";
  else severity = "low";

  const desc = typeof obj["description"] === "string" ? obj["description"] : type;
  const summary = desc.slice(0, 200);
  const raw = JSON.stringify(obj, null, 2);
  const source = `guardduty:${String(obj["id"] ?? "finding")}`;
  const ts = typeof obj["updatedAt"] === "string" ? obj["updatedAt"] : new Date().toISOString();
  const observations: Observation[] = [];

  const scanned = extractObservations(raw, source, ts);
  observations.push(...scanned.observations);

  return { format: "guardduty", title, summary, severity, observations, raw, ruleName: type };
}

/* ── Elastic Security / ECS Alert ─────────────────────────── */

function elasticAlert(obj: Record<string, unknown>): ParsedAlert | null {
  const isElastic =
    Boolean(obj["kibana.alert.rule.name"]) ||
    (Boolean(obj["rule"]) && typeof (obj["rule"] as Record<string, unknown>)["name"] === "string" && (Boolean(obj["host"]) || Boolean(obj["source"]))) ||
    (Boolean(obj["ecs"]) && Boolean(obj["host"]));
  if (!isElastic) return null;

  const ruleObj = obj["rule"] && typeof obj["rule"] === "object" ? (obj["rule"] as Record<string, unknown>) : {};
  const title =
    (typeof obj["kibana.alert.rule.name"] === "string" && obj["kibana.alert.rule.name"]) ||
    (typeof ruleObj["name"] === "string" && ruleObj["name"]) ||
    "Elastic Security Detection";

  let severity: Severity = "medium";
  const rawSev = String(ruleObj["severity"] ?? obj["kibana.alert.severity"] ?? "medium").toLowerCase();
  if (rawSev === "critical") severity = "critical";
  else if (rawSev === "high") severity = "high";
  else if (rawSev === "low") severity = "low";
  else severity = "medium";

  const message = typeof obj["message"] === "string" ? obj["message"] : String(ruleObj["description"] ?? title);
  const summary = message.slice(0, 200);
  const raw = JSON.stringify(obj, null, 2);
  const source = `elastic-alert:${title}`;
  const ts = typeof obj["@timestamp"] === "string" ? obj["@timestamp"] : new Date().toISOString();
  const observations: Observation[] = [];

  const scanned = extractObservations(raw, source, ts);
  observations.push(...scanned.observations);

  return { format: "elastic", title, summary, severity, observations, raw, ruleName: title };
}

/* ── dispatch ─────────────────────────────────────────────── */

export function detectAlertFormat(raw: string): AlertFormat | null {
  const obj = jsonObject(raw);
  if (obj) {
    if (obj["schema"] === "beyondlabs.alert.v1") return "beyondlabs";
    if (obj["event_type"] === "alert") return "suricata";
    if (
      Boolean(obj["DetectId"] || obj["CompositeId"] || obj["FalconHost"]) ||
      obj["event_type"] === "DetectionSummaryEvent" ||
      (Boolean(obj["ComputerName"]) && Boolean(obj["Tactic"] || obj["Technique"]))
    ) {
      return "crowdstrike";
    }
    if (
      Boolean(obj["alertId"] && (obj["detectorId"] || obj["serviceSource"])) ||
      (Boolean(obj["incidentId"]) && Array.isArray(obj["evidence"])) ||
      (Boolean(obj["category"]) && Array.isArray(obj["evidence"]))
    ) {
      return "defender";
    }
    if (Boolean(obj["service"] && obj["schemaVersion"] && typeof obj["type"] === "string")) return "guardduty";
    if (Boolean(obj["kibana.alert.rule.name"]) || (Boolean(obj["rule"]) && typeof (obj["rule"] as Record<string, unknown>)["name"] === "string")) {
      return "elastic";
    }
    return null;
  }
  if (/^\s*title\s*:/m.test(raw) && /^\s*detection\s*:/m.test(raw)) return "sigma";
  if (/<Event\b/.test(raw) && /Microsoft-Windows-Sysmon/.test(raw)) return "sysmon";
  return null;
}

/** Parse one supported alert format into canonical observations. Pure — no storage access. */
export function parseAlert(raw: string): ParsedAlert | null {
  const obj = jsonObject(raw);
  if (obj) {
    return (
      canonicalAlert(obj) ??
      suricataAlert(obj) ??
      crowdstrikeAlert(obj) ??
      defenderAlert(obj) ??
      guarddutyAlert(obj) ??
      elasticAlert(obj) ??
      null
    );
  }
  if (/^\s*title\s*:/m.test(raw) && /^\s*detection\s*:/m.test(raw)) return sigmaAlert(raw);
  if (/<Event\b/.test(raw) && /Microsoft-Windows-Sysmon/.test(raw)) return sysmonAlert(raw);
  return null;
}

export function observationKinds(observations: Observation[]): ObservationKind[] {
  return [...new Set(observations.map((o) => o.kind))];
}

/** Factual IOC kinds, for case assembly (ip/domain/url/email/hash only — commands/strings stay out of the IOC table). */
export function iocObservations(observations: Observation[]): Observation[] {
  return observations.filter((o) =>
    o.kind === "ip" || o.kind === "domain" || o.kind === "url" || o.kind === "email" || (o.kind === "hash" && classifyIoc(o.value) !== "unknown")
  );
}