import { refang, uniq } from "@/lib/ioc-patterns";
import { objectId } from "@/lib/ids";
import type { Observation, ObservationKind } from "@/types/objects";
import { INVESTIGATION_OBJECTS_V1 } from "@/types/objects";
import { classifyIoc, normalizeDomain, normalizeEmail, normalizeHash, normalizeIp, normalizeUrl } from "./normalize";

export function observationId(kind: ObservationKind, value: string): string {
  return objectId("observation", kind, value);
}

export function makeObservation(opts: {
  kind: ObservationKind;
  value: string;
  source: string;
  meta?: Record<string, string>;
  ts?: string;
}): Observation {
  return {
    id: observationId(opts.kind, opts.value),
    kind: opts.kind,
    value: opts.value,
    meta: opts.meta ?? {},
    source: opts.source,
    ts: opts.ts ?? new Date().toISOString(),
    schemaVersion: INVESTIGATION_OBJECTS_V1,
  };
}

const RX_URL = /\bhttps?:\/\/[^\s<>"')]+/gi;
const RX_IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const RX_HASH = /\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b/gi;
const RX_EMAIL = /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi;
const RX_DOMAIN = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;

export interface ExtractionResult {
  observations: Observation[];
  /** counts by kind, for consumers that report fact totals */
  counts: Record<ObservationKind, number>;
}

/**
 * Pure, deterministic, side-effect-free extraction (ANALYSIS_ENGINE §4a).
 * Facts only — never infers intent. Same canonical value yields the same
 * observation id across formats (ANALYSIS_ENGINE §4b acceptance).
 */
export function extractObservations(raw: string, source: string, ts?: string): ExtractionResult {
  const text = refang(raw);
  const out: Observation[] = [];
  const push = (kind: ObservationKind, value: string, meta?: Record<string, string>) => {
    out.push(makeObservation({ kind, value, source, meta, ts }));
  };

  const emailMatches = Array.from(text.matchAll(RX_EMAIL));
  for (const m of emailMatches) {
    const e = normalizeEmail(m[0]);
    if (e) push("email", e);
  }

  for (const m of text.matchAll(RX_URL)) {
    const u = normalizeUrl(m[0]);
    if (!u) continue;
    let host: string;
    try {
      host = new URL(u).hostname;
    } catch {
      continue;
    }
    const meta: Record<string, string> = { host };
    try {
      const parsed = new URL(u);
      meta.scheme = parsed.protocol.replace(":", "");
      if (parsed.pathname) meta.path = parsed.pathname;
    } catch {
      /* hostname already validated */
    }
    push("url", u, meta);
    if (normalizeIp(host)) {
      push("ip", host, { from: "url" });
    } else if (normalizeDomain(host) && host !== "localhost") {
      push("domain", host, { from: "url" });
    }
  }

  const working = text.replace(RX_URL, " ").replace(RX_EMAIL, " ");
  for (const m of working.matchAll(RX_IPV4)) {
    const ip = normalizeIp(m[0]);
    if (ip) push("ip", ip);
  }

  for (const m of working.matchAll(RX_HASH)) {
    const h = normalizeHash(m[0]);
    if (h) push("hash", h.value, { hashType: h.type });
  }

  for (const m of working.matchAll(RX_DOMAIN)) {
    const d = normalizeDomain(m[0]);
    if (d) push("domain", d);
  }

  const seen = new Set<string>();
  const observations = out.filter((o) => {
    if (seen.has(o.id)) return false;
    seen.add(o.id);
    return true;
  });
  const counts = observations.reduce(
    (acc, o) => {
      acc[o.kind] = (acc[o.kind] ?? 0) + 1;
      return acc;
    },
    {} as Record<ObservationKind, number>,
  );
  return { observations, counts };
}

const LEGACY_TO_OBSERVATION: Record<string, ObservationKind | undefined> = {
  URL: "url",
  Domain: "domain",
  IPv4: "ip",
  IPv6: "ip",
  Email: "email",
  MD5: "hash",
  SHA1: "hash",
  SHA256: "hash",
  CVE: "string",
  ATTACK: "string",
  MAC: "string",
  Base64: "string",
};

const LEGACY_TYPES: Record<string, string | undefined> = {
  CVE: "cve",
  ATTACK: "attack",
  MAC: "mac",
  Base64: "base64",
};

/** Bridge from the legacy parser IOC map (data/parser.ts) to canonical observations. */
export function observationsFromIocs(
  iocs: Record<string, string[]>,
  source: string,
  context = "legacy-parser",
  ts?: string,
): Observation[] {
  const out: Observation[] = [];
  for (const [kind, values] of Object.entries(iocs)) {
    const obsKind = LEGACY_TO_OBSERVATION[kind];
    if (!obsKind) continue;
    for (const raw of values) {
      const v = refang(raw).trim();
      let value = v;
      const meta: Record<string, string> = { context };
      if (obsKind === "url") {
        value = normalizeUrl(v) ?? v;
      } else if (obsKind === "domain") {
        value = normalizeDomain(v) ?? v;
      } else if (obsKind === "ip") {
        value = normalizeIp(v) ?? v;
      } else if (obsKind === "email") {
        value = normalizeEmail(v) ?? v;
      } else if (obsKind === "hash") {
        const h = normalizeHash(v);
        value = h?.value ?? v;
        meta.hashType = h?.type ?? kind.toLowerCase();
      }
      const legacyType = LEGACY_TYPES[kind];
      if (legacyType) meta.iocType = legacyType;
      if (classifyIoc(v) !== "unknown") meta.iocType = classifyIoc(v);
      out.push(makeObservation({ kind: obsKind, value, source, meta, ts }));
    }
  }
  const seen = new Set<string>();
  return out.filter((o) => {
    if (seen.has(o.id)) return false;
    seen.add(o.id);
    return true;
  });
}

export function uniqueObservationValues(observations: Observation[]): string[] {
  return uniq(observations.map((o) => o.value));
}

/**
 * Command-line extraction (facts only): deterministic per-line capture of
 * process invocations (powershell/cmd/wscript/etc). Feeds the command-kind
 * reasoning rules; never infers intent. No-ops on structured formats whose
 * adapters already emit command observations.
 */
const RX_PROCESS_TOKEN =
  /\b(?:powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|mshta(?:\.exe)?|certutil(?:\.exe)?|bitsadmin|schtasks(?:\.exe)?|wmic|whoami|ipconfig|netstat|tasklist)\b/i;

export function extractCommandLines(raw: string, source: string, ts?: string): Observation[] {
  const out: Observation[] = [];
  for (const line of raw.split("\n")) {
    const value = line.replace(/^\s*(?:Command\s*Line\s*:|\$\s*|>\s*)?\s*/, "").trim();
    if (!value || value.length > 512) continue;
    if (!RX_PROCESS_TOKEN.test(value)) continue;
    const m = value.match(RX_PROCESS_TOKEN);
    out.push(
      makeObservation({
        kind: "command",
        value,
        source,
        meta: { process: m?.[0]?.replace(/\.exe$/i, "") ?? "unknown" },
        ts,
      }),
    );
  }
  return out;
}