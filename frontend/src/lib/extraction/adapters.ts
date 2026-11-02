import { refang } from "@/lib/ioc-patterns";
import type { Observation, ObservationKind } from "@/types/objects";
import { makeObservation, extractObservations } from "./observations";
import { classifyIoc, normalizeDomain, normalizeEmail, normalizeHash, normalizeIp, normalizeUrl } from "./normalize";

export interface FormatAdapter {
  id: string;
  label: string;
  detect(raw: string): boolean;
  extract(raw: string, source: string, ts?: string): Observation[];
}

type EvtxField = [name: string, value: string];

function evtxFields(raw: string): EvtxField[] {
  const out: EvtxField[] = [];
  const re = /<Data\s+Name="([^"]+)">\s*([^<]*?)\s*<\/Data>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) if (m[1] && m[2]) out.push([m[1], m[2]]);
  return out;
}

function jsonLines(raw: string): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try {
      const j = JSON.parse(t);
      if (j && typeof j === "object") out.push(j as Record<string, unknown>);
    } catch {
      /* non-JSON line — generic scanner covers it */
    }
  }
  return out;
}

function dedup(obs: Observation[]): Observation[] {
  const seen = new Set<string>();
  return obs.filter((o) => {
    if (seen.has(o.id)) return false;
    seen.add(o.id);
    return true;
  });
}

/** Canonical value for a known kind; null when the value does not normalize. */
function resolveCanonical(kind: ObservationKind, raw: string): string | null {
  const v = refang(raw).trim();
  if (kind === "ip") return normalizeIp(v);
  if (kind === "domain") return normalizeDomain(v);
  if (kind === "email") return normalizeEmail(v);
  if (kind === "url") return normalizeUrl(v);
  if (kind === "hash") return normalizeHash(v)?.value ?? null;
  return v || null;
}

/** Any structured value recognizable as a classic IOC becomes an observation of that kind. */
function classifyValueToObservation(raw: string, source: string, ts?: string): Observation | null {
  const value = refang(raw).trim();
  if (!value) return null;
  const t = classifyIoc(value);
  if (t === "ipv4" || t === "ipv6") return makeObservation({ kind: "ip", value: resolveCanonical("ip", value) ?? value, source, ts });
  if (t === "email") return makeObservation({ kind: "email", value: resolveCanonical("email", value) ?? value, source, ts });
  if (t === "url") return makeObservation({ kind: "url", value: resolveCanonical("url", value) ?? value, source, ts });
  if (t === "domain") return makeObservation({ kind: "domain", value: resolveCanonical("domain", value) ?? value, source, ts });
  if (t === "md5" || t === "sha1" || t === "sha256") {
    const h = normalizeHash(value);
    if (h) return makeObservation({ kind: "hash", value: h.value, source, meta: { hashType: h.type }, ts });
  }
  return null;
}

export const EVTX_ADAPTER: FormatAdapter = {
  id: "evtx",
  label: "EVTX / Sysmon",
  detect: (raw) => /<Event[\s>]/.test(raw) && /<Data\s+Name=/.test(raw),
  extract(raw, source, ts) {
    const out: Observation[] = [];
    for (const [name, value] of evtxFields(raw)) {
      const n = name.toLowerCase();
      if (/image|new process name/i.test(n)) {
        out.push(makeObservation({ kind: "process", value: refang(value).trim(), source, meta: { attr: "image" }, ts }));
      } else if (/commandline/i.test(n)) {
        out.push(makeObservation({ kind: "command", value: refang(value).trim(), source, meta: { attr: /^parent/.test(n) ? "parent" : "cmdline" }, ts }));
      } else if (/^hashes$/i.test(n)) {
        for (const part of value.split(",")) {
          const h = part.split("=")[1];
          if (!h) continue;
          const norm = normalizeHash(h);
          if (norm) out.push(makeObservation({ kind: "hash", value: norm.value, source, meta: { hashType: norm.type }, ts }));
        }
      } else if (/user|account name/i.test(n)) {
        out.push(makeObservation({ kind: "string", value: refang(value).trim(), source, meta: { attr: "user" }, ts }));
      } else if (/targetfilename/i.test(n)) {
        out.push(makeObservation({ kind: "string", value: refang(value).trim(), source, meta: { attr: "file" }, ts }));
      } else {
        const o = classifyValueToObservation(value, source, ts);
        if (o) out.push(o);
      }
    }
    const scanned = extractObservations(raw, source, ts);
    return dedup([...out, ...scanned.observations]);
  },
};

const CSV_TYPE_TO_KIND: Record<string, ObservationKind> = {
  ipv4: "ip",
  ipv6: "ip",
  ip: "ip",
  domain: "domain",
  hostname: "domain",
  url: "url",
  email: "email",
  md5: "hash",
  sha1: "hash",
  sha256: "hash",
};

export const CSV_ADAPTER: FormatAdapter = {
  id: "csv",
  label: "CSV IOC sheet",
  detect: (raw) => /^\s*type\s*,\s*value/i.test(raw),
  extract(raw, source, ts) {
    const lines = raw.split("\n").map((l) => l.trim()).filter((l) => l && !/^#/.test(l));
    if (!lines.length) return [];
    const header = lines[0].split(",").map((c) => c.trim());
    if (!/^type$/i.test(header[0] ?? "")) return [];
    const out: Observation[] = [];
    for (const line of lines.slice(1)) {
      const row = line.split(",").map((c) => c.trim());
      const t = (row[0] ?? "").toLowerCase();
      const value = row[1] ?? "";
      const kind = CSV_TYPE_TO_KIND[t];
      if (kind) {
        const canonical = resolveCanonical(kind, value);
        if (!canonical) continue;
        const meta: Record<string, string> = { context: "csv" };
        if (kind === "hash") {
          const h = normalizeHash(value);
          if (h) meta.hashType = h.type;
        }
        header.slice(2).forEach((h, i) => {
          const v = row[i + 2];
          if (h && v) meta[h] = v;
        });
        out.push(makeObservation({ kind, value: canonical, source, meta, ts }));
      } else {
        const o = classifyValueToObservation(value, source, ts);
        if (o) out.push(o);
      }
    }
    const scanned = extractObservations(raw, source, ts);
    return dedup([...out, ...scanned.observations]);
  },
};

export const SURICATA_ADAPTER: FormatAdapter = {
  id: "suricata",
  label: "Suricata EVE JSON",
  detect: (raw) => raw.trim().startsWith("{") && /"event_type"|"src_ip"/.test(raw),
  extract(raw, source, ts) {
    const out: Observation[] = [];
    for (const row of jsonLines(raw)) {
      for (const key of ["src_ip", "dest_ip"]) {
        const v = row[key];
        if (typeof v !== "string") continue;
        const ip = normalizeIp(v);
        if (ip) out.push(makeObservation({ kind: "ip", value: ip, source, ts }));
      }
      const dns = row["dns"];
      if (dns && typeof dns === "object" && "rrname" in dns) {
        const rr = (dns as Record<string, unknown>)["rrname"];
        if (typeof rr === "string") {
          const d = normalizeDomain(rr);
          if (d) out.push(makeObservation({ kind: "domain", value: d, source, ts }));
        }
      }
    }
    const scanned = extractObservations(raw, source, ts);
    return dedup([...out, ...scanned.observations]);
  },
};

const RX_COMBINED_LOG = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(\S+)\s+(\S+)(?:\s+\S+)?"\s+(\d{3})(?:\s+(\d+))?/;

/** One combined-log line → measured facts (client IP, method, path, status, size). */
function combinedLogLine(line: string): { ip: string; method: string; path: string; status: string; size?: string } | null {
  const m = line.match(RX_COMBINED_LOG);
  if (!m) return null;
  return { ip: m[1], method: m[2], path: m[3], status: m[4], size: m[5] };
}

export const NGINX_ADAPTER: FormatAdapter = {
  id: "nginx",
  label: "Nginx access log",
  detect: (raw) => {
    const lines = raw.split("\n").map((l) => l.trim()).filter(Boolean);
    if (!lines.length) return false;
    return lines.filter((l) => combinedLogLine(l) !== null).length >= 1;
  },
  extract(raw, source, ts) {
    const out: Observation[] = [];
    for (const line of raw.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      const row = combinedLogLine(t);
      if (!row) continue;
      const ip = normalizeIp(row.ip);
      if (ip) out.push(makeObservation({ kind: "ip", value: ip, source, ts }));
      out.push(
        makeObservation({
          kind: "string",
          value: `${row.method} ${row.path}`,
          source,
          meta: { attr: "http-request", method: row.method, path: row.path, status: row.status, client: row.ip },
          ts,
        }),
      );
    }
    return dedup(out);
  },
};

export const ZEEK_ADAPTER: FormatAdapter = {
  id: "zeek",
  label: "Zeek conn.log",
  detect: (raw) => /#fields\s+ts\s+uid|#path\s+conn\b/i.test(raw),
  extract(raw, source, ts) {
    const out: Observation[] = [];
    let fields: string[] = [];
    for (const line of raw.split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("@")) continue;
      if (t.startsWith("#fields")) {
        fields = t.replace(/^#fields\s+/, "").split(/[\t\s]+/);
        continue;
      }
      if (t.startsWith("#")) continue;
      if (!fields.length) continue;
      const cols = t.split("\t");
      const origIdx = fields.findIndex((f) => /(orig_h|addr)$/.test(f));
      const respIdx = fields.findIndex((f) => /(resp_h|addr)$/.test(f));
      const stateIdx = fields.indexOf("conn_state");
      const uidIdx = fields.indexOf("uid");
      const state = stateIdx >= 0 ? (cols[stateIdx] ?? "").trim() : "";
      const orig = origIdx >= 0 ? (cols[origIdx] ?? "").trim() : "";
      const resp = respIdx >= 0 ? (cols[respIdx] ?? "").trim() : "";
      if (state) {
        const meta: Record<string, string> = { attr: "zeek-conn-state", state };
        if (orig) meta.src = orig;
        if (resp) meta.dst = resp;
        const uid = uidIdx >= 0 ? (cols[uidIdx] ?? "").trim() : "";
        if (uid) meta.uid = uid;
        const endpoint = orig && resp ? `${orig} → ${resp}` : "";
        out.push(makeObservation({ kind: "string", value: endpoint ? `${state} ${endpoint}` : state, source, meta, ts }));
      }
      fields.forEach((f, i) => {
        if (!/(orig_h|resp_h|addr)$/.test(f)) return;
        const ip = normalizeIp(cols[i] ?? "");
        if (ip) out.push(makeObservation({ kind: "ip", value: ip, source, ts }));
      });
    }
    return dedup(out);
  },
};

const RX_TCPDUMP_LINE = /^\d{2}:\d{2}:\d{2}\.\d+\s+IP\s+\S+\s*>\s*\S+/;
const RX_TSHARK_LINE = /^\s*\d+\s+\d+\.\d{6}\s+\S+\s*→\s*\S+\s+\S+(?:\s|$)/;

/** "192.168.1.100.443" (tcpdump renders port after a dot) → canonical IP. */
function tcpdumpIpWithPort(token: string): string | null {
  const m = token.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.\d+$/);
  return m ? normalizeIp(m[1]) : normalizeIp(token);
}

const RX_DNS_QUERY = /(?:A\?|AAAA\?)\s*([a-z0-9.-]+\.[a-z]{2,})/i;

export const PCAP_ADAPTER: FormatAdapter = {
  id: "pcap",
  label: "PCAP text (tcpdump/tshark)",
  detect: (raw) => {
    const lines = raw.split("\n").map((l) => l.trim()).filter(Boolean);
    if (lines.length < 2) return false;
    const scored = lines.filter((l) => RX_TCPDUMP_LINE.test(l) || RX_TSHARK_LINE.test(l)).length;
    return scored >= 2;
  },
  extract(raw, source, ts) {
    const out: Observation[] = [];
    for (const line of raw.split("\n")) {
      const t = line.trim();
      if (!t) continue;

      if (RX_TSHARK_LINE.test(t)) {
        const [from, to] = t.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) ?? [];
        for (const ip of [from, to]) {
          const norm = ip ? normalizeIp(ip) : null;
          if (norm) out.push(makeObservation({ kind: "ip", value: norm, source, ts }));
        }
        const sn = t.match(/SNI=([a-z0-9.-]+\.[a-z]{2,})/i);
        if (sn) {
          const d = normalizeDomain(sn[1]);
          if (d) out.push(makeObservation({ kind: "domain", value: d, source, meta: { attr: "tls-sni" }, ts }));
        }
        const dns = t.match(/DNS\s+Standard\s+query(?: response)?\s+\S+\s+([a-z0-9.-]+\.[a-z]{2,})/i);
        if (dns) {
          const d = normalizeDomain(dns[1]);
          if (d) out.push(makeObservation({ kind: "domain", value: d, source, meta: { attr: "dns-query" }, ts }));
        }
        const path = t.match(/HTTP\s+\w+\s+(\S+)/i);
        if (path) out.push(makeObservation({ kind: "string", value: path[1], source, meta: { attr: "http-path" }, ts }));
        continue;
      }

      if (RX_TCPDUMP_LINE.test(t)) {
        const pair = t.split(/\s*>\s*/)[1]?.split(":")[0] ?? "";
        const [fromTok] = t.split(/\s*>\s*/);
        const fromIp = tcpdumpIpWithPort(fromTok.split(/\s+/).pop() ?? "");
        if (fromIp) out.push(makeObservation({ kind: "ip", value: fromIp, source, ts }));
        const toIp = tcpdumpIpWithPort(pair);
        if (toIp) out.push(makeObservation({ kind: "ip", value: toIp, source, ts }));
        const dns = t.match(RX_DNS_QUERY);
        if (dns) {
          const d = normalizeDomain(dns[1]);
          if (d) out.push(makeObservation({ kind: "domain", value: d, source, meta: { attr: "dns-query" }, ts }));
        }
      }
    }
    const scanned = extractObservations(raw, source, ts);
    return dedup([...out, ...scanned.observations]);
  },
};

export const TEXT_ADAPTER: FormatAdapter = {
  id: "text",
  label: "Text",
  detect: () => true,
  extract(raw, source, ts) {
    return extractObservations(raw, source, ts).observations;
  },
};

export const FORMAT_ADAPTERS: FormatAdapter[] = [EVTX_ADAPTER, CSV_ADAPTER, SURICATA_ADAPTER, ZEEK_ADAPTER, PCAP_ADAPTER, NGINX_ADAPTER, TEXT_ADAPTER];

export function detectFormat(raw: string): FormatAdapter {
  return FORMAT_ADAPTERS.find((a) => a.detect(raw)) ?? TEXT_ADAPTER;
}

export interface NormalizationResult {
  format: string;
  adapter: string;
  observations: Observation[];
}

/** One canonical surface: raw input → canonical Observation set (ANALYSIS_ENGINE §4b). */
export function normalizeObservations(raw: string, opts?: { format?: string; source?: string; ts?: string }): NormalizationResult {
  const adapter = opts?.format ? FORMAT_ADAPTERS.find((a) => a.id === opts.format) ?? TEXT_ADAPTER : detectFormat(raw);
  const observations = dedup(adapter.extract(raw, opts?.source ?? "normalize", opts?.ts));
  return { format: adapter.id, adapter: adapter.label, observations };
}
