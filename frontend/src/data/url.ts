import type { UrlKnowledge, UrlKnowledgeRow, UrlObservable } from "@/types/url";

/**
 * Pure URL domain logic (parsing, canonicalization, punycode, knowledge
 * graphs). Inference lives in the engine (lib/urlArtifact.ts); this module
 * only derives measurable facts from a parsed URL. Migrated from the retired
 * legacy url analyzer.
 */

export const FILE_EXT_RX = /\.(exe|msi|scr|ps1|vbs|docm|xlsm|pptm|zip|rar|7z|iso|dmg|bat|cmd|jar|wsf|js|vbe|pif|gadget|application|appref-ms)$/i;

export const SUSPICIOUS_PATHS = ["login", "signin", "verify", "reset", "password", "update", "payment", "confirm", "auth", "secure", "challenge", "banking", "account", "recovery", "validate", "2fa", "mfa", "activation", "billing"];

export const SUSPICIOUS_PORT_WARN: Record<string, string> = { "8080": "common proxy/c2 port", "8443": "alt HTTPS", "4443": "alt HTTPS", "1337": "leet / c2", "6666": "common c2", "7777": "common c2", "9001": "tor default", "9150": "tor browser", "10000": "backup exec / c2", "31337": "leet elite", "2222": "alt SSH / c2", "2082": "cPanel alt" };

export const NUMERIC_IP_RX = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

export const TRACKING_PARAMS = new Set(["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "ref", "source", "mc_cid", "mc_eid", "_ga", "_gl", "pk_source", "pk_medium", "pk_campaign", "yclid", "igshid", "ttclid", "twclid", "sc_campaign", "wt_mc"]);

export const BASE64_PATH_RX = /(?:[A-Za-z0-9+/]{4,}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;

/**
 * Payload-depth facts (§4a URL deep list): named downloads, script download
 * cradles, and obfuscated client-side script markers. Pure token/substring
 * checks over the parsed URL — measurable, never inferred.
 */
export const DOWNLOAD_QUERY_ARGS = ["filename", "file", "download", "dl"];

export const CRADLE_MARKERS = [
  "bitsadmin", "certutil", "mshta", "rundll32", "regsvr32", "wscript", "cscript",
  "invoke-expression", "iex(", "-enc", "-encodedcommand",
];

export const SCRIPT_OBFUSCATION_MARKERS = [
  "eval(", "atob(", "unescape(", "fromcharcode", "document.write(", "wshshell",
];

function decodeSafe(s: string): string {
  try { return decodeURIComponent(s); } catch { return s; }
}

/** Named payload on the URL: terminal path segment or query download argument. */
export function downloadFileName(parsed: URL, fileExt: string | null): string | null {
  const seg = decodeSafe(parsed.pathname).split("/").filter(Boolean).pop() ?? "";
  if (fileExt && FILE_EXT_RX.test(seg)) return seg;
  for (const key of DOWNLOAD_QUERY_ARGS) {
    const arg = parsed.searchParams.get(key);
    if (!arg) continue;
    const name = decodeSafe(arg).split(/[\\/]/).pop() ?? arg;
    if (FILE_EXT_RX.test(name)) return name;
  }
  return null;
}

/** Execution/staging tokens and client-side obfuscation tokens visible in the URL. */
export function urlPayloadMarkers(href: string): { cradle: string[]; obfuscated: string[] } {
  const low = href.toLowerCase();
  return {
    cradle: CRADLE_MARKERS.filter((m) => low.includes(m)),
    obfuscated: SCRIPT_OBFUSCATION_MARKERS.filter((m) => low.includes(m)),
  };
}

export function hash(s: string) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return Math.abs(h); }

const PUNY_BASE = 36, PUNY_TMIN = 1, PUNY_TMAX = 26, PUNY_SKEW = 38, PUNY_DAMP = 700, PUNY_INITIAL_BIAS = 72, PUNY_INITIAL_N = 128;

function punyAdapt(delta: number, numpoints: number, firsttime: boolean): number {
  let d = firsttime ? Math.floor(delta / PUNY_DAMP) : delta >> 1;
  d += Math.floor(d / numpoints);
  let k = 0;
  while (d > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) >> 1) { d = Math.floor(d / (PUNY_BASE - PUNY_TMIN)); k += PUNY_BASE; }
  return k + Math.floor(((PUNY_BASE - PUNY_TMIN + 1) * d) / (d + PUNY_SKEW));
}

export function decodePunycode(input: string): string {
  const lastDash = input.lastIndexOf("-");
  const basicLen = lastDash > -1 ? lastDash : 0;
  const output: number[] = [];
  for (let j = 0; j < basicLen; j++) {
    const c = input.charCodeAt(j);
    if (c < 0x80) output.push(c); else throw new Error("invalid punycode");
  }
  let i = 0;
  let n = PUNY_INITIAL_N, bias = PUNY_INITIAL_BIAS;
  let pos = basicLen > 0 ? lastDash + 1 : 0;
  while (pos < input.length) {
    const oldi = i;
    let w = 1;
    let k = PUNY_BASE;
    for (;;) {
      if (pos >= input.length) throw new Error("invalid punycode");
      const c = input[pos++];
      let digit: number;
      if (c >= "0" && c <= "9") digit = c.charCodeAt(0) - 48 + 26;
      else if (c >= "A" && c <= "Z") digit = c.charCodeAt(0) - 65;
      else if (c >= "a" && c <= "z") digit = c.charCodeAt(0) - 97;
      else throw new Error("invalid punycode digit");
      i += digit * w;
      const t = k <= bias ? PUNY_TMIN : k >= bias + PUNY_TMAX ? PUNY_TMAX : k - bias;
      if (digit < t) break;
      w *= PUNY_BASE - t;
      k += PUNY_BASE;
    }
    bias = punyAdapt(i - oldi, output.length + 1, oldi === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...output);
}

const HOMOGLYPH_MAP: [string, string][] = [["o", "0"], ["0", "o"], ["l", "1"], ["i", "1"], ["a", "4"], ["e", "3"], ["s", "5"], ["t", "7"], ["g", "9"], ["rn", "m"], ["а", "a"], ["е", "e"], ["о", "o"], ["р", "p"], ["с", "c"], ["х", "x"], ["у", "y"], ["і", "i"]];

function digitToBasic(digit: number): string {
  if (digit < 26) return String.fromCharCode(97 + digit);
  if (digit < 36) return String.fromCharCode(48 + digit - 26);
  return "?";
}

export function encodePunycode(input: string): string {
  const basic: number[] = [];
  const nonBasic: number[] = [];
  for (const ch of input) {
    const cp = ch.codePointAt(0)!;
    if (cp < 0x80) basic.push(cp); else nonBasic.push(cp);
  }
  const output = [...basic.map((cp) => String.fromCharCode(cp))];
  if (basic.length) output.push("-");
  let n = PUNY_INITIAL_N, delta = 0, bias = PUNY_INITIAL_BIAS;
  let handled = basic.length;
  while (handled < input.length) {
    let m = Infinity;
    for (const cp of [...input].map((ch) => ch.codePointAt(0)!)) {
      if (cp >= n && cp < m) m = cp;
    }
    delta += (m - n) * (handled + 1);
    n = m;
    let i = 0;
    for (const ch of input) {
      const cp = ch.codePointAt(0)!;
      if (cp < n) delta++;
      if (cp === n) {
        let q = delta;
        for (let k = PUNY_BASE; ; k += PUNY_BASE) {
          const t = k <= bias ? PUNY_TMIN : k >= bias + PUNY_TMAX ? PUNY_TMAX : k - bias;
          if (q < t) break;
          output.push(digitToBasic(t + ((q - t) % (PUNY_BASE - t))));
          q = Math.floor((q - t) / (PUNY_BASE - t));
        }
        output.push(digitToBasic(q));
        bias = punyAdapt(delta, handled + 1, handled === basic.length);
        delta = 0;
        handled++;
      }
      if (cp === n && i++ >= input.length) break;
    }
    delta++;
    n++;
  }
  return output.join("");
}

export function lookalikeCandidates(label: string): string[] {
  if (!label || label.length < 4 || /^\d+$/.test(label)) return [];
  const out: string[] = [];
  const seen = new Set<string>([label]);
  for (const [from, to] of HOMOGLYPH_MAP) {
    if (out.length >= 6) break;
    for (let i = 0; i <= label.length - from.length; i++) {
      if (label.slice(i, i + from.length) === from) {
        const cand = label.slice(0, i) + to + label.slice(i + from.length);
        if (!seen.has(cand)) { seen.add(cand); out.push(cand); }
        if (out.length >= 6) break;
      }
    }
  }
  return out;
}

const IPV4_RX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const EMAIL_RX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const HASH_RX = /\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b/g;

export function ipv4Class(ip: string): string {
  const [a, b] = ip.split(".").map(Number);
  if (a === 10) return "private — RFC 1918 (10.0.0.0/8)";
  if (a === 172 && b >= 16 && b <= 31) return "private — RFC 1918 (172.16.0.0/12)";
  if (a === 192 && b === 168) return "private — RFC 1918 (192.168.0.0/16)";
  if (a === 127) return "loopback — RFC 5735 (127.0.0.0/8)";
  if (a === 169 && b === 254) return "link-local — RFC 3927 (169.254.0.0/16)";
  if (a === 100 && b >= 64 && b <= 127) return "CGNAT — RFC 6598 (100.64.0.0/10)";
  if (a >= 224 && a <= 239) return "multicast — RFC 5771";
  if (a >= 240) return "reserved — RFC 5735";
  return "public — ASN unknown (opt-in live enrichment)";
}

function extractObservables(parsed: URL): UrlObservable[] {
  const found: UrlObservable[] = [];
  const seen = new Set<string>();
  const scan = (text: string, source: "path" | "query") => {
    for (const ip of text.match(IPV4_RX) || []) {
      if (ip === parsed.hostname || /^0+\./.test(ip)) continue;
      if (!seen.has(`ip:${ip}`)) { seen.add(`ip:${ip}`); found.push({ kind: "ipv4", value: ip, source }); }
    }
    for (const em of text.match(EMAIL_RX) || []) {
      if (!seen.has(`em:${em}`)) { seen.add(`em:${em}`); found.push({ kind: "email", value: em, source }); }
    }
    for (const hsh of text.match(HASH_RX) || []) {
      if (!seen.has(`h:${hsh}`)) { seen.add(`h:${hsh}`); found.push({ kind: "hash", value: hsh, source }); }
    }
  };
  if (parsed.pathname) scan(parsed.pathname, "path");
  if (parsed.search) scan(parsed.search, "query");
  return found;
}

export function emptyUrlKnowledge(): UrlKnowledge {
  return {
    canonicalUrl: { value: "", changes: [] },
    redirectChainNote: "",
    whois: { derived: [], unavailable: [] },
    certificate: { derived: [], unavailable: [] },
    asn: [],
    relatedDomains: [],
    observables: [],
    relatedEntities: [],
    passiveDns: { configured: false, note: "" },
  };
}

export function buildUrlKnowledge(
  parsed: URL,
  ctx: { isNumericDomain: boolean; tld: string; punycode: boolean; isShortener: boolean; fileExt: string | null; isSuspiciousTLD: boolean }
): UrlKnowledge {
  const host = parsed.hostname.toLowerCase();
  const scheme = parsed.protocol.toLowerCase().replace(":", "");
  const labels = host.split(".");
  const registrable = ctx.isNumericDomain ? host : labels.slice(-2).join(".");
  const sld = labels.length >= 2 ? labels[labels.length - 2] : host;

  let port = parsed.port;
  if (port === "80" && scheme === "http") port = "";
  if (port === "443" && scheme === "https") port = "";

  const removedTracking: string[] = [];
  const canonParams = new URLSearchParams();
  for (const [k, v] of parsed.searchParams) {
    if (TRACKING_PARAMS.has(k.toLowerCase())) removedTracking.push(k);
    else canonParams.append(k, v);
  }
  const canonical = `${scheme}://${host}${port ? ":" + port : ""}${parsed.pathname === "" ? "/" : parsed.pathname}${canonParams.toString() ? "?" + canonParams.toString() : ""}`;
  const changes: string[] = [];
  if (parsed.protocol !== scheme + ":") changes.push("scheme lowercased");
  if (parsed.hostname !== host) changes.push("host lowercased");
  if (parsed.port && !port) changes.push(`default port stripped (${parsed.port})`);
  if (removedTracking.length) changes.push(`tracking params removed: ${removedTracking.join(", ")}`);
  if (parsed.pathname === "") changes.push("empty path normalized to \"/\"");
  if (parsed.hash) changes.push("fragment dropped");

  let decodedIdn: string | null = null;
  if (ctx.punycode) {
    try {
      const pLabel = host.split(".").find((l) => l.startsWith("xn--"));
      if (pLabel) decodedIdn = host.replace(pLabel, decodePunycode(pLabel.slice(4)));
    } catch { decodedIdn = null; }
  }

  const whoisDerived: UrlKnowledgeRow[] = [
    { label: "Registrable domain", value: registrable, derived: true },
    { label: "Second-level label", value: sld, derived: true },
    { label: "TLD", value: `.${ctx.tld}`, derived: true, tone: ctx.isSuspiciousTLD ? "warning" : "default" },
    { label: "Subdomain depth", value: String(Math.max(0, labels.length - 2)), derived: true },
    ...(decodedIdn ? [{ label: "IDN (decoded)", value: decodedIdn, derived: true, tone: "warning" as const }] : []),
  ];
  const whoisUnavailable = [
    "Registration date — unknown offline; requires opt-in live WHOIS query",
    "Registrant / registrar — unknown offline; requires opt-in live WHOIS query",
  ];

  const certDerived: UrlKnowledgeRow[] = [
    { label: "Scheme", value: scheme.toUpperCase(), derived: true },
    { label: "Assumed TLS port", value: scheme === "http" ? "80 (cleartext — no TLS expected)" : "443", derived: true, tone: scheme === "http" ? "warning" : "default" },
  ];
  const certUnavailable = [
    "Certificate not fetched — no live TLS handshake in offline analysis",
    "Issuer, validity window, SANs — unknown; requires opt-in TLS inspection",
  ];

  const asnRows: UrlKnowledgeRow[] = (() => {
    if (ctx.isNumericDomain) {
      return [
        { label: "Host style", value: "direct IPv4", derived: true },
        { label: "Address class", value: ipv4Class(host), derived: true, tone: /public/.test(ipv4Class(host)) ? "warning" : "default" },
      ];
    }
    return [
      { label: "Host style", value: "domain name", derived: true },
      { label: "ASN", value: "unknown — requires IP resolution + live lookup (opt-in)", derived: false },
    ];
  })();

  const candidateBase = decodedIdn ? decodedIdn.split(".")[0] : sld;
  const reencode = ctx.punycode && decodedIdn ? (l: string) => l.match(/[^\x00-\x7F]/) ? `xn--${encodePunycode(l)}` : l : (l: string) => l;
  const relatedDomains: { value: string; note: string; verified: boolean }[] = [
    { value: registrable, note: "registrable domain", verified: true },
    ...(labels.length > 2 ? [{ value: `www.${registrable}`, note: "alias candidate", verified: false }] : []),
    ...(decodedIdn ? [{ value: decodedIdn, note: "decoded IDN form", verified: true }] : []),
    ...lookalikeCandidates(candidateBase).map((c) => ({ value: `${reencode(c)}.${ctx.tld}`, note: "homoglyph candidate — verify before use", verified: false })),
  ];

  const observables = extractObservables(parsed);

  const relatedEntities: UrlKnowledgeRow[] = [
    { label: "Domain", value: host, derived: true },
    { label: "Registrable", value: registrable, derived: true },
    ...(ctx.isNumericDomain ? [{ label: "IP address", value: host, derived: true }] : []),
    ...(decodedIdn ? [{ label: "IDN form", value: decodedIdn, derived: true }] : []),
  ];

  return {
    canonicalUrl: { value: canonical, changes },
    redirectChainNote: ctx.isShortener
      ? "Shortener expansion derived from URL shape — observed hops require live fetch (opt-in)."
      : ctx.fileExt
        ? "Direct fetch expected; download responses may add a Content-Disposition landing hop — requires live fetch (opt-in)."
        : "Single-hop expectation — observed redirects require live fetch (opt-in).",
    whois: { derived: whoisDerived, unavailable: whoisUnavailable },
    certificate: { derived: certDerived, unavailable: certUnavailable },
    asn: asnRows,
    relatedDomains,
    observables,
    relatedEntities,
    passiveDns: {
      configured: false,
      note: "No passive DNS source configured. Enable opt-in backend enrichment to query historical DNS records for this domain.",
    },
  };
}
