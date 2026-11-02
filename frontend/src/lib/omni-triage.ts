import { defang, refang, isAuthParamToken } from "@/lib/ioc-patterns";
import type { Case } from "@/data/case";

export type OmniKind =
  | "ipv4"
  | "ipv6"
  | "domain"
  | "url"
  | "hash-md5"
  | "hash-sha1"
  | "hash-sha256"
  | "cve"
  | "email"
  | "base64"
  | "json-log"
  | "raw-text";

export interface OmniTriageResult {
  raw: string;
  kind: OmniKind;
  label: string;
  defanged: string;
  refanged: string;
  decodedPreview?: string;
  metadata?: Record<string, string>;
  pivots: {
    label: string;
    to: string;
    search?: Record<string, string>;
    primary?: boolean;
  }[];
}

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_REGEX = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i;
const CVE_REGEX = /^CVE-\d{4}-\d{4,7}$/i;
const EMAIL_REGEX = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;
const MD5_REGEX = /^[a-fA-F0-9]{32}$/;
const SHA1_REGEX = /^[a-fA-F0-9]{40}$/;
const SHA256_REGEX = /^[a-fA-F0-9]{64}$/;
const URL_REGEX = /^(?:hxxps?|https?|ftp):\/\/[^\s/$.?#].[^\s]*$/i;
const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;
  // 10.0.0.0/8
  if (parts[0] === 10) return true;
  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;
  // 127.0.0.0/8 (loopback)
  if (parts[0] === 127) return true;
  // 169.254.0.0/16 (link-local)
  if (parts[0] === 169 && parts[1] === 254) return true;
  return false;
}

export function tryDecodeBase64(str: string): string | null {
  const trimmed = str.trim();
  if (trimmed.length < 8 || trimmed.length % 4 !== 0) return null;
  if (!/^[A-Za-z0-9+/=]+$/.test(trimmed)) return null;
  try {
    const decoded = atob(trimmed);
    // Ensure decoded is mostly printable ascii
    const printable = decoded.replace(/[\x20-\x7E\r\n\t]/g, "");
    if (printable.length / decoded.length > 0.15) return null;
    return decoded;
  } catch {
    return null;
  }
}

export function classifyOmniInput(input: string): OmniTriageResult {
  const trimmed = input.trim();
  const cleaned = refang(trimmed);

  // 1. IPv4
  if (IPV4_REGEX.test(cleaned)) {
    const isPrivate = isPrivateIPv4(cleaned);
    const scope = isPrivate ? "Private / Internal (RFC1918)" : "Public Internet Address";
    return {
      raw: trimmed,
      kind: "ipv4",
      label: `IPv4 (${scope})`,
      defanged: defang(cleaned),
      refanged: cleaned,
      metadata: { Scope: scope, Category: isPrivate ? "Local Network" : "Routable External" },
      pivots: [
        { label: "Intel Lookup", to: "/intel", search: { q: cleaned }, primary: true },
        { label: "SIEM Sightings", to: "/siem", search: { q: cleaned } },
        { label: "Check in Logs", to: "/logs", search: { q: cleaned } },
      ],
    };
  }

  // 2. Hash MD5 / SHA1 / SHA256
  if (MD5_REGEX.test(trimmed)) {
    return {
      raw: trimmed,
      kind: "hash-md5",
      label: "MD5 File Hash",
      defanged: trimmed,
      refanged: trimmed,
      metadata: { Type: "MD5 (128-bit)", Length: "32 hex characters" },
      pivots: [
        { label: "File Reputation", to: "/file", search: { hash: trimmed }, primary: true },
        { label: "Intel Hub", to: "/intel", search: { q: trimmed } },
        { label: "SIEM Search", to: "/siem", search: { q: trimmed } },
      ],
    };
  }
  if (SHA1_REGEX.test(trimmed)) {
    return {
      raw: trimmed,
      kind: "hash-sha1",
      label: "SHA-1 File Hash",
      defanged: trimmed,
      refanged: trimmed,
      metadata: { Type: "SHA-1 (160-bit)", Length: "40 hex characters" },
      pivots: [
        { label: "File Reputation", to: "/file", search: { hash: trimmed }, primary: true },
        { label: "Intel Hub", to: "/intel", search: { q: trimmed } },
        { label: "SIEM Search", to: "/siem", search: { q: trimmed } },
      ],
    };
  }
  if (SHA256_REGEX.test(trimmed)) {
    return {
      raw: trimmed,
      kind: "hash-sha256",
      label: "SHA-256 File Hash",
      defanged: trimmed,
      refanged: trimmed,
      metadata: { Type: "SHA-256 (256-bit)", Length: "64 hex characters" },
      pivots: [
        { label: "File Reputation", to: "/file", search: { hash: trimmed }, primary: true },
        { label: "Intel Hub", to: "/intel", search: { q: trimmed } },
        { label: "SIEM Search", to: "/siem", search: { q: trimmed } },
      ],
    };
  }

  // 3. CVE
  if (CVE_REGEX.test(trimmed)) {
    const cveUpper = trimmed.toUpperCase();
    return {
      raw: trimmed,
      kind: "cve",
      label: "Common Vulnerabilities & Exposures",
      defanged: cveUpper,
      refanged: cveUpper,
      metadata: { Identifier: cveUpper, Standard: "MITRE CVE" },
      pivots: [
        { label: "View CVE in Intel Hub", to: "/intel", search: { q: cveUpper }, primary: true },
        { label: "Search Rules in Detection", to: "/detection", search: { q: cveUpper } },
      ],
    };
  }

  // 4. URL
  if (URL_REGEX.test(trimmed) || URL_REGEX.test(cleaned)) {
    const defangedUrl = defang(cleaned);
    let host = "";
    try {
      host = new URL(cleaned).hostname;
    } catch {
      host = cleaned.split("/")[2] || "";
    }
    return {
      raw: trimmed,
      kind: "url",
      label: "Uniform Resource Locator (URL)",
      defanged: defangedUrl,
      refanged: cleaned,
      metadata: { Host: host, Scheme: cleaned.split(":")[0] || "http" },
      pivots: [
        { label: "Dissect URL & Redirects", to: "/url", search: { target: cleaned }, primary: true },
        { label: "Investigate Host in Intel", to: "/intel", search: { q: host } },
        { label: "Decode in CyberChef", to: "/chef" },
      ],
    };
  }

  // 5. Email Address
  if (EMAIL_REGEX.test(cleaned)) {
    const [, domain] = cleaned.split("@");
    return {
      raw: trimmed,
      kind: "email",
      label: "Email Address",
      defanged: defang(cleaned),
      refanged: cleaned,
      metadata: { Mailbox: cleaned.split("@")[0], Domain: domain || "" },
      pivots: [
        { label: "Triage Phishing Mailbox", to: "/phishing", primary: true },
        { label: "Sender Domain Intel", to: "/intel", search: { q: domain || cleaned } },
        { label: "Search Auth Logs", to: "/logs", search: { q: cleaned } },
      ],
    };
  }

  // 6. Domain
  if (DOMAIN_REGEX.test(cleaned) && !isAuthParamToken(cleaned)) {
    return {
      raw: trimmed,
      kind: "domain",
      label: "Internet Domain Name",
      defanged: defang(cleaned),
      refanged: cleaned,
      metadata: { Domain: cleaned },
      pivots: [
        { label: "Intel & DNS Lookup", to: "/intel", search: { q: cleaned }, primary: true },
        { label: "Safe URL Analysis", to: "/url", search: { target: `https://${cleaned}` } },
        { label: "SIEM DNS Activity", to: "/siem", search: { q: cleaned } },
      ],
    };
  }

  // 7. Base64
  const b64Decoded = tryDecodeBase64(trimmed);
  if (b64Decoded && b64Decoded.length >= 4) {
    const isCommand = /powershell|cmd|bash|curl|wget|http/i.test(b64Decoded);
    return {
      raw: trimmed,
      kind: "base64",
      label: isCommand ? "Base64 Encoded Command / Payload" : "Base64 Encoded String",
      defanged: trimmed,
      refanged: trimmed,
      decodedPreview: b64Decoded.length > 200 ? b64Decoded.slice(0, 200) + "…" : b64Decoded,
      metadata: { Length: `${trimmed.length} chars`, DecodedSize: `${b64Decoded.length} bytes` },
      pivots: [
        { label: "Open in CyberChef", to: "/chef", primary: true },
        { label: "Analyze as Artifact in Parser", to: "/parser" },
      ],
    };
  }

  // 8. JSON Log
  if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
    try {
      const parsed = JSON.parse(trimmed);
      const isArr = Array.isArray(parsed);
      return {
        raw: trimmed,
        kind: "json-log",
        label: isArr ? "JSON Event Array" : "Structured JSON Event Record",
        defanged: trimmed,
        refanged: trimmed,
        metadata: { Keys: Object.keys(isArr ? parsed[0] || {} : parsed).slice(0, 6).join(", ") },
        pivots: [
          { label: "Parse & Extract Fields", to: "/parser", primary: true },
          { label: "Ingest into SIEM", to: "/siem" },
        ],
      };
    } catch {
      // not valid json, fall through
    }
  }

  // 9. Raw Text / Fallback
  return {
    raw: trimmed,
    kind: "raw-text",
    label: "Raw Text / Log Line",
    defanged: defang(trimmed),
    refanged: cleaned,
    pivots: [
      { label: "Extract IOCs in Parser", to: "/parser", primary: true },
      { label: "Ingest into SIEM", to: "/siem" },
      { label: "Decode in CyberChef", to: "/chef" },
    ],
  };
}

/* ─────────────────────────────────────────────────────────────
 * Analyst Field Kit: Subnet Calculator
 * ───────────────────────────────────────────────────────────── */

export interface SubnetCalculation {
  cidr: string;
  ip: string;
  maskBits: number;
  netmask: string;
  wildcard: string;
  network: string;
  broadcast: string;
  firstUsable: string;
  lastUsable: string;
  totalHosts: number;
  usableHosts: number;
  isPrivate: boolean;
  typeDescription: string;
}

function intToIp(int: number): string {
  return [
    (int >>> 24) & 255,
    (int >>> 16) & 255,
    (int >>> 8) & 255,
    int & 255,
  ].join(".");
}

function ipToInt(ip: string): number {
  return ip.split(".").reduce((acc, oct) => ((acc << 8) + Number(oct)) >>> 0, 0);
}

export function calculateSubnet(input: string): SubnetCalculation | null {
  const parts = input.trim().split("/");
  const ip = parts[0]?.trim() || "";
  const mask = parts[1] !== undefined ? Number(parts[1].trim()) : 32;

  if (!IPV4_REGEX.test(ip) || isNaN(mask) || mask < 0 || mask > 32) {
    return null;
  }

  const maskInt = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
  const wildcardInt = ~maskInt >>> 0;
  const ipInt = ipToInt(ip);
  const netInt = (ipInt & maskInt) >>> 0;
  const bcastInt = (netInt | wildcardInt) >>> 0;

  const totalHosts = Math.pow(2, 32 - mask);
  const usableHosts = mask >= 31 ? (mask === 31 ? 2 : 1) : Math.max(0, totalHosts - 2);

  const firstUsableInt = mask >= 31 ? netInt : (netInt + 1) >>> 0;
  const lastUsableInt = mask >= 31 ? bcastInt : (bcastInt - 1) >>> 0;

  const isPriv = isPrivateIPv4(ip);

  let typeDesc = "Public Routable Address Space";
  if (ip.startsWith("10.")) typeDesc = "Private RFC1918 Class A (10.0.0.0/8)";
  else if (ip.startsWith("172.")) typeDesc = "Private RFC1918 Class B (172.16.0.0/12)";
  else if (ip.startsWith("192.168.")) typeDesc = "Private RFC1918 Class C (192.168.0.0/16)";
  else if (ip.startsWith("127.")) typeDesc = "Loopback Address (127.0.0.0/8)";
  else if (ip.startsWith("169.254.")) typeDesc = "Link-Local / APIPA (169.254.0.0/16)";
  else if (ip.startsWith("100.64.")) typeDesc = "Carrier-Grade NAT RFC6598 (100.64.0.0/10)";

  return {
    cidr: `${ip}/${mask}`,
    ip,
    maskBits: mask,
    netmask: intToIp(maskInt),
    wildcard: intToIp(wildcardInt),
    network: intToIp(netInt),
    broadcast: intToIp(bcastInt),
    firstUsable: intToIp(firstUsableInt),
    lastUsable: intToIp(lastUsableInt),
    totalHosts,
    usableHosts,
    isPrivate: isPriv,
    typeDescription: typeDesc,
  };
}

/* ─────────────────────────────────────────────────────────────
 * Analyst Field Kit: Timestamp Converter
 * ───────────────────────────────────────────────────────────── */

export interface TimestampInterpretation {
  raw: string;
  utc: string;
  local: string;
  iso: string;
  unixSeconds: number;
  relative: string;
  valid: boolean;
}

export function parseTimestamp(input: string): TimestampInterpretation | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  let d: Date | null = null;

  // Numeric epoch
  if (/^\d{9,13}$/.test(trimmed)) {
    const num = Number(trimmed);
    const ms = trimmed.length <= 10 ? num * 1000 : num;
    d = new Date(ms);
  } else {
    // String date / ISO / syslog
    const parsed = Date.parse(trimmed);
    if (!isNaN(parsed)) {
      d = new Date(parsed);
    }
  }

  if (!d || isNaN(d.getTime())) {
    return null;
  }

  const now = Date.now();
  const diffMs = now - d.getTime();
  const isPast = diffMs >= 0;
  const absSeconds = Math.floor(Math.abs(diffMs) / 1000);

  let relative = "";
  if (absSeconds < 60) relative = `${absSeconds}s ${isPast ? "ago" : "from now"}`;
  else if (absSeconds < 3600) relative = `${Math.floor(absSeconds / 60)}m ${isPast ? "ago" : "from now"}`;
  else if (absSeconds < 86400) relative = `${Math.floor(absSeconds / 3600)}h ${isPast ? "ago" : "from now"}`;
  else relative = `${Math.floor(absSeconds / 86400)}d ${isPast ? "ago" : "from now"}`;

  return {
    raw: trimmed,
    utc: d.toUTCString(),
    local: d.toLocaleString(),
    iso: d.toISOString(),
    unixSeconds: Math.floor(d.getTime() / 1000),
    relative,
    valid: true,
  };
}

/* ─────────────────────────────────────────────────────────────
 * Shift Handoff Generator
 * ───────────────────────────────────────────────────────────── */

export function generateShiftHandoffReport(cases: Case[], alertsCount: number, recentEventsCount: number): string {
  const now = new Date();
  const activeCases = cases.filter((c) => c.state === "active");
  const closedCases = cases.filter((c) => c.state === "closed");

  const totalFindings = cases.reduce((acc, c) => acc + (c.findings?.length || 0), 0);
  const totalIocs = cases.reduce((acc, c) => acc + (c.iocs?.length || 0), 0);

  let md = `# SOC Shift Handoff Briefing\n`;
  md += `**Generated:** ${now.toUTCString()} | **Analyst Terminal:** BeyondLabs Console\n\n`;

  md += `## 1. Operational Overview\n`;
  md += `- **Active Investigations:** ${activeCases.length}\n`;
  md += `- **Closed / Dispositioned:** ${closedCases.length}\n`;
  md += `- **Open Ingested Alerts:** ${alertsCount}\n`;
  md += `- **Logged Timeline Events:** ${recentEventsCount}\n`;
  md += `- **Total Tracked Findings:** ${totalFindings}\n`;
  md += `- **Extracted IOC Inventory:** ${totalIocs}\n\n`;

  md += `## 2. Active Incidents & Investigations\n`;
  if (activeCases.length === 0) {
    md += `*No active cases open at shift changeover.*\n\n`;
  } else {
    for (const c of activeCases) {
      const date = new Date(c.createdAt).toLocaleDateString();
      md += `### [${c.id}] ${c.title}\n`;
      md += `- **Status:** ACTIVE | **Created:** ${date}\n`;
      if (c.analysisSummary?.verdict) {
        md += `- **Verdict:** ${c.analysisSummary.verdict.toUpperCase()} (Confidence: ${c.analysisSummary.confidence || "N/A"}%)\n`;
      }
      if (c.findings && c.findings.length > 0) {
        md += `- **Key Findings (${c.findings.length}):**\n`;
        for (const f of c.findings.slice(0, 3)) {
          md += `  - [${f.severity.toUpperCase()}] ${f.title}\n`;
        }
      }
      if (c.iocs && c.iocs.length > 0) {
        md += `- **Lead Indicators (${c.iocs.length}):** ${c.iocs.slice(0, 4).map((i) => defang(i.value)).join(", ")}\n`;
      }
      md += `\n`;
    }
  }

  md += `## 3. Recommended Actions for Next Shift\n`;
  if (activeCases.length > 0) {
    md += `1. Review ongoing lead indicators in active cases.\n`;
    md += `2. Check for correlation sightings across SIEM feeds.\n`;
    md += `3. Close out completed findings and generate final incident handoff packages.\n`;
  } else {
    md += `1. Monitor incoming alert ingestion queue.\n`;
    md += `2. Run scheduled threat hunts in SIEM.\n`;
  }

  return md;
}
