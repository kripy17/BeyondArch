/**
 * Tier-1 Universal Forensic Parser & Observable Extraction Engine.
 *
 * Responsibilities:
 * 1. Broad regex matching for modern DFIR indicators:
 *    - URLs, Domains, IPv4, CIDR, Hashes (MD5, SHA1, SHA256)
 *    - Emails, CVEs, MITRE ATT&CK techniques
 *    - Crypto Wallets (Bitcoin, Monero, Ethereum)
 *    - Windows Registry Keys & UNC paths
 *    - Cloud ARNs, JWT tokens, and Secrets
 * 2. Deterministic threat scoring and heuristic tagging (0 - 100 risk score).
 * 3. 1-click active case defensible ledger integration (c.iocs deduplication & entry).
 * 4. Multi-format DFIR export generators (RFC 4180 CSV, JSON, Markdown, Defanged list).
 */

import { refang, defang, SUSPICIOUS_TLDS, SHORTENERS, ABUSED_HOSTS, entropy, scanSecrets, isAuthParamToken } from "@/lib/ioc-patterns";
import { loadCases, saveCases, newId, ensureIocId, ACTIVE_CASE_EVENT } from "@/data/case";
import type { IOC, IocType } from "@/types/security";
import type { Severity } from "@/lib/severity";

export interface ScoredObservable {
  id: string;
  value: string;
  type: string; // "URL" | "Domain" | "IPv4" | "CIDR" | "MD5" | "SHA1" | "SHA256" | "Email" | "CVE" | "ATTACK" | "Crypto" | "Registry" | "UNC" | "AWS-ARN" | "JWT" | "Secret"
  score: number; // 0 - 100
  severity: Severity;
  tags: string[];
  defanged: string;
  raw: string;
  pivotRoute?: string;
}

export const MODERN_PATTERNS = {
  // Traditional Network & Host IOCs
  URL:    /\b(?:hxxps?|https?):\/\/[^\s)>"']+/gi,
  Domain: /\b(?:[a-z0-9-]+\[?\.\]?){1,5}[a-z]{2,}\b/gi,
  CIDR:   /\b(?:\d{1,3}\.){3}\d{1,3}\/(?:[1-2]?[0-9]|3[0-2])\b/g,
  IPv4:   /\b(?:\d{1,3}\[?\.\]?){3}\d{1,3}\b/g,
  MD5:    /\b[a-f0-9]{32}\b/gi,
  SHA1:   /\b[a-f0-9]{40}\b/gi,
  SHA256: /\b[a-f0-9]{64}\b/gi,
  Email:  /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi,
  CVE:    /\bCVE-\d{4}-\d{4,}\b/gi,
  ATTACK: /\bT\d{4}(?:\.\d{3})?\b/g,

  // Modern DFIR Extracted Observables
  CryptoBTC: /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,62})\b/g,
  CryptoXMR: /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{80,104}\b/g,
  CryptoETH: /\b0x[a-fA-F0-9]{40}\b/g,
  RegistryKey: /\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[A-Za-z0-9_\\\-.]{3,}\b/gi,
  UNCPath: /\\\\[a-zA-Z0-9._\-]{2,}\\[a-zA-Z0-9._$\-\\]{2,}/g,
  AWSArn: /\barn:aws[a-zA-Z-]*:[a-zA-Z0-9-]*:[a-zA-Z0-9-]*:\d{12}:[a-zA-Z0-9-_\/:.]+\b/g,
  JWT: /\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g,
};

const PHISHING_KEYWORDS = new Set([
  "login", "signin", "verify", "verification", "secure", "security", "account",
  "update", "confirm", "confirmation", "password", "credential", "banking",
  "invoice", "billing", "authenticate", "auth", "session", "recover", "unlock",
  "wallet", "portal", "office365", "microsoft", "google", "apple", "paypal",
]);

function isPrivateIp(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  return false;
}

/**
 * Calculates deterministic risk score (0-100), severity, and contextual forensic tags.
 */
export function scoreObservable(type: string, value: string): {
  score: number;
  severity: Severity;
  tags: string[];
} {
  let score = 20;
  const tags: string[] = [];
  const refanged = refang(value);

  switch (type) {
    case "URL": {
      try {
        const u = new URL(refanged);
        const host = u.hostname.toLowerCase();
        const tld = host.split(".").pop() ?? "";

        if (SUSPICIOUS_TLDS.has(tld)) {
          score += 30;
          tags.push(`Suspicious TLD (.${tld})`);
        }
        if (SHORTENERS.has(host.replace(/^www\./, ""))) {
          score += 20;
          tags.push("URL Shortener");
        }
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
          score += 25;
          tags.push("Direct IP Host");
        }
        if (u.username || u.password) {
          score += 35;
          tags.push("Embedded Credentials");
        }
        if (u.port && !["80", "443"].includes(u.port)) {
          score += 15;
          tags.push(`Non-standard Port (:${u.port})`);
        }

        const pathLower = (u.pathname + u.search).toLowerCase();
        for (const kw of PHISHING_KEYWORDS) {
          if (pathLower.includes(kw)) {
            score += 20;
            tags.push(`Phishing Keyword ('${kw}')`);
            break;
          }
        }

        const pathEnt = entropy(u.pathname + u.search);
        if (pathEnt > 4.5) {
          score += 15;
          tags.push("High Entropy Path");
        }
      } catch {
        score += 10;
        tags.push("Malformed URL");
      }
      break;
    }

    case "Domain": {
      const d = refanged.toLowerCase();
      const tld = d.split(".").pop() ?? "";
      if (SUSPICIOUS_TLDS.has(tld)) {
        score += 35;
        tags.push(`Suspicious TLD (.${tld})`);
      }
      if (SHORTENERS.has(d.replace(/^www\./, ""))) {
        score += 25;
        tags.push("URL Shortener Domain");
      }
      if (ABUSED_HOSTS.some((h) => d.endsWith(h))) {
        score += 30;
        tags.push("Abused Free/Tunnel Host");
      }
      const labels = d.replace(/\./g, "");
      if (entropy(labels) > 3.9) {
        score += 25;
        tags.push("High Domain Entropy");
      }
      break;
    }

    case "IPv4":
    case "CIDR": {
      const bareIp = refanged.split("/")[0];
      if (isPrivateIp(bareIp)) {
        score = 10;
        tags.push("RFC1918 Private Subnet");
      } else {
        score = 45;
        tags.push("Public Internet Address");
      }
      break;
    }

    case "Crypto": {
      score = 75;
      if (value.startsWith("4")) {
        tags.push("Monero (XMR) Ransom Wallet");
      } else if (value.startsWith("0x")) {
        tags.push("Ethereum (ETH) Wallet");
      } else {
        tags.push("Bitcoin (BTC) Extortion Wallet");
      }
      break;
    }

    case "Registry": {
      const lower = value.toLowerCase();
      if (
        lower.includes("run") ||
        lower.includes("runonce") ||
        lower.includes("services") ||
        lower.includes("winlogon") ||
        lower.includes("startup") ||
        lower.includes("tasks")
      ) {
        score = 80;
        tags.push("Persistence Autostart Key");
      } else {
        score = 40;
        tags.push("System Registry Key");
      }
      break;
    }

    case "UNC": {
      score = 55;
      tags.push("SMB Network Share Path");
      break;
    }

    case "AWS-ARN": {
      score = 60;
      tags.push("Cloud Infrastructure ARN");
      break;
    }

    case "JWT": {
      score = 85;
      tags.push("Active Session JWT Token");
      break;
    }

    case "Secret": {
      score = 90;
      tags.push("Exposed Secret / Key");
      break;
    }

    case "CVE": {
      score = 70;
      tags.push("Exploitable Vulnerability");
      break;
    }

    case "ATTACK": {
      score = 65;
      tags.push("MITRE Technique");
      break;
    }

    case "MD5":
    case "SHA1":
    case "SHA256": {
      score = 50;
      tags.push(`${type} File Hash`);
      break;
    }

    case "Email": {
      score = 30;
      tags.push("Email Address");
      break;
    }

    default:
      score = 25;
      tags.push("General Indicator");
  }

  score = Math.min(100, Math.max(0, score));

  let severity: Severity = "low";
  if (score >= 80) severity = "critical";
  else if (score >= 60) severity = "high";
  else if (score >= 40) severity = "medium";
  else if (score >= 20) severity = "low";
  else severity = "low";

  return { score, severity, tags };
}

/**
 * Extracts and scores all modern DFIR observables from raw text.
 */
export function extractObservables(rawText: string): ScoredObservable[] {
  const t = rawText.trim();
  if (!t) return [];

  const seen = new Set<string>();
  const observables: ScoredObservable[] = [];

  const add = (type: string, val: string, pivotRoute?: string) => {
    const clean = val.trim();
    if (!clean) return;
    const key = `${type}::${refang(clean).toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);

    const { score, severity, tags } = scoreObservable(type, clean);
    observables.push({
      id: `obs-${crypto.randomUUID().slice(0, 8)}`,
      value: clean,
      type,
      score,
      severity,
      tags,
      defanged: defang(clean),
      raw: refang(clean),
      pivotRoute,
    });
  };

  // 1. Secrets (API keys, cloud tokens, private keys)
  const secrets = scanSecrets(t);
  for (const s of secrets) {
    add("Secret", `${s.type}: ${s.value}`);
  }

  // 2. JWTs
  const jwts = Array.from(new Set(t.match(MODERN_PATTERNS.JWT) ?? []));
  for (const j of jwts) add("JWT", j);

  // 3. AWS ARNs
  const arns = Array.from(new Set(t.match(MODERN_PATTERNS.AWSArn) ?? []));
  for (const a of arns) add("AWS-ARN", a);

  // 4. Windows Registry Keys
  const regKeys = Array.from(new Set(t.match(MODERN_PATTERNS.RegistryKey) ?? []));
  for (const r of regKeys) add("Registry", r);

  // 5. UNC Paths
  const uncs = Array.from(new Set(t.match(MODERN_PATTERNS.UNCPath) ?? []));
  for (const u of uncs) add("UNC", u);

  // 6. Crypto Wallets
  const btcs = Array.from(new Set(t.match(MODERN_PATTERNS.CryptoBTC) ?? []));
  for (const b of btcs) add("Crypto", b);
  const xmrs = Array.from(new Set(t.match(MODERN_PATTERNS.CryptoXMR) ?? []));
  for (const x of xmrs) add("Crypto", x);
  const eths = Array.from(new Set(t.match(MODERN_PATTERNS.CryptoETH) ?? []));
  for (const e of eths) add("Crypto", e);

  // 7. URLs
  const urls = Array.from(new Set(t.match(MODERN_PATTERNS.URL) ?? []));
  for (const u of urls) add("URL", u, "/url");

  // 8. Emails
  const emails = Array.from(new Set(t.match(MODERN_PATTERNS.Email) ?? []));
  for (const e of emails) add("Email", e, "/phishing");

  // 9. Domains (excluding auth param headers and email addresses)
  const domains = Array.from(new Set(t.match(MODERN_PATTERNS.Domain) ?? [])).filter(
    (d) => !isAuthParamToken(d) && !emails.some((e) => e.toLowerCase().includes(d.toLowerCase()))
  );
  for (const d of domains) add("Domain", d, "/intel");

  // 10. CIDR & IPv4
  const cidrs = Array.from(new Set(t.match(MODERN_PATTERNS.CIDR) ?? []));
  for (const c of cidrs) add("CIDR", c, "/intel");

  const ips = Array.from(new Set(t.match(MODERN_PATTERNS.IPv4) ?? [])).filter((v) =>
    v.split(/[.\[\]]/).every((x) => !x || +x <= 255)
  );
  for (const ip of ips) {
    if (!cidrs.some((c) => c.startsWith(ip))) {
      add("IPv4", ip, "/intel");
    }
  }

  // 11. Hashes
  const sha256s = Array.from(new Set(t.match(MODERN_PATTERNS.SHA256) ?? []));
  for (const h of sha256s) add("SHA256", h, "/attachment");

  const sha1s = Array.from(new Set(t.match(MODERN_PATTERNS.SHA1) ?? [])).filter(
    (h) => !sha256s.some((s) => s.toLowerCase().includes(h.toLowerCase()))
  );
  for (const h of sha1s) add("SHA1", h, "/attachment");

  const md5s = Array.from(new Set(t.match(MODERN_PATTERNS.MD5) ?? [])).filter(
    (h) =>
      !sha256s.some((s) => s.toLowerCase().includes(h.toLowerCase())) &&
      !sha1s.some((s) => s.toLowerCase().includes(h.toLowerCase()))
  );
  for (const h of md5s) add("MD5", h, "/attachment");

  // 12. CVEs & ATT&CK
  const cves = Array.from(new Set(t.match(MODERN_PATTERNS.CVE) ?? []));
  for (const c of cves) add("CVE", c);

  const attacks = Array.from(new Set(t.match(MODERN_PATTERNS.ATTACK) ?? []));
  for (const a of attacks) add("ATTACK", a, "/mitre");

  // Sort by score descending
  return observables.sort((a, b) => b.score - a.score);
}

/**
 * Maps a parser observable type to the case IOC type schema.
 */
export function mapObservableToIocType(type: string): IocType {
  switch (type.toUpperCase()) {
    case "URL": return "url";
    case "DOMAIN": return "domain";
    case "IPV4": return "ipv4";
    case "CIDR": return "ipv4";
    case "MD5": return "md5";
    case "SHA1": return "sha1";
    case "SHA256": return "sha256";
    case "EMAIL": return "email";
    case "CVE": return "cve";
    default: return "unknown";
  }
}

/**
 * Bulk promotes scored observables into the active case's defensible evidence ledger.
 */
export function promoteObservablesToCase(
  caseId: string,
  observables: ScoredObservable[]
): { added: number; total: number; skipped: number } {
  if (!caseId || observables.length === 0) return { added: 0, total: 0, skipped: 0 };

  const cases = loadCases();
  const c = cases.find((item) => item.id === caseId);
  if (!c) return { added: 0, total: 0, skipped: observables.length };

  const existingValues = new Set((c.iocs ?? []).map((i) => i.value.toLowerCase().trim()));
  const newIocs: IOC[] = [];

  for (const obs of observables) {
    const rawVal = obs.raw.trim();
    if (!rawVal || existingValues.has(rawVal.toLowerCase())) {
      continue;
    }
    existingValues.add(rawVal.toLowerCase());

    const ioc: IOC = ensureIocId({
      id: newId("ioc"),
      value: rawVal,
      type: mapObservableToIocType(obs.type),
      source: "/parser",
      severity: obs.severity,
      context: obs.tags.join("; ") || `Extracted observable [${obs.type}]`,
    });
    newIocs.push(ioc);
  }

  if (newIocs.length > 0) {
    c.iocs = [...(c.iocs ?? []), ...newIocs];
    c.entries = [
      ...(c.entries ?? []),
      {
        id: newId("e"),
        ts: new Date().toISOString(),
        kind: "ioc",
        body: `### IOC Station Ingest\nPromoted **${newIocs.length}** observables from Universal Log Parser:\n` +
          newIocs.slice(0, 10).map((i) => `- \`${defang(i.value)}\` (${i.type.toUpperCase()}) — ${i.context}`).join("\n") +
          (newIocs.length > 10 ? `\n...and ${newIocs.length - 10} more.` : ""),
      },
    ];

    saveCases(cases);
    try {
      window.dispatchEvent(new Event(ACTIVE_CASE_EVENT));
      window.dispatchEvent(new Event("storage"));
    } catch { /* noop */ }
  }

  return {
    added: newIocs.length,
    total: observables.length,
    skipped: observables.length - newIocs.length,
  };
}

/* ── Export Suite (RFC 4180 CSV, JSON, Markdown, Defanged List) ── */

export function exportObservablesCsv(observables: ScoredObservable[]): string {
  const escapeCsv = (str: string) => {
    if (str.includes(",") || str.includes('"') || str.includes("\n")) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const headers = ["type", "value", "defanged", "severity", "score", "tags"];
  const rows = observables.map((o) =>
    [
      escapeCsv(o.type),
      escapeCsv(o.raw),
      escapeCsv(o.defanged),
      escapeCsv(o.severity),
      escapeCsv(String(o.score)),
      escapeCsv(o.tags.join("; ")),
    ].join(",")
  );

  return [headers.join(","), ...rows].join("\r\n");
}

export function exportObservablesJson(
  observables: ScoredObservable[],
  metadata: Record<string, unknown> = {}
): string {
  return JSON.stringify(
    {
      version: "1.0",
      generatedAt: new Date().toISOString(),
      generator: "BeyondArch Tier-1 DFIR Universal Parser",
      total: observables.length,
      ...metadata,
      observables: observables.map((o) => ({
        id: o.id,
        type: o.type,
        value: o.raw,
        defanged: o.defanged,
        severity: o.severity,
        score: o.score,
        tags: o.tags,
      })),
    },
    null,
    2
  );
}

export function exportObservablesMarkdown(
  observables: ScoredObservable[],
  title = "Extracted Observable Inventory"
): string {
  const lines = [
    `# ${title}`,
    `**Total Observables:** ${observables.length}  |  **Generated:** ${new Date().toISOString()}`,
    "",
    "| Type | Indicator (Defanged) | Severity | Risk Score | Forensic Context |",
    "| :--- | :--- | :--- | :--- | :--- |",
    ...observables.map(
      (o) =>
        `| **${o.type}** | \`${o.defanged}\` | ${o.severity.toUpperCase()} | ${o.score} | ${o.tags.join(", ")} |`
    ),
  ];
  return lines.join("\n");
}

export function exportObservablesDefangedList(observables: ScoredObservable[]): string {
  const byType: Record<string, string[]> = {};
  for (const o of observables) {
    if (!byType[o.type]) byType[o.type] = [];
    byType[o.type].push(o.defanged);
  }

  const sections: string[] = [];
  for (const [type, items] of Object.entries(byType)) {
    sections.push(`## ${type} (${items.length})\n${items.join("\n")}`);
  }
  return sections.join("\n\n");
}
