/**
 * IOC Delta Extraction & Classification for Forensic Diffing
 * Analyzes baseline ("Old") vs incident ("New") text to extract:
 * - Net-New IOCs (potential indicators of compromise introduced in incident)
 * - Removed IOCs (remediated or changed indicators)
 * - Unchanged / Persistent IOCs
 */

export type IocType = "ip" | "domain" | "url" | "hash" | "email" | "cve";

export interface IocDeltaItem {
  value: string;
  type: IocType;
  status: "added" | "removed" | "unchanged";
  risk: "critical" | "high" | "medium" | "low" | "info";
}

export interface IocDeltaReport {
  added: IocDeltaItem[];
  removed: IocDeltaItem[];
  unchanged: IocDeltaItem[];
  totalAdded: number;
  totalRemoved: number;
  hasThreats: boolean;
}

const RX = {
  ip: /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g,
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g,
  url: /https?:\/\/[^\s"'<>]+/gi,
  hash: /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g,
  email: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
  cve: /\bCVE-\d{4}-\d{4,7}\b/gi,
};

function extractFromText(text: string): Map<string, IocType> {
  const result = new Map<string, IocType>();
  if (!text) return result;

  // URLs
  const urls = text.match(RX.url) || [];
  for (const u of urls) result.set(u, "url");

  // CVEs
  const cves = text.match(RX.cve) || [];
  for (const c of cves) result.set(c.toUpperCase(), "cve");

  // Hashes
  const hashes = text.match(RX.hash) || [];
  for (const h of hashes) result.set(h.toLowerCase(), "hash");

  // Emails
  const emails = text.match(RX.email) || [];
  for (const e of emails) result.set(e.toLowerCase(), "email");

  // IPs
  const ips = text.match(RX.ip) || [];
  for (const ip of ips) {
    if (ip !== "127.0.0.1" && ip !== "0.0.0.0") {
      result.set(ip, "ip");
    }
  }

  // Domains (exclude typical internal/common domains)
  const domains = text.match(RX.domain) || [];
  for (const d of domains) {
    const dLower = d.toLowerCase();
    if (
      !dLower.endsWith(".local") &&
      !dLower.endsWith(".internal") &&
      !result.has(d) &&
      !Array.from(result.keys()).some((k) => k.includes(d))
    ) {
      result.set(dLower, "domain");
    }
  }

  return result;
}

function assignRisk(type: IocType, value: string): IocDeltaItem["risk"] {
  if (type === "cve") return "critical";
  if (type === "hash") return "high";
  if (type === "url" && (value.includes(".exe") || value.includes(".ps1") || value.includes("evil"))) return "critical";
  if (type === "url") return "high";
  if (type === "ip") return "medium";
  if (type === "domain") return "medium";
  return "low";
}

export function computeIocDelta(oldText: string, newText: string): IocDeltaReport {
  const oldIocs = extractFromText(oldText);
  const newIocs = extractFromText(newText);

  const added: IocDeltaItem[] = [];
  const removed: IocDeltaItem[] = [];
  const unchanged: IocDeltaItem[] = [];

  // Find added (in new, not in old)
  for (const [val, type] of newIocs.entries()) {
    if (!oldIocs.has(val)) {
      added.push({
        value: val,
        type,
        status: "added",
        risk: assignRisk(type, val),
      });
    } else {
      unchanged.push({
        value: val,
        type,
        status: "unchanged",
        risk: assignRisk(type, val),
      });
    }
  }

  // Find removed (in old, not in new)
  for (const [val, type] of oldIocs.entries()) {
    if (!newIocs.has(val)) {
      removed.push({
        value: val,
        type,
        status: "removed",
        risk: assignRisk(type, val),
      });
    }
  }

  // Sort added items by risk
  const riskWeights = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  added.sort((a, b) => riskWeights[b.risk] - riskWeights[a.risk]);

  return {
    added,
    removed,
    unchanged,
    totalAdded: added.length,
    totalRemoved: removed.length,
    hasThreats: added.some((i) => i.risk === "critical" || i.risk === "high"),
  };
}
