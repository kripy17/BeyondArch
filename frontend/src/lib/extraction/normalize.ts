import { refang } from "@/lib/ioc-patterns";
import type { IocType } from "@/types/objects";

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;
const EMAIL_RE = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/;
const HEX_RE = /^[a-f0-9]+$/;

function validIpv4(octets: string[]): boolean {
  return octets.length === 4 && octets.every((o) => Number(o) <= 255);
}

export function normalizeIp(value: string): string | null {
  const v = refang(value).trim().replace(/^\[(.*)\]$/, "$1").toLowerCase();
  const parts = v.split(".");
  if (IPV4_RE.test(v) && validIpv4(parts)) return v;
  if (IPV6_RE.test(v)) return v.replace(/::/g, ":").replace(/:$/, "");
  return null;
}

export function normalizeDomain(value: string): string | null {
  const v = refang(value).trim().toLowerCase().replace(/\.$/, "").replace(/^\./, "");
  const bare = v.split(":")[0] ?? v;
  if (!DOMAIN_RE.test(bare)) return null;
  return bare;
}

export function normalizeEmail(value: string): string | null {
  const v = refang(value).trim().toLowerCase();
  if (!EMAIL_RE.test(v)) return null;
  return v;
}

export function normalizeHash(value: string): { type: "md5" | "sha1" | "sha256"; value: string } | null {
  const v = refang(value).trim().toLowerCase();
  if (!HEX_RE.test(v)) return null;
  if (v.length === 32) return { type: "md5", value: v };
  if (v.length === 40) return { type: "sha1", value: v };
  if (v.length === 64) return { type: "sha256", value: v };
  return null;
}

export function normalizeUrl(value: string): string | null {
  const v = refang(value).trim();
  if (!/^https?:\/\//i.test(v)) return null;
  try {
    const u = new URL(v);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    if (!u.hostname) return null;
    u.hostname = u.hostname.toLowerCase();
    return u.href;
  } catch {
    return null;
  }
}

export function classifyIoc(value: string): IocType {
  const v = refang(value).trim().toLowerCase();
  if (normalizeIp(v)) return v.includes(":") ? "ipv6" : "ipv4";
  if (normalizeEmail(v)) return "email";
  const h = normalizeHash(v);
  if (h) return h.type === "md5" ? "md5" : h.type === "sha1" ? "sha1" : "sha256";
  if (normalizeUrl(v)) return "url";
  if (normalizeDomain(v)) return "domain";
  return "unknown";
}
