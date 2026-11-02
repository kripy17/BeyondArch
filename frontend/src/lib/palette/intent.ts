import type { ObservableKind } from "./types";

const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const IPV6_RE = /^[0-9a-f:]+:[0-9a-f:]+(:[0-9a-f.]+)?$/i;
const URL_RE = /^https?:\/\/.+/i;
const DOMAIN_RE = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const MITRE_RE = /^T\d{4}(\.\d{3})?$/;
const MD5_RE = /^[a-f0-9]{32}$/i;
const SHA1_RE = /^[a-f0-9]{40}$/i;
const SHA256_RE = /^[a-f0-9]{64}$/i;
const SHA512_RE = /^[a-f0-9]{128}$/i;
const WIN_EVENT_RE = /^\d{3,5}$/;

export function detectObservable(input: string): ObservableKind | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  if (IPV4_RE.test(trimmed)) {
    const parts = trimmed.split(".").map(Number);
    if (parts.every((p) => p >= 0 && p <= 255)) return "ipv4";
    return null;
  }
  if (IPV6_RE.test(trimmed)) return "ipv6";
  if (URL_RE.test(trimmed)) return "url";
  if (EMAIL_RE.test(trimmed)) return "email";
  if (CVE_RE.test(trimmed)) return "cve";
  if (MITRE_RE.test(trimmed)) return "mitre";
  if (SHA512_RE.test(trimmed)) return "hash-sha512";
  if (SHA256_RE.test(trimmed)) return "hash-sha256";
  if (SHA1_RE.test(trimmed)) return "hash-sha1";
  if (MD5_RE.test(trimmed)) return "hash-md5";
  if (DOMAIN_RE.test(trimmed)) return "domain";
  if (WIN_EVENT_RE.test(trimmed)) return "win-event-id";
  return null;
}

export function observableLabel(kind: ObservableKind): string {
  const map: Record<ObservableKind, string> = {
    ipv4: "IP Address", ipv6: "IPv6 Address", url: "URL",
    domain: "Domain", email: "Email Address",
    "hash-md5": "MD5 Hash", "hash-sha1": "SHA1 Hash",
    "hash-sha256": "SHA256 Hash", "hash-sha512": "SHA512 Hash",
    cve: "CVE", mitre: "MITRE Technique",
    "win-event-id": "Windows Event ID", ja3: "JA3 Fingerprint",
    unknown: "Observable",
  };
  return map[kind];
}
