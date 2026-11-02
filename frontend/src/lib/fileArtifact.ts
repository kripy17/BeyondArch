import type { Artifact, IOC } from "@/types/security";
import type { Severity } from "@/lib/severity";
import type { AnalysisSummary, EvidenceItem } from "@/types/analysis";
import { entropy, scanSecrets, type Secret } from "@/lib/ioc-patterns";
import { objectId } from "@/lib/ids";
import { normalizeObservations, extractCommandLines, makeObservation } from "@/lib/extraction";
import { analyzeAndCorrelate, type CorrelationHistory, type CorrelationMatch } from "@/lib/correlation";
import type { MitreMapping } from "@/lib/analysis";
import type { AnalysisQuality, DetectionOpportunity, Finding, Observation, Recommendation, Relationship } from "@/types/objects";
import { parseClientPeHeaders, type PeAnalysis } from "./malware/pe-models";
import {
  dissectClientOffice,
  dissectClientPdf,
  dissectClientScript,
  type OfficeAnalysis,
  type PdfAnalysis,
  type ScriptAnalysis,
} from "./malware/document-dissector";
import { synthesizeYaraRule } from "./malware/yara-synthesizer";

/* ── extraction facts: hashes, strings, structure (ANALYSIS_ENGINE §4 — never infers intent) ── */

const MD5_K = new Int32Array([
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]);

const MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];

function md5Hex(s: string): string {
  const bytes = new TextEncoder().encode(s);
  const ml = bytes.length * 8;
  const paddedLen = ((bytes.length + 8) >> 6 << 6) + 64;
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
  return [...new Uint8Array(out.buffer)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function shaHex(alg: "SHA-1" | "SHA-256", s: string): Promise<string> {
  const buf = await crypto.subtle.digest(alg, new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function classifyString(s: string): "email" | "url" | "ipv4" | "hex" | "base64" | "file-ref" | "path" | "api" | "string" {
  if (/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(s)) return "email";
  if (/^https?:\/\//i.test(s)) return "url";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return "ipv4";
  if (/^[0-9a-fA-F]{16,}$/.test(s)) return "hex";
  if (/^[A-Za-z0-9+/]{12,}={0,2}$/.test(s)) return "base64";
  if (/^[A-Za-z0-9_]+\.(dll|ocx|sys|exe|ps1|bat|vbs|js|py|sh)$/i.test(s)) return "file-ref";
  if (/[\\/]/.test(s) && /[A-Za-z0-9_\-.\\/]{6,}/.test(s)) return "path";
  if (/^(Create|Write|Virtual|Load|Open|Get|Set|Win|Internet|Http|Shell|Reg|Crypto|Is|Check|Queue|Nt|Process|Enum|Key|Clipboard|URL|Download|Exec|Memory|Thread)[A-Za-z]*$/.test(s)) return "api";
  return "string";
}

const SUSPICIOUS_EXTS = new Set([
  "exe", "msi", "scr", "ps1", "vbs", "docm", "xlsm", "pptm", "zip", "rar", "7z", "iso", "dmg",
  "bat", "cmd", "jar", "wsf", "js", "vbe", "pif", "gadget", "application", "appref-ms", "com",
  "cpl", "reg", "sh", "bash", "py", "pyc", "php", "php3", "php4", "php5", "phtml", "asp",
  "aspx", "cer", "hta", "lnk", "ocx", "sct", "shs", "vb", "wsc", "wsh",
]);

const SAFE_EXTS = new Set(["txt", "log", "csv", "json", "xml", "html", "css", "md", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico", "mp3", "mp4", "avi", "mov", "wav", "flac"]);

const EXT_MAGIC_MAP: Record<string, string[]> = {
  exe: ["MZ"], msi: ["MZ"], pdf: ["%PDF"], zip: ["PK"], rar: ["Rar!"], gif: ["GIF8"],
  jpeg: ["\xff\xd8\xff"], png: ["\x89PNG"],
  doc: ["\xd0\xcf\x11\xe0", "PK"], xls: ["\xd0\xcf\x11\xe0", "PK"], ppt: ["\xd0\xcf\x11\xe0", "PK"],
  docx: ["PK"], xlsx: ["PK"], pptx: ["PK"],
};

/** Double-extension masquerade: base name ends in a document/media extension AND the final extension is suspicious (e.g. invoice.pdf.exe). */
const MASQUERADE_EXT_RX = /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|rtf|jpg|jpeg|png|gif|bmp|mp3|mp4|avi|htm|html)$/i;

function isDoubleExtension(fileName: string): boolean {
  const base = fileName.slice(0, fileName.lastIndexOf("."));
  const finalExt = (fileName.split(".").pop() || "").toLowerCase();
  return MASQUERADE_EXT_RX.test(base) && SUSPICIOUS_EXTS.has(finalExt);
}

const SUSPICIOUS_APIS = new Set([
  "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess", "GetProcAddress",
  "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
  "InternetOpen", "InternetOpenUrl", "InternetConnect", "HttpSendRequest", "ShellExecute", "ShellExecuteEx",
  "RegSetValueEx", "RegOpenKeyEx", "CryptAcquireContext", "CryptEncrypt", "IsDebuggerPresent",
  "CheckRemoteDebuggerPresent", "VirtualProtect", "QueueUserAPC", "NtUnmapViewOfSection",
  "Process32First", "Process32Next", "EnumProcesses", "SetWindowsHookEx", "GetAsyncKeyState",
  "GetKeyState", "keybd_event", "OpenClipboard", "GetClipboardData", "URLDownloadToFile", "WinExec",
]);

const OFFICE_EXTS = new Set(["docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "doc", "xls", "ppt"]);

const MACHINE_CODES: Record<number, string> = { 0x014c: "i386", 0x8664: "x86-64", 0xaa64: "ARM64", 0x01c0: "ARM", 0x0200: "IA64", 0x5032: "RISC-V" };
const SUBSYSTEM_CODES: Record<number, string> = { 1: "NATIVE", 2: "Windows GUI", 3: "Windows CUI (console)", 9: "Windows CE GUI", 12: "EFI app", 14: "EFI ROM" };

function guessMime(ext: string): string {
  const map: Record<string, string> = {
    exe: "application/x-msdownload", msi: "application/x-msi", pdf: "application/pdf",
    zip: "application/zip", rar: "application/vnd.rar", "7z": "application/x-7z-compressed",
    iso: "application/x-iso9660-image", dmg: "application/x-apple-diskimage",
    doc: "application/msword", docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    xls: "application/vnd.ms-excel", xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ppt: "application/vnd.ms-powerpoint", pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    js: "text/javascript", py: "text/x-python", ps1: "text/x-powershell",
    bat: "text/x-bat", cmd: "text/x-bat", sh: "text/x-shellscript",
    txt: "text/plain", csv: "text/csv", json: "application/json", xml: "application/xml",
    html: "text/html", htm: "text/html",
    png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif",
  };
  return map[ext] || "application/octet-stream";
}

export interface FileStrings {
  total: number;
  samples: { value: string; length: number; kind: string }[];
  categories: Record<string, number>;
}

export interface PeInfo {
  detected: boolean;
  signature: string | null;
  machine: string | null;
  subsystem: string | null;
  entryPoint: string | null;
  note: string;
}

export interface ApiEvidence {
  dlls: string[];
  apis: { name: string; suspicious: boolean }[];
  note: string;
}

export interface ArchiveInfo {
  kind: string | null;
  entries: string[];
  note: string;
}

export interface OfficeInfo {
  detected: boolean;
  fields: { label: string; value: string }[];
  macros: boolean;
  note: string;
}

export interface YaraRule {
  name: string;
  tags: string[];
  description: string;
  matched: boolean;
  evidence: string[];
}

/* ── extraction of structural facts ── */

function extractStrings(content: string): FileStrings {
  const runs = (content.match(/[\x20-\x7E]{4,}/g) || []);
  const categories: Record<string, number> = {};
  for (const r of runs) { const k = classifyString(r); categories[k] = (categories[k] || 0) + 1; }
  const samples = runs.slice(0, 24).map(r => ({ value: r.length > 160 ? r.slice(0, 160) + "…" : r, length: r.length, kind: classifyString(r) }));
  return { total: runs.length, samples, categories };
}

function peInspect(content: string): PeInfo {
  const bytes = content.slice(0, 4096);
  const sig = bytes.indexOf("PE\u0000\u0000");
  if (sig < 0) return { detected: false, signature: null, machine: null, subsystem: null, entryPoint: null, note: "No PE signature (PE\\0\\0) found in first 4 KB — not a PE image, or header beyond text-projected range." };
  const at = (off: number, len: number): number[] | null => {
    const out: number[] = [];
    for (let i = 0; i < len; i++) {
      const c = content.charCodeAt(sig + off + i);
      if (c > 0x7f) return null;
      out.push(c);
    }
    return out;
  };
  const machineBytes = at(4, 2);
  const subsystemBytes = at(68, 2);
  const entryBytes = at(40, 4);
  const machine = machineBytes ? MACHINE_CODES[(machineBytes[0] | (machineBytes[1] << 8)) >>> 0] ?? null : null;
  const subsystem = subsystemBytes ? SUBSYSTEM_CODES[subsystemBytes[0] | (subsystemBytes[1] << 8)] ?? null : null;
  const entryPoint = entryBytes ? entryBytes.reduce((a, b, i) => a + (b << (8 * i)), 0).toString(16).padStart(8, "0") : null;
  return {
    detected: true,
    signature: "MZ … PE\\0\\0",
    machine,
    subsystem,
    entryPoint,
    note: "Header fields read from text-projected bytes; values with non-ASCII bytes are shown as unknown. Verify with byte-level upload (opt-in).",
  };
}

function importEvidence(content: string): ApiEvidence {
  const dllSet = new Set<string>();
  for (const m of content.matchAll(/\b[A-Za-z0-9_]+\.(?:dll|ocx|sys)\b/gi)) dllSet.add(m[0].toLowerCase());
  const dlls = [...dllSet].sort().slice(0, 40);
  const apis: { name: string; suspicious: boolean }[] = [];
  const seenApi = new Set<string>();
  for (const run of content.match(/[\x20-\x7E]{4,}/g) || []) {
    if (SUSPICIOUS_APIS.has(run) && !seenApi.has(run)) { seenApi.add(run); apis.push({ name: run, suspicious: true }); }
  }
  for (const m of content.matchAll(/\b[A-Za-z][A-Za-z0-9]{3,}(?:A|W|Ex|ExA|ExW)?\s*\(/g)) {
    const name = m[0].replace(/\s*\($/, "");
    if (!seenApi.has(name) && /^(Create|Write|Virtual|Load|Open|Get|Set|Win|Internet|Http|Shell|Reg|Crypto|Is|Check|Queue|Nt|Process|Enum|Key|Clipboard|URL|Download|Exec|Memory|Thread)[A-Za-z]*$/.test(name)) {
      seenApi.add(name); apis.push({ name, suspicious: SUSPICIOUS_APIS.has(name) });
    }
  }
  return {
    dlls,
    apis: apis.slice(0, 40),
    note: "String-derived from ASCII runs — not a parsed import table. Verify before trusting (binary imports require byte-level upload, opt-in).",
  };
}

function archiveInspect(content: string): ArchiveInfo {
  if (content.startsWith("PK\u0003\u0004")) {
    const entries: string[] = [];
    let pos = 0;
    while (entries.length < 40 && pos < content.length) {
      const idx = content.indexOf("PK\u0003\u0004", pos);
      if (idx < 0) break;
      const nameLen = content.charCodeAt(idx + 26) | (content.charCodeAt(idx + 27) << 8);
      if (nameLen > 0 && nameLen < 256 && idx + 30 + nameLen <= content.length) {
        const name = content.slice(idx + 30, idx + 30 + nameLen);
        if (/^[\x20-\x7E]+$/.test(name)) entries.push(name);
      }
      pos = idx + 4;
    }
    return { kind: "ZIP", entries, note: "Best-effort local-header scan of text-projected bytes; binary-mangled names or 40-entry cap may truncate the list." };
  }
  if (content.startsWith("Rar!")) return { kind: "RAR", entries: [], note: "RAR archive — entry listing requires byte-level upload (opt-in)." };
  if (content.startsWith("\x1f\x8b")) return { kind: "GZIP", entries: [], note: "GZIP stream detected — decompression requires byte-level upload (opt-in)." };
  if (content.startsWith("7z")) return { kind: "7Z", entries: [], note: "7z signature detected — entry listing requires byte-level upload (opt-in)." };
  if (content.startsWith("MZ")) return { kind: "PE/EXE", entries: [], note: "Executable image — not an archive; inspect PE section instead." };
  if (content.startsWith("%PDF")) return { kind: "PDF", entries: [], note: "PDF document — embedded objects listed elsewhere." };
  return { kind: null, entries: [], note: "No archive magic detected in text projection." };
}

function officeInspect(content: string, ext: string): OfficeInfo {
  if (!OFFICE_EXTS.has(ext)) return { detected: false, fields: [], macros: false, note: `Not an Office document extension (${ext || "none"}).` };
  if (!content.includes("[Content_Types].xml")) return { detected: false, fields: [], macros: false, note: "OOXML manifest not found — legacy OLE (doc/xls/ppt) properties need byte-level upload (opt-in)." };
  const fieldRx: [string, RegExp][] = [
    ["Creator", /<dc:creator(?:[^>]*)>([^<]{0,200})<\/dc:creator>/],
    ["Title", /<dc:title(?:[^>]*)>([^<]{0,200})<\/dc:title>/],
    ["Last modified by", /<cp:lastModifiedBy(?:[^>]*)>([^<]{0,200})<\/cp:lastModifiedBy>/],
    ["Revision", /<cp:revision(?:[^>]*)>([^<]{0,50})<\/cp:revision>/],
    ["Created", /<dcterms:created(?:[^>]*)>([^<]{0,100})<\/dcterms:created>/],
    ["Modified", /<dcterms:modified(?:[^>]*)>([^<]{0,100})<\/dcterms:modified>/],
  ];
  const fields = fieldRx.flatMap(([label, re]) => {
    const m = content.match(re);
    return m ? [{ label, value: m[1] }] : [];
  });
  const macros = /vbaProject\.bin|word\/vba|xl\/vba|ppt\/vba/i.test(content);
  return {
    detected: true,
    fields,
    macros,
    note: macros ? "Macro-enabled document (VBA project detected)." : "OOXML metadata read from core.xml text projection; binary parts listed as unknown.",
  };
}

const YARA_RULES: { name: string; tags: string[]; description: string; match: (c: string, fn: string) => string[] }[] = [
  { name: "has_pe_header", tags: ["executable"], description: "MZ header with PE signature", match: (c) => (c.startsWith("MZ") && c.includes("PE\u0000\u0000") ? ["PE signature found"] : []) },
  { name: "powershell_encoded", tags: ["script", "execution"], description: "PowerShell -enc encoded command", match: (c) => { const m = c.match(/(-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{40,})/i); return m ? [m[1].slice(0, 60)] : []; } },
  { name: "powershell_download_cradle", tags: ["script", "c2"], description: "PowerShell download cradle (IEX/WebClient)", match: (c) => { const m = c.match(/(IEX\s*\(\s*(?:New-Object|\([^)]*\))\s*\)|[Nn]et\.[Ww]eb[Cc]lient)/); return m ? [m[1]] : []; } },
  { name: "base64_blob", tags: ["obfuscation"], description: "Large base64 string", match: (c) => { const m = c.match(/[A-Za-z0-9+/]{200,}={0,2}/); return m ? [m[0].slice(0, 60)] : []; } },
  { name: "suspicious_api", tags: ["injection"], description: "Process injection / API-hook family", match: (c) => { const hits = [...new Set([...SUSPICIOUS_APIS].filter(a => new RegExp(`\\b${a}\\b`).test(c)))].slice(0, 6); return hits; } },
  { name: "bitcoin_address", tags: ["ransomware"], description: "Cryptocurrency address", match: (c) => { const m = c.match(/\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b/); return m ? [m[0]] : []; } },
  { name: "private_key", tags: ["credential"], description: "RSA/private key material", match: (c) => { const m = c.match(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/); return m ? [m[0]] : []; } },
  { name: "many_urls", tags: ["exfil", "c2"], description: "5+ URLs embedded", match: (c) => { const n = (c.match(/https?:\/\//g) || []).length; return n >= 5 ? [`${n} URLs`] : []; } },
  { name: "many_ips", tags: ["c2"], description: "5+ IPv4 addresses", match: (c) => { const n = (c.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || []).length; return n >= 5 ? [`${n} IPs`] : []; } },
  { name: "suspicious_masquerade", tags: ["deception"], description: "Double-extension filename pattern", match: (_c, fn) => (isDoubleExtension(fn) ? ["double extension in name"] : []) },
  { name: "office_macro", tags: ["office"], description: "VBA macro presence", match: (c) => (/vbaProject\.bin/i.test(c) ? ["vbaProject.bin"] : []) },
  { name: "encoded_script", tags: ["obfuscation"], description: "eval/atob/exec shell markers", match: (c) => { const hits = [...new Set((c.match(/\b(atob|eval|exec|system|ShellExecute)\s*\(/g) || []))].slice(0, 6); return hits; } },
];

function yaraPreview(content: string, fileName: string): YaraRule[] {
  return YARA_RULES.map(r => {
    const evidence = r.match(content, fileName);
    return { name: r.name, tags: r.tags, description: r.description, matched: evidence.length > 0, evidence };
  });
}

function hashRelations(content: string, own: { md5: string; sha1: string; sha256: string }): { own: { alg: string; value: string }[]; embedded: { alg: string; value: string }[]; embeddedOwnMatch: boolean; note: string } {
  const embedded: { alg: string; value: string }[] = [];
  const seen = new Set<string>();
  const scan = (re: RegExp, alg: string) => {
    for (const m of content.matchAll(re)) {
      const v = m[0].toLowerCase();
      if (!seen.has(v) && v !== own.md5 && v !== own.sha1 && v !== own.sha256) { seen.add(v); embedded.push({ alg, value: v }); }
    }
  };
  scan(/\b[0-9a-f]{32}\b/gi, "MD5");
  scan(/\b[0-9a-f]{40}\b/gi, "SHA1");
  scan(/\b[0-9a-f]{64}\b/gi, "SHA256");
  const embeddedOwnMatch = [own.md5, own.sha1, own.sha256].some(v => new RegExp(`\\b${v}\\b`).test(content.toLowerCase()));
  return {
    own: [
      { alg: "MD5", value: own.md5 },
      { alg: "SHA1", value: own.sha1 },
      { alg: "SHA256", value: own.sha256 },
    ],
    embedded,
    embeddedOwnMatch,
    note: embeddedOwnMatch ? "Embedded hash matches this file's own hash — self-reference present." : "Embedded hashes are candidates from content; cross-check against threat intel.",
  };
}

/** Best-effort text-projected magic-byte check. */

export interface FileSignals {
  ext: string;
  doubleExt: boolean;
  suspiciousExt: boolean;
  hiddenExt: boolean;
  highEntropy: boolean;
  magicMismatch: boolean;
  largeFile: boolean;
  longName: boolean;
  extension: string;
  mime: string;
  secrets: Secret[];
}

export function collectFileSignals(fileName: string, content: string): FileSignals {
  const ext = (fileName.split(".").pop() || "").toLowerCase();
  const nameWithoutExt = fileName.slice(0, fileName.lastIndexOf("."));
  const doubleExt = isDoubleExtension(fileName);
  const suspiciousExt = SUSPICIOUS_EXTS.has(ext) && !SAFE_EXTS.has(ext);
  const hiddenExt = /\u200B|\u200C|\u200D|\u202E/.test(fileName) || /％[a-z0-9]{2}|%[a-z0-9]{2}/i.test(fileName);
  const contentEntropy = entropy(content);
  const highEntropy = contentEntropy > 5.0 && content.length > 20;
  const expectedMagic = EXT_MAGIC_MAP[ext];
  const magicMismatch = expectedMagic ? !expectedMagic.some(m => content.startsWith(m)) : false;
  const largeFile = content.length > 100_000;
  const longName = nameWithoutExt.length > 30;
  return {
    ext, doubleExt, suspiciousExt, hiddenExt, highEntropy, magicMismatch, largeFile, longName,
    extension: ext,
    mime: guessMime(ext),
    secrets: scanSecrets(content)
  };
}

/* ── orchestrator (ANALYSIS_ENGINE §4c pipeline for the File surface) ── */

export interface FileAnalysisInput {
  fileName: string;
  content: string;
  committed: boolean;
}

export interface FileAnalysisOptions {
  source?: string;
  ts?: string;
  history?: CorrelationHistory;
}

export interface HashRelations {
  own: { alg: string; value: string }[];
  embedded: { alg: string; value: string }[];
  embeddedOwnMatch: boolean;
  note: string;
}

export interface DisplayFinding {
  severity: Severity;
  title: string;
  reason: string;
  action: string;
  technique?: string;
  confidence?: Finding["confidence"];
}

export interface FileAnalysisResult {
  id: string;
  analyzer: "file";
  artifact: Artifact;
  raw: string;
  findings: Finding[];
  iocs: IOC[];
  evidenceItems: EvidenceItem[];
  summary: AnalysisSummary;
  generatedAt: string;
  // page-specific fields
  fileName: string;
  fileSize: number;
  extension: string;
  mimeGuess: string;
  hashes: { md5: string; sha1: string; sha256: string };
  doubleExtension: boolean;
  suspiciousExtension: boolean;
  hiddenExtension: boolean;
  highEntropy: boolean;
  hasEmbeddedUrls: boolean;
  hasEmbeddedIps: boolean;
  hasEmbeddedEmails: boolean;
  hasSecrets: boolean;
  fileTypeMismatch: boolean;
  displayFindings: DisplayFinding[];
  mitre: MitreMapping[];
  // depth sections (text-projected extraction facts)
  strings: FileStrings;
  pe: PeInfo;
  imports: ApiEvidence;
  archive: ArchiveInfo;
  office: OfficeInfo;
  yara: YaraRule[];
  hashRelations: HashRelations;
  // advanced forensic models (DiE / Ghidra / YARA / OLE)
  peAnalysis?: PeAnalysis;
  officeAnalysis?: OfficeAnalysis;
  pdfAnalysis?: PdfAnalysis;
  scriptAnalysis?: ScriptAnalysis;
  synthesizedYara?: string;
  // analysis-engine sections
  observations: Observation[];
  relationships: Relationship[];
  recommendations: Recommendation[];
  opportunities: DetectionOpportunity[];
  quality: AnalysisQuality;
  correlation: CorrelationMatch[];
  correlationRelationships: Relationship[];
}

function signalsToMeta(s: FileSignals): Record<string, string> {
  const meta: Record<string, string> = { extension: s.extension, mime: s.mime };
  if (s.doubleExt) meta.doubleExt = "true";
  if (s.suspiciousExt) meta.suspiciousExt = "true";
  if (s.hiddenExt) meta.hiddenExt = "true";
  if (s.highEntropy) meta.highEntropy = "true";
  if (s.magicMismatch) meta.magicMismatch = "true";
  if (s.largeFile) meta.largeFile = "true";
  if (s.longName) meta.longName = "true";
  return meta;
}

const FINDING_ACTIONS: Record<string, string> = {
  "Double extension masquerade": "Do not open; triage in sandbox.",
  "Suspicious file extension": "Scan with antivirus before opening.",
  "Hidden extension characters": "Rename to reveal true extension before analysis.",
  "File type / extension mismatch": "Identify real type via magic byte analysis.",
  "High entropy content": "Submit to sandbox analysis.",
  "Large file": "Inspect for embedded payloads.",
  "Unusually long filename": "Compare against known malware naming patterns.",
  "Potential secrets exposed": "Rotate exposed credentials immediately.",
  "Initial payload retrieval": "Trace the download source and block associated URLs.",
  "Encoded PowerShell command": "Decode and review the command in a sandbox.",
  "Macro-enabled document": "Open only in a macro-isolated environment.",
};

const DEFAULT_ACTION: Record<Severity, string> = {
  critical: "Treat as critical; isolate the file and escalate.",
  high: "Do not open on production systems; analyze in isolation.",
  medium: "Review context and verify before trusting.",
  low: "Note and monitor.",
  info: "No action required beyond awareness.",
};

function displayFrom(findings: Finding[]): DisplayFinding[] {
  return findings.map((f) => ({
    severity: f.severity,
    title: f.title,
    reason: f.detail,
    action: FINDING_ACTIONS[f.title] ?? DEFAULT_ACTION[f.severity],
    technique: f.technique,
    confidence: f.confidence,
  }));
}

function summaryFrom(findings: Finding[]): AnalysisSummary {
  const crit = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const med = findings.filter((f) => f.severity === "medium").length;
  const score = Math.min(100, crit * 25 + high * 12 + med * 5);
  const verdict = crit > 0 ? "malicious" : high > 0 ? "suspicious" : med > 0 ? "suspicious" : "clean";
  const confidence = findings.some((f) => f.confidence?.level === "high")
    ? 0.85
    : findings.some((f) => f.confidence?.level === "medium")
      ? 0.65
      : findings.length > 0
        ? 0.35
        : 0.15;
  return { verdict, score, confidence };
}

function dedupObservations(obs: Observation[]): Observation[] {
  const seen = new Set<string>();
  return obs.filter((o) => {
    if (seen.has(o.id)) return false;
    seen.add(o.id);
    return true;
  });
}

/**
 * File orchestrator: raw file text → canonical Observation set (extraction
 * §4b, incl. file/macro/secret signals) → Analysis Engine → correlation.
 * The page consumes this output; it never computes findings, MITRE,
 * recommendations, or relationships itself (ANALYSIS_ENGINE §4c, P11).
 */
export async function analyzeFileArtifact(
  input: FileAnalysisInput,
  opts: FileAnalysisOptions = {},
): Promise<FileAnalysisResult | null> {
  const { fileName, content, committed } = input;
  if (!committed || !fileName.trim()) return null;
  const source = opts.source ?? "file";
  const ts = opts.ts;
  const fileSize = content.length;
  const generatedAt = new Date().toISOString();

  /* ── extraction facts (never infers intent) ── */
  const signals = collectFileSignals(fileName, content);
  const ext = signals.extension;
  const strings = extractStrings(content);
  const pe = peInspect(content);
  const imports = importEvidence(content);
  const archive = archiveInspect(content);
  const office = officeInspect(content, ext);
  const yara = yaraPreview(content, fileName);
  const secrets = signals.secrets;

  /* ── deep static forensics (PE sections, office macros, pdf tokens, script cradles, yara) ── */
  const rawBytes = new Uint8Array(content.length);
  for (let i = 0; i < content.length; i++) {
    rawBytes[i] = content.charCodeAt(i) & 0xff;
  }
  const peAnalysis = parseClientPeHeaders(rawBytes);
  const officeAnalysis = dissectClientOffice(content, fileName);
  const pdfAnalysis = dissectClientPdf(content);
  const scriptAnalysis = dissectClientScript(content, fileName);

  const embeddedUrls = [...new Set(content.match(/https?:\/\/[^\s)"'\]>]+/gi) ?? [])];
  const embeddedIps = [...new Set(content.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) ?? [])];
  const embeddedEmails = [...new Set(content.match(/[\w.+-]+@[\w-]+\.[\w.]+/g) ?? [])];

  /* ── real hashes over the exact analyzed text ── */
  const [sha1, sha256] = await Promise.all([shaHex("SHA-1", content), shaHex("SHA-256", content)]);
  const hashes = { md5: md5Hex(content), sha1, sha256 };
  const hashRel = hashRelations(content, hashes);

  /* ── canonical Observation set via extraction (§4b facade) ── */
  const norm = normalizeObservations(content, { source, ts });
  const commands = norm.format === "text" ? extractCommandLines(content, source, ts) : [];
  const fileObs = makeObservation({ kind: "file", value: fileName, source, meta: signalsToMeta(signals), ts });
  const macroObs = office.macros
    ? [makeObservation({ kind: "macro", value: "vbaProject.bin", source, meta: { macro: "true" }, ts })]
    : [];
  const secretObs = secrets.map((s) =>
    makeObservation({ kind: "string", value: s.value, source, meta: { secretType: s.type }, ts }),
  );
  const observations = dedupObservations([...norm.observations, ...commands, fileObs, ...macroObs, ...secretObs]);

  /* ── Analysis Engine + correlation (post-analysis, local history) ── */
  const engine = analyzeAndCorrelate(observations, opts.history ?? {}, { source, ts });

  /* ── presentation mapping (engine conclusions + extraction facts) ── */
  const summary = summaryFrom(engine.findings);
  const displayFindings = displayFrom(engine.findings);
  const iocSeverity: Severity = summary.verdict === "malicious" ? "high" : summary.verdict === "suspicious" ? "medium" : "info";

  const iocs: IOC[] = [
    ...embeddedUrls.map((u) => ({ value: u, type: "url" as const, context: "Embedded in file content", source: "/file", severity: iocSeverity })),
    ...embeddedIps.map((ip) => ({ value: ip, type: "ipv4" as const, context: "Embedded in file content", source: "/file", severity: iocSeverity })),
    ...embeddedEmails.map((e) => ({ value: e, type: "email" as const, context: "Embedded in file content", source: "/file", severity: iocSeverity })),
    ...hashRel.embedded.slice(0, 20).map((h) => ({
      value: h.value,
      type: (h.alg === "MD5" ? "md5" : h.alg === "SHA1" ? "sha1" : "sha256") as IOC["type"],
      context: `Embedded ${h.alg} hash in file content`,
      source: "/file",
      severity: iocSeverity,
    })),
    { value: hashes.sha256, type: "sha256" as const, context: "File SHA-256 hash", source: "/file", severity: iocSeverity },
  ];

  const artifact: Artifact = {
    id: objectId("artifact", "file", fileName, hashes.sha256),
    kind: "file",
    title: fileName,
    metadata: {
      name: fileName,
      extension: ext,
      size: String(fileSize),
      mime: guessMime(ext),
      md5: hashes.md5,
      sha1: hashes.sha1,
      sha256: hashes.sha256,
    },
    created: generatedAt,
  };

  const evidenceItems: EvidenceItem[] = [
    ...engine.findings.map((f) => ({ type: "finding" as const, title: f.title, detail: f.detail, source })),
    ...secrets.map((s) => ({ type: "secret" as const, title: s.type, detail: s.value, source })),
  ];

  return {
    id: objectId("analysis", "file", fileName, hashes.sha256),
    analyzer: "file",
    artifact,
    raw: content,
    findings: engine.findings,
    iocs,
    evidenceItems,
    summary,
    generatedAt,
    fileName,
    fileSize,
    extension: ext,
    mimeGuess: guessMime(ext),
    hashes,
    doubleExtension: signals.doubleExt,
    suspiciousExtension: signals.suspiciousExt,
    hiddenExtension: signals.hiddenExt,
    highEntropy: signals.highEntropy,
    hasEmbeddedUrls: embeddedUrls.length > 0,
    hasEmbeddedIps: embeddedIps.length > 0,
    hasEmbeddedEmails: embeddedEmails.length > 0,
    hasSecrets: secrets.length > 0,
    fileTypeMismatch: signals.magicMismatch,
    displayFindings,
    mitre: engine.mitre,
    strings,
    pe,
    imports,
    archive,
    office,
    yara,
    hashRelations: hashRel,
    peAnalysis,
    officeAnalysis,
    pdfAnalysis,
    scriptAnalysis,
    synthesizedYara: synthesizeYaraRule({
      filename: fileName,
      sha256: hashes.sha256,
      imphash: peAnalysis.imphash,
      isPe: peAnalysis.detected,
      isOpenXml: officeAnalysis.detected,
      strings: strings.samples.map((s) => s.value),
    }),
    observations,
    relationships: [...engine.relationships, ...engine.correlationRelationships],
    recommendations: engine.recommendations,
    opportunities: engine.opportunities,
    quality: engine.quality,
    correlation: engine.correlation,
    correlationRelationships: engine.correlationRelationships,
  };
}