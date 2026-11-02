import { SUSPICIOUS_TLDS, SHORTENERS, FREE_WEBMAIL, ABUSED_HOSTS, REDIRECT_PARAMS, refang, entropy, scanSecrets } from "@/lib/ioc-patterns";
 // prettier-ignore

export const SAMPLES: Record<string, string> = {
  lure: `From: "Microsoft 365 Security" <security-alert@microsoft-auth-verify.xyz>
To: target.user@enterprise.org
Subject: URGENT: Microsoft 365 Password Expiration Notice
Return-Path: <bounce@microsoft-auth-verify.xyz>
Reply-To: security-reply@microsoft-auth-verify.xyz
Authentication-Results: mx.enterprise.org;
  spf=pass smtp.mailfrom=bounces@marketing-sender.net;
  dkim=pass d=marketing-sender.net s=s1;
  dmarc=fail (p=reject) header.from=microsoft-auth-verify.xyz;
  arc=pass
Received: from mail-relay.enterprise.org (192.0.2.10) by mx.enterprise.org with ESMTPS id abc;
  Wed, 11 May 2022 14:32:15 +0000
Received: from outbound.marketing-sender.net (198.51.100.25) by mail-relay.enterprise.org with ESMTP id def;
  Wed, 11 May 2022 14:32:05 +0000
Received: from client-pc-04.dhcp.evil-isp.ru (185.220.101.44) by outbound.marketing-sender.net with ESMTP id ghi;
  Wed, 11 May 2022 14:32:00 +0000
Content-Type: text/html; charset=utf-8

<html>
<body>
  <h2>Urgent: Microsoft 365 Account Suspension</h2>
  <p>Your password is scheduled to expire within 24 hours. Immediate verification is required to preserve your mailbox.</p>
  <p>Please review and confirm your credentials at the security center:</p>
  <p><a href="https://evil-c2-portal.ru/auth/m365/login?redirect=https://login.microsoftonline.com">https://account.microsoft.com/security/login</a></p>
  <p>Failure to act will terminate your active directory session immediately.</p>
  <p>Reference: 44d88612fea8a8f36de82e1278abb02f</p>
</body>
</html>`,

  bec: `From: Jane Doe <jane.doe@acmme-corp.com>
To: finance@acme-corp.com
Subject: Re: Wire transfer for vendor onboarding
Return-Path: <jane.doe@acmme-corp.com>
Reply-To: jane.doe.cfo@gmail.com
Authentication-Results: mx.acme-corp.com; spf=pass smtp.mailfrom=acmme-corp.com; dkim=softfail; dmarc=fail
Received: from mx.acme-corp.com (192.0.2.10) by mailbox.internal with ESMTPS; Wed, 11 May 2022 10:15:08 +0000
Received: from smtp-relay.gmail.com (209.85.220.41) by mx.acme-corp.com with ESMTPS; Wed, 11 May 2022 10:15:02 +0000
Received: from mail.acmme-corp.com (192.0.2.88) by smtp-relay.gmail.com with ESMTP; Wed, 11 May 2022 10:15:00 +0000
Content-Type: multipart/mixed; boundary="----=_Part_123"

Hi team,
Quick request before my flight — please process the wire for our new vendor today.
Bank details attached. Confirm once sent, I'll sign the invoice on landing.
Thanks, Jane (sent from mobile)`,

  invoice: `From: Billing <billing@invoice-portal[.]net>
To: ap@example.org
Subject: Invoice INV-90213 ready for download
Return-Path: noreply@invoice-portal.net
Reply-To: billing@invoice-portal.net
Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=invoice-portal.net; dkim=pass; dmarc=pass
Received: from mta-12.invoice-portal.net (192.0.2.201) by mx.example.org
Content-Disposition: attachment; filename=invoice.pdf

Hello,
Your invoice is available: https://invoice-portal.net/download?ref=INV-90213
SHA-1 attached: 275a021bbfb6489e54d471899f7db9d1663fc695
Pay before due date to avoid late fees.`,

  html: `From: Newsletter <noreply@phish-mg.tk>
To: user@example.org
Subject: Your account has been suspended
Return-Path: bounce@phish-mg.tk
Reply-To: support@phish-mg.tk
Authentication-Results: mx.example.org; spf=fail; dkim=none; dmarc=fail
Received: from mail.phish-mg.tk (185.220.101.44) by mx.example.org
Content-Type: text/html; charset=utf-8

<html>
<body>
<form action="hxxps[:]//login.example[.]com/verify" method="POST">
  <h2>Security Alert</h2>
  <p>Your account has been suspended due to unusual activity.</p>
  <input type="hidden" name="token" value="ghp_abcdefghijklmnopqrstuvwxyz1234567890">
  <label>Email: <input type="text" name="email"></label>
  <label>Password: <input type="password" name="pass"></label>
  <button type="submit">Verify Now</button>
</form>
</body>
</html>`,

  suspicious_invoice: `From: Accounts Payable <invoices@acmecorp-billing[.]net>
To: finance@example.org
Subject: INV-2024-8932 — Overdue payment notice
Return-Path: noreply@acmecorp-billing.net
Reply-To: disputes@acmecorp-billing.net
Authentication-Results: mx.example.org; spf=softfail smtp.mailfrom=acmecorp-billing.net; dkim=neutral; dmarc=fail
Received: from mail.acmecorp-billing.net (198.51.100.99) by mx.example.org with ESMTPS

Dear Finance Department,

Your invoice INV-2024-8932 for $12,847.50 is now overdue.
To avoid service interruption and late fees, please process payment immediately.

View and pay your invoice here: hxxps[:]//acmecorp-billing[.]net/pay/invoice/INV-2024-8932

Reference: 7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
If you have already paid, please disregard this notice.

Accounts Receivable
ACMECorp Billing Portal
disputes@acmecorp-billing.net`,

  account_alert: `From: Security Alerts <alert@secure-verify[.]tk>
To: user@example.org
Subject: Security Alert: Unusual sign-in detected
Return-Path: bounce@secure-verify.tk
Reply-To: support@secure-verify.tk
Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=secure-verify.tk; dkim=none; dmarc=fail
Received: from mail.secure-verify.tk (203.0.113.77) by mx.example.org with ESMTPS

We detected a sign-in attempt from an unfamiliar device or location.

• Location: Moscow, Russia
• Device: Windows 10 / Chrome 124
• Time: April 15, 2026 3:42 AM UTC

If this was not you, your account may be compromised.

Secure your account now: hxxps[:]//secure-verify[.]tk/account/recovery?id=U2FsdGVkX18

This is an automated security alert. Do not reply to this message.

— Account Security Team`,
};

export const RX = {
  URL:    /\b(?:hxxps?|https?):\/\/[^\s)>"']+/gi,
  Domain: /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi,
  IPv4:   /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  MD5:    /\b[a-f0-9]{32}\b/gi,
  SHA256: /\b[a-f0-9]{64}\b/gi,
  Email:  /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi,
  CVE:    /CVE-\d{4}-\d{4,}/gi,
  ATTACK: /\bT\d{4}(?:\.\d{3})?\b/g,
};

export const SENDER_TLDS = new Set(["tk","ml","ga","cf","gq","xyz","top","download","review","work","date","men","loan","win","bid","cam","click","quest","trade","webcam","cyou","bond"]);

export const BRAND_KEYWORDS = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook", "instagram", "linkedin", "twitter", "x.com", "dropbox", "adobe", "dhl", "fedex", "ups", "usps", "bank of america", "chase", "wells fargo", "citi", "capital one", "american express", "visa", "mastercard", "github", "gitlab", "bitbucket", "slack", "zoom", "teams", "office 365", "microsoft 365", "outlook", "gmail", "yahoo", "aol"];

export type AuthState = "pass" | "fail" | "softfail" | "none";

export function getDomain(email: string): string {
  const m = email.match(/@([^\s>]+)/);
  return m ? m[1].toLowerCase().replace(/[\[\]]/g, "") : "";
}

export function detectAuth(input: string, family: "spf" | "dkim" | "dmarc"): AuthState {
  const hasAuth = /Authentication-Results:/i.test(input);
  if (!hasAuth) return "none";
  const rx = new RegExp(family + "=([a-z]+)", "i");
  const m = input.match(rx);
  const v = m?.[1]?.toLowerCase();
  if (v === "pass") return "pass";
  if (v === "softfail" || v === "neutral" || v === "policy" || v === "temperror" || v === "permerror") return "softfail";
  if (v === "fail" || v === "none") return "fail";
  return "none";
}

export interface AuthResultsSummary {
  headerCount: number;
  spf: AuthState;
  dkim: AuthState;
  dmarc: AuthState;
  conflict: { spf: boolean; dkim: boolean; dmarc: boolean };
}

function normalizeVerdict(v: string): AuthState {
  if (v === "pass") return "pass";
  if (v === "softfail" || v === "neutral" || v === "policy" || v === "temperror" || v === "permerror") return "softfail";
  if (v === "fail" || v === "none") return "fail";
  return "none";
}

function authHeaderBlocks(input: string): string[] {
  const lines = input.split(/\r?\n/);
  const blocks: string[] = [];
  let cur: string[] | null = null;
  for (const line of lines) {
    if (/^Authentication-Results:/i.test(line)) {
      if (cur) blocks.push(cur.join("\n"));
      cur = [line];
    } else if (cur && /^[ \t]/.test(line)) {
      cur.push(line);
    } else if (cur) {
      blocks.push(cur.join("\n"));
      cur = null;
    }
  }
  if (cur) blocks.push(cur.join("\n"));
  return blocks;
}

/**
 * Parses every Authentication-Results header (including folded continuation
 * lines). Display verdicts come from the TOPMOST header — each receiving MTA
 * prepends its own A-R header, so the first block is the last evaluator.
 * Conflicting verdicts across headers are flagged per family instead of
 * silently hidden.
 */
export function parseAuthResults(input: string): AuthResultsSummary {
  const blocks = authHeaderBlocks(input);
  const families = ["spf", "dkim", "dmarc"] as const;
  const perFamily: Record<(typeof families)[number], AuthState[]> = { spf: [], dkim: [], dmarc: [] };
  for (const b of blocks) {
    for (const f of families) {
      const m = b.match(new RegExp(f + "=([a-z]+)", "i"));
      if (!m) continue;
      perFamily[f].push(normalizeVerdict(m[1].toLowerCase()));
    }
  }
  const first = (f: (typeof families)[number]): AuthState => perFamily[f][0] ?? "none";
  return {
    headerCount: blocks.length,
    spf: first("spf"),
    dkim: first("dkim"),
    dmarc: first("dmarc"),
    conflict: { spf: new Set(perFamily.spf).size > 1, dkim: new Set(perFamily.dkim).size > 1, dmarc: new Set(perFamily.dmarc).size > 1 },
  };
}

export function extractBody(input: string): string {
  const parts = input.split(/\r?\n\r?\n/);
  return parts.length > 1 ? parts.slice(1).join("\n\n").trim() : "";
}

export function extractHeaders(input: string): string {
  return input.split(/\r?\n\r?\n/)[0] || input;
}

export function detectAttachments(input: string): { hasAttachments: boolean; detail: string[] } {
  const d: string[] = [];
  if (/Content-Type:\s*multipart\//i.test(input)) d.push("Multipart content (may carry attachments)");
  const dispos = Array.from(input.matchAll(/Content-Disposition:\s*attachment;?\s*(.*)/gi));
  for (const m of dispos) d.push(`Attachment: ${m[1]?.trim() || "unnamed"}`);
  return { hasAttachments: d.length > 0, detail: d };
}

/** Filenames from Content-Disposition/Content-Type attachment lines. RFC 2231
 *  extended form (filename*=UTF-8''...) is decoded; duplicates removed. */
export function extractAttachmentFilenames(input: string): string[] {
  const names: string[] = [];
  const rx = /filename\*?=(?:"([^"]*)"|([^\s;]+))/gi;
  for (const m of input.matchAll(rx)) {
    let name = (m[1] ?? m[2] ?? "").trim();
    name = name.replace(/^[^']*''/, "");
    try { name = decodeURIComponent(name); } catch {}
    if (name && !names.includes(name)) names.push(name);
  }
  return names;
}

// ---------------------------------------------------------------------------
// Raw mail (RFC 5322 / MIME) parsing. Pasted .eml source is multipart MIME:
// without decoding, the "body" is base64 blobs + boundaries, so lure signals
// (urgency, forms, password fields) silently miss and IOC regexes fire on
// encoded noise. parseRawMail decodes transfer encodings, unfolds headers,
// pulls readable text + link targets + real attachment inventory.
// ---------------------------------------------------------------------------

export interface RawMailAttachment { filename: string; mime: string; size: number; }

export interface RawMail {
  /** True when a MIME Content-Type was found (multipart or single part). */
  isMime: boolean;
  /** Unfolded top-level headers, lowercased names, RFC 2047 words decoded. */
  headers: Record<string, string>;
  /** Decoded readable text (text/plain part, else stripped HTML). */
  textBody: string;
  /** Decoded HTML source (empty when no text/html part). */
  htmlBody: string;
  /** href/src targets pulled from the HTML part (phish links live here). */
  linkUrls: string[];
  attachments: RawMailAttachment[];
}

/** RFC 2047 encoded-words (=?charset?Q/B?text?=) → readable text. */
export function decodeEncodedWords(value: string): string {
  return value.replace(/=\?([^?\s]+)\?([bqBQ])\?([^?]*)\?=(\s+(?==\?))?/g, (_m, charset: string, enc: string, text: string) => {
    try {
      const bytes: number[] = enc.toUpperCase() === "B"
        ? Array.from(atob(text.replace(/\s/g, "")), (c) => c.charCodeAt(0))
        : Array.from(text.replace(/_/g, " ").replace(/=([0-9A-Fa-f]{2})/g, (_h, hx: string) => String.fromCharCode(parseInt(hx, 16))), (c) => c.charCodeAt(0) & 0xff);
      // Q-encoding above already yields a latin1 string; re-encode to bytes.
      const raw = enc.toUpperCase() === "B" ? new Uint8Array(bytes) : new TextEncoder().encode(bytes.map((b) => String.fromCharCode(b)).join(""));
      return new TextDecoder(charset || "utf-8", { fatal: false }).decode(raw);
    } catch { return text; }
  });
}

/** Folded (multi-line) header block → { lowercase-name: decoded value }. */
export function unfoldHeaders(block: string): Record<string, string> {
  const out: Record<string, string> = {};
  let name = "";
  let value = "";
  const flush = () => {
    if (name) out[name] = decodeEncodedWords(value.trim().replace(/\s+/g, " "));
    name = ""; value = "";
  };
  for (const line of block.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && name) value += " " + line.trim();
    else {
      flush();
      const i = line.indexOf(":");
      if (i > 0) { name = line.slice(0, i).trim().toLowerCase(); value = line.slice(i + 1).trim(); }
    }
  }
  flush();
  return out;
}

function parseContentType(value: string): { mime: string; params: Record<string, string> } {
  const [mime, ...rest] = value.split(";");
  const params: Record<string, string> = {};
  for (const p of rest) {
    const i = p.indexOf("=");
    if (i > 0) params[p.slice(0, i).trim().toLowerCase()] = p.slice(i + 1).trim().replace(/^"|"$/g, "");
  }
  return { mime: (mime || "").trim().toLowerCase(), params };
}

/** Content-Transfer-Encoding → decoded text (charset-aware, never throws). */
export function decodePartBody(raw: string, encoding: string, charset: string): string {
  const enc = (encoding || "").toLowerCase();
  try {
    if (enc === "base64") {
      const bin = atob(raw.replace(/\s/g, ""));
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      try { return new TextDecoder(charset || "utf-8", { fatal: false }).decode(bytes); }
      catch { return new TextDecoder("utf-8", { fatal: false }).decode(bytes); }
    }
    if (enc === "quoted-printable" || enc === "quotedprintable") {
      const latin = raw.replace(/=\r?\n/g, "").replace(/=([0-9A-Fa-f]{2})/g, (_h, hx: string) => String.fromCharCode(parseInt(hx, 16)));
      try { return new TextDecoder(charset || "utf-8", { fatal: false }).decode(new TextEncoder().encode(latin)); }
      catch { return latin; }
    }
  } catch { /* fall through to raw */ }
  return raw;
}

/** RFC 2231 continuations (filename*0*, filename*1*...) + single encoded. */
function rfc2231Filename(params: Record<string, string>): string {
  const cont = Object.keys(params).filter((k) => /^filename\*\d+\*?$/.test(k)).sort();
  let name = "";
  if (cont.length) {
    name = cont.map((k) => params[k]).join("").replace(/^[^']*''/, "");
    try { name = decodeURIComponent(name); } catch {}
  } else {
    const v = params["filename*"] ?? params["filename"] ?? params["name*"] ?? params["name"] ?? "";
    name = v.replace(/^[^']*''/, "");
    if (/^filename\*|^name\*/.test(Object.keys(params).find((k) => params[k] === v) ?? "") || /%[0-9A-Fa-f]{2}/.test(name)) {
      try { name = decodeURIComponent(name); } catch {}
    }
    name = decodeEncodedWords(name.replace(/^"|"$/g, ""));
  }
  return name.trim();
}

function splitParts(body: string, boundary: string): string[] {
  const marker = "--" + boundary;
  return body.split(marker).slice(1).filter((c) => c.trim() && c.trim() !== "--").map((c) => c.replace(/\r?\n?--\s*$/, "").replace(/^\r?\n/, ""));
}

function hrefTargets(html: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/(?:href|src)\s*=\s*["']([^"'#\s>]+)["']/gi)) {
    const u = m[1];
    if (/^https?:\/\//i.test(u) && !out.includes(u)) out.push(u);
  }
  return out;
}

function ingestPart(chunk: string, mail: RawMail): void {
  const idx = chunk.search(/\r?\n\r?\n/);
  const head = idx >= 0 ? chunk.slice(0, idx) : "";
  const content = idx >= 0 ? chunk.slice(idx).replace(/^\r?\n\r?\n/, "") : chunk;
  const h = unfoldHeaders(head);
  const { mime, params } = parseContentType(h["content-type"] ?? "text/plain");
  // Nested multipart (e.g. mixed > alternative): recurse into sub-parts.
  if (mime.startsWith("multipart/") && params["boundary"]) {
    for (const sub of splitParts(content, params["boundary"])) ingestPart(sub, mail);
    return;
  }
  const charset = (params["charset"] || "").replace(/^"|"$/g, "");
  const decoded = decodePartBody(content.trim(), h["content-transfer-encoding"] ?? "", charset);
  const filename = rfc2231Filename(params);
  const disp = (h["content-disposition"] ?? "").toLowerCase();
  if (filename || disp.startsWith("attachment")) {
    if (!mail.attachments.some((a) => a.filename === (filename || "unnamed"))) {
      mail.attachments.push({ filename: filename || "unnamed", mime: mime || "application/octet-stream", size: decoded.length });
    }
    return;
  }
  if (mime === "text/html") {
    if (!mail.htmlBody) {
      mail.htmlBody = decoded;
      for (const u of hrefTargets(decoded)) if (!mail.linkUrls.includes(u)) mail.linkUrls.push(u);
    }
    return;
  }
  if (mime === "text/plain") {
    mail.textBody = mail.textBody ? mail.textBody + "\n\n" + decoded : decoded;
  }
}

/**
 * Parse pasted .eml / RFC 5322 source. Non-MIME input returns isMime=false
 * (callers fall back to the legacy blank-line split). Deterministic, no deps.
 */
export function parseRawMail(input: string): RawMail {
  const mail: RawMail = { isMime: false, headers: {}, textBody: "", htmlBody: "", linkUrls: [], attachments: [] };
  const idx = input.search(/\r?\n\r?\n/);
  if (idx < 0) return mail;
  mail.headers = unfoldHeaders(input.slice(0, idx));
  const { mime, params } = parseContentType(mail.headers["content-type"] ?? "");
  if (!mime || (!mime.startsWith("multipart/") && !mail.headers["mime-version"] && !/multipart\//i.test(input))) return mail;
  mail.isMime = true;
  const rest = input.slice(idx).replace(/^\r?\n\r?\n/, "");
  if (mime.startsWith("multipart/") && params["boundary"]) {
    for (const chunk of splitParts(rest, params["boundary"])) ingestPart(chunk, mail);
  } else {
    // Single-part MIME (e.g. lone base64 text/html): decode the whole body.
    ingestPart(`Content-Type: ${mail.headers["content-type"]}\nContent-Transfer-Encoding: ${mail.headers["content-transfer-encoding"] ?? "7bit"}\n\n${rest}`, mail);
  }
  if (!mail.textBody && mail.htmlBody) mail.textBody = htmlToText(mail.htmlBody);
  mail.textBody = mail.textBody.trim();
  return mail;
}

export function detectLookalike(from: string, replyTo: string, returnPath: string): string[] {
  const flags: string[] = [];
  const fromDomain = getDomain(from);
  const replyDomain = getDomain(replyTo);
  const pathDomain = getDomain(returnPath);
  if (fromDomain && replyDomain && fromDomain !== replyDomain) flags.push(`Reply-To domain (${replyDomain}) differs from From domain (${fromDomain})`);
  if (fromDomain && pathDomain && fromDomain !== pathDomain) flags.push(`Return-Path domain (${pathDomain}) differs from From domain (${fromDomain})`);
  return flags;
}

export interface DisplaySpoof {
  kind: "brand" | "bec";
  detail: string;
  brand?: string;
}

/* Display-name spoofing + BEC behavioural signals. Auth headers cannot catch
 * these: a display name is free text, and BEC arrives from a real free
 * mailbox that passes SPF/DKIM/DMARC. Two checks: (a) the display name
 * claims a known brand while the sender domain is unrelated/typosquat;
 * (b) a personal display name sent from free webmail (executive-impersonation
 * tell). Returns structured flags so the engine can score them. */
export function detectDisplaySpoof(fromLine: string, fromDomain: string | undefined): DisplaySpoof[] {
  const out: DisplaySpoof[] = [];
  if (!fromDomain) return out;
  const m = fromLine.match(/^\s*"?([^"<]*?)"?\s*<[^>]+>/);
  const display = (m?.[1] ?? "").trim();
  if (!display) return out;
  const dl = display.toLowerCase();
  for (const b of BRAND_KEYWORDS) {
    if (!dl.includes(b)) continue;
    const dm = detectBrandDomainMatch(fromDomain, b);
    if (!dm || dm.typosquat) {
      out.push({ kind: "brand", brand: b, detail: dm ? `Display name claims '${b}' — ${dm.claim}` : `Display name claims '${b}' but sender domain ${fromDomain} is unrelated` });
    }
  }
  if (!out.length && FREE_WEBMAIL.has(fromDomain.toLowerCase()) && /^[A-Z][a-z]+(\s+[A-Z][a-z'.-]+){1,3}$/.test(display)) {
    out.push({ kind: "bec", detail: `Personal display name '${display}' sent from free webmail ${fromDomain} — possible BEC impersonation` });
  }
  return out;
}

function urlTrustBadges(parsed: URL): { label: string; tone: "warning" | "destructive" | "info" | "success" }[] {
  const badges: { label: string; tone: "warning" | "destructive" | "info" | "success" }[] = [];
  const host = parsed.hostname.toLowerCase();
  for (const [k] of parsed.searchParams) {
    if (REDIRECT_PARAMS.has(k.toLowerCase())) {
      badges.push({ label: "open redirect", tone: "warning" });
      break;
    }
  }
  if (ABUSED_HOSTS.some((h) => host === h || host.endsWith("." + h))) {
    badges.push({ label: "abused host", tone: "warning" });
  }
  return badges;
}

export function analyzeUrls(urls: string[]): { value: string; suspicious: boolean; badges: { label: string; tone: "warning" | "destructive" | "info" | "success" }[] }[] {
  return urls.map((u) => {
    const badges: { label: string; tone: "warning" | "destructive" | "info" | "success" }[] = [];
    try {
      const parsed = new URL(refang(u));
      const host = parsed.hostname;
      const tld = host.split(".").pop()?.toLowerCase();
      if (tld && SUSPICIOUS_TLDS.has(tld)) badges.push({ label: "suspicious TLD", tone: "warning" });
      if (SHORTENERS.has(host.replace(/^www\./, ""))) badges.push({ label: "shortener", tone: "warning" });
      if (parsed.username || parsed.password) badges.push({ label: "embedded creds", tone: "destructive" });
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) badges.push({ label: "IP-based", tone: "warning" });
      badges.push(...urlTrustBadges(parsed));
      if (entropy(parsed.pathname + parsed.search) > 4.5) badges.push({ label: "high entropy", tone: "info" });
    } catch {}
    return { value: u, suspicious: badges.length > 0, badges };
  });
}

export function htmlToText(html: string): string {
  return html
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<[^>]*>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export type LanguageDetection = {
  script: string;
  label: string;
  samples: string[];
};

const SCRIPT_PATTERNS: { script: string; label: string; re: RegExp }[] = [
  { script: "cyrillic", label: "Cyrillic", re: /[\u0400-\u04FF]/ },
  { script: "arabic", label: "Arabic", re: /[\u0600-\u06FF]/ },
  { script: "devanagari", label: "Devanagari", re: /[\u0900-\u097F]/ },
  { script: "cjk", label: "CJK", re: /[\u4E00-\u9FFF\u3400-\u4DBF\u3040-\u30FF\uAC00-\uD7AF]/ },
  { script: "greek", label: "Greek", re: /[\u0370-\u03FF]/ },
  { script: "hebrew", label: "Hebrew", re: /[\u0590-\u05FF]/ },
  { script: "thai", label: "Thai", re: /[\u0E00-\u0E7F]/ },
];

const LATIN_HINTS: { script: string; label: string; re: RegExp }[] = [
  { script: "latin-acc", label: "Latin (accented)", re: /[\u00C0-\u017F]/ },
  { script: "latin-ext", label: "Latin Extended", re: /[\u0180-\u024F]/ },
];

const BRAND_DOMAIN_HINTS: Record<string, string[]> = {
  "paypal": ["paypal.com", "paypal.co.uk", "paypal.de", "paypal.fr"],
  "apple": ["apple.com"],
  "google": ["google.com", "gmail.com"],
  "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com"],
  "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
  "netflix": ["netflix.com"],
  "facebook": ["facebook.com"],
  "instagram": ["instagram.com"],
  "linkedin": ["linkedin.com"],
  "twitter": ["twitter.com", "x.com"],
  "dropbox": ["dropbox.com"],
  "adobe": ["adobe.com"],
  "dhl": ["dhl.com"],
  "fedex": ["fedex.com"],
  "ups": ["ups.com"],
  "usps": ["usps.com"],
  "chase": ["chase.com"],
  "wells fargo": ["wellsfargo.com"],
  "citi": ["citibank.com", "citi.com"],
  "visa": ["visa.com"],
  "mastercard": ["mastercard.com"],
  "github": ["github.com"],
  "gitlab": ["gitlab.com"],
  "slack": ["slack.com"],
  "zoom": ["zoom.us"],
  "outlook": ["outlook.com"],
  "gmail": ["gmail.com"],
  "yahoo": ["yahoo.com"],
};

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

export function detectLanguage(text: string): LanguageDetection | null {
  const clean = htmlToText(text);
  if (!clean.trim()) return null;
  for (const s of SCRIPT_PATTERNS) {
    const m = clean.match(s.re);
    if (m) {
      const samples = Array.from(new Set(clean.match(new RegExp(`[^\\s]*[${s.re.source.slice(1, -1)}]+[^\\s]*`, "g")))).slice(0, 4);
      return { script: s.script, label: s.label, samples };
    }
  }
  for (const l of LATIN_HINTS) {
    if (l.re.test(clean)) {
      const samples = Array.from(new Set(clean.match(/[\u00C0-\u024F]+[a-z]*/gi))).slice(0, 4);
      return { script: l.script, label: l.label, samples };
    }
  }
  return { script: "latin", label: "Latin", samples: [] };
}

export function detectBrandDomainMatch(fromDomain: string | undefined, brand: string): { claim: string; typosquat: boolean } | null {
  if (!fromDomain) return null;
  const hints = BRAND_DOMAIN_HINTS[brand];
  if (!hints) return null;
  const normalized = fromDomain.replace(/^www\./, "").toLowerCase();
  for (const h of hints) {
    if (normalized === h || normalized.endsWith("." + h)) {
      return { claim: `sender domain ${fromDomain} matches official ${h}`, typosquat: false };
    }
  }
  const brandWord = brand.replace(/\s+/g, "").toLowerCase();
  const host = normalized.split(".")[0];
  const dist = levenshtein(host, brandWord);
  const sub = normalized.includes(brandWord);
  if (dist <= 2 || (sub && host.length > brandWord.length)) {
    return { claim: `sender domain ${fromDomain} resembles '${brand}' (distance ${dist})`, typosquat: true };
  }
  return null;
}

export function buildRecommendations(findings: { sev: "destructive" | "warning" | "info"; a: string; s: string }[]): { text: string; sev: "destructive" | "warning" | "info"; source: string }[] {
  const out: { text: string; sev: "destructive" | "warning" | "info"; source: string }[] = [];
  const seen = new Set<string>();
  const rank = { destructive: 0, warning: 1, info: 2 };
  const sorted = [...findings].sort((x, y) => rank[x.sev] - rank[y.sev]);
  for (const f of sorted) {
    const action = f.a.trim();
    if (!action || seen.has(action)) continue;
    seen.add(action);
    out.push({ text: action, sev: f.sev, source: f.s });
  }
  return out;
}

export function computeBrandClaims(fromDomain: string | undefined, fromLine: string, body: string, subject: string): { brand: string; claim: string; typosquat: boolean }[] {
  const claims: { brand: string; claim: string; typosquat: boolean }[] = [];
  if (!fromDomain) return claims;
  const bodyLower = body.toLowerCase();
  const subjLower = subject.toLowerCase();
  const fromLower = fromLine.toLowerCase();
  for (const b of BRAND_KEYWORDS) {
    const mentioned = bodyLower.includes(b) || subjLower.includes(b) || fromLower.includes(b);
    if (!mentioned) continue;
    const dm = detectBrandDomainMatch(fromDomain, b);
    if (dm) claims.push({ brand: b, claim: dm.claim, typosquat: dm.typosquat });
    else claims.push({ brand: b, claim: `Message claims '${b}' but sender domain ${fromDomain} is unrelated`, typosquat: false });
  }
  return claims;
}

export function genMarkdown(input: string, data: any, iocs: any): string {
  const verdict = data.verdict?.label ?? data.verdict;
  const spf = data.auth?.spf ?? data.spf;
  const dkim = data.auth?.dkim ?? data.dkim;
  const dmarc = data.auth?.dmarc ?? data.dmarc;
  const findings = data.displayFindings ?? data.findings;
  const lines = [
    `# Phishing Triage Report`,
    `**Verdict:** ${verdict}`,
    `**SPF:** ${spf}  **DKIM:** ${dkim}  **DMARC:** ${dmarc}`,
    "",
    "## Findings",
    ...findings.map((f: any) => {
      const sev = f.severity ?? f.sev;
      const title = f.title ?? f.t;
      const reason = f.reason ?? f.r;
      return `- [${sev.toUpperCase()}] ${title} — ${reason}`;
    }),
    "",
  ];
  if (iocs) {
    lines.push("## Indicators");
    for (const [k, v] of Object.entries(iocs) as [string, string[]][]) if (v.length) lines.push(`### ${k} (${v.length})`, ...v.map((i) => `- \`${i}\``), "");
  }
  if (data.language) lines.push("## Language", `- Script: ${data.language.label}${data.language.samples.length ? ` (samples: ${data.language.samples.join(", ")})` : ""}`, "");
  const claims = Array.isArray(data.brandClaims) ? data.brandClaims : [];
  if (claims.length) {
    lines.push("## Brand impersonation", ...claims.map((c: any) => `- ${c.typosquat ? "[TYPOSQUAT] " : ""}${c.brand} — ${c.claim}`), "");
  }
  const recs = Array.isArray(data.recommendations) ? data.recommendations : [];
  if (recs.length) {
    lines.push("## Recommendations", ...recs.map((r: any, i: number) => `${i + 1}. [${r.sev.toUpperCase()}] ${r.text}`), "");
  }
  lines.push("---", "Generated by BeyondLabs Phishing Triage");
  return lines.join("\n");
}

export function genJsonExport(data: any, _iocs: any): string {
  const verdict = data.verdict?.label ?? data.verdict;
  const spf = data.auth?.spf ?? data.spf;
  const dkim = data.auth?.dkim ?? data.dkim;
  const dmarc = data.auth?.dmarc ?? data.dmarc;
  const findings = data.displayFindings ?? data.findings;
  const iocs = data.iocsByCategory ?? data.iocs ?? _iocs;
  const exportData = {
    version: "1.0",
    generated: new Date().toISOString(),
    verdict,
    authentication: { spf, dkim, dmarc },
    findings: findings.map((f: any) => ({ severity: f.severity ?? f.sev, title: f.title ?? f.t, reason: f.reason ?? f.r, action: f.action ?? f.a })),
    iocs: iocs ? { ...iocs } : {},
    secrets: (data.secrets || []).map((s: any) => ({ type: s.type, value: s.value })),
    mitre: (data.mitre || []).map((m: any) => ({ id: m.id, name: m.name, source: m.source })),
    signalBreakdown: (data.breakdown || []).map((b: any) => ({ signal: b.signal, state: b.state, weight: b.weight })),
  };
  return JSON.stringify(exportData, null, 2);
}

export function genBodySignals(body: string, iocs: { urls: string[] }): { sev: "destructive" | "warning" | "info"; t: string; r: string; a: string }[] {
  const s: { sev: "destructive" | "warning" | "info"; t: string; r: string; a: string }[] = [];
  const lower = body.toLowerCase();
  if (/<form/i.test(body) && /action\s*=\s*["']?https?:\/\//i.test(body))
    s.push({ sev: "destructive", t: "Form submits data to external URL", r: "Email contains a form that posts to an external server.", a: "Verify form action URL before any interaction." });
  if (iocs.urls.length > 1 && /https?:\/\/[^\s]+/i.test(body) && /<a\s/i.test(body))
    s.push({ sev: "warning", t: "Multiple embedded links in body", r: "Body contains multiple hyperlinks with potential mismatched display text.", a: "Inspect each link's href vs visible text." });
  if (/click here|download now|login|sign in|update (your )?(account|billing|payment)|confirm/i.test(lower))
    s.push({ sev: "warning", t: "Call-to-action language in body", r: "Body contains action-oriented phrases common in phishing lures.", a: "Cross-reference with known legitimate communications." });
  if (/\$\d[\d,]*\.?\d*|payment|invoice|wire|transfer|bank|reimbursement/i.test(lower))
    s.push({ sev: "info", t: "Financial language detected", r: "Body references payments, invoices, or wire transfers.", a: "Confirm with sender via out-of-band channel." });
  return s;
}

export function buildFromApi(apiResult: Record<string, any> | null, input: string, committed: boolean) {
  if (!apiResult || !committed) return null;
  const body = extractBody(input);
  const headers = extractHeaders(input);
  const bodyLower = body.toLowerCase();
  const subject = (input.match(/Subject:\s*(.+)/i)?.[1] ?? "").toLowerCase();
  const brandMatch = BRAND_KEYWORDS.find(b => bodyLower.includes(b) || subject.includes(b));

  const ha = apiResult.header_analysis || {};
  const bs = apiResult.body_signals || {};
  const auth = ha.authentication || {};
  const hdrs = ha.headers || {};
  const doms = ha.domains || {};

  const spf: AuthState = auth.spf === "pass" ? "pass" : auth.spf === "softfail" ? "softfail" : auth.spf === "fail" || auth.spf === "not_found" ? "fail" : "none";
  const dkim: AuthState = auth.dkim === "pass" ? "pass" : auth.dkim === "softfail" ? "softfail" : auth.dkim === "fail" || auth.dkim === "not_found" ? "fail" : "none";
  const dmarc: AuthState = auth.dmarc === "pass" ? "pass" : auth.dmarc === "softfail" ? "softfail" : auth.dmarc === "fail" || auth.dmarc === "not_found" ? "fail" : "none";

  const combined = apiResult.combined_findings || [];
  const findings = combined.map((f: any) => ({
    sev: f.severity === "high" ? "destructive" as const : f.severity === "medium" ? "warning" as const : "info" as const,
    t: f.title,
    r: f.description || f.detail,
    a: f.recommendation || f.action,
  }));

  const destructiveCount = findings.filter((f: any) => f.sev === "destructive").length;
  const warningCount = findings.filter((f: any) => f.sev === "warning").length;
  const hasCriticalAuth = spf === "fail" && dmarc === "fail";
  const verdict = destructiveCount > 0 || hasCriticalAuth ? "Likely Phishing" : warningCount > 0 ? "Suspicious" : "Inconclusive";
  const tone = destructiveCount > 0 || hasCriticalAuth ? "destructive" as const : warningCount > 0 ? "warning" as const : "success" as const;

  const fromLine = hdrs.from || (input.match(/From:\s*(.+)/i)?.[1] ?? "").trim();
  const replyLine = hdrs.reply_to || (input.match(/Reply-To:\s*(.+)/i)?.[1] ?? "").trim();
  const pathLine = hdrs.return_path || (input.match(/Return-Path:\s*(.+)/i)?.[1] ?? "").trim();

  const iocs = apiResult.iocs || {};
  const urlAnalysis = (iocs.urls || []).map((u: string) => {
    const badges: { label: string; tone: "warning" | "destructive" | "info" | "success" }[] = [];
    try {
      const parsed = new URL(refang(u));
      const host = parsed.hostname;
      const tld = host.split(".").pop()?.toLowerCase();
      if (tld && SUSPICIOUS_TLDS.has(tld)) badges.push({ label: "suspicious TLD", tone: "warning" });
      if (SHORTENERS.has(host.replace(/^www\./, ""))) badges.push({ label: "shortener", tone: "warning" });
      if (parsed.username || parsed.password) badges.push({ label: "embedded creds", tone: "destructive" });
      badges.push(...urlTrustBadges(parsed));
    } catch {}
    return { value: u, suspicious: badges.length > 0, badges };
  });

  const hasAttachment = detectAttachments(input);
  const envelopeFlags = detectLookalike(fromLine, replyLine, pathLine);

  const mitre: { id: string; name: string; source: string }[] = [];
  const mitreSeen = new Set<string>();
  for (const f of combined) {
    const mid = f.mitre_id;
    if (mid && !mitreSeen.has(mid)) {
      mitreSeen.add(mid);
      mitre.push({ id: mid, name: f.mitre_name || mid, source: f.source || "analysis" });
    }
  }

  return {
    spf, dkim, dmarc,
    replyMismatch: !!(doms.from_domain && doms.reply_to_domain && doms.from_domain !== doms.reply_to_domain),
    defangedUrl: /hxxps?:\/\/|\[\.\]/i.test(input),
    urgency: /urgent|immediately|within \d+h|suspend|today|asap|before my flight/i.test(input),
    findings, verdict, tone,
    breakdown: [],
    body, headers,
    hasForm: (bs.forms_detected || []).length > 0 || /<form/i.test(body),
    hasPasswordField: (bs.forms_detected || []).some((f: string) => /password/i.test(f)) || /<input.*type=["']?password["' ]/i.test(body),
    hasHtmlForm: bs.has_html || /<form\s/i.test(body),
    hasAttachment, envelopeFlags,
    authResults: parseAuthResults(input),
    attachmentFiles: extractAttachmentFilenames(input),
    hasLookalike: envelopeFlags.length > 0,
    iocs: {
      urls: iocs.urls || [],
      domains: iocs.domains || [],
      ips: iocs.ipv4 || [],
      hashes: [...(iocs.hashes?.md5 || []), ...(iocs.hashes?.sha256 || [])],
      emails: iocs.emails || [],
      cve: iocs.cves || [],
      attack: [],
    },
    secrets: scanSecrets(body || input),
    urlAnalysis,
    mitre,
    fromDomain: doms.from_domain,
    fromLine, replyLine, pathLine,
    brandMatch,
    brandClaims: computeBrandClaims(doms.from_domain, fromLine, body, subject),
  };
}
