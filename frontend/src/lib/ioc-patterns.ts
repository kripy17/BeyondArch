export const SECRET_RX: { type: string; re: RegExp }[] = [
  { type: "AWS Access Key", re: /AKIA[0-9A-Z]{16}\b/g },
  { type: "GitHub Token", re: /(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}\b|github_pat_[a-zA-Z0-9_]{22,}\b/g },
  { type: "JWT Token", re: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g },
  { type: "Slack Token", re: /xox[baprs]-[a-zA-Z0-9-]{10,48}\b/g },
  { type: "Private Key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { type: "Discord Token", re: /[MN][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6,7}\.[a-zA-Z0-9_-]{27,}/g },
];

export const SUSPICIOUS_TLDS = new Set([
  "tk","ml","ga","cf","gq","xyz","top","download","review","work","date","men","loan","win","bid","cam",
  "click","quest","trade","webcam","science","party","gdn","racing","accountant","country","faith","online",
  "site","rest","cyou","bond","bar","club","kim","cfd","mom","link","tech","space","press","host","wiki",
  "ink","ru","cn",
]);

export const SHORTENERS = new Set([
  "bit.ly","tinyurl.com","ow.ly","is.gd","buff.ly","shorturl.at","cutt.ly","t.co","goo.gl","tiny.cc",
  "cli.gs","url.ie","rb.gy","short.link","shrten.com","v.gd","snipr.com","snipurl.com","surl.li",
  "lnkd.in","rebrandly","vur.me",
]);

/* Free-webmail providers. A personal display name (or executive title) sent
 * from one of these is the classic BEC tell — auth passes because the
 * mailbox is real, so the signal has to come from behaviour, not infra. */
export const FREE_WEBMAIL = new Set([
  "gmail.com","yahoo.com","ymail.com","outlook.com","hotmail.com","live.com","msn.com",
  "aol.com","icloud.com","me.com","proton.me","protonmail.com","gmx.com","gmx.net",
  "yandex.com","zoho.com","mail.com","tutanota.com","fastmail.com",
]);

/* Legitimate services routinely abused as phishing delivery infrastructure.
 * A lure riding one of these inherits the host's reputation, so flag the
 * pattern even though the domain itself is benign. Suffix match. */
export const ABUSED_HOSTS = [
  "docs.google.com","drive.google.com","sites.google.com","storage.googleapis.com",
  "firebaseapp.com","web.app","sharepoint.com","onedrive.live.com","onedrive.com",
  "dropbox.com","ngrok.io","ngrok-free.app","trycloudflare.com","vercel.app",
  "netlify.app","pages.dev","workers.dev","glitch.me","repl.co","replit.dev",
  "github.io","gitlab.io","s3.amazonaws.com","blob.core.windows.net",
];

/* Query parameters that forward the victim to an attacker-controlled target
 * (open-redirect pattern). The visible link looks benign; the destination
 * hides in the parameter value. */
export const REDIRECT_PARAMS = new Set([
  "url","redirect","redir","r","next","dest","destination","target","u",
  "continue","return","returnto","callback","goto","link",
]);

/* Email-auth parameter names (e.g. `smtp.mailfrom=evil.com` in
 * Authentication-Results / Received-SPF) match the domain pattern but are
 * header syntax, not observables. Never surface them as IOCs. */
const AUTH_PARAM_RX = /^(?:smtp\.(?:mailfrom|helo)|header\.(?:from|d|i|s)|envelope-from|body\.hash)$/i;

export function isAuthParamToken(value: string): boolean {
  return AUTH_PARAM_RX.test(value.trim());
}

export const LOLBINS = [
  "powershell","cmd.exe","wscript","cscript","mshta","regsvr32","rundll32","wmic","certutil","bitsadmin",
  "msiexec","scrcons","wshom.ocx","shell32",
];

export const DOWNLOAD_CRADLES = [
  "Invoke-WebRequest","iwr","wget","curl","Invoke-RestMethod","irm","Start-BitsTransfer",
  "bitsadmin /transfer","(new-object system.net.webclient).downloadstring",
  "(new-object system.net.webclient).downloadfile","System.Net.WebClient","XMLHttpRequest",
  "WinHttp.WinHttpRequest",
];

export const AMSI_BYPASS_PATTERNS = [
  "amsiutils","amsiinitfailed","system.management.automation.amsiutils","etw",
];

export interface Secret { type: string; value: string; }

export function refang(s: string): string {
  return s
    .replace(/\[\.\]/g, ".")
    .replace(/\(\.\)/g, ".")
    .replace(/\{\.\}/g, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[@\]/g, "@")
    .replace(/\bhxxp/gi, "http");
}

export function defang(s: string): string {
  const r = refang(s);
  return r
    .replace(/https:\/\//g, "hxxps[:]//")
    .replace(/http:\/\//g, "hxxp[:]//")
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");
}

export function entropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  return -Object.values(freq).reduce((sum, n) => { const p = n / s.length; return sum + p * Math.log2(p); }, 0);
}

export function domainEntropy(host: string): number {
  const labels = host.replace(/\./g, "");
  return Math.round(entropy(labels) * 100) / 100;
}

export function scanSecrets(t: string): Secret[] {
  const found: Secret[] = [];
  for (const { type, re } of SECRET_RX) {
    const matches = t.match(re);
    if (matches) {
      for (const m of new Set(matches)) {
        const masked = m.length > 12 ? m.slice(0, 6) + "*".repeat(m.length - 12) + m.slice(-6) : m;
        found.push({ type, value: masked });
      }
    }
  }
  return found;
}

export function uniq<T>(a: T[]): T[] {
  return Array.from(new Set(a));
}
