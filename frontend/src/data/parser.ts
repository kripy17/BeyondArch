import { LOLBINS, DOWNLOAD_CRADLES, AMSI_BYPASS_PATTERNS, type Secret } from "@/lib/ioc-patterns";
import { Link2, Globe, Network, Hash, AtSign, Bug, Crosshair, Terminal, Coins, Database, Server, Cloud, Key } from "lucide-react";
import type { Finding } from "@/types/objects";
import type { MitreMapping } from "@/lib/analysis";

export const IOC_KIND_MAP: Record<string, string> = {
  URL: "url", Domain: "domain", IPv4: "ip", Email: "email",
  MD5: "hash", SHA1: "hash", SHA256: "hash", CVE: "raw", ATTACK: "raw", MAC: "raw", Base64: "raw",
  Crypto: "raw", Registry: "raw", UNC: "raw", "AWS-ARN": "raw", JWT: "raw", Secret: "raw", CIDR: "ip",
};

export const SAMPLES: Record<string, { label: string; text: string }> = {
  ransom_note: {
    label: "Ransomware note",
    text: `--- !!! ALL YOUR FILES ARE ENCRYPTED !!! ---
Your network, workstations, and hypervisors have been locked with AES-256 and RSA-4096 algorithms.
All databases and file shares including \\\\fs01.corp.local\\finance and \\\\backup.corp.local\\vzdump are unreachable.

To recover your systems:
1. Pay 2.5 BTC to Bitcoin wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
   OR 45 XMR to Monero wallet: 44AFFq5AxYBfmGWymQAQ88f8a1vK81kEwQvT87sQ7C4YqQ7Zq8xR4Q4V9W9mZ9dY1x7y7x8w7v7u6t5s4r3q2p1
2. Contact recovery desk: decrypter-team@proton.me or support@onion-decrypt.su
3. Visit our Tor portal: hxxps[:]//lockbit-portal324.onion/login?token=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidmljdGltIn0.123456

Persistence Key injected: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost_updater
C2 beacon: 185.220.101.5 / 198.51.100.77
`,
  },
  cloud_trail: {
    label: "AWS CloudTrail excerpt",
    text: `{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAJQABLZS4A3QDU576Q",
    "arn": "arn:aws:iam::123456789012:user/compromised-analyst",
    "accountId": "123456789012",
    "accessKeyId": "AKIAIOSFODNN7EXAMPLE"
  },
  "eventTime": "2026-04-25T14:32:10Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "PutBucketPolicy",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "198.51.100.89",
  "userAgent": "aws-cli/2.15.15 Python/3.11.8 Linux/5.15.0",
  "requestParameters": {
    "bucketName": "corp-sensitive-exfil",
    "subnet": "10.100.0.0/16"
  }
}`,
  },
  phishing: { label: "Phishing email", text: "From: Security Team <security-alert@example-login.com>\nTo: user@example.org\nSubject: Password reset required\nAuthentication-Results: spf=fail dkim=fail dmarc=fail\nReply-To: Security Team <security-alert@example-login.com>\nReceived: from mail.example-login.com (203.0.113.44)\n\nPlease verify your account at hxxps[:]//login.example-login[.]com/reset?id=1234" },
  headers: { label: "Email headers only", text: "From: security@example.com\nTo: user@example.org\nSubject: Urgent password reset\nReturn-Path: bounce@example-login.com\nReply-To: support@example-login.com\nReceived-SPF: fail\nAuthentication-Results: spf=fail dkim=none dmarc=fail" },
  iocs: { label: "Mixed IOCs", text: "hxxps[:]//phish.example[.]com/login\nexample[.]net\n198[.]51[.]100[.]23\n44d88612fea8a8f36de82e1278abb02f\n275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\nCVE-2024-12345\nT1566.002\nanalyst@corp.local\nSK-ABC123DEF456GHIJ7890\nghp_abc123def456ghi789jkl012mno345pqr678st" },
  linux: { label: "Linux SSH auth", text: "Apr 25 10:10:10 arch sshd[123]: Failed password for invalid user admin from 8.8.8.8 port 4444 ssh2\nApr 25 10:11:44 arch sshd[124]: Accepted password for root from 1.1.1.1 port 55910 ssh2" },
  windows: { label: "Windows 4688", text: "Event ID: 4688\nProvider: Microsoft-Windows-Security-Auditing\nNew Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nCommand Line: powershell.exe -NoP -EncodedCommand SQBFAFgA\nAccount Name: krish" },
  suricata: { label: "Suricata EVE", text: '{"timestamp":"2026-04-25T10:12:00Z","event_type":"alert","src_ip":"198.51.100.23","dest_ip":"10.0.0.5","alert":{"signature":"ET WEB_SERVER Possible SQL Injection","severity":2}}' },
  access: { label: "Web log SQLi", text: '198.51.100.23 - - [25/Apr/2026:10:12:00 +0530] "GET /../../etc/passwd HTTP/1.1" 404 123 "-" "sqlmap/1.7"' },
  powershell: { label: "PowerShell encoded", text: "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA" },
  secrets: { label: "Code w/ secrets", text: 'const apiKey = "AIzaSyD-example";\nGITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' },
  sigma: { label: "Sigma rule", text: "title: Suspicious PowerShell Encoded Command\nid: 6f1f0c20-1111-4444-8888-123456789abc\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: '-EncodedCommand'\n  condition: selection\ntags:\n  - attack.t1059.001" },
  notes: { label: "Analyst notes", text: "10:04 - User reported suspicious password reset email.\n10:08 - Extracted URL hxxps[:]//login.example[.]com/reset\nFinding: Sender domain does not match expected organization.\nNext step: collect headers and draft user-facing summary." },
  email_headers: { label: "Sample email headers", text: "From: \"Security Team\" <security@company.com>\nTo: user@example.org\nSubject: Urgent: Action required on your account\nDate: Mon, 15 Jun 2026 09:23:45 +0000\nReturn-Path: bounce@phish-target.tk\nReply-To: security-verify@phish-target.tk\nReceived: from mx.phish-target.tk (203.0.113.50) by mx.company.com with ESMTPS id ABC123\nReceived-SPF: fail (domain of phish-target.tk does not designate 203.0.113.50 as permitted sender)\nAuthentication-Results: mx.company.com; spf=fail smtp.mailfrom=phish-target.tk; dkim=none; dmarc=fail\nDKIM-Signature: v=1; a=rsa-sha256; d=phish-target.tk; s=selector1;\n bh=2bd0e4a8c9f1b3d5e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9;\nX-Priority: 1 (Highest)\nMIME-Version: 1.0\nContent-Type: text/plain; charset=\"UTF-8\"\n\nDear User,\n\nWe detected suspicious activity on your account. Please verify your identity immediately by clicking the link below:\n\nhttps://login-company.secure-phish.tk/verify?token=abc123def456\n\nFailure to verify within 24 hours will result in account suspension.\n\nThank you,\nSecurity Team" },
  ioc_list: { label: "Sample IOC list", text: "45.33.32.156\n185.94.188.22\n91.121.87.34\n198.51.100.23\n203.0.113.44\n51.15.0.100\nhxxps[:]//evil[.]com/setup.exe\nhxxps[:]//phish-login[.]tk/verify\nhttp://185[.]220[.]101[.]161/payload.ps1\nhxxp://malware[.]download/payload\nexample[.]net\nmalicious[.]com\nphish-target[.]tk\nevil-host[.]ru\n7e0eaa6c2a2c7a0d5c4a3d8e9f0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a\na1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\n44d88612fea8a8f36de82e1278abb02f\nCVE-2024-1234\nCVE-2025-5678\nT1566.002\nT1059.001\nT1204\nphish@evil-host[.]ru\nadmin@malicious[.]com" },
  sysmon: {
    label: "Sysmon EVTX (XML)",
    text: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
<EventID>1</EventID>
<Version>5</Version>
<Level>4</Level>
<Task>1</Task>
<Opcode>0</Opcode>
<Keywords>0x8000000000000000</Keywords>
<TimeCreated SystemTime="2025-06-15T10:30:00.123456Z"/>
<EventRecordID>12345</EventRecordID>
<Computer>DC01.corp.local</Computer>
</System>
<EventData>
<Data Name="UtcTime">2025-06-15 10:30:00.123</Data>
<Data Name="ProcessGuid">{A123-B456-C789-D012}</Data>
<Data Name="ProcessId">4523</Data>
<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name="CommandLine">powershell.exe -nop -w hidden -enc SQBFAFgA</Data>
<Data Name="CurrentDirectory">C:\\Users\\analyst\\</Data>
<Data Name="User">CORP\\analyst</Data>
<Data Name="LogonGuid">{E456-F789-A012-B345}</Data>
<Data Name="LogonId">0x3E7</Data>
<Data Name="TerminalSessionId">1</Data>
<Data Name="IntegrityLevel">High</Data>
<Data Name="Hashes">MD5=44d88612fea8a8f36de82e1278abb02f,SHA256=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2</Data>
<Data Name="ParentProcessGuid">{B789-C012-D345-E678}</Data>
<Data Name="ParentProcessId">1234</Data>
<Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>
<Data Name="ParentCommandLine">cmd.exe /c start powershell</Data>
<Data Name="ParentUser">CORP\\analyst</Data>
</EventData>
</Event>`,
  },
  zeek: {
    label: "Zeek conn.log",
    text: `#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2026-04-25-10-12-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	string	port	string	port	port_specific	service	duration	count	port	enum	count	count	count	count	count	count	addr
1501501007.123456	CiFdP63fiUqBpbDZll	10.2.3.4	2273	185.94.188.22	443	tcp	ssl	73.871	4165	4791	SF	0	30	6011	27	5377	-
1501501015.902113	CHhAvVWN1dTqn45ik	192.168.10.53	51034	195.54.175.121	8888	tcp	-	0.205	3890	6592	SF	0	14	5026	17	7189	-
1501501022.330123	C2E1j9tG44Flnm4sha	192.168.10.9	49502	85.209.159.98	80	tcp	http	6.118	412	2048	RSTR	0	8	606	6	2667	-
1501501027.884210	CLJtMq2hK7Q1Tb3mzr	10.2.3.4	44321	45.155.205.233	8080	tcp	-	0.000	0	0	S0	0	1	40	0	0	-
1501501031.445120	CmZzVt3zhdRxK8kqne	10.2.3.4	44322	45.155.205.233	8443	tcp	-	0.000	0	0	REJ	0	2	80	1	40	-`,
  },
  nginx: {
    label: "Nginx access log",
    text: '198.51.100.23 - - [25/Apr/2026:10:12:00 +0000] "GET /wp-login.php HTTP/2.0" 401 512 "-" "curl/7.88.1"\n91.121.87.34 - - [25/Apr/2026:10:13:22 +0000] "POST /wp-json/custom/v1/order HTTP/1.1" 200 1243 "https://site.example" "Mozilla/5.0 (compatible; YandexBot/3.0)"\n198.51.100.23 - - [25/Apr/2026:10:14:05 +0000] "GET /../../etc/passwd HTTP/2.0" 404 153 "-" "curl/7.88.1"\n198.51.100.23 - - [25/Apr/2026:10:14:06 +0000] "GET /.env HTTP/2.0" 404 153 "-" "curl/7.88.1"\n198.51.100.23 - - [25/Apr/2026:10:14:07 +0000] "GET /actuator/env HTTP/2.0" 404 153 "-" "curl/7.88.1"',
  },
  csv: {
    label: "CSV IOC sheet",
    text: 'type,value,source,note\nipv4,198.51.100.23,alerts.csv,"scan source"\nipv4,203.0.113.44,alerts.csv,phish rbl\ndomain,evil-example[.]com,threatintel,targeted\nsha256,a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2,vxhub,stealer',
  },
};

export const RX = {
  URL:    /\b(?:hxxps?|https?):\/\/[^\s)>"']+/gi,
  Domain: /\b(?:[a-z0-9-]+\[?\.\]?){1,5}[a-z]{2,}\b/gi,
  IPv4:   /\b(?:\d{1,3}\[?\.\]?){3}\d{1,3}\b/g,
  MD5:    /\b[a-f0-9]{32}\b/gi,
  SHA256: /\b[a-f0-9]{64}\b/gi,
  Email:  /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi,
  CVE:    /CVE-\d{4}-\d{4,}/gi,
  ATTACK: /\bT\d{4}(?:\.\d{3})?\b/g,
};

export const RX_MAC = /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g;
export const RX_B64 = /\b(?:[A-Za-z0-9+/]{40,}(?:==|=)?)\b/g;

export type DetectConfidence = "high" | "medium" | "low";

/** Format detection with honest confidence: each family lists the anchors it
 *  matched; ≥2 anchors = high, one strong anchor = medium, one weak = low.
 *  evidence[] is shown in the UI so the analyst can verify the call. */
export function autoDetectInputType(text: string): { label: string; tone: "primary" | "success" | "warning" | "info" | "default"; level: DetectConfidence; evidence: string[] } | null {
  const t = text.trim();
  if (!t) return null;
  const single = t.split("\n").length === 1;
  if (/@/.test(t) && /\./.test(t) && (/From:|To:|Subject:/i.test(t) || /@[a-z0-9.-]+\.[a-z]{2,}/i.test(t))) {
    const ev = [/From:|To:|Subject:/i.test(t) ? "RFC-5322 header lines" : null, /@[a-z0-9.-]+\.[a-z]{2,}/i.test(t) ? "email addresses" : null].filter(Boolean) as string[];
    return { label: "Phishing email", tone: "warning", level: ev.length >= 2 ? "high" : "medium", evidence: ev };
  }
  if (!single && /^Begin/i.test(t)) return { label: "Email / EML", tone: "primary", level: "medium", evidence: ["PGP BEGIN block"] };
  if (/MIME-Version:/i.test(t)) return { label: "Email / EML", tone: "primary", level: "high", evidence: ["MIME-Version header"] };
  if (!single && /:\/\//.test(t)) return { label: "URL", tone: "info", level: "medium", evidence: ["URL scheme"] };
  if (/^GET |^POST |HTTP\/2\.\d/i.test(t) && /\[\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} \+0000\]/.test(t))
    return { label: "Nginx access log", tone: "primary", level: "high", evidence: ["HTTP verb", "common-log timestamp"] };
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(t)) return { label: "IP address", tone: "info", level: "high", evidence: ["bare IPv4"] };
  if (/#fields\s|^#separator/im.test(t)) return { label: "Zeek log", tone: "primary", level: "high", evidence: ["#fields/#separator directive"] };
  if (/^\{\s*"timestamp"/.test(t.trim()) || /"event_type"\s*:/.test(t))
    return { label: "JSON log (EVE-like)", tone: "primary", level: "medium", evidence: ["JSON object per line"] };
  if (/CEF:\d/.test(t)) return { label: "CEF log", tone: "primary", level: "high", evidence: ["CEF header version"] };
  if (/^\w{3}\s+\d{1,2}\s[\d:]{8}\s\S+\s[\w-]+(\[\d+\])?:/m.test(t))
    return { label: "Syslog", tone: "primary", level: "medium", evidence: ["syslog timestamp + host prefix"] };
  if (/\[\d|sshd|systemd|sudo:/i.test(t))
    return { label: "Log file", tone: "primary", level: "low", evidence: ["bracketed pid or daemon name"] };
  if (/^\s*type,\s*value,\s*source/i.test(t) && /ipv4|sha256|domain/i.test(t))
    return { label: "CSV IOC sheet", tone: "warning", level: "high", evidence: ["header row", "indicator keywords"] };
  const lines = t.split("\n");
  const hashHits = (t.match(/\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi) ?? []).length;
  if (lines.length > 1 && hashHits > 0)
    return { label: "IOC list", tone: "warning", level: hashHits >= 3 ? "high" : "medium", evidence: [`${hashHits} hash literal(s)`] };
  return null;
}

export const KIND_META: Record<string, { icon: any; tone: "default" | "primary" | "warning" | "destructive"; pivot?: string }> = {
  URL:       { icon: Link2,     tone: "warning",     pivot: "/url" },
  Domain:    { icon: Globe,     tone: "default",     pivot: "/intel" },
  IPv4:      { icon: Network,   tone: "default",     pivot: "/intel" },
  CIDR:      { icon: Network,   tone: "default",     pivot: "/intel" },
  MD5:       { icon: Hash,      tone: "primary",     pivot: "/attachment" },
  SHA1:      { icon: Hash,      tone: "primary",     pivot: "/attachment" },
  SHA256:    { icon: Hash,      tone: "primary",     pivot: "/attachment" },
  Email:     { icon: AtSign,    tone: "default",     pivot: "/phishing" },
  CVE:       { icon: Bug,       tone: "destructive" },
  ATTACK:    { icon: Crosshair, tone: "destructive", pivot: "/mitre" },
  Crypto:    { icon: Coins,     tone: "destructive", pivot: "/intel" },
  Registry:  { icon: Database,  tone: "warning" },
  UNC:       { icon: Server,    tone: "warning" },
  "AWS-ARN": { icon: Cloud,     tone: "primary" },
  JWT:       { icon: Key,       tone: "destructive" },
  Secret:    { icon: Key,       tone: "destructive" },
  MAC:       { icon: Hash,      tone: "default",     pivot: "/logs" },
  Base64:    { icon: Terminal,  tone: "warning",     pivot: "/parser" },
};

export interface CmdFinding { type: string; detail: string; }

export function scanCmdLines(t: string): CmdFinding[] {
  const f: CmdFinding[] = [];
  const tLower = t.toLowerCase();
  for (const bin of LOLBINS) if (tLower.includes(bin)) { f.push({ type: "lolbin", detail: bin }); break; }
  if (DOWNLOAD_CRADLES.some((c) => tLower.includes(c))) f.push({ type: "download", detail: "Download cradle" });
  if (/-EncodedCommand\b/i.test(t)) f.push({ type: "encoded", detail: "Encoded PowerShell" });
  if (AMSI_BYPASS_PATTERNS.some((p) => tLower.includes(p))) f.push({ type: "amsi", detail: "AMSI bypass" });
  if (/-WindowStyle\s+(Hidden|Minimized)/i.test(t)) f.push({ type: "hidden", detail: "Hidden window" });
  return f;
}

export function genMarkdownExport(input: string, iocs: Record<string, string[]>, findings: Finding[], total: number, family: string, primary: string, secrets: Secret[], cmds: CmdFinding[], mitre: MitreMapping[]): string {
  const lines = [
    `# Smart Parser Report — ${primary}`,
    `**Family:** ${family}  **IOCs:** ${total}`,
    "",
    "## Indicators",
    ...Object.entries(iocs).filter(([, v]) => v.length).flatMap(([k, v]) => [`### ${k} (${v.length})`, ...v.map((i) => `- \`${i}\``), ""]),
  ];
  if (findings.length) {
    lines.push("## Findings");
    for (const f of findings) lines.push(`- [${f.severity.toUpperCase()}] ${f.title} — ${f.detail}${f.technique ? ` [${f.technique}]` : ""}${f.confidence?.level && f.confidence.level !== "unknown" ? ` (confidence: ${f.confidence.level})` : ""}`);
    lines.push("");
  }
  if (secrets.length) {
    lines.push("## Secrets", ...secrets.map((s) => `- ${s.type}: \`${s.value}\``), "");
  }
  if (mitre.length) {
    lines.push("## MITRE ATT&CK", ...mitre.map((m) => `- ${m.technique}: ${m.name} (${m.tactic})`), "");
  }
  return lines.join("\n");
}

export function genJsonExport(input: string, iocs: Record<string, string[]>, findings: Finding[], total: number, family: string, primary: string, secrets: Secret[], cmds: CmdFinding[], mitre: MitreMapping[]): string {
  const data = {
    version: "1.0",
    generated: new Date().toISOString(),
    classification: { family, primary },
    indicators: iocs,
    findings: findings.map(f => ({ severity: f.severity, title: f.title, detail: f.detail, technique: f.technique, confidence: f.confidence?.level })),
    secrets: secrets.map(s => ({ type: s.type, value: s.value })),
    commandAnalysis: cmds.map(c => ({ type: c.type, detail: c.detail })),
    mitre: mitre.map(m => ({ technique: m.technique, name: m.name, tactic: m.tactic, confidence: m.confidence?.level })),
    stats: { total, lines: input.split("\n").length },
  };
  return JSON.stringify(data, null, 2);
}

export const OSINT_TOOLS_PER_KIND: Record<string, { label: string; url: (v: string) => string }[]> = {
  URL: [
    { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` },
    { label: "urlscan.io", url: (v) => `https://urlscan.io/search/#${encodeURIComponent(v)}` },
  ],
  Domain: [
    { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/domain/${encodeURIComponent(v)}` },
    { label: "crt.sh", url: (v) => `https://crt.sh/?q=${encodeURIComponent(v)}` },
    { label: "Shodan", url: (v) => `https://www.shodan.io/search?query=${encodeURIComponent(v)}` },
    { label: "SecurityTrails", url: (v) => `https://securitytrails.com/list/apex_domain/${encodeURIComponent(v)}` },
    { label: "ViewDNS", url: (v) => `https://viewdns.info/reverseip/?host=${encodeURIComponent(v)}` },
    { label: "DNSDumpster", url: (v) => `https://dnsdumpster.com/domain/${encodeURIComponent(v)}` },
    { label: "BuiltWith", url: (v) => `https://builtwith.com/${encodeURIComponent(v)}` },
    { label: "WhoisXML", url: (v) => `https://whois.whoisxmlapi.com/lookup?domain=${encodeURIComponent(v)}` },
    { label: "Pulsedive", url: (v) => `https://pulsedive.com/indicator/?query=${encodeURIComponent(v)}` },
    { label: "Talos", url: (v) => `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(v)}` },
    { label: "Wayback", url: (v) => `https://web.archive.org/web/*/${encodeURIComponent(v)}` },
  ],
  IPv4: [
    { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(v)}` },
    { label: "AbuseIPDB", url: (v) => `https://www.abuseipdb.com/check/${encodeURIComponent(v)}` },
    { label: "Shodan", url: (v) => `https://www.shodan.io/host/${encodeURIComponent(v)}` },
    { label: "GreyNoise", url: (v) => `https://viz.greynoise.io/ip/${encodeURIComponent(v)}` },
    { label: "Censys", url: (v) => `https://search.censys.io/search?q=${encodeURIComponent(v)}` },
    { label: "LeakIX", url: (v) => `https://leakix.net/search?q=${encodeURIComponent(v)}` },
  ],
  CIDR: [
    { label: "BGPView", url: (v) => `https://bgpview.io/prefix/${encodeURIComponent(v)}` },
    { label: "Shodan", url: (v) => `https://www.shodan.io/search?query=net:${encodeURIComponent(v)}` },
  ],
  MD5: [
    { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` },
    { label: "AlienVault OTX", url: (v) => `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(v)}` },
  ],
  SHA1: [
    { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` },
    { label: "AlienVault OTX", url: (v) => `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(v)}` },
  ],
  SHA256: [
    { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` },
    { label: "AlienVault OTX", url: (v) => `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(v)}` },
  ],
  Email: [
    { label: "Have I Been Pwned", url: (v) => `https://haveibeenpwned.com/account/${encodeURIComponent(v)}` },
    { label: "DeHashed", url: (v) => `https://dehashed.com/search?query=${encodeURIComponent(v)}` },
    { label: "Hunter.io", url: (v) => `https://hunter.io/search/${encodeURIComponent(v)}` },
  ],
  Crypto: [
    { label: "Mempool", url: (v) => `https://mempool.space/address/${encodeURIComponent(v)}` },
    { label: "Blockstream", url: (v) => `https://blockstream.info/address/${encodeURIComponent(v)}` },
    { label: "Etherscan", url: (v) => `https://etherscan.io/address/${encodeURIComponent(v)}` },
  ],
  CVE: [
    { label: "NVD NIST", url: (v) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v)}` },
    { label: "MITRE CVE", url: (v) => `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${encodeURIComponent(v)}` },
  ],
};
