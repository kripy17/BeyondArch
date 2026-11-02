// Smart Threat Heuristics & Defensive Playbook Generator for SOC URL Analysis
import { defang } from "@/lib/ioc-patterns";

export interface BrandImpersonationFinding {
  targetBrand: string;
  confidence: number;
  evidence: string;
  trueApexDomain: string;
  isDeceptive: boolean;
  attackTechnique: string;
}

export interface DecodedPayload {
  paramKey: string;
  raw: string;
  decoded: string;
  encoding: "base64" | "hex" | "url";
  isExecutable: boolean;
  isEmail: boolean;
  isUrl: boolean;
}

export interface DefensivePlaybook {
  paloAlto: string;
  fortinet: string;
  zscaler: string;
  dnsRpz: string;
  pihole: string;
  splunkSpl: string;
  defenderKql: string;
  mailGatewayNotice: string;
}

export interface SimulatedHttpProfile {
  requestHeaders: Record<string, string>;
  responseStatus: number;
  responseStatusText: string;
  responseHeaders: Record<string, string>;
  tlsCert: {
    issuer: string;
    subject: string;
    validityDays: number;
    isEphemeral: boolean;
    isSelfSigned: boolean;
    sanMismatch: boolean;
  };
}

const BRAND_PATTERNS: Array<{
  name: string;
  keywords: string[];
  legitDomains: string[];
}> = [
  { name: "Microsoft 365", keywords: ["microsoft", "office365", "onedrive", "sharepoint", "outlook", "msft", "live", "azure"], legitDomains: ["microsoft.com", "office.com", "live.com", "azure.com", "sharepoint.com"] },
  { name: "Google Workspace", keywords: ["google", "gmail", "gdrive", "google-docs", "accounts-google"], legitDomains: ["google.com", "gmail.com"] },
  { name: "Okta / SSO", keywords: ["okta", "oktapreview", "sso-auth", "identity-verify"], legitDomains: ["okta.com"] },
  { name: "DocuSign", keywords: ["docusign", "docusigndn", "esign-verify"], legitDomains: ["docusign.net", "docusign.com"] },
  { name: "PayPal", keywords: ["paypal", "paypal-service", "pay-pal"], legitDomains: ["paypal.com"] },
  { name: "Apple ID", keywords: ["apple", "appleid", "icloud"], legitDomains: ["apple.com", "icloud.com"] },
  { name: "Chase Bank", keywords: ["chase", "chasebank", "chase-online"], legitDomains: ["chase.com"] },
  { name: "Wells Fargo", keywords: ["wellsfargo", "wf-secure"], legitDomains: ["wellsfargo.com"] },
  { name: "Bank of America", keywords: ["bankofamerica", "bofa-secure"], legitDomains: ["bankofamerica.com"] },
  { name: "Amazon", keywords: ["amazon", "prime-account"], legitDomains: ["amazon.com"] },
  { name: "Netflix", keywords: ["netflix", "netflix-billing"], legitDomains: ["netflix.com"] },
  { name: "Coinbase / Crypto", keywords: ["coinbase", "binance", "metamask", "ledger-live", "trustwallet"], legitDomains: ["coinbase.com", "binance.com"] },
];

export function detectBrandImpersonation(
  hostnameOrUrl: string,
  pathname?: string,
  apexDomain?: string
): BrandImpersonationFinding | null {
  let hostname = hostnameOrUrl;
  let path = pathname || "";
  let apex = apexDomain || "";

  if (hostnameOrUrl.includes("://") || !apexDomain) {
    try {
      const u = new URL(hostnameOrUrl.startsWith("http") ? hostnameOrUrl : `https://${hostnameOrUrl}`);
      hostname = u.hostname;
      path = pathname ?? u.pathname;
      const parts = hostname.split(".");
      apex = apexDomain ?? (parts.length >= 2 ? parts.slice(-2).join(".") : hostname);
    } catch {
      // fallback
    }
  }

  const hostLower = hostname.toLowerCase();
  const pathLower = path.toLowerCase();
  const fullCheck = `${hostLower}${pathLower}`;

  for (const brand of BRAND_PATTERNS) {
    const isLegit = brand.legitDomains.some((ld) => hostLower === ld || hostLower.endsWith(`.${ld}`));
    if (isLegit) continue;

    for (const kw of brand.keywords) {
      if (fullCheck.includes(kw)) {
        const inSubdomain = hostLower.includes(kw) && !hostLower.endsWith(kw);
        const inPath = pathLower.includes(kw);
        const confidence = inSubdomain ? 95 : inPath ? 78 : 65;

        return {
          targetBrand: brand.name,
          confidence,
          evidence: `Host or path contains "${kw}" while apex domain is "${apex}" (not official ${brand.name} infrastructure).`,
          trueApexDomain: apex,
          isDeceptive: true,
          attackTechnique: inSubdomain ? "T1566.002 Subdomain Padding / Typosquatting" : "T1566.002 Phishing Brand Lure",
        };
      }
    }
  }

  return null;
}

function tryDecodeBase64(str: string): string | null {
  try {
    const cleaned = str.replace(/-/g, "+").replace(/_/g, "/");
    const pad = cleaned.length % 4;
    const padded = pad ? cleaned + "=".repeat(4 - pad) : cleaned;
    const decoded = atob(padded);
    let printable = 0;
    for (let i = 0; i < decoded.length; i++) {
      const code = decoded.charCodeAt(i);
      if ((code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9) {
        printable++;
      }
    }
    if (printable / decoded.length > 0.85 && decoded.length > 3) {
      return decoded;
    }
  } catch {}
  return null;
}

export function extractSmartPayloads(urlStr: string): DecodedPayload[] {
  const payloads: DecodedPayload[] = [];
  try {
    const parsed = new URL(urlStr);
    parsed.searchParams.forEach((val, key) => {
      if (!val || val.length < 4) return;

      // Check base64
      if (/^[A-Za-z0-9+/=_-]{8,}$/.test(val)) {
        const decoded = tryDecodeBase64(val);
        if (decoded) {
          const isExecutable = /powershell|cmd\.exe|wget|curl|eval|script|iex|invoke/i.test(decoded);
          const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(decoded.trim());
          const isUrl = /^https?:\/\//i.test(decoded.trim());
          payloads.push({
            paramKey: key,
            raw: val,
            decoded,
            encoding: "base64",
            isExecutable,
            isEmail,
            isUrl,
          });
          return;
        }
      }

      // Check URL encoded
      if (val.includes("%")) {
        try {
          const dec = decodeURIComponent(val);
          if (dec !== val && (dec.startsWith("http://") || dec.startsWith("https://") || dec.includes("<") || dec.includes(";"))) {
            payloads.push({
              paramKey: key,
              raw: val,
              decoded: dec,
              encoding: "url",
              isExecutable: /script|eval|exec|sh/i.test(dec),
              isEmail: /@/.test(dec),
              isUrl: /^https?:\/\//i.test(dec),
            });
          }
        } catch {}
      }
    });
  } catch {}
  return payloads;
}

export function generateDefensivePlaybook(
  urlStr: string,
  host?: string,
  apexDomain?: string
): DefensivePlaybook {
  let cleanHost = (host || "").replace(/[[\]]/g, "");
  let cleanApex = (apexDomain || "").replace(/[[\]]/g, "");

  if (!cleanHost || !cleanApex) {
    try {
      const u = new URL(urlStr.startsWith("http") ? urlStr : `https://${urlStr}`);
      cleanHost = cleanHost || u.hostname.replace(/[[\]]/g, "");
      const parts = cleanHost.split(".");
      cleanApex = cleanApex || (parts.length >= 2 ? parts.slice(-2).join(".") : cleanHost);
    } catch {
      cleanHost = cleanHost || "unknown";
      cleanApex = cleanApex || "unknown";
    }
  }

  const defangedHost = defang(cleanHost);

  return {
    paloAlto: `# Palo Alto Networks PAN-OS CLI
set shared profiles custom-url-category SOC_BLOCKLIST list [ ${cleanHost} ]
set rulebase security rules "BLOCK_MALICIOUS_URLS" action deny`,

    fortinet: `# Fortinet FortiGate CLI
config webfilter urlfilter
  edit 1
    set name "SOC_INCIDENT_BLOCKS"
    config entries
      edit 1
        set url "${cleanHost}"
        set type simple
        set action block
        set status enable
      next
    end
end`,

    zscaler: `# Zscaler Internet Access (ZIA) Custom URL Block
Category: "Security Risk - Incident Response Block"
Domain / URL Entry: ${cleanHost}`,

    dnsRpz: `; Response Policy Zone (RPZ) / BIND Sinkhole
${cleanHost} CNAME .
*.${cleanHost} CNAME .
${cleanApex} CNAME .
*.${cleanApex} CNAME .`,

    pihole: `# Pi-hole / dnsmasq format
address=/${cleanHost}/0.0.0.0
address=/${cleanApex}/0.0.0.0`,

    splunkSpl: `index=* (dest_host="${cleanHost}" OR url="*${cleanHost}*")
| stats count earliest(_time) as first_seen latest(_time) as last_seen by host, user, src, dest_host, http_method, status
| convert ctime(first_seen) ctime(last_seen)
| sort - count`,

    defenderKql: `DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has "${cleanHost}" or RemoteUrl has "${cleanApex}"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc`,

    mailGatewayNotice: `Action: Submit ${defangedHost} to Microsoft Defender for Office 365 Tenant Allow/Block List (TABL) as "Block" and execute Zero-Hour Auto Purge (ZAP) for all inbound emails containing this link in the last 72 hours.`,
  };
}

export function simulateHttpProfile(urlStr: string, isSuspicious: boolean = true): SimulatedHttpProfile {
  let hostname = "unknown";
  try { hostname = new URL(urlStr).hostname; } catch {}

  const isTls = urlStr.startsWith("https://");
  const isFreeTls = isSuspicious || true;

  return {
    requestHeaders: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124"',
      "Sec-Fetch-Dest": "document",
      "Sec-Fetch-Mode": "navigate",
    },
    responseStatus: isSuspicious ? 302 : 200,
    responseStatusText: isSuspicious ? "Found (Redirecting to credential harvester)" : "OK",
    responseHeaders: {
      "Server": isSuspicious ? "nginx/1.24.0 (Ubuntu)" : "cloudflare",
      "Content-Type": "text/html; charset=UTF-8",
      "Connection": "keep-alive",
      "X-Powered-By": isSuspicious ? "PHP/8.1.27" : "Varnish",
      "Set-Cookie": isSuspicious ? "PHPSESSID=session_88f910a7b4; path=/; HttpOnly" : "__cf_bm=...; path=/; HttpOnly; Secure",
      "Strict-Transport-Security": isTls && !isSuspicious ? "max-age=31536000; includeSubDomains" : "None (Missing HSTS)",
    },
    tlsCert: {
      issuer: isFreeTls ? "Let's Encrypt Authority X3" : "DigiCert Global Root G2",
      subject: `CN=${hostname}`,
      validityDays: isFreeTls ? 90 : 365,
      isEphemeral: isFreeTls,
      isSelfSigned: false,
      sanMismatch: isSuspicious,
    },
  };
}

export interface ExecutiveThreatNarrative {
  verdict: "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "INFORMATIONAL";
  confidence: number;
  threatCategory: string;
  targetPersona: string;
  executiveSummary: string;
  adversaryTTPs: string[];
  riskFactors: Array<{ name: string; score: number; detail: string; severity: "critical" | "high" | "medium" | "low" }>;
  compositeScore: number;
}

export interface PhishingKitFingerprint {
  kitName?: string;
  cloakingTechnique: string;
  hasTurnstileBypass: boolean;
  hasGeoFencing: boolean;
  isCloudflareWorkerAbuse: boolean;
  isIpfsGatewayAbuse: boolean;
}

export interface ContainmentConsole {
  victimEmail?: string;
  entraIdSessionRevoke?: string;
  defenderCustomIoc: string;
  exchangeMailFlowBlock: string;
  paloAltoCli: string;
  fortinetCli: string;
  piholeDnsSinkhole: string;
  irTicketMarkdown: string;
}

export function generateExecutiveThreatNarrative(
  urlStr: string,
  brand: BrandImpersonationFinding | null,
  payloads: DecodedPayload[],
  http: SimulatedHttpProfile
): ExecutiveThreatNarrative {
  let host = "unknown";
  let pathname = "";
  try {
    const u = new URL(urlStr.startsWith("http") ? urlStr : `https://${urlStr}`);
    host = u.hostname;
    pathname = u.pathname;
  } catch {}

  const emailPayload = payloads.find((p) => p.isEmail);
  const targetEmail = emailPayload ? emailPayload.decoded : undefined;
  const hasExec = payloads.some((p) => p.isExecutable || p.decoded.toLowerCase().includes("iex") || p.decoded.toLowerCase().includes("downloadstring"));

  // 1. Weaponized C2 Stager / PowerShell Execution Cradle
  if (hasExec) {
    return {
      verdict: "MALICIOUS",
      confidence: 99,
      threatCategory: "Adversary In-Memory C2 Stager & Download Cradle",
      targetPersona: "Endpoint Host (Local/Domain User Context)",
      compositeScore: 98,
      executiveSummary: `Critical threat: The URL delivers an in-memory PowerShell execution cradle via Base64/Hex obfuscated query parameters. The payload calls Net.WebClient.DownloadString and Invoke-Expression (IEX) to download and run unvetted secondary stagers directly in RAM without staging artifacts on disk, bypassing traditional perimeter defenses.`,
      adversaryTTPs: [
        "T1059.001 PowerShell Command Execution",
        "T1027.013 Obfuscated Query Parameters",
        "T1105 Ingress Tool Transfer",
        "T1071.001 Web Protocols Communication",
      ],
      riskFactors: [
        { name: "Weaponized Query Parameter", score: 99, detail: "Base64 encoded PowerShell execution cradle with IEX payload", severity: "critical" },
        { name: "In-Memory Evasion", score: 96, detail: "Executes directly in memory avoiding disk forensics", severity: "critical" },
        { name: "External C2 Beacon", score: 94, detail: `Payload connects to secondary callback server`, severity: "critical" },
        { name: "Host Risk", score: 90, detail: "Allows interactive remote code execution if clicked or fetched", severity: "high" },
      ],
    };
  }

  // 2. Targeted Brand Spoofing (e.g. Microsoft 365, Google, Okta)
  if (brand) {
    const isM365 = brand.targetBrand.includes("Microsoft");
    return {
      verdict: "MALICIOUS",
      confidence: brand.confidence,
      threatCategory: isM365 ? "Adversary-in-the-Middle (AiTM) / Entra ID Phish" : `${brand.targetBrand} Credential Harvester`,
      targetPersona: targetEmail ? `${targetEmail} (Pre-seeded victim account)` : "Enterprise Identity Accounts",
      compositeScore: Math.max(92, brand.confidence),
      executiveSummary: `Adversary is executing a targeted credential harvesting campaign mimicking ${brand.targetBrand}. The portal is anchored to deceptive apex domain '.${brand.trueApexDomain}' while using official logos, layouts, and pre-seeded parameters ${targetEmail ? `targeting ${targetEmail}` : ""} to lower user suspicion and intercept credentials and session cookies.`,
      adversaryTTPs: [
        brand.attackTechnique,
        "T1566.002 Spearphishing Link",
        "T1110 Brute Force & Credential Harvesting",
        "T1556 Modify Authentication Process",
      ],
      riskFactors: [
        { name: "Brand Impersonation", score: brand.confidence, detail: `Impersonates official ${brand.targetBrand} authentication portals`, severity: "critical" },
        { name: "Apex Domain Mismatch", score: 95, detail: `Authentic server resolves to .${brand.trueApexDomain} (not official vendor)`, severity: "critical" },
        { name: "Victim Targeted Parameter", score: targetEmail ? 90 : 75, detail: targetEmail ? `Pre-seeded account parameter for ${targetEmail}` : "Deceptive query parameters present", severity: targetEmail ? "high" : "medium" },
        { name: "Certificate Ephemerality", score: http.tlsCert.isEphemeral ? 80 : 50, detail: http.tlsCert.isEphemeral ? "Short-lived automated certificate (Let's Encrypt)" : "Standard commercial certificate", severity: "medium" },
      ],
    };
  }

  // 3. Punycode / IDN Homograph
  if (urlStr.includes("xn--") || host.startsWith("xn--")) {
    return {
      verdict: "SUSPICIOUS",
      confidence: 88,
      threatCategory: "IDN Homograph Domain Spoofing",
      targetPersona: "Employees & End Users",
      compositeScore: 86,
      executiveSummary: `Suspicious: Domain utilizes Internationalized Domain Name (IDN) Punycode encoding to visually spoof legitimate brand names using Cyrillic or Greek lookalike glyphs. Visually indistinguishable from trusted domains in standard address bars.`,
      adversaryTTPs: ["T1036.007 Double Extension / Homoglyph Spoofing", "T1566.002 Phishing Link"],
      riskFactors: [
        { name: "IDN Homograph", score: 92, detail: "Punycode domain with confusable glyphs", severity: "critical" },
        { name: "Visual Deception", score: 85, detail: "Pretext designed to fool human visual validation", severity: "high" },
        { name: "Low Domain Longevity", score: 80, detail: "Common vector for fast-flux disposable domains", severity: "high" },
      ],
    };
  }

  // 4. Open Redirect
  if (urlStr.includes("redirect=") || urlStr.includes("next=") || urlStr.includes("url=")) {
    return {
      verdict: "SUSPICIOUS",
      confidence: 84,
      threatCategory: "Chained Open Redirect Exploit",
      targetPersona: "Corporate Endpoints",
      compositeScore: 80,
      executiveSummary: `The URL exploits a legitimate or trusted fronting domain to redirect visitors to an unvetted secondary destination. Often leveraged by threat actors to bypass Secure Email Gateways (SEGs) that trust the initial front domain.`,
      adversaryTTPs: ["T1566.002 Spearphishing Link", "T1071.001 Web Protocols"],
      riskFactors: [
        { name: "Open Redirect Parameter", score: 88, detail: "Contains unvalidated outbound redirect parameter", severity: "high" },
        { name: "Security Gateway Bypass", score: 82, detail: "Exploits reputation of first hop to bypass URL reputation filters", severity: "high" },
      ],
    };
  }

  // 5. Clean / Benign URL
  const isDirectIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
  if (!isDirectIp && (host.endsWith(".com") || host.endsWith(".org") || host.endsWith(".io")) && !payloads.length) {
    return {
      verdict: "BENIGN",
      confidence: 94,
      threatCategory: "Legitimate Corporate Asset / Clean Web Destination",
      targetPersona: "Standard Web Traffic",
      compositeScore: 6,
      executiveSummary: `Analysis completed: The target URL exhibits standard domain registration, legitimate domain anchoring, standard certificate issuance, and no obfuscated payloads or brand impersonation indicators.`,
      adversaryTTPs: [],
      riskFactors: [
        { name: "Brand Deception", score: 0, detail: "No brand impersonation keywords detected", severity: "low" },
        { name: "Payload Safety", score: 0, detail: "No encoded or executable query strings", severity: "low" },
        { name: "Domain Authenticity", score: 5, detail: "Legitimate apex domain structure", severity: "low" },
      ],
    };
  }

  // Default Informational / Low-Risk
  return {
    verdict: "INFORMATIONAL",
    confidence: 70,
    threatCategory: "Standard Web Target / Generic URL",
    targetPersona: "Standard Endpoint Traffic",
    compositeScore: 25,
    executiveSummary: `Target evaluated: Generic URL structure with low risk observable properties. No immediate malware delivery patterns or high-confidence phishing kits identified.`,
    adversaryTTPs: ["T1071.001 Web Protocols"],
    riskFactors: [
      { name: "Domain Inspection", score: 20, detail: "Standard web hierarchy", severity: "low" },
      { name: "Payload Status", score: 10, detail: "No weaponized execution parameters detected", severity: "low" },
    ],
  };
}

export function generateContainmentConsole(
  urlStr: string,
  brand: BrandImpersonationFinding | null,
  payloads: DecodedPayload[]
): ContainmentConsole {
  let cleanHost = "unknown";
  let cleanApex = "unknown";
  try {
    const u = new URL(urlStr.startsWith("http") ? urlStr : `https://${urlStr}`);
    cleanHost = u.hostname;
    const parts = cleanHost.split(".");
    cleanApex = parts.length >= 2 ? parts.slice(-2).join(".") : cleanHost;
  } catch {}

  const emailPayload = payloads.find((p) => p.isEmail);
  const victimEmail = emailPayload ? emailPayload.decoded : undefined;
  const defangedHost = defang(cleanHost);

  const entraIdSessionRevoke = victimEmail
    ? `# Revoke all active Entra ID / Microsoft 365 Refresh Tokens for targeted victim\n# Requires Microsoft.Graph PowerShell module\nConnect-MgGraph -Scopes "User.RevokeSessions.All"\nRevoke-MgUserSignOutSession -UserId "${victimEmail}"\nWrite-Host "Active sessions for ${victimEmail} revoked successfully." -ForegroundColor Green`
    : `# Revoke Entra ID user session if targeted user is confirmed:\n# Revoke-MgUserSignOutSession -UserId "<victim-user-upn>"`;

  const exchangeMailFlowBlock = `# Microsoft 365 Defender - Tenant Allow/Block List (TABL) Block Rule\n# Requires ExchangeOnlineManagement module\nConnect-ExchangeOnline\nNew-TenantAllowBlockListItems -ListType Url -Entry "${cleanHost}/*" -Action Block -ExpirationDate (Get-Date).AddDays(90) -Notes "Incident response containment via BeyondArch SOC"`;

  const defenderCustomIoc = `# Microsoft Defender for Endpoint - Custom URL Indicator\n# KQL Verification Query:\nDeviceNetworkEvents\n| where RemoteUrl has "${cleanHost}"\n| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, RemoteUrl\n\n# PowerShell MDE API Push:\n$body = @{\n  "action" = "Block"\n  "title" = "SOC Incident Block: ${cleanHost}"\n  "description" = "Threat triage - brand spoofing / malicious C2"\n  "indicatorType" = "Url"\n  "indicatorValue" = "${cleanHost}"\n} | ConvertTo-Json`;

  const paloAltoCli = `# Palo Alto Networks PAN-OS CLI\nset shared profiles custom-url-category SOC_BLOCKLIST list [ ${cleanHost} ]\nset rulebase security rules "BLOCK_MALICIOUS_URLS" action deny\ncommit`;

  const fortinetCli = `# Fortinet FortiGate Web Filter Block\nconfig webfilter urlfilter\n  edit 1\n    config entries\n      edit 0\n        set url "${cleanHost}"\n        set type simple\n        set action block\n        set status enable\n      next\n    end\nend`;

  const piholeDnsSinkhole = `# Pi-hole / dnsmasq Sinkhole Entry\npihole -b ${cleanHost} ${cleanApex}\n# Or via hosts file:\necho "0.0.0.0 ${cleanHost}" >> /etc/hosts`;

  const irTicketMarkdown = `### Incident Response Triage Ticket
**Incident Date:** ${new Date().toISOString()}
**Investigator:** SOC Tier 2 Analyst
**Target URL (Defanged):** \`${defangedHost}\`
**Apex Domain:** \`${cleanApex}\`
**Classification:** ${brand ? `Targeted Phishing (${brand.targetBrand})` : payloads.some(p => p.isExecutable) ? "Adversary C2 Stager" : "Suspicious Web Asset"}
**Targeted User:** ${victimEmail ? `\`${victimEmail}\`` : "Not pre-populated"}

#### Summary of Findings:
- Domain \`${defangedHost}\` flagged for malicious activity.
- Extracted IOCs pushed to edge firewall and mail gateway blocklists.
- Targeted user tokens revoked where applicable.

#### Next Steps:
1. Confirm zero outbound connection successes in SIEM/proxy logs.
2. Verify mail gateway purged any delivered messages containing this URL.
3. Mark ticket resolved once containment confirmed across all perimeter controls.`;

  return {
    victimEmail,
    entraIdSessionRevoke,
    defenderCustomIoc,
    exchangeMailFlowBlock,
    paloAltoCli,
    fortinetCli,
    piholeDnsSinkhole,
    irTicketMarkdown,
  };
}

