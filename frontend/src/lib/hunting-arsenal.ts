import { newId } from "@/data/case";

export type SnippetCategory = "splunk" | "sentinel" | "elastic" | "suricata" | "checklists";

export interface HuntingSnippet {
  id: string;
  title: string;
  category: SnippetCategory;
  mitreTechnique?: string;
  description: string;
  queryTemplate: string;
  variables: string[];
  tags: string[];
  isCustom?: boolean;
}

export const HUNTING_PRESETS: HuntingSnippet[] = [
  // --- SPLUNK SPL ---
  {
    id: "spl-kerberoast",
    title: "Active Directory Kerberoasting (Ticket Request Spike)",
    category: "splunk",
    mitreTechnique: "T1558.003",
    description: "Detects multiple Kerberos TGS requests with RC4 encryption (Ticket Encryption 0x17) indicating offline hash cracking attempts.",
    queryTemplate: `index=windows sourcetype="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17" Service_Name!="*$"\n| stats count dc(Service_Name) as unique_spns values(Service_Name) as target_spns by src_ip, Target_User_Name\n| where unique_spns > 3\n| sort -unique_spns`,
    variables: [],
    tags: ["ad", "kerberos", "credential-access", "t1558.003"],
  },
  {
    id: "spl-bloodhound",
    title: "BloodHound / SharpHound LDAP Reconnaissance",
    category: "splunk",
    mitreTechnique: "T1087.002",
    description: "Detects high-frequency LDAP searches querying domain trusts, computers, and group memberships in rapid succession.",
    queryTemplate: `index=windows sourcetype="XmlWinEventLog:Security" EventCode=1644 SearchFilter="*(samAccountType=*)*" \n| stats count by src_ip, user\n| where count > 100\n| sort -count`,
    variables: [],
    tags: ["reconnaissance", "bloodhound", "ldap", "t1087.002"],
  },
  {
    id: "spl-psexec",
    title: "PsExec / Impacket Lateral Movement via Named Pipes",
    category: "splunk",
    mitreTechnique: "T1569.002",
    description: "Detects default PsExec service installation and access to IPC$ / ADMIN$ administrative shares.",
    queryTemplate: `index=windows sourcetype="WinEventLog:System" EventCode=7045 ServiceName="PSEXESVC" OR ServiceFileName="*\\\\PSEXESVC.exe*"\n| table _time, host, ServiceName, ServiceFileName, user`,
    variables: ["TARGET_HOST"],
    tags: ["lateral-movement", "psexec", "t1569.002"],
  },
  {
    id: "spl-vss-delete",
    title: "Volume Shadow Copy Deletion (Ransomware Prep)",
    category: "splunk",
    mitreTechnique: "T1490",
    description: "Detects execution of vssadmin, wmic, or bcdedit terminating backup infrastructure prior to encryption.",
    queryTemplate: `index=windows sourcetype="WinEventLog:Security" EventCode=4688 \n  (CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*wmic*shadowcopy*delete*" OR CommandLine="*wbadmin*delete*catalog*")\n| table _time, ComputerName, NewProcessName, CommandLine, SubjectUserName`,
    variables: ["TARGET_HOST"],
    tags: ["ransomware", "impact", "t1490"],
  },
  {
    id: "spl-dns-tunnel",
    title: "DNS Tunneling & High Entropy Subdomains",
    category: "splunk",
    mitreTechnique: "T1071.004",
    description: "Detects anomalous outbound DNS queries with high query lengths and high entropy indicative of C2 data tunneling.",
    queryTemplate: `index=dns (dest_port=53 OR dest_port=5353) src_ip="{{TARGET_IP}}"\n| eval query_len=len(query)\n| where query_len > 50\n| stats count, dc(query) as unique_subdomains by src_ip, domain\n| where count > 200\n| sort -count`,
    variables: ["TARGET_IP"],
    tags: ["dns", "c2", "tunneling", "t1071.004"],
  },
  {
    id: "spl-data-stage",
    title: "Data Staging via Archival Utilities (7z / WinRAR)",
    category: "splunk",
    mitreTechnique: "T1560.001",
    description: "Detects command-line archiving utilities creating password-protected or multi-volume archives in temporary directories.",
    queryTemplate: `index=windows sourcetype="WinEventLog:Security" EventCode=4688\n  (NewProcessName="*\\\\7z.exe" OR NewProcessName="*\\\\rar.exe" OR NewProcessName="*\\\\tar.exe")\n  (CommandLine="* -p*" OR CommandLine="* -mhe=on*" OR CommandLine="* a *")\n| table _time, ComputerName, CommandLine, SubjectUserName`,
    variables: [],
    tags: ["exfiltration", "staging", "t1560.001"],
  },

  // --- MICROSOFT SENTINEL KQL ---
  {
    id: "kql-aitm-phishing",
    title: "Adversary-in-the-Middle (AitM) Session Replay",
    category: "sentinel",
    mitreTechnique: "T1566.002",
    description: "Correlates initial authentication bypass with anomalous foreign IP session cookie replay in Azure AD.",
    queryTemplate: `SigninLogs\n| where TimeGenerated > ago({{TIMEFRAME}})\n| where IPAddress == "{{TARGET_IP}}" or UserPrincipalName has "{{USERNAME}}"\n| extend DeviceId = tostring(DeviceDetail.deviceId)\n| summarize Count=count(), IPs=make_set(IPAddress), Locations=make_set(Location) by UserPrincipalName\n| where array_length(IPs) > 1`,
    variables: ["TIMEFRAME", "TARGET_IP", "USERNAME"],
    tags: ["identity", "phishing", "aitm", "t1566.002"],
  },
  {
    id: "kql-oauth-grant",
    title: "Suspicious OAuth Application Consent Grant",
    category: "sentinel",
    mitreTechnique: "T1528",
    description: "Identifies newly consented enterprise Azure AD multi-tenant applications requesting Mail.ReadWrite or Offline_Access permissions.",
    queryTemplate: `AuditLogs\n| where OperationName == "Consent to application"\n| extend TargetApp = tostring(TargetResources[0].displayName)\n| extend Permissions = tostring(TargetResources[0].modifiedProperties)\n| where Permissions has "Mail.ReadWrite" or Permissions has "Mail.Read" or Permissions has "Files.ReadWrite.All"\n| project TimeGenerated, InitiatedBy=tostring(InitiatedBy.user.userPrincipalName), TargetApp, Permissions`,
    variables: [],
    tags: ["cloud", "oauth", "t1528"],
  },
  {
    id: "kql-cloud-assumerole",
    title: "Anomalous Cloud STS AssumeRole from Foreign ASN",
    category: "sentinel",
    mitreTechnique: "T1078.004",
    description: "Detects AWS or Azure CloudTrail AssumeRole API invocations originating from unrecognized external ASNs or Tor nodes.",
    queryTemplate: `AWSCloudTrail\n| where EventName == "AssumeRole"\n| where SourceIpAddress == "{{TARGET_IP}}" or UserAgent has "Boto3"\n| project TimeGenerated, SourceIpAddress, UserIdentityArn, RequestParameters, ErrorCode`,
    variables: ["TARGET_IP"],
    tags: ["aws", "cloud", "iam", "t1078.004"],
  },
  {
    id: "kql-impossible-travel",
    title: "Impossible Travel & MFA Prompt Fatigue",
    category: "sentinel",
    mitreTechnique: "T1078",
    description: "Identifies successive logins for the same user account from geographical locations with physically impossible travel velocity.",
    queryTemplate: `SigninLogs\n| where TimeGenerated > ago(24h)\n| where ResultType in (0, 500121) // Success or MFA denied\n| extend City = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion)\n| order by UserPrincipalName, TimeGenerated asc\n| serialize \n| extend PrevTime = prev(TimeGenerated), PrevCountry = prev(Country)\n| where UserPrincipalName == prev(UserPrincipalName) and Country != PrevCountry\n| extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime)\n| where TimeDiffMinutes < 60\n| project TimeGenerated, UserPrincipalName, Country, PrevCountry, TimeDiffMinutes, IPAddress`,
    variables: [],
    tags: ["identity", "travel", "mfa-fatigue", "t1078"],
  },
  {
    id: "kql-lolbins-network",
    title: "LOLBins Spawning Outbound Network Connections",
    category: "sentinel",
    mitreTechnique: "T1059",
    description: "Detects living-off-the-land binaries (certutil, bitsadmin, mshta, regsvr32) establishing outbound internet connections.",
    queryTemplate: `DeviceNetworkEvents\n| where InitiatingProcessFileName in~ ("certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe")\n| where RemoteIPType == "Public"\n| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort`,
    variables: [],
    tags: ["endpoint", "lolbin", "network", "t1059"],
  },

  // --- ELASTIC EQL / LUCENE ---
  {
    id: "eql-lsass-dump",
    title: "LSASS Process Memory Read & Credential Dumping",
    category: "elastic",
    mitreTechnique: "T1003.001",
    description: "Detects unprivileged process opening LSASS handle with PROCESS_VM_READ access rights.",
    queryTemplate: `process where event.type == "start" and \n  process.pe.original_file_name in ("procdump.exe", "mimikatz.exe") or\n  (process.name == "rundll32.exe" and process.command_line : "*comsvcs.dll*#24*")`,
    variables: [],
    tags: ["credentials", "lsass", "eql", "t1003.001"],
  },
  {
    id: "eql-unsigned-dll",
    title: "Unsigned DLL Loaded into System Process",
    category: "elastic",
    mitreTechnique: "T1055.001",
    description: "Detects unsigned or self-signed dynamic link library loaded into critical Windows binaries (svchost, lsass, explorer).",
    queryTemplate: `library where process.name in ("svchost.exe", "explorer.exe", "lsass.exe") and \n  dll.code_signature.trusted == false and \n  not dll.path : "C:\\\\Windows\\\\System32\\\\*"`,
    variables: [],
    tags: ["dll-hijack", "defense-evasion", "t1055.001"],
  },
  {
    id: "eql-certutil-cradle",
    title: "Certutil Download Cradle Execution",
    category: "elastic",
    mitreTechnique: "T1105",
    description: "Detects certutil.exe invoking -urlcache, -split, or -f switches to download remote payloads.",
    queryTemplate: `process where event.type == "start" and \n  process.name == "certutil.exe" and \n  process.command_line : ("*-urlcache*", "*-split*", "*-f*") and \n  process.command_line : ("*http://*", "*https://*")`,
    variables: [],
    tags: ["lolbin", "download", "ingress", "t1105"],
  },
  {
    id: "eql-wmi-persistence",
    title: "WMI Event Subscription Persistence",
    category: "elastic",
    mitreTechnique: "T1546.003",
    description: "Detects creation of __EventFilter, CommandLineEventConsumer, or __FilterToConsumerBinding for persistence.",
    queryTemplate: `process where event.type == "start" and \n  process.name == "wmic.exe" and \n  process.command_line : ("*EventFilter*", "*CommandLineEventConsumer*", "*FilterToConsumerBinding*")`,
    variables: [],
    tags: ["persistence", "wmi", "t1546.003"],
  },

  // --- SURICATA IDS SIGNATURES ---
  {
    id: "suricata-cobalt-beacon",
    title: "Cobalt Strike Malleable C2 Beaconing Rule",
    category: "suricata",
    mitreTechnique: "T1071.001",
    description: "Suricata network rule detecting characteristic HTTP cookie metadata staging and URI paths.",
    queryTemplate: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"BEYONDLABS MALWARE Cobalt Strike Malleable HTTP Beacon"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/pixel.gif"; http.header; content:"Cookie|3a 20|"; pcre:"/Cookie\\x3a\\x20[A-Za-z0-9+\\/]{32,}==/"; classtype:trojan-activity; sid:9001001; rev:1;)`,
    variables: [],
    tags: ["ids", "suricata", "c2", "cobalt-strike", "t1071.001"],
  },
  {
    id: "suricata-fast-flux",
    title: "Dynamic DNS Fast-Flux Resolution Activity",
    category: "suricata",
    mitreTechnique: "T1568.001",
    description: "Alerts on DNS responses returning multiple anomalous A records with TTL less than 60 seconds.",
    queryTemplate: `alert dns $EXTERNAL_NET 53 -> $HOME_NET any (msg:"BEYONDLABS SUSPICIOUS Low TTL Fast-Flux DNS Response"; dns.opcode:0; dns.response; content:"|00 01|"; content:"|00 00 00 1e|"; distance:4; classtype:bad-unknown; sid:9001002; rev:1;)`,
    variables: [],
    tags: ["dns", "fast-flux", "suricata", "t1568.001"],
  },

  // --- DFIR RESPONSE CHECKLISTS ---
  {
    id: "chk-nist-triage",
    title: "NIST SP 800-61r2 Initial Triage & Scoping Checklist",
    category: "checklists",
    description: "Standardized first-responder checklist covering detection confirmation, scoping, containment strategy, and preservation.",
    queryTemplate: `## NIST SP 800-61r2 Incident Intake Checklist
- [ ] 1. Identify primary alert source, telemetry sensor, and timestamp window.
- [ ] 2. Extract and defang all observed indicators (IP: {{TARGET_IP}}, Host: {{HOSTNAME}}, User: {{USERNAME}}).
- [ ] 3. Validate impact scope: Isolate patient-zero host if actively beaconing or encrypting.
- [ ] 4. Preserve volatile evidence (endpoint memory dump, active network socket states).
- [ ] 5. Query SIEM for lateral spread from patient-zero to internal production VLANs.
- [ ] 6. Classify incident severity (P1/P2/P3) and designate incident lead.
- [ ] 7. Open case dossier in Case Workbench and record cryptographic evidence custody.`,
    variables: ["TARGET_IP", "HOSTNAME", "USERNAME"],
    tags: ["nist", "triage", "checklist", "dfir"],
  },
  {
    id: "chk-ransomware-first-60",
    title: "Enterprise Ransomware Outbreak: First 60 Minutes Runbook",
    category: "checklists",
    description: "Emergency operational procedures for containing live ransomware outbreaks before domain-wide propagation.",
    queryTemplate: `## Ransomware Containment: First 60 Minutes
1. [NETWORK PARTITION]: Sever WAN gateway and isolate impacted host {{HOSTNAME}} at switch port / EDR sensor level.
2. [BACKUP PROTECTION]: Immediately sever network access to immutable backup repositories and offline air-gapped stores.
3. [DOMAIN DEFENSE]: Disable compromised service account: {{USERNAME}}. Force Kerberos krbtgt rotation on Primary DC.
4. [EVIDENCE CAPTURE]: Capture in-memory minidump of encryption process before rebooting or terminating machines.
5. [C2 NULL-ROUTE]: Blackhole destination IP: {{TARGET_IP}} across perimeter Palo Alto / Fortinet security policies.
6. [SCOPE SWEEP]: Run EDR sweep for extension markers (.locked, .encrypted) across file servers.`,
    variables: ["HOSTNAME", "USERNAME", "TARGET_IP"],
    tags: ["ransomware", "playbook", "first-response", "checklist"],
  },
  {
    id: "chk-memory-forensics",
    title: "Live Endpoint Memory Forensics Acquisition Runbook",
    category: "checklists",
    description: "Step-by-step forensic guide for volatile RAM preservation using WinPmem / LiME.",
    queryTemplate: `## Volatile Memory Preservation Runbook
- Target Host: {{HOSTNAME}}
- Investigator: SOC DFIR Team

Steps:
1. Ensure target machine remains POWERED ON. Do not reboot or log off the current user.
2. Connect forensic USB drive (hardware write-blocked if possible) or mapped forensic share.
3. Execute acquisition utility:
   \`\`\`cmd
   winpmem.exe -o D:\\ForensicDumps\\{{HOSTNAME}}_mem.raw --mode 1
   \`\`\`
4. Calculate cryptographic verification hash immediately:
   \`\`\`powershell
   Get-FileHash -Algorithm SHA256 D:\\ForensicDumps\\{{HOSTNAME}}_mem.raw
   \`\`\`
5. Record physical RAM size, hardware serial number, and exact acquisition UTC timestamp.
6. Log image SHA256 into active incident case chain-of-custody ledger.`,
    variables: ["HOSTNAME"],
    tags: ["memory", "forensics", "winpmem", "volatility"],
  },
];

export const LS_SNIPPETS_KEY = "ba.snippets.v3";

/** Loads all snippets combining presets and custom user snippets. */
export function loadHuntingSnippets(): HuntingSnippet[] {
  try {
    const raw = localStorage.getItem(LS_SNIPPETS_KEY);
    if (!raw) return HUNTING_PRESETS;
    const userCustom: HuntingSnippet[] = JSON.parse(raw);
    return [...HUNTING_PRESETS, ...userCustom.filter((u) => u.isCustom)];
  } catch {
    return HUNTING_PRESETS;
  }
}

/** Saves custom user snippets to localStorage. */
export function saveCustomSnippets(snippets: HuntingSnippet[]) {
  try {
    const customOnly = snippets.filter((s) => s.isCustom);
    localStorage.setItem(LS_SNIPPETS_KEY, JSON.stringify(customOnly));
    try {
      window.dispatchEvent(new Event("ba:snippets-changed"));
    } catch {
      // non-window
    }
  } catch {
    // noop
  }
}

/** Interpolates variables into a query template string. */
export function interpolateQuery(template: string, vars: Record<string, string>): string {
  let result = template;
  for (const [key, val] of Object.entries(vars)) {
    if (val && val.trim()) {
      const rx = new RegExp(`\\{\\{${key}\\}\\}`, "g");
      result = result.replace(rx, val.trim());
    }
  }
  return result;
}

/** Computes high-level arsenal telemetry metrics. */
export function calculateArsenalTelemetry(snippets: HuntingSnippet[]) {
  const total = snippets.length;
  const splunkCount = snippets.filter((s) => s.category === "splunk").length;
  const sentinelCount = snippets.filter((s) => s.category === "sentinel").length;
  const elasticCount = snippets.filter((s) => s.category === "elastic").length;
  const suricataCount = snippets.filter((s) => s.category === "suricata").length;
  const checklistsCount = snippets.filter((s) => s.category === "checklists").length;

  return {
    total,
    splunkCount,
    sentinelCount,
    elasticCount,
    suricataCount,
    checklistsCount,
  };
}

/** Creates a fresh custom snippet object. */
export function createCustomSnippet(params: {
  title: string;
  category: SnippetCategory;
  description: string;
  queryTemplate: string;
  tags: string[];
  mitreTechnique?: string;
}): HuntingSnippet {
  // Extract {{VARS}}
  const varMatches = params.queryTemplate.matchAll(/\{\{([A-Za-z0-9_-]+)\}\}/g);
  const variables = Array.from(new Set(Array.from(varMatches).map((m) => m[1])));

  return {
    id: `snip-${newId("custom")}`,
    title: params.title,
    category: params.category,
    description: params.description,
    queryTemplate: params.queryTemplate,
    variables,
    tags: params.tags,
    mitreTechnique: params.mitreTechnique,
    isCustom: true,
  };
}
