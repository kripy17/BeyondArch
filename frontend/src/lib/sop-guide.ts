import type { Case, Entry, EntryKind } from "@/data/case";
import { newId, newCaseTitle } from "@/data/case";
import type { Severity } from "@/lib/severity";

export type SopPhase = "preparation" | "detection" | "containment" | "eradication" | "recovery" | "post_incident";

export interface SopStep {
  id: string;
  phase: SopPhase;
  phaseLabel: string;
  text: string;
  criticality: "mandatory" | "recommended" | "optional";
  pivot?: { to: string; label: string };
  guidance?: string;
}

export interface SopRunbook {
  id: string;
  title: string;
  shortName: string;
  severity: "P1" | "P2" | "P3";
  eta: string;
  targetMtrMinutes: number;
  category: "Malware" | "Network" | "Identity" | "Cloud" | "Email" | "Web" | "Development" | "Insider";
  iconName: string;
  summary: string;
  objective: string;
  escalationTrigger: string;
  attack: string[];
  steps: SopStep[];
  alwaysRules: string[];
  neverRules: string[];
  kpis: {
    typicalDwellTime: string;
    containmentSla: string;
    falsePositiveRate: string;
  };
}

export const SOP_PHASE_CONFIG: Record<SopPhase, { label: string; tone: "default" | "primary" | "warning" | "destructive" | "success" | "info"; order: number }> = {
  preparation: { label: "1. Preparation", tone: "default", order: 1 },
  detection: { label: "2. Detection & Analysis", tone: "primary", order: 2 },
  containment: { label: "3. Containment", tone: "destructive", order: 3 },
  eradication: { label: "4. Eradication", tone: "warning", order: 4 },
  recovery: { label: "5. Recovery", tone: "success", order: 5 },
  post_incident: { label: "6. Post-Incident Review", tone: "info", order: 6 },
};

export const SOP_RUNBOOKS: SopRunbook[] = [
  {
    id: "ransomware-outbreak",
    title: "Endpoint Ransomware Outbreak & Extortion Defense",
    shortName: "Ransomware Outbreak",
    severity: "P1",
    eta: "15 min",
    targetMtrMinutes: 15,
    category: "Malware",
    iconName: "Siren",
    summary: "Active endpoint encryption, shadow copy destruction, or mass ransom note delivery detected on workstation or server.",
    objective: "Immediately halt adversary lateral movement, preserve memory telemetry, isolate affected hosts, and safeguard online backup repositories.",
    escalationTrigger: "More than 1 machine reporting locked extensions (.locked, .enc) or vssadmin delete shadows execution.",
    attack: ["T1486", "T1490", "T1070.004", "T1059.001", "T1021.002"],
    kpis: {
      typicalDwellTime: "2 - 7 days",
      containmentSla: "< 15 minutes",
      falsePositiveRate: "Low (< 2%)",
    },
    alwaysRules: [
      "Isolate network interface card (NIC) or switch VLAN immediately; do NOT reboot immediately if memory forensics is possible.",
      "Capture volatile RAM and running process trees before terminating processes.",
      "Check domain controller replication and cloud sync status before restoring backups.",
    ],
    neverRules: [
      "Never pay ransom or contact threat actor negotiation portals without legal and CISO signoff.",
      "Never reboot the machine before capturing memory if BitLocker / memory-only keys might be salvageable.",
      "Never connect unaffected backup storage to the contaminated VLAN.",
    ],
    steps: [
      {
        id: "rs-1",
        phase: "preparation",
        phaseLabel: "Preparation",
        criticality: "mandatory",
        text: "Verify EDR network isolation policy is active and accessible via secondary out-of-band channel.",
        guidance: "Ensure your management plane retains control even when the endpoint's default gateway is severed.",
      },
      {
        id: "rs-2",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Inspect SIEM for high-frequency file rename/write events and volume shadow copy deletion (Event ID 4688: vssadmin, wmic shadowcopy).",
        pivot: { to: "/siem", label: "Mini SIEM Query" },
        guidance: "Search for commands: vssadmin.exe delete shadows /all /quiet or bcdedit /set {default} recoveryenabled No.",
      },
      {
        id: "rs-3",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Extract dropped executable or script payload, calculate SHA256 hash, and check IOC database.",
        pivot: { to: "/attachment", label: "Attachment Triage" },
        guidance: "Preserve sample in encrypted archive (pass: infected) for reverse engineering.",
      },
      {
        id: "rs-4",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Isolate host at EDR / firewall perimeter and block internal SMB (445), RDP (3389), and WinRM (5985).",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Sever lateral hops immediately to prevent enterprise-wide encryption cascade.",
      },
      {
        id: "rs-5",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Force disable compromised Active Directory user and computer accounts; revoke Kerberos TGT tickets.",
        guidance: "Execute Kerberos ticket purge (klist purge) and disable service accounts used for lateral spread.",
      },
      {
        id: "rs-6",
        phase: "eradication",
        phaseLabel: "Eradication",
        criticality: "mandatory",
        text: "Locate and terminate persistence mechanisms (Run keys, scheduled tasks, WMI event subscriptions).",
        pivot: { to: "/logs", label: "Windows Event Logs" },
        guidance: "Check Event ID 7045 (Service Creation) and Event ID 4698 (Scheduled Task Creation).",
      },
      {
        id: "rs-7",
        phase: "recovery",
        phaseLabel: "Recovery",
        criticality: "recommended",
        text: "Restore systems from air-gapped immutable backups; re-image operating system from golden image.",
        guidance: "Verify backup integrity and ensure no ransomware binary was staged prior to the restore snapshot.",
      },
      {
        id: "rs-8",
        phase: "post_incident",
        phaseLabel: "Post-Incident Review",
        criticality: "recommended",
        text: "Publish formal SANS/NIST incident report, catalog root cause vector, and create custom Sigma detection rules.",
        pivot: { to: "/sigma-tester", label: "Sigma Tester" },
        guidance: "Deploy Canary file tripwires and SMB signing enforcement across all subnet boundaries.",
      },
    ],
  },
  {
    id: "c2-beaconing",
    title: "Outbound Command & Control (C2) Beaconing",
    shortName: "C2 Beaconing",
    severity: "P1",
    eta: "20 min",
    targetMtrMinutes: 20,
    category: "Network",
    iconName: "Radio",
    summary: "Periodic high-cadence or low-and-slow telemetry beaconing to untrusted external IP/domain matching Cobalt Strike, Sliver, or Havoc C2 profiles.",
    objective: "Identify the compromised host process, sever command channels, identify exfiltrated data volume, and sinkhole adversary infrastructure.",
    escalationTrigger: "Beacon observed originating from domain controller, jump box, or executive workstation.",
    attack: ["T1071.001", "T1573.001", "T1571", "T1095", "T1041"],
    kpis: {
      typicalDwellTime: "4 - 24 hours",
      containmentSla: "< 20 minutes",
      falsePositiveRate: "Medium (~8% NTP/Cloud Sync)",
    },
    alwaysRules: [
      "Capture PCAP stream to calculate exact jitter, interval periodicity, and JA3/JA4 TLS fingerprints.",
      "Check parent-child process tree to isolate the process hosting the injected DLL or shellcode.",
      "Add destination IP and domain to edge perimeter firewall and DNS sinkholes.",
    ],
    neverRules: [
      "Never navigate to the C2 domain using a standard web browser on your corporate network.",
      "Never reboot the machine until process memory of the beaconing PID has been dumped.",
      "Never assume single-host compromise once C2 channel is established.",
    ],
    steps: [
      {
        id: "c2-1",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Analyze PCAP or NetFlow to determine beacon interval cadence, jitter variance, and packet size distribution.",
        pivot: { to: "/pcap", label: "PCAP Stream Analyzer" },
        guidance: "Filter for destination IP and inspect TLS SNI or HTTP User-Agent consistency.",
      },
      {
        id: "c2-2",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Perform threat intelligence lookup on C2 IP/domain; evaluate ASN reputation and WHOIS age.",
        pivot: { to: "/intel", label: "Intel Hub" },
        guidance: "Check for Bulletproof hosting ASNs, newly registered domains (<30 days), and known threat group associations.",
      },
      {
        id: "c2-3",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Apply DNS sinkhole and proxy block for the C2 FQDN; inject null route at perimeter BGP/firewall.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Ensure internal DNS resolvers return 0.0.0.0 or redirect to internal honeynet collector.",
      },
      {
        id: "c2-4",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Quarantine originating endpoint and dump memory of the beaconing PID using Volatility or ProcDump.",
        guidance: "Preserve process memory to extract in-memory configuration, AES encryption keys, and staged shellcode.",
      },
      {
        id: "c2-5",
        phase: "eradication",
        phaseLabel: "Eradication",
        criticality: "mandatory",
        text: "Kill rogue process and purge injected thread or DLL injection persistence from system libraries.",
        pivot: { to: "/logs", label: "Windows Event Logs" },
        guidance: "Audit Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess) in Sysmon logs.",
      },
      {
        id: "c2-6",
        phase: "recovery",
        phaseLabel: "Recovery",
        criticality: "recommended",
        text: "Verify all beaconing activity ceases; validate network telemetry for alternative backup C2 channels.",
        pivot: { to: "/siem", label: "Mini SIEM Query" },
        guidance: "Monitor outbound traffic for 48 hours to confirm dormant secondary fallback beacons do not activate.",
      },
      {
        id: "c2-7",
        phase: "post_incident",
        phaseLabel: "Post-Incident Review",
        criticality: "recommended",
        text: "Author Suricata / Snort IDS rule and add Sigma query for beaconing cadence detection.",
        pivot: { to: "/detection", label: "Detection Rule Editor" },
        guidance: "Submit IOCs to Threat Intel sharing community and update proxy egress filtering policy.",
      },
    ],
  },
  {
    id: "kerberoasting-dcsync",
    title: "Active Directory Kerberoasting & DCSync Privilege Escalation",
    shortName: "Kerberoasting & DCSync",
    severity: "P1",
    eta: "20 min",
    targetMtrMinutes: 20,
    category: "Identity",
    iconName: "KeyRound",
    summary: "Suspicious volume of Kerberos TGS-REQ tickets with RC4 encryption (Event 4769) or DS-Replication-Get-Changes requests to Domain Controller.",
    objective: "Protect Domain Controller integrity, identify compromised user accounts requesting service tickets, and force Krbtgt password rotation.",
    escalationTrigger: "Non-domain controller host invoking DsGetNcChanges RPC protocol against Active Directory.",
    attack: ["T1558.003", "T1003.006", "T1078", "T1068"],
    kpis: {
      typicalDwellTime: "1 - 3 hours",
      containmentSla: "< 20 minutes",
      falsePositiveRate: "Very Low (< 1%)",
    },
    alwaysRules: [
      "Audit Event ID 4769 for Ticket Options 0x40810000 and Encryption Type 0x17 (RC4-HMAC).",
      "Treat any non-DC host performing replication synchronization as an active domain compromise.",
      "Coordinate Krbtgt account password reset twice (with replication delay in between) if DCSync is validated.",
    ],
    neverRules: [
      "Never reboot Domain Controllers simultaneously without verifying replication health.",
      "Never dismiss RC4 TGS requests as benign legacy application traffic without service principal review.",
      "Never alert the compromised account owner via unmonitored communication channels.",
    ],
    steps: [
      {
        id: "kb-1",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Search Windows Event 4769 in SIEM for Ticket Encryption Type 0x17 (RC4) requested by regular user accounts.",
        pivot: { to: "/siem", label: "Mini SIEM Query" },
        guidance: "Adversaries request RC4 tickets to perform offline cracking via Hashcat/John the Ripper.",
      },
      {
        id: "kb-2",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Search Directory Service Replication logs (Event 4662) on DCs for GUID {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}.",
        pivot: { to: "/logs", label: "Windows Event Logs" },
        guidance: "This GUID corresponds to DS-Replication-Get-Changes-All (the privilege required for DCSync dumping).",
      },
      {
        id: "kb-3",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Immediately isolate source endpoint initiating DCSync RPC calls; disable compromised caller account.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Revoke active logon sessions and disable network access at the switch port level if necessary.",
      },
      {
        id: "kb-4",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Identify all SPNs (Service Principal Names) targeted by the Kerberoasting query and force credential rotation.",
        guidance: "Change passwords to 25+ character random strings with AES-256 encryption enabled.",
      },
      {
        id: "kb-5",
        phase: "eradication",
        phaseLabel: "Eradication",
        criticality: "mandatory",
        text: "Initiate KRBTGT account double password reset protocol using Microsoft recommended PowerShell script.",
        guidance: "Reset once, wait 10 hours for replication, then reset a second time to invalidate Golden Tickets.",
      },
      {
        id: "kb-6",
        phase: "recovery",
        phaseLabel: "Recovery",
        criticality: "recommended",
        text: "Audit Active Directory ACL delegations on Domain root; remove rogue Replicating Directory Changes permissions.",
        guidance: "Verify AdminSDHolder permissions and ensure no unauthorized objects inherit administrative rights.",
      },
      {
        id: "kb-7",
        phase: "post_incident",
        phaseLabel: "Post-Incident Review",
        criticality: "recommended",
        text: "Deploy Group Managed Service Accounts (gMSA) to replace legacy SPN accounts and eliminate Kerberoasting risk.",
        pivot: { to: "/snippets", label: "Query Arsenal" },
        guidance: "Add persistent SIEM alerts for any Event ID 4662 referencing Directory Service access from non-DC IPs.",
      },
    ],
  },
  {
    id: "cloud-iam-compromise",
    title: "AWS / Azure Cloud IAM Credential Compromise & Resource Hijack",
    shortName: "Cloud IAM Compromise",
    severity: "P1",
    eta: "25 min",
    targetMtrMinutes: 25,
    category: "Cloud",
    iconName: "Cloud",
    summary: "CloudTrail or Azure Activity log anomaly: high-privilege API calls from foreign ASN, new IAM admin creation, or rogue GPU compute provisioning.",
    objective: "Revoke compromised cloud access keys, terminate unauthorized virtual machines, audit S3 bucket access, and enforce MFA.",
    escalationTrigger: "Creation of rogue administrator IAM users, modifications to IAM roles, or CloudTrail logging disablement.",
    attack: ["T1078.004", "T1528", "T1098", "T1530", "T1496"],
    kpis: {
      typicalDwellTime: "30 minutes - 2 hours",
      containmentSla: "< 25 minutes",
      falsePositiveRate: "Low (< 3%)",
    },
    alwaysRules: [
      "Immediately deactivate the compromised Access Key ID and revoke all active STS temporary sessions.",
      "Check CloudTrail / Azure Activity logs for StopLogging or DeleteTrail events.",
      "Audit all created compute instances, serverless Lambdas, and modified security group rules.",
    ],
    neverRules: [
      "Never delete compromised IAM users or access keys before downloading complete CloudTrail audit logs.",
      "Never assume compromise was limited to a single AWS region; check all global regions.",
      "Never commit cloud API keys or service principal secrets into code repositories.",
    ],
    steps: [
      {
        id: "cl-1",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Query CloudTrail / Azure Monitor for API calls from anomalous geographical origins or VPN/Tor exit nodes.",
        pivot: { to: "/siem", label: "Mini SIEM Query" },
        guidance: "Focus on events: CreateAccessKey, CreateUser, AttachUserPolicy, RunInstances, UpdateAssumeRolePolicy.",
      },
      {
        id: "cl-2",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Deactivate access key in AWS IAM / Azure Entra ID and attach inline DenyAll policy to the principal.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Attach: {\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}]}.",
      },
      {
        id: "cl-3",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Revoke active STS federation tokens by modifying role session policy or using aws iam put-user-policy.",
        guidance: "Existing temporary STS credentials remain valid until explicitly revoked via RevokeOlderSessions timestamp.",
      },
      {
        id: "cl-4",
        phase: "eradication",
        phaseLabel: "Eradication",
        criticality: "mandatory",
        text: "Identify and terminate unauthorized EC2 instances, crypto-mining pods, and delete newly spawned IAM credentials.",
        guidance: "Cross-check all AWS regions (eu-west, ap-southeast, us-east, etc.) for instances launched in the attack window.",
      },
      {
        id: "cl-5",
        phase: "recovery",
        phaseLabel: "Recovery",
        criticality: "recommended",
        text: "Audit S3 bucket access logs for data exfiltration; verify bucket policies and KMS encryption keys.",
        guidance: "Check GetObject volume and external destination endpoints for sensitive database backups or PII.",
      },
      {
        id: "cl-6",
        phase: "post_incident",
        phaseLabel: "Post-Incident Review",
        criticality: "recommended",
        text: "Enforce SCP (Service Control Policies) restricting root account access and mandating hardware token MFA.",
        pivot: { to: "/snippets", label: "Query Arsenal" },
        guidance: "Configure AWS GuardDuty and Azure Defender with automated Lambda containment playbooks.",
      },
    ],
  },
  {
    id: "spear-phishing-aitm",
    title: "AitM Spear-Phishing & Session Token Hijack",
    shortName: "AitM Phishing",
    severity: "P2",
    eta: "15 min",
    targetMtrMinutes: 15,
    category: "Email",
    iconName: "Mail",
    summary: "Targeted spear-phishing email delivered to employee with Adversary-in-the-Middle (AitM) reverse-proxy session token theft.",
    objective: "Determine user interaction, revoke stolen session tokens, purge malicious inbox forwarding rules, and quarantine email lure across all recipients.",
    escalationTrigger: "User completed authentication on proxy lure, followed by immediate M365/Google Workspace sign-in from foreign IP.",
    attack: ["T1566.002", "T1539", "T1114.003", "T1078.004"],
    kpis: {
      typicalDwellTime: "10 - 45 minutes",
      containmentSla: "< 15 minutes",
      falsePositiveRate: "Medium (~5%)",
    },
    alwaysRules: [
      "Revoke session tokens immediately via Revoke-AzureADUserAllRefreshToken or Google Admin API.",
      "Check mailbox inbox rules for forwarding or deletion rules created in the last 24 hours.",
      "Block the reverse-proxy domain and origin IP across perimeter email gateways and proxy filters.",
    ],
    neverRules: [
      "Never click the lure URL directly in an uncontained browser without isolation.",
      "Never rely solely on password reset without revoking active authentication session cookies.",
      "Never leave unquarantined copies of the email in other employee inboxes.",
    ],
    steps: [
      {
        id: "ph-1",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Analyze raw RFC 822 email headers, SPF/DKIM/DMARC status, and reverse proxy landing page.",
        pivot: { to: "/phishing", label: "Phishing Analyzer" },
        guidance: "Inspect Authentication-Results header for SPF fail and extract originating sending server IP.",
      },
      {
        id: "ph-2",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Defang lure URL and inspect domain age, SSL issuer, and HTTP response redirection chain.",
        pivot: { to: "/url", label: "Safe URL Analyzer" },
        guidance: "Check for Evilginx / Modlishka reverse proxy patterns and token-capturing JavaScript payloads.",
      },
      {
        id: "ph-3",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Revoke all active sessions and refresh tokens for victim account in IdP (Entra ID / Okta / Google Workspace).",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Run PowerShell: Revoke-MgUserAllRefreshToken -UserId <UserUPN> to kill all live web sessions.",
      },
      {
        id: "ph-4",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Execute tenant-wide search-and-purge (SoftDelete / HardDelete) for all emails with matching Message-ID or Subject.",
        guidance: "Purge mail using M365 Security Compliance Center or Google Vault query across all mailboxes.",
      },
      {
        id: "ph-5",
        phase: "eradication",
        phaseLabel: "Eradication",
        criticality: "mandatory",
        text: "Inspect and delete unauthorized inbox forwarding rules (Get-InboxRule) and newly granted OAuth app consent.",
        guidance: "Adversaries create rules to move security notifications to RSS Feeds or Deleted Items automatically.",
      },
      {
        id: "ph-6",
        phase: "recovery",
        phaseLabel: "Recovery",
        criticality: "recommended",
        text: "Enforce FIDO2 WebAuthn / Passkey phishing-resistant MFA policy for the affected organizational unit.",
        guidance: "Phishing-resistant credentials tie domain origin to hardware token, neutralizing AitM reverse proxies.",
      },
      {
        id: "ph-7",
        phase: "post_incident",
        phaseLabel: "Post-Incident Review",
        criticality: "recommended",
        text: "Document incident findings in Case Workbench, update email gateway regex filters, and conduct simulated security training.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Extract lure domains to IOC locker and cross-correlate across external threat feeds.",
      },
    ],
  },
  {
    id: "web-shell-rce",
    title: "Public DMZ Web Shell & Remote Code Execution (RCE)",
    shortName: "Web Shell & RCE",
    severity: "P1",
    eta: "15 min",
    targetMtrMinutes: 15,
    category: "Web",
    iconName: "Globe2",
    summary: "Suspicious file upload (.php, .jsp, .aspx) followed by process spawn (cmd.exe, /bin/sh, powershell) under web server daemon (IIS, Nginx, Apache).",
    objective: "Isolate DMZ server, identify entry vector vulnerability, kill active backdoor shells, and remove persistence artifacts.",
    escalationTrigger: "Child process execution under w3wp.exe, httpd, or tomcat process hierarchy.",
    attack: ["T1505.003", "T1190", "T1059.001", "T1059.004", "T1036"],
    kpis: {
      typicalDwellTime: "15 minutes - 4 hours",
      containmentSla: "< 15 minutes",
      falsePositiveRate: "Very Low (< 1%)",
    },
    alwaysRules: [
      "Isolate server from internal corporate LAN immediately to prevent pivot from DMZ to Active Directory.",
      "Preserve web server access logs (access.log) with accurate timestamps before rotating or clearing logs.",
      "Calculate SHA256 of all files modified in the web root during the incident window.",
    ],
    neverRules: [
      "Never delete the web shell file directly without creating a forensic bitstream copy or hash.",
      "Never leave server online on the public Internet while analyzing the vulnerability.",
      "Never execute the web shell via web browser to see what it does.",
    ],
    steps: [
      {
        id: "ws-1",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Analyze web server access logs for anomalous POST requests to uploaded script files or HTTP 200 responses to obscure URIs.",
        pivot: { to: "/parser", label: "Universal Parser" },
        guidance: "Search for single IP executing frequent POST requests to files inside upload or static asset directories.",
      },
      {
        id: "ws-2",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Inspect web shell code for deobfuscation, evaluation wrappers, and command execution primitives.",
        pivot: { to: "/chef", label: "CyberChef Workbench" },
        guidance: "Look for base64_decode, eval, system, Runtime.getRuntime().exec, or ProcessBuilder calls.",
      },
      {
        id: "ws-3",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Sever external inbound traffic at edge WAF; block outbound internet egress from the DMZ subnet.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Apply strict zero-trust egress filter: DMZ servers should not be able to initiate outbound connections.",
      },
      {
        id: "ws-4",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Terminate web server worker processes and kill interactive shell sub-processes (sh, bash, cmd.exe, powershell.exe).",
        guidance: "Check for spawned reverse shells communicating over non-standard ports (e.g. 4444, 1337, 8443).",
      },
      {
        id: "ws-5",
        phase: "eradication",
        phaseLabel: "Eradication",
        criticality: "mandatory",
        text: "Remove web shell file, purge secondary stagers, and patch root cause web vulnerability (file upload, LFI, SQLi, deserialization).",
        guidance: "Ensure upload directory permissions enforce no-execution flags (chmod -R -x or IIS execute permissions None).",
      },
      {
        id: "ws-6",
        phase: "recovery",
        phaseLabel: "Recovery",
        criticality: "recommended",
        text: "Deploy file integrity monitoring (FIM) across web root directory; restore application from verified git commit.",
        guidance: "Verify no secondary backdoors or cron jobs were left in /tmp, /dev/shm, or ProgramData.",
      },
      {
        id: "ws-7",
        phase: "post_incident",
        phaseLabel: "Post-Incident Review",
        criticality: "recommended",
        text: "Publish incident timeline, implement WAF virtual patch, and add Sigma detection for web daemon process spawning.",
        pivot: { to: "/sigma-tester", label: "Sigma Tester" },
        guidance: "Rule logic: Image endswith ['cmd.exe', 'powershell.exe', 'sh'] and ParentImage endswith ['w3wp.exe', 'httpd.exe', 'nginx'].",
      },
    ],
  },
  {
    id: "bec-wire-fraud",
    title: "Business Email Compromise (BEC) & Financial Wire Interception",
    shortName: "BEC & Wire Fraud",
    severity: "P2",
    eta: "20 min",
    targetMtrMinutes: 20,
    category: "Email",
    iconName: "FileWarning",
    summary: "Compromised finance or executive mailbox used to initiate fraudulent vendor invoice modification, payment redirection, or bank wire transfer.",
    objective: "Halt pending financial transactions, secure compromised email accounts, audit mailbox audit logs, and notify legal and banking partners.",
    escalationTrigger: "Wire transfer initiated or email correspondence regarding bank routing numbers originating from attacker-controlled IP.",
    attack: ["T1566.002", "T1114.003", "T1534", "T1078"],
    kpis: {
      typicalDwellTime: "1 - 14 days",
      containmentSla: "< 20 minutes",
      falsePositiveRate: "Very Low (< 1%)",
    },
    alwaysRules: [
      "Contact financial institution fraud team immediately if wire has been dispatched within 72 hours.",
      "Preserve all MailItemsAccessed and SendAs audit events for forensic and insurance evidence.",
      "Conduct out-of-band voice verification with vendor accounting departments using known verified phone numbers.",
    ],
    neverRules: [
      "Never reply to wire verification emails using the Reply button in the email client.",
      "Never communicate with internal executives regarding the compromise using their compromised email accounts.",
      "Never delete fraudulent invoices or messages before preserving forensic EML exports.",
    ],
    steps: [
      {
        id: "bec-1",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Initiate emergency recall with sending and receiving banks for any unauthorized wire transfers.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Speed is paramount: SWIFT recalls within 24-48 hours have significantly higher recovery success rates.",
      },
      {
        id: "bec-2",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Disable compromised user mailbox, terminate active sessions, and reset credentials with password change.",
        guidance: "Revoke mobile device ActiveSync partnerships and OAuth tokens.",
      },
      {
        id: "bec-3",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Audit Exchange Mailbox Audit logs (MailItemsAccessed, SendAs, Create, Move) to determine scope of accessed messages.",
        pivot: { to: "/siem", label: "Mini SIEM Query" },
        guidance: "Search for queries filtering on keywords: 'invoice', 'wire', 'banking', 'payment', 'routing'.",
      },
      {
        id: "bec-4",
        phase: "eradication",
        phaseLabel: "Eradication",
        criticality: "mandatory",
        text: "Identify and delete hidden inbox rules forwarding emails to external look-alike domains or moving replies to Archive.",
        guidance: "Adversaries frequently create rules like: If Subject contains 'wire' or 'invoice', redirect to external address and delete.",
      },
      {
        id: "bec-5",
        phase: "recovery",
        phaseLabel: "Recovery",
        criticality: "recommended",
        text: "Issue formal vendor security notice with verified banking instructions and coordinate external forensic disclosure.",
        guidance: "Ensure vendor establishes dual-authorization protocol for all future bank account detail changes.",
      },
      {
        id: "bec-6",
        phase: "post_incident",
        phaseLabel: "Post-Incident Review",
        criticality: "recommended",
        text: "Implement strict outbound mail transport rules flagging external email forwarding and alerts for new mailbox rules.",
        pivot: { to: "/snippets", label: "Query Arsenal" },
        guidance: "Deploy automated detection alerting SOC whenever an inbox rule with 'RedirectTo' or 'ForwardTo' is created.",
      },
    ],
  },
  {
    id: "supply-chain-hijack",
    title: "Software Supply Chain Dependency Hijacking",
    shortName: "Supply Chain Hijack",
    severity: "P2",
    eta: "30 min",
    targetMtrMinutes: 30,
    category: "Development",
    iconName: "Package",
    summary: "Direct or transitive third-party dependency (npm, PyPI, Maven, Go module) identified with malicious obfuscated backdoors or active CVE exploit.",
    objective: "Halt CI/CD pipelines, quarantine vulnerable package versions, audit production deployments for indicators of execution, and pin clean dependencies.",
    escalationTrigger: "Public advisory or static analysis identifying backdoor code in production build artifact.",
    attack: ["T1195.001", "T1195.002", "T1526", "T1059"],
    kpis: {
      typicalDwellTime: "Hours to Weeks",
      containmentSla: "< 30 minutes",
      falsePositiveRate: "Low (< 2%)",
    },
    alwaysRules: [
      "Freeze all automated CI/CD deployments until SBOM (Software Bill of Materials) verification passes.",
      "Check artifact repository proxy cache (Nexus / Artifactory) to block downloading of compromised package versions.",
      "Inspect build server environment variables for stolen AWS/SSH deployment secrets.",
    ],
    neverRules: [
      "Never push quick fixes directly to production without testing compatibility and verifying clean package hashes.",
      "Never rely on SemVer ranges (^ or ~) in package.json/requirements.txt during incident remediation.",
      "Never run npm install or pip install on developer workstations with the compromised package version.",
    ],
    steps: [
      {
        id: "sc-1",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Identify exact package name, compromised version range, and advisory CVE identifiers.",
        pivot: { to: "/intel", label: "Intel Hub" },
        guidance: "Verify whether vulnerable code path is invoked by application logic or is dormant.",
      },
      {
        id: "sc-2",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Query internal SBOM and dependency graphs to identify every service, repository, and container image referencing the package.",
        pivot: { to: "/diff", label: "Diff Workbench" },
        guidance: "Compare lockfiles (package-lock.json, poetry.lock, Cargo.lock) before and after incident window.",
      },
      {
        id: "sc-3",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Blacklist package version in internal registry proxies (Artifactory, Nexus) and pause CI/CD build runners.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Prevent any developer or automated build from pulling the poisoned dependency artifact.",
      },
      {
        id: "sc-4",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Rotate all secrets, API tokens, and private keys exposed to build containers during compilation.",
        guidance: "Malicious supply chain packages commonly exfiltrate environment variables (AWS_SECRET_KEY, GITHUB_TOKEN) during postinstall.",
      },
      {
        id: "sc-5",
        phase: "eradication",
        phaseLabel: "Eradication",
        criticality: "mandatory",
        text: "Pin dependency to verified clean upstream version or implement vendor-supplied patch; re-compile clean artifacts.",
        guidance: "Verify cryptographic SHA512 hash of downloaded package matches clean registry baseline.",
      },
      {
        id: "sc-6",
        phase: "recovery",
        phaseLabel: "Recovery",
        criticality: "recommended",
        text: "Re-deploy sanitized containers and run vulnerability scanner (Trivy / Snyk) to confirm 0 high-severity CVEs.",
        guidance: "Gradually promote clean builds through staging to production with enhanced runtime anomaly detection.",
      },
      {
        id: "sc-7",
        phase: "post_incident",
        phaseLabel: "Post-Incident Review",
        criticality: "recommended",
        text: "Establish automated dependency review policy, enforce signed commits, and mandate locked hash verification.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Document incident details, supplier breach timeline, and notify compliance stakeholders.",
      },
    ],
  },
  {
    id: "lateral-movement-smb",
    title: "Lateral Movement via SMB / WMI / PsExec",
    shortName: "Lateral Movement",
    severity: "P1",
    eta: "20 min",
    targetMtrMinutes: 20,
    category: "Network",
    iconName: "ShieldAlert",
    summary: "Adversary traversing subnet boundaries using privileged credentials via SMB admin shares (ADMIN$, C$), WMI remote execution, or PsExec service installs.",
    objective: "Identify the patient zero foothold, sever lateral hops, terminate rogue service executions, and isolate intermediate staging jump boxes.",
    escalationTrigger: "Logon Type 3 followed by Event ID 7045 or 4697 on multiple target servers within short window.",
    attack: ["T1021.002", "T1047", "T1570", "T1021.006", "T1078"],
    kpis: {
      typicalDwellTime: "30 minutes - 4 hours",
      containmentSla: "< 20 minutes",
      falsePositiveRate: "Low (< 2%)",
    },
    alwaysRules: [
      "Correlate Windows Event 4624 (Logon Type 3) with source IP and target workstation name.",
      "Check ADMIN$ and IPC$ share access events (Event ID 5140 and 5145).",
      "Isolate both source and destination endpoints while auditing authentication chains.",
    ],
    neverRules: [
      "Never use Domain Admin credentials to log in interactively to a suspected compromised machine.",
      "Never ignore PsExec-like service creation events (PSEXESVC.exe) in Windows Event 7045.",
      "Never reboot without checking for staged payloads in \\Windows\\System32 or \\Windows\\Temp.",
    ],
    steps: [
      {
        id: "lm-1",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Correlate Event ID 4624 (Type 3 Network Logon) with subsequent Event ID 7045 (New Service Installed) in SIEM.",
        pivot: { to: "/siem", label: "Mini SIEM Query" },
        guidance: "Look for service binaries located in C:\\Windows\\Temp\\*.exe or random names like a8b4.exe.",
      },
      {
        id: "lm-2",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Audit WMI process creation (Sysmon Event ID 1: wmic.exe process call create or wmiprvse.exe parentage).",
        pivot: { to: "/logs", label: "Windows Event Logs" },
        guidance: "Adversaries use WMI to execute commands silently without writing service artifacts to disk.",
      },
      {
        id: "lm-3",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Isolate patient-zero host and all target endpoints reached via the lateral movement path.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Block workstation-to-workstation SMB (TCP 445) and RPC (TCP 135) at host firewall level.",
      },
      {
        id: "lm-4",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Disable compromised account used for the network logon; purge Kerberos tickets and invalidate active sessions.",
        guidance: "If a local administrator account was used, change the local admin password on all endpoints immediately.",
      },
      {
        id: "lm-5",
        phase: "eradication",
        phaseLabel: "Eradication",
        criticality: "mandatory",
        text: "Delete rogue service binaries, purge remote scheduled tasks (at.exe, schtasks), and verify registry run keys.",
        guidance: "Check for remnant PsExec service executables (PSEXESVC.exe) in C:\\Windows.",
      },
      {
        id: "lm-6",
        phase: "recovery",
        phaseLabel: "Recovery",
        criticality: "recommended",
        text: "Deploy Microsoft LAPS (Local Administrator Password Solution) and enforce Tiered Administration Model.",
        guidance: "Ensure workstation admins cannot log in to servers, and server admins cannot log in to domain controllers.",
      },
      {
        id: "lm-7",
        phase: "post_incident",
        phaseLabel: "Post-Incident Review",
        criticality: "recommended",
        text: "Deploy Sigma rules for PsExec service creation and lateral WMI execution across detection stack.",
        pivot: { to: "/detection", label: "Detection Rule Editor" },
        guidance: "Enforce network segmentation restricting SMB traffic strictly between clients and dedicated file servers.",
      },
    ],
  },
  {
    id: "dns-tunnel-exfil",
    title: "Data Exfiltration via Encrypted DNS Tunneling",
    shortName: "DNS Tunneling",
    severity: "P1",
    eta: "20 min",
    targetMtrMinutes: 20,
    category: "Network",
    iconName: "ShieldAlert",
    summary: "Mass volume of high-entropy DNS queries (TXT, CNAME, NULL records) with base64/hex-encoded subdomain labels exfiltrating sensitive organizational data.",
    objective: "Detect covert DNS channels, identify exfiltrating internal client IP, sinkhole tunnel domain, and calculate total stolen data volume.",
    escalationTrigger: "Internal DNS resolver processing >1,000 queries per minute to a single foreign root domain.",
    attack: ["T1572", "T1048.003", "T1071.004", "T1560.001"],
    kpis: {
      typicalDwellTime: "1 - 8 hours",
      containmentSla: "< 20 minutes",
      falsePositiveRate: "Low (< 3% Antivirus Telemetry)",
    },
    alwaysRules: [
      "Capture DNS PCAP packets to calculate Shannon entropy and aggregate byte volume transferred.",
      "Identify the internal host generating the queries before applying broad DNS drops.",
      "Sinkhole domain at internal DNS recursors and upstream cloud resolver.",
    ],
    neverRules: [
      "Never flush DNS server logs or restart DNS service before saving query audit logs.",
      "Never assume DNS cannot be used for bidirectional command-and-control.",
      "Never permit internal endpoints to bypass internal DNS servers to query public resolvers directly.",
    ],
    steps: [
      {
        id: "dt-1",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Analyze DNS query log spikes: filter by highest query count, unusual record types (TXT, NULL), and high label length.",
        pivot: { to: "/siem", label: "Mini SIEM Query" },
        guidance: "Look for domains with >50 unique subdomains per minute where subdomains exceed 30 alphanumeric characters.",
      },
      {
        id: "dt-2",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Reconstruct and decode encoded subdomain payloads using CyberChef to determine nature of exfiltrated data.",
        pivot: { to: "/chef", label: "CyberChef Workbench" },
        guidance: "Common tunnel tools (dnscat2, iodine) use hex or modified base64 encoding with sequence numbers.",
      },
      {
        id: "dt-3",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Configure Response Policy Zone (RPZ) or DNS sinkhole on internal resolvers returning NXDOMAIN for the root domain.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Ensure both internal corporate DNS servers and DHCP-assigned resolvers enforce the sinkhole.",
      },
      {
        id: "dt-4",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Quarantine originating internal IP; block outbound UDP/TCP port 53 to the Internet at the perimeter firewall.",
        guidance: "Internal workstations must never be allowed to query 8.8.8.8 or external DNS resolvers directly.",
      },
      {
        id: "dt-5",
        phase: "eradication",
        phaseLabel: "Eradication",
        criticality: "mandatory",
        text: "Identify process executing tunnel queries (e.g. dnscat2 client, Cobalt Strike DNS stager) and terminate PID.",
        pivot: { to: "/logs", label: "Windows Event Logs" },
        guidance: "Check process network connections in Sysmon Event ID 3 (NetworkConnect to port 53).",
      },
      {
        id: "dt-6",
        phase: "recovery",
        phaseLabel: "Recovery",
        criticality: "recommended",
        text: "Calculate estimated exfiltration data volume from total query count multiplied by average subdomain payload size.",
        guidance: "A standard DNS query exfiltrates ~60-120 bytes of payload per query; 100k queries ≈ 8-12 MB of compressed data.",
      },
      {
        id: "dt-7",
        phase: "post_incident",
        phaseLabel: "Post-Incident Review",
        criticality: "recommended",
        text: "Deploy DNS entropy inspection heuristics and Suricata/Snort detection for DNS tunnel signatures.",
        pivot: { to: "/detection", label: "Detection Rule Editor" },
        guidance: "Add threshold alerting for any domain with >200 unique subdomains in 5 minutes.",
      },
    ],
  },
  {
    id: "vpn-spray-surge",
    title: "Distributed VPN / SSH Credential Stuffing & Password Spray",
    shortName: "VPN Password Spray",
    severity: "P2",
    eta: "15 min",
    targetMtrMinutes: 15,
    category: "Network",
    iconName: "Lock",
    summary: "Large-scale automated authentication barrage across enterprise VPN or SSH gateway from distributed residential proxies and VPN ranges.",
    objective: "Block rotating adversary IP ranges, identify any successful authentication events, enforce conditional access, and reset compromised credentials.",
    escalationTrigger: "Successful authentication recorded from an IP address previously involved in failed brute force attempts.",
    attack: ["T1110.001", "T1110.003", "T1110.004", "T1078"],
    kpis: {
      typicalDwellTime: "20 minutes - 2 hours",
      containmentSla: "< 15 minutes",
      falsePositiveRate: "Low (< 2%)",
    },
    alwaysRules: [
      "Aggregate failed authentications by targeted username and originating source ASN.",
      "Check for successful logons immediately following a string of failed attempts.",
      "Apply geo-blocking or rate-limiting at edge perimeter gateway.",
    ],
    neverRules: [
      "Never assume failure codes mean total safety without verifying subsequent successful logons.",
      "Never disable account lockout policies without compensating WAF/CAPTCHA protection.",
      "Never allow legacy single-factor authentication (PAP/CHAP/MSCHAPv2) on public VPN gateways.",
    ],
    steps: [
      {
        id: "vs-1",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Analyze VPN/RADIUS authentication logs: calculate failure-to-success ratio and identify targeted account list.",
        pivot: { to: "/siem", label: "Mini SIEM Query" },
        guidance: "Spray attacks target many usernames with 1-2 common passwords (e.g. Autumn2024!) to evade lockouts.",
      },
      {
        id: "vs-2",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Correlate failed source IPs against Threat Intel Hub to identify residential proxy networks or known botnets.",
        pivot: { to: "/intel", label: "Intel Hub" },
        guidance: "Extract IOCs directly to locker for cross-case correlation.",
      },
      {
        id: "vs-3",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Apply temporary rate-limiting and dynamic IP ban on offending subnets at firewall perimeter.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Implement Fail2ban or edge Cloudflare / Palo Alto dynamic blocklist.",
      },
      {
        id: "vs-4",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Audit every account with a successful logon from spray source IPs; force immediate session termination and password reset.",
        guidance: "Check if the successful login prompted and passed MFA, or if legacy auth protocols bypassed MFA.",
      },
      {
        id: "vs-5",
        phase: "eradication",
        phaseLabel: "Eradication",
        criticality: "mandatory",
        text: "Disable legacy authentication protocols (Basic Auth, ActiveSync, IMAP) on perimeter identity endpoints.",
        guidance: "Enforce modern authentication requiring MFA claims for all VPN and SSO connections.",
      },
      {
        id: "vs-6",
        phase: "recovery",
        phaseLabel: "Recovery",
        criticality: "recommended",
        text: "Verify account lockout thresholds and monitor authentication success rate for the next 24 hours.",
        guidance: "Ensure unlocked accounts resume normal operations without residual lockouts.",
      },
      {
        id: "vs-7",
        phase: "post_incident",
        phaseLabel: "Post-Incident Review",
        criticality: "recommended",
        text: "Implement Conditional Access policies mandating managed device compliance or FIDO2 tokens for external access.",
        pivot: { to: "/snippets", label: "Query Arsenal" },
        guidance: "Add continuous SIEM monitoring query for password spray detection (>10 distinct users from single IP in 10m).",
      },
    ],
  },
  {
    id: "insider-exfiltration",
    title: "Insider Threat Mass Data Scraping & DLP Exfiltration",
    shortName: "Insider Exfiltration",
    severity: "P2",
    eta: "25 min",
    targetMtrMinutes: 25,
    category: "Insider",
    iconName: "User",
    summary: "Internal authenticated user downloading gigabytes of proprietary documents, customer PII, or source code outside normal business hours.",
    objective: "Preserve legally defensible forensic evidence, revoke account access, secure local endpoint hardware, and notify HR and Legal counsel.",
    escalationTrigger: "Employee under notice or PIP downloading >10x daily baseline document volume or uploading to personal cloud.",
    attack: ["T1078", "T1530", "T1213", "T1567.002"],
    kpis: {
      typicalDwellTime: "Hours to Days",
      containmentSla: "< 25 minutes",
      falsePositiveRate: "Medium (~10% Business Backup)",
    },
    alwaysRules: [
      "Maintain chain of custody and preserve all audit logs without tipping off the suspected employee.",
      "Coordinate with Legal and People Ops before disabling account access or seizing physical hardware.",
      "Verify whether download volume aligns with documented business responsibilities.",
    ],
    neverRules: [
      "Never confront the suspected employee before remote session logs and cloud audit records are secured.",
      "Never alter timestamps or edit files on the user's workstation.",
      "Never execute remote wipe on personal mobile devices without legal authorization.",
    ],
    steps: [
      {
        id: "in-1",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Inspect DLP and SharePoint / Google Drive audit telemetry for mass download events, zip archive creation, or USB mounts.",
        pivot: { to: "/siem", label: "Mini SIEM Query" },
        guidance: "Query events: FileDownloaded, MassDownload, UsbDriveMounted, CloudStorageUpload.",
      },
      {
        id: "in-2",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Review user's role, recent termination notices, or HR performance status through secure management channels.",
        guidance: "Check if the employee recently submitted resignation or is undergoing role restructuring.",
      },
      {
        id: "in-3",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Revoke corporate account credentials, disable active VPN and SSO sessions, and restrict email access.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Execute credential suspension synchronously with physical workstation containment.",
      },
      {
        id: "in-4",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Remotely lock and freeze the corporate laptop; disable remote desktop connection capabilities.",
        guidance: "Preserve bitstream disk image and volatile RAM before laptop undergoes any reboot or hardware wipe.",
      },
      {
        id: "in-5",
        phase: "eradication",
        phaseLabel: "Eradication",
        criticality: "mandatory",
        text: "Audit destination cloud storage endpoints (personal Dropbox, Mega, Google Drive) and revoke any shared public links.",
        guidance: "Inspect browser history and upload POST requests to identify external file destination URLs.",
      },
      {
        id: "in-6",
        phase: "recovery",
        phaseLabel: "Recovery",
        criticality: "recommended",
        text: "Deliver formal forensic report to Legal and General Counsel detailing document inventory and timestamps.",
        guidance: "Document exact file paths, MD5/SHA256 hashes, file sizes, and classifications (Confidential, Trade Secret, PII).",
      },
      {
        id: "in-7",
        phase: "post_incident",
        phaseLabel: "Post-Incident Review",
        criticality: "recommended",
        text: "Refine DLP policy rules to block uploads to unapproved personal storage services and USB mass storage devices.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Implement strict CASB (Cloud Access Security Broker) controls on corporate-managed devices.",
      },
    ],
  },
  {
    id: "macro-attachment",
    title: "Weaponized Office Macro / OneNote Payload Ingestion",
    shortName: "Macro Attachment",
    severity: "P2",
    eta: "20 min",
    targetMtrMinutes: 20,
    category: "Malware",
    iconName: "FileWarning",
    summary: "User received email with weaponized attachment (.docm, .xlsm, .one, .vbs) designed to spawn PowerShell or cmd.exe upon opening.",
    objective: "Quarantine email message, detonate payload in sandbox, extract dropped stage-2 hashes, and verify endpoint did not execute payload.",
    escalationTrigger: "Parent process winword.exe, excel.exe, or onenote.exe spawning powershell.exe, cmd.exe, or mshta.exe.",
    attack: ["T1204.002", "T1059.001", "T1059.005", "T1566.001"],
    kpis: {
      typicalDwellTime: "5 - 30 minutes",
      containmentSla: "< 20 minutes",
      falsePositiveRate: "Very Low (< 1%)",
    },
    alwaysRules: [
      "Quarantine attachment at mail gateway before employee clicks or enables content.",
      "Analyze VBA macros using static analysis tools (olevba, ViperMonkey) without executing on triage machine.",
      "Check EDR telemetry for any process execution spawned by Office executables.",
    ],
    neverRules: [
      "Never click 'Enable Content' or 'Enable Editing' in Microsoft Office on an uncontained endpoint.",
      "Never upload confidential customer files to public sandbox multi-tenant environments.",
      "Never permit outbound macro execution in production Office baseline policies.",
    ],
    steps: [
      {
        id: "ma-1",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Extract attachment from email, calculate MD5/SHA256, and inspect embedded VBA macro code.",
        pivot: { to: "/attachment", label: "Attachment Triage" },
        guidance: "Look for AutoOpen, Document_Open, Workbook_Open, Shell, and WScript.Shell invocation routines.",
      },
      {
        id: "ma-2",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Deobfuscate obfuscated string arrays and character chr() concatenation routines using CyberChef.",
        pivot: { to: "/chef", label: "CyberChef Workbench" },
        guidance: "Adversaries use string reversal, base64, and XOR to hide the C2 staging URL inside the macro body.",
      },
      {
        id: "ma-3",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Purge email and attachment from all recipient mailboxes across the organization.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Execute mail search by attachment SHA256 and subject line.",
      },
      {
        id: "ma-4",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Block C2 staging URLs and payload delivery domains at perimeter proxy and web gateway.",
        pivot: { to: "/url", label: "Safe URL Analyzer" },
        guidance: "Extract URLs from macro strings and add them to URL blocklists immediately.",
      },
      {
        id: "ma-5",
        phase: "eradication",
        phaseLabel: "Eradication",
        criticality: "mandatory",
        text: "Verify endpoint did not execute stage-2 stager: query SIEM for Sysmon Event ID 1 where ParentImage is WINWORD.EXE.",
        pivot: { to: "/siem", label: "Mini SIEM Query" },
        guidance: "If execution occurred, isolate endpoint immediately and escalate to Malware Outbreak runbook.",
      },
      {
        id: "ma-6",
        phase: "recovery",
        phaseLabel: "Recovery",
        criticality: "recommended",
        text: "Verify Group Policy mandates 'Block macros from running in Office files from the Internet' (Mark of the Web enforcement).",
        guidance: "Enforce modern ASR (Attack Surface Reduction) rule: 'Block all Office applications from creating child processes'.",
      },
      {
        id: "ma-7",
        phase: "post_incident",
        phaseLabel: "Post-Incident Review",
        criticality: "recommended",
        text: "Add YARA rule for macro code patterns and author Sigma rule for Office child process spawning.",
        pivot: { to: "/sigma-tester", label: "Sigma Tester" },
        guidance: "Test Sigma rule logic against recent EDR logs to ensure zero false positive production alert noise.",
      },
    ],
  },
  {
    id: "ddos-syn-flood",
    title: "Distributed Denial of Service (DDoS) & Volumetric Attack",
    shortName: "DDoS Defense",
    severity: "P3",
    eta: "30 min",
    targetMtrMinutes: 30,
    category: "Network",
    iconName: "Activity",
    summary: "Perimeter bandwidth saturation or application exhaustion attack (SYN flood, DNS amplification, HTTP GET/POST flood) degrading services.",
    objective: "Engage cloud scrubbers, mitigate Layer 7 application abuse, preserve legitimate traffic, and maintain service availability.",
    escalationTrigger: "Inbound traffic exceeding 80% of upstream transit capacity or edge web server HTTP 503 response rate > 20%.",
    attack: ["T1498.001", "T1498.002", "T1499.001", "T1499.002"],
    kpis: {
      typicalDwellTime: "30 minutes - 6 hours",
      containmentSla: "< 30 minutes",
      falsePositiveRate: "Very Low (< 1%)",
    },
    alwaysRules: [
      "Engage upstream cloud DDoS mitigation provider (Cloudflare, AWS Shield, Akamai) early.",
      "Distinguish Layer 3/4 volumetric saturation from Layer 7 application resource exhaustion.",
      "Verify origin IP address is not publicly exposed or directly queryable via historical DNS records.",
    ],
    neverRules: [
      "Never attempt to absorb multi-gigabit volumetric DDoS on local on-premise firewall appliances.",
      "Never restart web services repeatedly under load without applying upstream rate-limiting.",
      "Never blackhole all incoming traffic if selective geolocation or challenge shielding is available.",
    ],
    steps: [
      {
        id: "dd-1",
        phase: "detection",
        phaseLabel: "Detection & Analysis",
        criticality: "mandatory",
        text: "Capture network telemetry and inspect traffic profiles: determine whether attack is Layer 4 (SYN, UDP) or Layer 7 (HTTP Flood).",
        pivot: { to: "/pcap", label: "PCAP Stream Analyzer" },
        guidance: "Look for high SYN/ACK ratio or uniform HTTP User-Agents hitting expensive search or login endpoints.",
      },
      {
        id: "dd-2",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Activate Cloudflare Under Attack Mode / AWS Shield Advanced mitigation with JavaScript challenges.",
        pivot: { to: "/case", label: "Case Workbench" },
        guidance: "Challenge-response (Turnstile / CAPTCHA) filters automated bot traffic before reaching origin servers.",
      },
      {
        id: "dd-3",
        phase: "containment",
        phaseLabel: "Containment",
        criticality: "mandatory",
        text: "Implement rate-limiting rules at reverse proxy (Nginx / Envoy) for expensive API paths (/api/search, /auth/login).",
        guidance: "Limit requests to 10 req/sec per IP address with burst allowances.",
      },
      {
        id: "dd-4",
        phase: "eradication",
        phaseLabel: "Eradication",
        criticality: "mandatory",
        text: "Verify origin server firewall only allows inbound connections from designated cloud scrubber IP ranges.",
        guidance: "Adversaries bypass WAF by sending direct traffic to origin IP discovered in historic MX or SPF records.",
      },
      {
        id: "dd-5",
        phase: "recovery",
        phaseLabel: "Recovery",
        criticality: "recommended",
        text: "Monitor edge throughput, HTTP response codes, and database CPU utilization as traffic normalizes.",
        guidance: "Gradually ease Under Attack mode to standard managed challenge mode once attack packet rate drops.",
      },
      {
        id: "dd-6",
        phase: "post_incident",
        phaseLabel: "Post-Incident Review",
        criticality: "recommended",
        text: "Rotate origin IP address if origin was discovered; update DNS records with proxied CNAME records.",
        guidance: "Document peak gigabits per second (Gbps) and millions of packets per second (Mpps) for infrastructure capacity planning.",
      },
    ],
  },
];

export interface SopCatalogMetrics {
  totalRunbooks: number;
  p1Count: number;
  p2Count: number;
  p3Count: number;
  avgMtrMinutes: number;
  uniqueMitreTechniques: number;
  totalSteps: number;
  categoryBreakdown: Record<string, number>;
}

export function calculateSopCatalogMetrics(runbooks: SopRunbook[] = SOP_RUNBOOKS): SopCatalogMetrics {
  const totalRunbooks = runbooks.length;
  let p1Count = 0;
  let p2Count = 0;
  let p3Count = 0;
  let totalMtr = 0;
  let totalSteps = 0;
  const mitreSet = new Set<string>();
  const categoryBreakdown: Record<string, number> = {};

  for (const r of runbooks) {
    if (r.severity === "P1") p1Count++;
    else if (r.severity === "P2") p2Count++;
    else p3Count++;

    totalMtr += r.targetMtrMinutes;
    totalSteps += r.steps.length;

    r.attack.forEach((t) => mitreSet.add(t));
    categoryBreakdown[r.category] = (categoryBreakdown[r.category] || 0) + 1;
  }

  const avgMtrMinutes = totalRunbooks > 0 ? Math.round(totalMtr / totalRunbooks) : 0;

  return {
    totalRunbooks,
    p1Count,
    p2Count,
    p3Count,
    avgMtrMinutes,
    uniqueMitreTechniques: mitreSet.size,
    totalSteps,
    categoryBreakdown,
  };
}

/**
 * Creates a real incident case from a SOP runbook, populating NIST SP 800-61 phase entries,
 * action items, severity, tags, and MITRE references ready for investigation.
 */
export function instantiateCaseFromSop(runbook: SopRunbook, titlePrefix?: string): Case {
  const now = new Date().toISOString();
  const caseId = newId("case");
  const caseTitle = titlePrefix?.trim()
    ? `${titlePrefix.trim()} — ${runbook.shortName}`
    : `${runbook.shortName} Incident - ${newCaseTitle()}`;

  const sevMapping: Record<"P1" | "P2" | "P3", Severity> = {
    P1: "critical",
    P2: "high",
    P3: "medium",
  };

  const initialEntries: Entry[] = [
    {
      id: newId("entry"),
      ts: now,
      kind: "decision" as EntryKind,
      body: `[INITIATED FROM SOP] ${runbook.title}\nSeverity: ${runbook.severity} | Target SLA: ~${runbook.eta}\nObjective: ${runbook.objective}\nEscalation Trigger: ${runbook.escalationTrigger}`,
    },
    {
      id: newId("entry"),
      ts: now,
      kind: "note" as EntryKind,
      body: `## Operational Guardrails\n### Always\n${runbook.alwaysRules.map((r) => `- ${r}`).join("\n")}\n\n### Never\n${runbook.neverRules.map((r) => `- ${r}`).join("\n")}`,
    },
  ];

  // Group steps by phase and add initial action checklist entries
  const groupedByPhase: Record<string, SopStep[]> = {};
  for (const step of runbook.steps) {
    if (!groupedByPhase[step.phaseLabel]) groupedByPhase[step.phaseLabel] = [];
    groupedByPhase[step.phaseLabel].push(step);
  }

  for (const [phaseLabel, steps] of Object.entries(groupedByPhase)) {
    const checklistBody = `### Checklist: ${phaseLabel}\n` +
      steps.map((s, idx) => `[ ] ${idx + 1}. [${s.criticality.toUpperCase()}] ${s.text}${s.pivot ? ` (Pivot: ${s.pivot.label})` : ""}`).join("\n");

    initialEntries.push({
      id: newId("entry"),
      ts: now,
      kind: "action" as EntryKind,
      body: checklistBody,
    });
  }

  const tags = [
    `sop:${runbook.id}`,
    `severity:${runbook.severity.toLowerCase()}`,
    `cat:${runbook.category.toLowerCase()}`,
    ...runbook.attack.map((t) => `mitre:${t.toLowerCase()}`),
    "nist-sp-800-61",
  ];

  const createdCase: Case = {
    id: caseId,
    title: caseTitle,
    tags,
    createdAt: now,
    state: "active",
    entries: initialEntries,
    events: [
      {
        id: crypto.randomUUID(),
        ts: now,
        kind: "case_created",
        category: "case",
        importance: runbook.severity === "P1" ? "critical" : "high",
        actor: "analyst",
        origin: "Analyst Field Guide (SOP)",
        title: `Incident Case Initiated from SOP: ${runbook.shortName}`,
        detail: `Runbook: ${runbook.title}. ${runbook.steps.length} NIST checklist items staged.`,
        references: [],
      },
    ],
  };

  return createdCase;
}

/**
 * Generates an audit-ready Markdown document of the SOP runbook with current completion state.
 */
export function exportSopRunbookMarkdown(runbook: SopRunbook, doneStepIds: Set<string>): string {
  const completedCount = runbook.steps.filter((s) => doneStepIds.has(s.id)).length;
  const progressPercent = Math.round((completedCount / runbook.steps.length) * 100);

  const lines = [
    `# SOC Incident Response SOP: ${runbook.title}`,
    "",
    `**Standard Operating Procedure ID:** \`${runbook.id}\`  `,
    `**Severity Classification:** **${runbook.severity}** | **Category:** ${runbook.category} | **Target SLA:** ${runbook.eta}  `,
    `**NIST SP 800-61r2 Execution Progress:** ${completedCount} of ${runbook.steps.length} steps completed (${progressPercent}%)  `,
    `**MITRE ATT&CK Mapping:** ${runbook.attack.map((t) => `\`${t}\``).join(", ")}  `,
    `**Export Timestamp:** ${new Date().toISOString()}  `,
    "",
    "---",
    "",
    "## 1. Executive Summary & Objective",
    "",
    runbook.summary,
    "",
    `**Primary Objective:** ${runbook.objective}`,
    "",
    `**Immediate Escalation Trigger:** ${runbook.escalationTrigger}`,
    "",
    "## 2. Operational Guardrails",
    "",
    "### Mandatory Protocols (Always)",
    ...runbook.alwaysRules.map((r) => `- [x] ${r}`),
    "",
    "### Prohibited Actions (Never)",
    ...runbook.neverRules.map((r) => `- [!] **DO NOT:** ${r}`),
    "",
    "## 3. Incident Response Checklist (NIST SP 800-61 Lifecycle)",
    "",
  ];

  const phases: SopPhase[] = ["preparation", "detection", "containment", "eradication", "recovery", "post_incident"];

  for (const phase of phases) {
    const phaseSteps = runbook.steps.filter((s) => s.phase === phase);
    if (phaseSteps.length === 0) continue;

    const phaseConfig = SOP_PHASE_CONFIG[phase];
    lines.push(`### ${phaseConfig.label}`);
    lines.push("");

    for (const step of phaseSteps) {
      const isDone = doneStepIds.has(step.id);
      const mark = isDone ? "[x]" : "[ ]";
      const pivotText = step.pivot ? ` *(Pivot: ${step.pivot.label} -> \`${step.pivot.to}\`)*` : "";
      lines.push(`- ${mark} **[${step.criticality.toUpperCase()}]** ${step.text}${pivotText}`);
      if (step.guidance) {
        lines.push(`  > *Guidance:* ${step.guidance}`);
      }
    }
    lines.push("");
  }

  lines.push("---");
  lines.push("## 4. Telemetry Benchmarks");
  lines.push(`- **Typical Dwell Time:** ${runbook.kpis.typicalDwellTime}`);
  lines.push(`- **Target Containment SLA:** ${runbook.kpis.containmentSla}`);
  lines.push(`- **Historical False Positive Likelihood:** ${runbook.kpis.falsePositiveRate}`);
  lines.push("");

  return lines.join("\n");
}
