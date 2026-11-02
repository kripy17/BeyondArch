import type { Severity } from "@/lib/severity";
import { newId } from "@/data/case";

export type PlaybookCategory = "email" | "endpoint" | "network" | "cloud" | "forensics";
export type AutomationLevel = "automated" | "semi-automated" | "manual";

export interface PlaybookStep {
  id: string;
  title: string;
  description: string;
  actionType: "api_call" | "tool_dispatch" | "analyst_verification" | "quarantine" | "notification";
  targetParam?: string;
  toolRoute?: string;
  estimatedSeconds: number;
}

export interface PlaybookInputDef {
  id: string;
  label: string;
  placeholder: string;
  defaultValue?: string;
  description?: string;
}

export interface Playbook {
  id: string;
  title: string;
  category: PlaybookCategory;
  severity: Severity;
  description: string;
  estimatedRuntime: string;
  automationLevel: AutomationLevel;
  mitreTactics: string[];
  requiredInputs: PlaybookInputDef[];
  steps: PlaybookStep[];
}

export interface PlaybookRunRecord {
  id: string;
  playbookId: string;
  playbookTitle: string;
  status: "in_progress" | "completed" | "failed";
  startedAt: string;
  completedAt?: string;
  analyst: string;
  inputs: Record<string, string>;
  stepsCompleted: number;
  totalSteps: number;
  logs: string[];
  caseId?: string;
}

export const SOAR_PLAYBOOKS: Playbook[] = [
  {
    id: "phishing-purge",
    title: "Phishing Auto-Triage & Mailbox Remediation",
    category: "email",
    severity: "high",
    description: "Automated verification of email SPF/DKIM/DMARC headers, URL detonation, message-trace tenant querying, and multi-inbox purge.",
    estimatedRuntime: "35s",
    automationLevel: "automated",
    mitreTactics: ["TA0001 (Initial Access)", "T1566.002 (Spearphishing Link)"],
    requiredInputs: [
      { id: "sender", label: "Sender Address", placeholder: "attacker@spoofed-bank.com", defaultValue: "security-alert@service-verify.net" },
      { id: "subject", label: "Email Subject", placeholder: "Urgent: Account Verification Required", defaultValue: "Urgent Action Required: Executive Handoff" },
      { id: "url", label: "Embedded URL", placeholder: "https://login-auth-verify.workers.dev/login", defaultValue: "https://auth-portal.azurelogin-sso.workers.dev/login" },
    ],
    steps: [
      {
        id: "step-1",
        title: "Extract Header & Sender Authenticity",
        description: "Parse RFC 822 headers; verify SPF, DKIM signature, and DMARC alignment status.",
        actionType: "tool_dispatch",
        toolRoute: "/parser",
        targetParam: "sender",
        estimatedSeconds: 5,
      },
      {
        id: "step-2",
        title: "Detonate Suspicious URLs & Check Threat Intel",
        description: "Submit embedded URL to sandbox detonation crawler and query URLhaus / VirusTotal threat feeds.",
        actionType: "tool_dispatch",
        toolRoute: "/intel",
        targetParam: "url",
        estimatedSeconds: 8,
      },
      {
        id: "step-3",
        title: "Query O365 / Google Workspace Message Trace",
        description: "Execute tenant-wide message trace using sender IP and subject regex to identify all recipient mailboxes.",
        actionType: "api_call",
        targetParam: "subject",
        estimatedSeconds: 7,
      },
      {
        id: "step-4",
        title: "Execute Automated Soft-Delete Across Inboxes",
        description: "Issue administrative PowerShell / Graph API batch HardDelete command to remove message from user mailboxes.",
        actionType: "quarantine",
        estimatedSeconds: 6,
      },
      {
        id: "step-5",
        title: "Update Mail Gateway & DNS Sinkhole",
        description: "Push sender domain to Secure Email Gateway (SEG) blackhole and DNS RPZ blocklist.",
        actionType: "api_call",
        estimatedSeconds: 4,
      },
      {
        id: "step-6",
        title: "Append Telemetry to Incident Case",
        description: "Attach defanged IOCs, purge recipient count, and remediation receipt to active case dossier.",
        actionType: "notification",
        toolRoute: "/case",
        estimatedSeconds: 5,
      },
    ],
  },
  {
    id: "ransomware-containment",
    title: "Ransomware Outbreak Host Isolation & VSS Rollback",
    category: "endpoint",
    severity: "critical",
    description: "Rapid endpoint isolation, process tree termination, Volume Shadow Copy preservation, and domain Kerberos session invalidation.",
    estimatedRuntime: "1m 15s",
    automationLevel: "semi-automated",
    mitreTactics: ["TA0040 (Impact)", "T1486 (Data Encrypted for Impact)", "T1490 (Inhibit System Recovery)"],
    requiredInputs: [
      { id: "hostname", label: "Impacted Hostname", placeholder: "SRV-FIN-PRD01", defaultValue: "SRV-FIN-PRD02" },
      { id: "ip", label: "Endpoint IP", placeholder: "10.14.3.45", defaultValue: "10.14.3.45" },
      { id: "maliciousProcess", label: "Detected Binary / PID", placeholder: "encsvc.exe (PID: 4920)", defaultValue: "encsvc.exe" },
    ],
    steps: [
      {
        id: "step-1",
        title: "Validate Hostname & Patient-Zero Telemetry",
        description: "Verify host active status and correlate endpoint sensor with DHCP/Active Directory computer records.",
        actionType: "api_call",
        targetParam: "hostname",
        estimatedSeconds: 10,
      },
      {
        id: "step-2",
        title: "Trigger EDR Network Containment",
        description: "Enforce kernel-level firewall isolation rule; restrict host to SOC management tunnel only.",
        actionType: "quarantine",
        targetParam: "ip",
        estimatedSeconds: 15,
      },
      {
        id: "step-3",
        title: "Terminate Malicious Process Tree",
        description: "Send SIGKILL / TerminateProcess to culprit binary and child command shells.",
        actionType: "api_call",
        targetParam: "maliciousProcess",
        estimatedSeconds: 12,
      },
      {
        id: "step-4",
        title: "Audit & Protect Volume Shadow Copies (VSS)",
        description: "Query vssadmin list shadows; lock existing shadow storage against tamper.",
        actionType: "analyst_verification",
        estimatedSeconds: 15,
      },
      {
        id: "step-5",
        title: "Revoke Domain Kerberos TGT & Rotate Password",
        description: "Force computer account password reset and purge active Kerberos tickets from domain controllers.",
        actionType: "api_call",
        estimatedSeconds: 10,
      },
      {
        id: "step-6",
        title: "Record Cryptographic IOCs in Case Ledger",
        description: "Submit calculated sample hashes and ransom note text to case evidence locker.",
        actionType: "notification",
        toolRoute: "/case",
        estimatedSeconds: 8,
      },
    ],
  },
  {
    id: "c2-perimeter-blackhole",
    title: "C2 Domain Sinkhole & Perimeter Firewall Blackhole",
    category: "network",
    severity: "high",
    description: "Perimeter null-routing, internal NetFlow sweep for beaconing hosts, and automated threat intel indicator tagging.",
    estimatedRuntime: "25s",
    automationLevel: "automated",
    mitreTactics: ["TA0011 (Command and Control)", "T1071.001 (Web Protocols)"],
    requiredInputs: [
      { id: "c2Domain", label: "Adversary C2 Domain / Hostname", placeholder: "beacon.apt-threat.org", defaultValue: "relay-gateway.telemetry-sync.org" },
      { id: "c2Ip", label: "C2 Destination IP", placeholder: "198.51.100.77", defaultValue: "198.51.100.77" },
    ],
    steps: [
      {
        id: "step-1",
        title: "Validate Domain Entropy & Passive DNS",
        description: "Query Whois and passive DNS records to confirm malicious infrastructure registration.",
        actionType: "tool_dispatch",
        toolRoute: "/intel",
        targetParam: "c2Domain",
        estimatedSeconds: 5,
      },
      {
        id: "step-2",
        title: "Push Sinkhole to Enterprise DNS Resolvers",
        description: "Add DNS RPZ response policy returning 127.0.0.1 for target domain and subdomains.",
        actionType: "api_call",
        targetParam: "c2Domain",
        estimatedSeconds: 4,
      },
      {
        id: "step-3",
        title: "Deploy Automated Drop Rule to Perimeter Firewalls",
        description: "Inject destination null-route block in edge Palo Alto / Fortinet security policies.",
        actionType: "quarantine",
        targetParam: "c2Ip",
        estimatedSeconds: 6,
      },
      {
        id: "step-4",
        title: "Search SIEM NetFlow for Internal Communicators",
        description: "Query last 7 days of NetFlow logs to identify all internal source IPs connecting to C2.",
        actionType: "api_call",
        estimatedSeconds: 6,
      },
      {
        id: "step-5",
        title: "Flag Compromised Internal Hosts for Investigation",
        description: "Automatically dispatch triage investigation stubs for every identified internal host.",
        actionType: "notification",
        toolRoute: "/case",
        estimatedSeconds: 4,
      },
    ],
  },
  {
    id: "cloud-iam-revocation",
    title: "Cloud IAM Compromise & Active Session Revocation",
    category: "cloud",
    severity: "critical",
    description: "Rapid invalidation of compromised AWS/Azure IAM access keys, temporary STS tokens, and active administrative console sessions.",
    estimatedRuntime: "40s",
    automationLevel: "automated",
    mitreTactics: ["TA0006 (Credential Access)", "T1078.004 (Cloud Accounts)"],
    requiredInputs: [
      { id: "iamUserArn", label: "Compromised User / Role ARN", placeholder: "arn:aws:iam::123456789012:user/svc-ci", defaultValue: "arn:aws:iam::884920194821:user/svc-github-ci" },
      { id: "accessKeyId", label: "Access Key ID", placeholder: "AKIAIOSFODNN7EXAMPLE", defaultValue: "AKIAIOSFODNN7EXAMPLE" },
    ],
    steps: [
      {
        id: "step-1",
        title: "Identify IAM Role & Query CloudTrail Audit Trail",
        description: "Retrieve last 100 API calls made by principal ARN from AWS CloudTrail / Azure Activity Log.",
        actionType: "api_call",
        targetParam: "iamUserArn",
        estimatedSeconds: 8,
      },
      {
        id: "step-2",
        title: "Deactivate Active IAM Access Key Pairs",
        description: "Execute UpdateAccessKey(Status='Inactive') to instantly terminate programmatic API access.",
        actionType: "quarantine",
        targetParam: "accessKeyId",
        estimatedSeconds: 6,
      },
      {
        id: "step-3",
        title: "Attach Immediate Explicit DenyAll Inline Policy",
        description: "Attach emergency inline IAM policy with effect Deny on *:* to restrict all remaining cached permissions.",
        actionType: "quarantine",
        estimatedSeconds: 8,
      },
      {
        id: "step-4",
        title: "Revoke Active STS AssumeRole Sessions & Tokens",
        description: "Issue RevokeSecurityTokens or set revocation epoch to expire in-flight temporary STS credentials.",
        actionType: "api_call",
        estimatedSeconds: 8,
      },
      {
        id: "step-5",
        title: "Log Audit Record to Case Dossier",
        description: "File revocation receipt, policy JSON, and affected CloudTrail API history to active incident.",
        actionType: "notification",
        toolRoute: "/case",
        estimatedSeconds: 10,
      },
    ],
  },
  {
    id: "memory-forensics-triage",
    title: "Suspicious Process Memory & In-Memory Payload Extraction",
    category: "forensics",
    severity: "medium",
    description: "In-flight process suspension, minidump acquisition, YARA string scanning, and injected shellcode carving.",
    estimatedRuntime: "1m 45s",
    automationLevel: "semi-automated",
    mitreTactics: ["TA0005 (Defense Evasion)", "T1055 (Process Injection)"],
    requiredInputs: [
      { id: "host", label: "Target Hostname", placeholder: "DESKTOP-ENG-988", defaultValue: "DESKTOP-ENG-988" },
      { id: "pid", label: "Process ID (PID)", placeholder: "4812", defaultValue: "3816" },
      { id: "processName", label: "Process Name", placeholder: "powershell.exe", defaultValue: "rundll32.exe" },
    ],
    steps: [
      {
        id: "step-1",
        title: "Suspend Target Process Threads",
        description: "Suspend executing threads to freeze in-memory state and prevent payload anti-forensic wiping.",
        actionType: "quarantine",
        targetParam: "pid",
        estimatedSeconds: 15,
      },
      {
        id: "step-2",
        title: "Capture Process Minidump (.dmp)",
        description: "Generate structured memory dump file using EDR kernel driver.",
        actionType: "api_call",
        targetParam: "host",
        estimatedSeconds: 30,
      },
      {
        id: "step-3",
        title: "Scan Dumped Memory with YARA Rules",
        description: "Execute signature scans across memory sections looking for Cobalt Strike, Metasploit, or custom reflectors.",
        actionType: "tool_dispatch",
        toolRoute: "/chef",
        estimatedSeconds: 25,
      },
      {
        id: "step-4",
        title: "Extract Injected PE Headers & Shellcode",
        description: "Carve unbacked executable memory regions and reconstruct Portable Executable (PE) headers.",
        actionType: "tool_dispatch",
        toolRoute: "/chef",
        estimatedSeconds: 20,
      },
      {
        id: "step-5",
        title: "Register Memory Dump with Chain of Custody",
        description: "Compute SHA256 hash of extracted artifacts and append forensic evidence item to case workbench.",
        actionType: "notification",
        toolRoute: "/case",
        estimatedSeconds: 15,
      },
    ],
  },
];

export const LS_PLAYBOOK_RUNS = "ba.soar.runs.v1";

/** Loads persisted playbook runs from localStorage. */
export function loadPlaybookRuns(): PlaybookRunRecord[] {
  try {
    const raw = localStorage.getItem(LS_PLAYBOOK_RUNS);
    if (!raw) return getDefaultPlaybookRuns();
    return JSON.parse(raw) as PlaybookRunRecord[];
  } catch {
    return getDefaultPlaybookRuns();
  }
}

/** Saves playbook runs list to localStorage. */
export function savePlaybookRuns(runs: PlaybookRunRecord[]) {
  try {
    localStorage.setItem(LS_PLAYBOOK_RUNS, JSON.stringify(runs));
    try {
      window.dispatchEvent(new Event("ba:soar-runs-changed"));
    } catch {
      // non-window
    }
  } catch {
    // noop
  }
}

/** Records a new or updated playbook execution. */
export function recordPlaybookRun(run: PlaybookRunRecord) {
  const existing = loadPlaybookRuns();
  const updated = [run, ...existing.filter((r) => r.id !== run.id)];
  savePlaybookRuns(updated);
}

/** Computes high-level operational telemetry for SOAR playbooks. */
export function calculatePlaybookTelemetry(runs: PlaybookRunRecord[]) {
  const totalPlaybooks = SOAR_PLAYBOOKS.length;
  let totalAutomatedActions = 0;
  for (const p of SOAR_PLAYBOOKS) {
    totalAutomatedActions += p.steps.filter((s) => s.actionType === "api_call" || s.actionType === "quarantine").length;
  }

  const totalRuns = runs.length;
  const completedRuns = runs.filter((r) => r.status === "completed").length;
  const successRate = totalRuns > 0 ? Math.round((completedRuns / totalRuns) * 100) : 100;

  return {
    totalPlaybooks,
    totalAutomatedActions,
    totalRuns,
    completedRuns,
    successRate,
  };
}

/** Formats a completed or running playbook execution into publication-grade Markdown for filing into case notes. */
export function generatePlaybookRunMarkdown(run: PlaybookRunRecord, playbook: Playbook): string {
  const lines: string[] = [];

  lines.push(`### SOAR Playbook Execution: ${playbook.title}`);
  lines.push(`- **Run ID:** \`${run.id}\``);
  lines.push(`- **Status:** **${run.status.toUpperCase()}** (${run.stepsCompleted}/${run.totalSteps} steps)`);
  lines.push(`- **Analyst Actor:** ${run.analyst}`);
  lines.push(`- **Started:** ${run.startedAt}`);
  if (run.completedAt) {
    lines.push(`- **Completed:** ${run.completedAt}`);
  }
  lines.push(`- **Automation Level:** ${playbook.automationLevel.toUpperCase()}`);
  lines.push(`- **MITRE Tactics:** ${playbook.mitreTactics.join(", ")}`);

  lines.push("");
  lines.push("#### Target Parameters & Inputs");
  for (const [k, v] of Object.entries(run.inputs)) {
    lines.push(`- **${k}:** \`${v}\``);
  }

  lines.push("");
  lines.push("#### Execution Log & Step Receipts");
  for (const log of run.logs) {
    lines.push(`- ${log}`);
  }

  return lines.join("\n");
}

function getDefaultPlaybookRuns(): PlaybookRunRecord[] {
  const now = new Date(Date.now() - 3600000).toISOString();
  return [
    {
      id: `run-${newId("soar")}`,
      playbookId: "phishing-purge",
      playbookTitle: "Phishing Auto-Triage & Mailbox Remediation",
      status: "completed",
      startedAt: now,
      completedAt: new Date(Date.now() - 3565000).toISOString(),
      analyst: "Lead SOC SecOps Specialist",
      inputs: {
        sender: "security-alert@service-verify.net",
        subject: "Urgent Action Required: Executive Handoff",
        url: "https://auth-portal.azurelogin-sso.workers.dev/login",
      },
      stepsCompleted: 6,
      totalSteps: 6,
      logs: [
        "[00:01] RFC 822 header extracted: SPF=FAIL, DKIM=NONE, DMARC=REJECT.",
        "[00:08] URL detonation confirmed AitM credential harvesting kit.",
        "[00:15] Message trace identified 14 recipient mailboxes across tenant.",
        "[00:21] Batch HardDelete executed successfully for 14/14 mailboxes.",
        "[00:25] Edge email gateway blackholed sender domain service-verify.net.",
        "[00:30] Execution telemetry filed to incident dossier.",
      ],
    },
    {
      id: `run-${newId("soar")}`,
      playbookId: "c2-perimeter-blackhole",
      playbookTitle: "C2 Domain Sinkhole & Perimeter Firewall Blackhole",
      status: "completed",
      startedAt: new Date(Date.now() - 86400000).toISOString(),
      completedAt: new Date(Date.now() - 86375000).toISOString(),
      analyst: "Threat Intel Analyst",
      inputs: {
        c2Domain: "relay-gateway.telemetry-sync.org",
        c2Ip: "198.51.100.77",
      },
      stepsCompleted: 5,
      totalSteps: 5,
      logs: [
        "[00:02] Entropy and Whois verification confirmed malicious fast-flux domain.",
        "[00:06] Enterprise DNS RPZ sinkhole activated.",
        "[00:12] Drop rule injected on edge firewall cluster.",
        "[00:18] SIEM query identified 1 internal endpoint beaconing to C2.",
        "[00:22] Forensic containment dispatched for DESKTOP-ENG-988.",
      ],
    },
  ];
}
