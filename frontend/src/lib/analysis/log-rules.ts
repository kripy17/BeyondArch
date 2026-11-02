import type { Severity } from "@/lib/severity";

/**
 * Log detection rule table (migrated from the retired data/analyzers/logs.ts).
 * Pure data — shared by the Analysis Engine reasoning module (which converts
 * each row into a ReasoningRule) and the Logs orchestrator (which emits
 * log-event observations and page-level aggregation). Single source of truth.
 */

export interface LogRule {
  eventId: string;
  title: string;
  reason: string;
  action: string;
  severity: Severity;
  mitre: { id: string; name: string };
}

/** Log-event observation weight floor per severity band (weighting.ts). */
export const LOG_SEVERITY_FLOOR: Record<Severity, number> = {
  critical: 0.9,
  high: 0.8,
  medium: 0.6,
  low: 0.4,
  info: 0.35,
};

export const LOG_RULES: LogRule[] = [
  { eventId: "4625", severity: "high", title: "Failed login attempt", reason: "An account failed to log on — potential brute force or credential stuffing.", action: "Correlate source IP across timeframe; check for surrounding 4625 events.", mitre: { id: "T1110", name: "Brute Force" } },
  { eventId: "4672", severity: "medium", title: "Special privileges assigned to new logon", reason: "User received admin-equivalent privileges (SeTcbPrivilege, SeDebugPrivilege).", action: "Verify if this elevation was expected for the User or process.", mitre: { id: "T1078", name: "Valid Accounts" } },
  { eventId: "4673", severity: "medium", title: "Privileged service called", reason: "A privileged service was accessed — may indicate privilege escalation.", action: "Review the calling process and target service.", mitre: { id: "T1068", name: "Exploitation for Privilege Escalation" } },
  { eventId: "4103", severity: "high", title: "PowerShell module logging", reason: "PowerShell pipeline execution detected — module logging captures cmdlet invocations.", action: "Inspect the command details for malicious intent.", mitre: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell" } },
  { eventId: "4104", severity: "high", title: "PowerShell script block logging", reason: "PowerShell script block execution captured — may contain obfuscated or malicious code.", action: "Review script block content for IOCs and encoded commands.", mitre: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell" } },
  { eventId: "4697", severity: "high", title: "Service installed", reason: "A new service was installed on the system — potential persistence mechanism.", action: "Verify service name, binary path, and startup type against known-good baseline.", mitre: { id: "T1543.003", name: "Create or Modify System Process: Windows Service" } },
  { eventId: "4698", severity: "high", title: "Scheduled task created", reason: "A scheduled task was created — commonly used for persistence or execution.", action: "Review task name, trigger, and action; check for encoded commands.", mitre: { id: "T1053.005", name: "Scheduled Task/Job: Scheduled Task" } },
  { eventId: "4720", severity: "medium", title: "User account created", reason: "A new user account was created — verify if authorized.", action: "Check who created the account and whether it was approved.", mitre: { id: "T1136.001", name: "Create Account: Local Account" } },
  { eventId: "4728", severity: "medium", title: "Member added to security-enabled global group", reason: "A user was added to a security group — potential privilege escalation.", action: "Verify the group membership change was authorized.", mitre: { id: "T1098", name: "Account Manipulation" } },
  { eventId: "4732", severity: "medium", title: "Member added to security-enabled local group", reason: "A user was added to a local group — may indicate lateral movement preparation.", action: "Verify the group membership change for the specific user.", mitre: { id: "T1098", name: "Account Manipulation" } },
  { eventId: "4648", severity: "medium", title: "Explicit credential logon attempted", reason: "A process attempted to log on using explicit credentials (RunAs).", action: "Verify the target system and account; investigate the calling process.", mitre: { id: "T1550", name: "Use Alternate Authentication Material" } },
  { eventId: "4688", severity: "medium", title: "Process creation", reason: "A new process was created — may indicate execution of malicious binaries.", action: "Review process command line for suspicious arguments.", mitre: { id: "T1204", name: "User Execution" } },
  { eventId: "5156", severity: "info", title: "Outbound connection allowed", reason: "The Windows Filtering Platform allowed an outbound connection.", action: "Correlate with known-good destinations; flag unusual external targets.", mitre: { id: "T1572", name: "Protocol Tunneling" } },
  { eventId: "5158", severity: "info", title: "Bind to listening port", reason: "A process bound to a local port — potential backdoor listener.", action: "Verify the process and port against baseline.", mitre: { id: "T1071", name: "Application Layer Protocol" } },
  { eventId: "1102", severity: "high", title: "Security log cleared", reason: "The security event log was cleared — common anti-forensics technique.", action: "Treat as critical; correlate with surrounding events for evidence of cleanup.", mitre: { id: "T1070.001", name: "Indicator Removal: Clear Windows Event Logs" } },
  { eventId: "4616", severity: "medium", title: "System time changed", reason: "The system time was modified — may indicate log tampering or timestamp manipulation.", action: "Compare with authoritative time source; investigate who changed it.", mitre: { id: "T1070.006", name: "Indicator Removal: Timestomp" } },
  { eventId: "4740", severity: "medium", title: "User account locked out", reason: "A user account was locked out due to repeated failed logins.", action: "Check source IP for brute force; notify the user.", mitre: { id: "T1110", name: "Brute Force" } },
  { eventId: "1116", severity: "high", title: "Defender detected malware", reason: "Windows Defender detected a threat — malware may be present.", action: "Review detection details; quarantine affected system.", mitre: { id: "T1205", name: "Execution" } },
  { eventId: "1117", severity: "high", title: "Defender acted on malware", reason: "Windows Defender performed remediation action (clean/quarantine/remove).", action: "Verify remediation was successful; investigate the initial infection vector.", mitre: { id: "T1205", name: "Execution" } },
  { eventId: "4778", severity: "info", title: "RDP session reconnected", reason: "A user reconnected to an existing RDP session.", action: "Verify this matches expected user behavior.", mitre: { id: "T1021.001", name: "Remote Services: Remote Desktop" } },
  { eventId: "4779", severity: "info", title: "RDP session disconnected", reason: "An RDP session was disconnected.", action: "Verify disconnection was intentional.", mitre: { id: "T1021.001", name: "Remote Services: Remote Desktop" } },
  { eventId: "4657", severity: "medium", title: "Registry value modified", reason: "A registry value was modified — may indicate persistence via Run key.", action: "Check if modification targets autorun or RunOnce keys.", mitre: { id: "T1112", name: "Modify Registry" } },
  { eventId: "encoded_cmd", severity: "high", title: "Encoded command detected", reason: "A Base64-encoded command was found in process creation or PowerShell logs.", action: "Decode and analyze; look for download cradles, obfuscation, or reverse shells.", mitre: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell" } },
  { eventId: "lolbin_exec", severity: "high", title: "LOLBIN execution detected", reason: "A Living-Off-the-Land binary was invoked — commonly used to bypass application controls.", action: "Review parent process and command line; correlate with network connections.", mitre: { id: "T1218", name: "System Binary Proxy Execution" } },
  { eventId: "amsi_bypass", severity: "critical", title: "Potential AMSI bypass", reason: "Keywords associated with AMSI bypass techniques detected in log content.", action: "Escalate immediately — indicates defense evasion with high confidence.", mitre: { id: "T1562.001", name: "Impair Defenses: Disable or Modify Tools" } },
  { eventId: "suspicious_reg_run", severity: "high", title: "Registry RUN key modification", reason: "Modification to Run/RunOnce registry keys — classic persistence mechanism.", action: "Inspect the binary path; verify against deployment baseline.", mitre: { id: "T1547.001", name: "Boot or Logon Autostart Execution: Registry Run Keys" } },
  { eventId: "brute_force", severity: "critical", title: "Brute force attack detected", reason: "Multiple failed login attempts from the same source IP within a short window.", action: "Block source IP; enable account lockout; investigate for credential compromise.", mitre: { id: "T1110", name: "Brute Force" } },
  { eventId: "suspicious_user_agent", severity: "medium", title: "Suspicious user agent", reason: "A known malicious or unusual user agent string was detected in web logs.", action: "Correlate with IP and URI; check threat intelligence for the user agent.", mitre: { id: "T1071.001", name: "Web Protocols" } },
  { eventId: "wmi_persistence", severity: "high", title: "WMI persistence event", reason: "WMI event subscription or filter creation detected — potential persistence.", action: "Review the WMI filter and consumer; check for known WMI abuse patterns.", mitre: { id: "T1546.003", name: "Event Triggered Execution: Windows Management Instrumentation" } },
];