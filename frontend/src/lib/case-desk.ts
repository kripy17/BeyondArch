import type { Case, Entry, EntryKind } from "@/data/case";
import { newId, newCaseTitle } from "@/data/case";
import { getUnifiedFindings, getUnifiedIOCs } from "@/components/investigation/legacy-adapter";
import { calculateCaseIncidentMetrics } from "@/lib/real-world-report";
import type { Severity } from "@/lib/severity";

export type ContainmentStage = "Triage" | "Containment" | "Eradication" | "Recovery" | "Closed";

export interface QueueMetrics {
  totalCases: number;
  activeCases: number;
  closedCases: number;
  criticalCases: number;
  highCases: number;
  avgMttcMinutes: number;
  totalCorrelatedIocs: number;
  totalEvidenceCount: number;
}

export interface CrossCaseObservable {
  key: string;
  type: string;
  value: string;
  caseIds: string[];
  caseTitles: string[];
  count: number;
  firstSeen: string;
  lastSeen: string;
  severity: Severity;
}

export interface QueueFilters {
  search: string;
  status: "all" | "active" | "closed";
  severity: "all" | "critical" | "high" | "medium" | "low" | "info";
  tag: string;
}

export interface IrIncidentTemplate {
  id: string;
  name: string;
  category: string;
  severity: Severity;
  summary: string;
  recommendedTags: string[];
  hypotheses: string[];
  initialChecklist: string[];
  defaultEntries: { kind: EntryKind; body: string }[];
}

export const IR_TEMPLATES: IrIncidentTemplate[] = [
  {
    id: "spear-phishing",
    name: "Spear-Phishing Credential Lure & Session Hijack",
    category: "Email & Identity",
    severity: "high",
    summary: "Targeted spear-phishing email delivered to VIP/finance role with AitM reverse-proxy credential harvesting and session token replay.",
    recommendedTags: ["phishing", "credential-access", "t1566.002", "oauth-abuse", "aitm"],
    hypotheses: [
      "Adversary leveraged reverse-proxy infrastructure (Evilginx) to bypass FIDO2/MFA authentication.",
      "Harvested session tokens were immediately utilized to access corporate cloud storage and email archives.",
    ],
    initialChecklist: [
      "Obtain RFC 822 raw message headers and extract originating SMTP hops.",
      "Query message-trace for all corporate recipients of identical Subject / Message-ID.",
      "Extract and defang lure URL; check hosting provider ASN and SSL certificate creation time.",
      "Audit Azure AD / Okta sign-in logs for anomalous IP/ASN during the victim session window.",
      "Initiate immediate session revocation and password reset for impacted user accounts.",
      "Execute automated purge of malicious email from all recipient inboxes.",
    ],
    defaultEntries: [
      {
        kind: "evidence",
        body: "[HIGH] Initial Email Triage\n- **Sender:** alerts@accounts-verify-security.com (Spoofed)\n- **Target:** CFO Executive Assistant\n- **Subject:** Urgent: Quarterly Audit Financial Verification\n- **SPF:** Fail | **DKIM:** None | **DMARC:** Reject\n(from: M365 Security Center)",
      },
      {
        kind: "ioc",
        body: "url: https://auth-verify.azurelogin-sso.workers.dev/login?ref=cfo\nSource: Email Header Body",
      },
      {
        kind: "note",
        body: "HYPOTHESIS: AitM credential harvesting kit configured on Cloudflare Workers reverse-proxying login.microsoftonline.com.",
      },
      {
        kind: "action",
        body: "ACTION: Submit domain takedown request to registrar and block workers.dev subpath on edge web proxies.",
      },
    ],
  },
  {
    id: "ransomware",
    name: "Enterprise Ransomware Outbreak & Data Stage",
    category: "Endpoint & Malware",
    severity: "critical",
    summary: "Mass file encryption activity detected with Volume Shadow Copy (VSS) deletion, service termination, and lateral SMB staging.",
    recommendedTags: ["ransomware", "impact", "t1486", "defense-evasion", "t1490", "lateral-movement"],
    hypotheses: [
      "Initial access gained via unpatched edge VPN appliance or compromised domain service account.",
      "Adversary executed PsExec or Impacket SMB scripts to distribute payload across production cluster.",
      "Sensitive file repositories staged and exfiltrated to Mega/Rclone endpoint prior to encryption.",
    ],
    initialChecklist: [
      "Immediately isolate infected hosts at switch/EDR level to sever SMB and C2 channels.",
      "Preserve memory dump on at least one patient-zero endpoint before system shutdown.",
      "Identify ransomware strain from ransom note file format, extension pattern, and public decryptor status.",
      "Locate and protect offline immutable backup repositories; disconnect backup network interfaces.",
      "Review perimeter firewall and NetFlow logs for large outbound transfers to cloud storage endpoints.",
      "Assemble executive incident command team and prepare internal breach escalation brief.",
    ],
    defaultEntries: [
      {
        kind: "evidence",
        body: "[CRITICAL] Outbreak Detection\n- **Patient Zero:** SRV-FIN-PRD02 (10.14.3.45)\n- **Affected Extension:** .locked_beyond\n- **VSS Status:** vssadmin delete shadows /all /quiet executed at 03:14 UTC\n(from: CrowdStrike Falcon)",
      },
      {
        kind: "ioc",
        body: "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nSource: C:\\Windows\\Temp\\encsvc.exe",
      },
      {
        kind: "decision",
        body: "VERDICT: Active BlackCat/ALPHV derivative ransomware deployment in progress. Immediate network partition authorized.",
      },
      {
        kind: "action",
        body: "ACTION: Host network isolation toggled for VLAN 10.14.3.0/24.",
      },
    ],
  },
  {
    id: "cloud-iam",
    name: "Cloud IAM Token Compromise & Exfiltration",
    category: "Cloud Infrastructure",
    severity: "critical",
    summary: "Anomalous STS AssumeRole calls originating from suspicious foreign ASN querying CloudTrail logs and attempting mass S3 bucket sync.",
    recommendedTags: ["cloud", "iam-compromise", "t1078.004", "aws", "exfiltration", "s3"],
    hypotheses: [
      "Long-lived AWS access credentials leaked into public GitHub repository or test container image.",
      "Adversary executed CloudGoat / Pacu reconnaissance tools to enumerate role permissions and escalate to AdministratorAccess.",
    ],
    initialChecklist: [
      "Deactivate compromised IAM access key pair immediately via AWS CLI / Console.",
      "Attach AWS managed deny-all policy `AWSDenyAll` to compromised user/role ARN.",
      "Review CloudTrail EventHistory for GetSecretValue, DescribeBuckets, and S3 GetObject calls.",
      "Identify all S3 objects accessed or exfiltrated during the compromised window.",
      "Validate AWS GuardDuty anomalies for `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`.",
      "Rotate all credentials, API keys, and database secrets stored in AWS Secrets Manager.",
    ],
    defaultEntries: [
      {
        kind: "evidence",
        body: "[CRITICAL] AWS CloudTrail Alert\n- **IAM User:** svc-github-ci\n- **Anomalous Source IP:** 185.220.101.45 (Tor Exit Node)\n- **Events:** iam:ListRoles, iam:AttachUserPolicy, s3:ListAllMyBuckets\n(from: AWS GuardDuty)",
      },
      {
        kind: "ioc",
        body: "ipv4: 185.220.101.45\nSource: AWS CloudTrail SourceIP",
      },
      {
        kind: "action",
        body: "ACTION: Access key AKIAIOSFODNN7EXAMPLE deactivated and explicit DenyAll inline policy attached.",
      },
    ],
  },
  {
    id: "supply-chain",
    name: "Supply-Chain C2 & DLL Side-Loading",
    category: "Supply Chain & Network",
    severity: "high",
    summary: "Legitimate digitally signed binary hijacked to side-load malicious unsigned DLL establishing jittered TLS C2 beaconing.",
    recommendedTags: ["supply-chain", "c2", "t1574.002", "t1071.001", "defense-evasion", "dll-sideload"],
    hypotheses: [
      "Software vendor automatic update channel was compromised or upstream GitHub release substituted.",
      "Encrypted payload injected into legitimate process memory space to evade signature-based AV.",
    ],
    initialChecklist: [
      "Collect the signed loader executable and malicious DLL payload for sandbox detonator analysis.",
      "Verify code-signing certificate validity and timestamp counter-signature.",
      "Extract embedded C2 domains and IP addresses from DLL configuration section.",
      "Sinkhole identified C2 domains across corporate DNS resolvers and perimeter firewalls.",
      "Scan enterprise endpoint fleet for presence of matching file hashes and directory paths.",
      "Notify software vendor security team regarding compromised supply-chain component.",
    ],
    defaultEntries: [
      {
        kind: "evidence",
        body: "[HIGH] DLL Side-Loading Detected\n- **Host:** DESKTOP-ENG-988\n- **Parent Binary:** C:\\Program Files\\VendorApp\\updater.exe (Signed: Valid)\n- **Loaded DLL:** C:\\Program Files\\VendorApp\\version.dll (Unsigned / Unknown Hash)\n(from: Windows Sysmon Event 7)",
      },
      {
        kind: "ioc",
        body: "sha256: d544b025d0c75c88b9016be3230ec2b281f08e492cbcf514e8fd42cd4948a332\nSource: version.dll",
      },
      {
        kind: "action",
        body: "ACTION: Blackhole DNS query responses for *.cloud-telemetry-relay.org.",
      },
    ],
  },
  {
    id: "insider-threat",
    name: "Insider Data Exfiltration via Encrypted Channel",
    category: "Insider Threat & DLP",
    severity: "medium",
    summary: "Departing employee copied high-volume intellectual property to encrypted archive and staged egress via cloud storage.",
    recommendedTags: ["insider-threat", "data-exfiltration", "t1567.002", "dlp", "usb-storage"],
    hypotheses: [
      "Departing personnel intentionally packaging source code repositories prior to joining competitor.",
      "Archive encrypted using proprietary passphrases to bypass Deep Packet Inspection (DPI) scanners.",
    ],
    initialChecklist: [
      "Correlate file access timestamps with HR departure notification dates and GitLab commit history.",
      "Review DLP gateway logs for upload volume spikes to personal cloud storage (Google Drive, Box, Mega).",
      "Inspect endpoint USB storage connection logs (Windows Event 2003 / 24577).",
      "Coordinate with Legal Counsel and HR to preserve forensic image of employee assigned laptop.",
      "Revoke VPN, Single Sign-On, and building physical badge access credentials.",
    ],
    defaultEntries: [
      {
        kind: "evidence",
        body: "[MEDIUM] High Volume Archive Creation\n- **User:** dev.lead@beyondlabs.internal\n- **Action:** 7z a -p -mhe=on D:\\ProjectArchive.7z C:\\Git\\ProprietaryEngine\\* (28.4 GB)\n(from: Endpoint DLP Agent)",
      },
      {
        kind: "action",
        body: "ACTION: Placed employee account on legal hold and suspended active corporate tokens.",
      },
    ],
  },
];

function getSeverityWeight(sev?: string): number {
  if (!sev) return 0;
  switch (sev) {
    case "critical": return 5;
    case "high": return 4;
    case "medium": return 3;
    case "low": return 2;
    case "info": return 1;
    default: return 0;
  }
}

/** Determines the aggregate severity of a case based on tags, findings, IOCs, and entry text. */
export function computeCaseSeverity(c: Case): Severity {
  const lowerTags = c.tags.map((t) => t.toLowerCase());
  if (lowerTags.some((t) => t === "critical" || t === "p1" || t === "sev-1" || t === "sev1")) return "critical";
  if (lowerTags.some((t) => t === "high" || t === "p2" || t === "sev-2" || t === "sev2")) return "high";
  if (lowerTags.some((t) => t === "medium" || t === "p3" || t === "sev-3" || t === "sev3")) return "medium";
  if (lowerTags.some((t) => t === "low" || t === "p4" || t === "sev-4" || t === "sev4")) return "low";

  const metrics = calculateCaseIncidentMetrics(c);
  if (metrics.maxSeverity !== "low" && metrics.maxSeverity !== "info") {
    return metrics.maxSeverity;
  }

  for (const e of c.entries) {
    const text = e.body.toUpperCase();
    if (text.includes("[CRITICAL]") || text.includes("SEVERITY: CRITICAL") || text.includes("VERDICT: CONFIRMED")) {
      return "critical";
    }
    if (text.includes("[HIGH]") || text.includes("SEVERITY: HIGH")) {
      return "high";
    }
    if (text.includes("[MEDIUM]") || text.includes("SEVERITY: MEDIUM")) {
      return "medium";
    }
  }

  return metrics.maxSeverity;
}

/** Computes the operational containment stage of a case. */
export function computeContainmentStage(c: Case): ContainmentStage {
  if (c.state === "closed") return "Closed";

  const hasDecisions = c.entries.some((e) => e.kind === "decision");
  const actions = c.entries.filter((e) => e.kind === "action");

  if (actions.some((a) => /recov|restor|patch|re-image|rebuild/i.test(a.body))) {
    return "Recovery";
  }
  if (actions.some((a) => /eradicat|clean|purg|remov|wipe/i.test(a.body))) {
    return "Eradication";
  }
  if (actions.length > 0 || /isolat|block|contain|quarantin|partit/i.test(c.entries.map((e) => e.body).join(" "))) {
    return "Containment";
  }
  if (hasDecisions) {
    return "Containment";
  }
  return "Triage";
}

/** Computes real-world incident desk telemetry across the entire case portfolio. */
export function calculateQueueMetrics(cases: Case[]): QueueMetrics {
  const totalCases = cases.length;
  const activeCases = cases.filter((c) => c.state === "active").length;
  const closedCases = cases.filter((c) => c.state === "closed").length;

  let criticalCases = 0;
  let highCases = 0;
  let totalEvidenceCount = 0;
  let totalDurationMinutes = 0;
  let durationSamples = 0;

  for (const c of cases) {
    const sev = computeCaseSeverity(c);
    if (sev === "critical") criticalCases++;
    if (sev === "high") highCases++;

    const findings = getUnifiedFindings(c);
    const iocs = getUnifiedIOCs(c);
    const artifacts = c.artifacts?.length ?? 0;
    const evidenceItems = c.evidenceItems?.length ?? 0;
    totalEvidenceCount += findings.length + iocs.length + artifacts + evidenceItems;

    try {
      const start = new Date(c.createdAt).getTime();
      if (!isNaN(start)) {
        let end = Date.now();
        if (c.state === "closed" && c.entries.length > 0) {
          const lastTs = new Date(c.entries[c.entries.length - 1].ts).getTime();
          if (!isNaN(lastTs) && lastTs >= start) {
            end = lastTs;
          }
        }
        const diffMin = Math.max(1, Math.round((end - start) / 60000));
        totalDurationMinutes += diffMin;
        durationSamples++;
      }
    } catch {
      // ignore date parse errors
    }
  }

  const crossObservables = findCrossCaseObservables(cases);
  const avgMttcMinutes = durationSamples > 0 ? Math.round(totalDurationMinutes / durationSamples) : 0;

  return {
    totalCases,
    activeCases,
    closedCases,
    criticalCases,
    highCases,
    avgMttcMinutes,
    totalCorrelatedIocs: crossObservables.length,
    totalEvidenceCount,
  };
}

/** Identifies observables appearing in multiple distinct cases to expose multi-incident campaign linkages. */
export function findCrossCaseObservables(cases: Case[]): CrossCaseObservable[] {
  const map = new Map<string, {
    type: string;
    value: string;
    caseMap: Map<string, string>;
    firstSeen: string;
    lastSeen: string;
    maxSeverity: Severity;
  }>();

  for (const c of cases) {
    const iocs = getUnifiedIOCs(c);
    for (const ioc of iocs) {
      const cleanValue = ioc.value.trim();
      if (!cleanValue) continue;
      const key = `${ioc.type}:${cleanValue.toLowerCase()}`;

      let record = map.get(key);
      if (!record) {
        record = {
          type: ioc.type,
          value: cleanValue,
          caseMap: new Map(),
          firstSeen: c.createdAt,
          lastSeen: c.createdAt,
          maxSeverity: (ioc.severity as Severity) || "info",
        };
        map.set(key, record);
      }

      record.caseMap.set(c.id, c.title);

      if (c.createdAt < record.firstSeen) record.firstSeen = c.createdAt;
      if (c.createdAt > record.lastSeen) record.lastSeen = c.createdAt;

      const currentWeight = getSeverityWeight(record.maxSeverity);
      const newWeight = getSeverityWeight(ioc.severity);
      if (newWeight > currentWeight) {
        record.maxSeverity = (ioc.severity as Severity) || "info";
      }
    }
  }

  const result: CrossCaseObservable[] = [];
  for (const [key, data] of map.entries()) {
    if (data.caseMap.size >= 2) {
      result.push({
        key,
        type: data.type,
        value: data.value,
        caseIds: Array.from(data.caseMap.keys()),
        caseTitles: Array.from(data.caseMap.values()),
        count: data.caseMap.size,
        firstSeen: data.firstSeen,
        lastSeen: data.lastSeen,
        severity: data.maxSeverity,
      });
    }
  }

  // Sort descending by occurrence count, then by severity
  return result.sort((a, b) => {
    if (b.count !== a.count) return b.count - a.count;
    const wA = getSeverityWeight(a.severity);
    const wB = getSeverityWeight(b.severity);
    return wB - wA;
  });
}

/** Filters the incident desk case backlog using multi-facet criteria. */
export function filterCaseQueue(cases: Case[], filters: QueueFilters): Case[] {
  return cases.filter((c) => {
    if (filters.status !== "all" && c.state !== filters.status) {
      return false;
    }

    if (filters.severity !== "all") {
      const sev = computeCaseSeverity(c);
      if (sev !== filters.severity) return false;
    }

    if (filters.tag && !c.tags.some((t) => t.toLowerCase().includes(filters.tag.toLowerCase()))) {
      return false;
    }

    if (filters.search) {
      const q = filters.search.toLowerCase();
      const inTitle = c.title.toLowerCase().includes(q);
      const inTags = c.tags.some((t) => t.toLowerCase().includes(q));
      const inEntries = c.entries.some((e) => e.body.toLowerCase().includes(q));
      if (!inTitle && !inTags && !inEntries) {
        return false;
      }
    }

    return true;
  });
}

/** Generates an enterprise-ready CSV export of the incident queue ledger. */
export function exportCaseQueueCsv(cases: Case[]): string {
  const headers = ["Case ID", "Title", "Status", "Severity", "Stage", "Created At", "Entries", "IOCs", "Findings", "Tags"];
  const rows = cases.map((c) => {
    const sev = computeCaseSeverity(c);
    const stage = computeContainmentStage(c);
    const iocs = getUnifiedIOCs(c).length;
    const findings = getUnifiedFindings(c).length;
    const tags = c.tags.join("; ");

    return [
      `"${c.id}"`,
      `"${c.title.replace(/"/g, '""')}"`,
      `"${c.state}"`,
      `"${sev.toUpperCase()}"`,
      `"${stage}"`,
      `"${c.createdAt}"`,
      c.entries.length,
      iocs,
      findings,
      `"${tags.replace(/"/g, '""')}"`,
    ].join(",");
  });

  return [headers.join(","), ...rows].join("\n");
}

/** Generates a structured JSON export of the incident portfolio. */
export function exportCaseQueueJson(cases: Case[]): string {
  const exportPayload = {
    exportedAt: new Date().toISOString(),
    generator: "BeyondLabs Incident Operations Desk",
    totalCases: cases.length,
    cases: cases.map((c) => ({
      id: c.id,
      title: c.title,
      state: c.state,
      severity: computeCaseSeverity(c),
      stage: computeContainmentStage(c),
      createdAt: c.createdAt,
      tags: c.tags,
      entryCount: c.entries.length,
      findingsCount: getUnifiedFindings(c).length,
      iocsCount: getUnifiedIOCs(c).length,
      entries: c.entries,
      findings: c.findings,
      iocs: c.iocs,
    })),
  };

  return JSON.stringify(exportPayload, null, 2);
}

/** Instantiates a full enterprise case structure from an IR template. */
export function instantiateCaseFromTemplate(template: IrIncidentTemplate, customTitle?: string): Case {
  const title = customTitle?.trim() || `${template.name} - ${newCaseTitle()}`;
  const now = new Date().toISOString();

  const entries: Entry[] = [];

  // 1. Initial Intake & Overview Note
  entries.push({
    id: newId("e"),
    ts: now,
    kind: "note",
    body: `[INITIAL INTAKE] Incident initiated from template: ${template.name}\n\nCategory: ${template.category}\nSeverity Target: ${template.severity.toUpperCase()}\n\nExecutive Summary:\n${template.summary}`,
  });

  // 2. Initial Investigation Hypotheses Note
  if (template.hypotheses.length > 0) {
    entries.push({
      id: newId("e"),
      ts: now,
      kind: "note",
      body: `## Working Hypotheses\n${template.hypotheses.map((h, i) => `${i + 1}. ${h}`).join("\n")}`,
    });
  }

  // 3. Operational IR Checklist
  if (template.initialChecklist.length > 0) {
    entries.push({
      id: newId("e"),
      ts: now,
      kind: "action",
      body: `## Incident Response Checklist\n${template.initialChecklist.map((c) => `- [ ] ${c}`).join("\n")}`,
    });
  }

  // 4. Default Evidence & IOC Entries
  for (const de of template.defaultEntries) {
    entries.push({
      id: newId("e"),
      ts: now,
      kind: de.kind,
      body: de.body,
    });
  }

  const tags = Array.from(new Set([...template.recommendedTags, template.severity, "incident"]));

  return {
    id: newId("case"),
    title,
    tags,
    createdAt: now,
    state: "active",
    entries,
  };
}
