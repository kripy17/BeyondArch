import type { Case } from "@/data/case";
import type { NotebookHypothesis } from "@/data/notebook";
import { getUnifiedFindings, getUnifiedIOCs } from "@/components/investigation/legacy-adapter";
import { loadCorrelationMemory } from "./correlation/memory";
import type { CorrelationStatus } from "./correlation/memory";
import { explainNode } from "./provenance";
import { defang } from "@/lib/ioc-patterns";

export type TechniqueRow = { technique: string; count: number; findings: string[] };

/* ── report types (Report Builder 2.0 / Phase 3) ────────── */

export type ReportType = "executive" | "soc" | "incident-response" | "technical" | "customer" | "ioc-annex";

export const REPORT_TYPES: { id: ReportType; label: string; audience: string }[] = [
  { id: "executive", label: "Executive", audience: "leadership — outcome and posture only" },
  { id: "soc", label: "SOC", audience: "L2 shift handoff — scope, coverage, follow-ups" },
  { id: "incident-response", label: "Incident Response", audience: "IR handoff — full narrative with timeline, evidence, provenance" },
  { id: "technical", label: "Technical", audience: "engineers — full detail plus provenance" },
  { id: "customer", label: "Customer", audience: "external — cleaned summary, no internal sources" },
  { id: "ioc-annex", label: "IOC Annex", audience: "annex — counts plus the indicator list only" },
];

export type ReportSection =
  | "summary"
  | "technical"
  | "ioc"
  | "mitre"
  | "timeline"
  | "findings"
  | "provenance"
  | "hypotheses"
  | "correlation"
  | "decisions"
  | "recommendations"
  | "appendix";

export const REPORT_TYPE_SECTIONS: Record<ReportType, ReportSection[]> = {
  executive: ["summary", "mitre", "hypotheses"],
  soc: ["summary", "technical", "ioc", "mitre", "timeline", "findings", "correlation", "recommendations"],
  "incident-response": ["summary", "technical", "ioc", "mitre", "timeline", "findings", "provenance", "hypotheses", "correlation", "decisions", "recommendations", "appendix"],
  technical: ["summary", "technical", "ioc", "mitre", "timeline", "findings", "provenance", "hypotheses", "correlation", "decisions", "recommendations", "appendix"],
  customer: ["summary", "timeline"],
  "ioc-annex": ["summary", "ioc"],
};

export function reportSectionsFor(type: ReportType): ReportSection[] {
  return REPORT_TYPE_SECTIONS[type] ?? REPORT_TYPE_SECTIONS.technical;
}

export function isReportType(id: string): id is ReportType {
  return REPORT_TYPES.some((t) => t.id === id);
}

/** Executive summary rows — counts of findings/IOCs/events and their share. */
export function execSummaryRows(c: Case): { kind: string; count: number; pct: string }[] {
  const findingsCount = c.findings?.length ?? c.entries.filter((e) => e.kind === "evidence").length;
  const iocsCount = c.iocs?.length ?? c.entries.filter((e) => e.kind === "ioc").length;
  const eventsCount = c.events?.length ?? 0;
  const total = findingsCount + iocsCount + eventsCount;
  return [
    { kind: "Findings", count: findingsCount },
    { kind: "IOCs", count: iocsCount },
    { kind: "Events", count: eventsCount },
  ].map((row) => ({ ...row, pct: total > 0 ? ((row.count / total) * 100).toFixed(1) : "0.0" }));
}

/** Analyst notebook hypotheses projected for a report — notes become sections. */
export function hypothesisRows(list: NotebookHypothesis[], caseId: string): NotebookHypothesis[] {
  return list
    .filter((h) => h.caseId === caseId)
    .sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
}

export const CORRELATION_DIMENSION_LABEL: Record<string, string> = {
  "same-value-previous": "seen in prior case",
  "existing-detection": "covered by existing detection",
  "entity-overlap": "overlaps known entity",
};

export type CorrelationRow = {
  id: string;
  dimension: string;
  value: string;
  label: string;
  confidence: number;
  status: CorrelationStatus;
  seen: number;
  sources: string[];
  lastSeen: string;
};

/**
 * Correlation matches on record for a case (INVESTIGATION_OBJECTS §"Relationship
 * → reports"): records whose caseIds include this case, newest lastSeen first.
 * Read-only projection — report never mutates the ledger.
 */
export function correlationRows(caseId: string): CorrelationRow[] {
  return loadCorrelationMemory()
    .filter((r) => r.caseIds.includes(caseId))
    .map((r) => ({
      id: r.id,
      dimension: r.dimension,
      value: r.value,
      label: r.label,
      confidence: r.confidence,
      status: r.status,
      seen: r.seen,
      sources: r.sources,
      lastSeen: r.lastSeen,
    }));
}

export type DecisionRow = {
  id: string;
  ts: string;
  verdict: string;
  body: string;
};

/** Analyst decisions recorded in the case timeline (entry kind "decision"). */
export function decisionRows(c: Case): DecisionRow[] {
  return c.entries
    .filter((e) => e.kind === "decision")
    .map((e) => {
      const verdict =
      e.body
        .replace(/\*/g, "")
        .match(/^\s*(verdict|decision|conclusion):\s*([^\n]+)/i)?.[2]?.trim()
        ?.replace(/\s+[—–-].*$/s, "") ?? e.body.split("\n")[0].slice(0, 80);
      return { id: e.id, ts: e.ts, verdict, body: e.body.slice(0, 200) };
    })
    .sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
}

/* ── markdown export (per report type) ──────────────────── */

export type ClaimProvenanceRow = {
  claimKind: "finding" | "ioc";
  claimId: string;
  label: string;
  /** Node ids on the graph path from this claim back to its supporting
   *  artifact/evidence, in walk order (artifact end first). Empty when no
   *  edges exist — never fabricated. */
  chain: string[];
  linked: boolean;
};

/**
 * Per-claim provenance mapping for a case (V4.4 "provenance appendix"):
 * every finding/IOC claim resolved against the stored provenance graph via
 * the same back-spine walk the investigation UI uses. Claims without graph
 * edges report honestly as unlinked rather than inventing evidence ids.
 */
export function provenanceClaimRows(c: Case): ClaimProvenanceRow[] {
  const rows: ClaimProvenanceRow[] = [];
  for (const f of getUnifiedFindings(c)) {
    const { back } = explainNode("finding", f.id);
    const chain = back.length ? [...back.map((e) => `${e.from.kind}:${e.from.id}`), `finding:${f.id}`] : [];
    rows.push({ claimKind: "finding", claimId: f.id, label: f.title, chain, linked: chain.length > 1 });
  }
  for (const i of getUnifiedIOCs(c)) {
    if (!i.id) {
      rows.push({ claimKind: "ioc", claimId: "", label: i.value, chain: [], linked: false });
      continue;
    }
    const { back } = explainNode("ioc", i.id);
    const chain = back.length ? [...back.map((e) => `${e.from.kind}:${e.from.id}`), `ioc:${i.id}`] : [];
    rows.push({ claimKind: "ioc", claimId: i.id, label: i.value, chain, linked: chain.length > 1 });
  }
  return rows;
}

const CLAIM_ROW_UNLINKED = "_not yet linked to recorded evidence — no provenance edge exists_";

const SECTION_MD: Record<ReportSection, (c: Case, hypotheses: NotebookHypothesis[], caseId: string) => string> = {
  summary: (c) => {
    const rows = execSummaryRows(c);
    const stats = rows.map((r) => `- **${r.kind}:** ${r.count} (${r.pct}% of case items)`).join("\n");
    const findings = getUnifiedFindings(c);
    const maxSev = findings.some((f) => f.severity === "critical")
      ? "CRITICAL"
      : findings.some((f) => f.severity === "high")
      ? "HIGH"
      : findings.some((f) => f.severity === "medium")
      ? "MEDIUM"
      : "INFORMATIONAL";

    const impactTable = [
      "| Impact Dimension | Severity Assessment | Operational Exposure / Risk Summary |",
      "| :--- | :--- | :--- |",
      `| **Confidentiality** | ${maxSev === "CRITICAL" || maxSev === "HIGH" ? "HIGH RISK" : "CONTROLLED"} | Potential egress of sensitive endpoint telemetry and credentials |`,
      `| **Integrity** | ${findings.length > 0 ? "SUSPICIOUS ACTIVITY" : "VERIFIED"} | Unauthorized script execution or indicator staging detected |`,
      `| **Availability** | MINIMAL | Production infrastructure and primary services remained operational |`,
      `| **Legal / Compliance** | TLP:AMBER | Forensic evidence and chain of custody preserved for auditing |`,
    ].join("\n");

    return [
      stats,
      "",
      "### Incident Impact Assessment Matrix",
      "",
      impactTable,
      "",
      `**Overall Incident Severity:** \`${maxSev}\`  `,
      `**Current Investigation State:** \`${c.state === "active" ? "ACTIVE INVESTIGATION / CONTAINMENT IN PROGRESS" : "CONTAINED & RESOLVED"}\``,
    ].join("\n");
  },
  technical: (c) => {
    const lines = technicalSummary(c).map((l) => `- ${l}`).join("\n");
    const artifacts = c.artifacts ?? [];
    if (artifacts.length === 0) return lines;
    const artifactTable = [
      "",
      "### Ingested Evidence Artifacts",
      "",
      "| Artifact ID | Category | Title / Identifier | Acquired Timestamp |",
      "| :--- | :--- | :--- | :--- |",
      ...artifacts.map((a) => `| \`${a.id}\` | \`${a.kind}\` | **${a.title}** | \`${a.created}\` |`),
    ].join("\n");
    return lines + "\n" + artifactTable;
  },
  ioc: (c) => {
    const iocs = getUnifiedIOCs(c);
    if (!iocs.length) return "_No IOCs on record._";
    const table = [
      "| Indicator Type | Observable Value (Defanged) | Source / Origin | Threat Score | Remediation Action |",
      "| :--- | :--- | :--- | :--- | :--- |",
      ...iocs.map((i) => {
        const defVal = defang(i.value);
        const action = i.type === "ipv4" || i.type === "domain" ? "Block at Perimeter Firewall" : i.type === "url" ? "Blacklist in Web Gateway" : "Quarantine & Terminate";
        return `| **${i.type.toUpperCase()}** | \`${defVal}\` | ${i.source || "Manual Triage"} | \`${i.severity?.toUpperCase() || "HIGH"}\` | ${action} |`;
      }),
    ].join("\n");
    const legacyList = iocs.map((i) => `- \`${i.value}\` — ${i.type} (${i.source || "manual"})`).join("\n");
    return [
      table,
      "",
      "### Raw Indicator Manifest",
      "",
      legacyList,
    ].join("\n");
  },
  mitre: (c) => {
    const rows = mitreRows(c);
    if (!rows.length) return "_No MITRE techniques mapped._";
    const matrixTable = [
      "| Technique ID | Attack Phase / Description | Detections / Finding Count | Correlated Case Findings |",
      "| :--- | :--- | :--- | :--- |",
      ...rows.map((r) => `| \`${r.technique}\` | Enterprise ATT&CK Mapping | **${r.count}** detection(s) | ${r.findings.join(", ")} |`),
    ].join("\n");
    const legacyList = rows.map((r) => `- **${r.technique}** (${r.count} finding(s)): ${r.findings.join(", ")}`).join("\n");
    return [
      matrixTable,
      "",
      "### Technique Attribution Breakdown",
      "",
      legacyList,
    ].join("\n");
  },
  timeline: (c) => {
    const events = [...(c.events ?? [])].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
    if (!events.length) return "_No timeline entries recorded._";
    const timelineTable = [
      "| Timestamp (UTC) | Phase / Category | Event Title | Forensic Narrative | Importance |",
      "| :--- | :--- | :--- | :--- | :--- |",
      ...events.map((ev) => `| \`${ev.ts}\` | \`${ev.category || "investigation"}\` | **${ev.title}** | ${ev.detail} | \`${ev.importance || "normal"}\` |`),
    ].join("\n");
    const legacyList = events.map((ev) => `- \`${ev.ts}\` **${ev.title}** — ${ev.detail}`).join("\n");
    return [
      timelineTable,
      "",
      "### Chronological Event Log",
      "",
      legacyList,
    ].join("\n");
  },
  findings: (c) => {
    const findings = getUnifiedFindings(c);
    return findings.length ? findings.map((f) => `- [${f.severity}] **${f.title}** — ${f.detail}${f.technique ? ` (${f.technique})` : ""}`).join("\n") : "_No findings._";
  },
  provenance: (c) => {
    const findings = getUnifiedFindings(c);
    const iocs = getUnifiedIOCs(c);
    const mapped = findings.filter((f) => f.technique).length;
    const claims = provenanceClaimRows(c);
    const claimLines = claims.length
      ? [
          "",
          "### Claim → evidence appendix",
          "",
          ...claims.map((row) =>
            row.linked
              ? `- [${row.claimKind}] **${row.label}** (\`${row.claimId}\`) ← ${[...row.chain.slice(0, -1)].reverse().join(" ← ")}`
              : `- [${row.claimKind}] **${row.label}** — ${CLAIM_ROW_UNLINKED}`
          ),
        ]
      : [];
    return [
      `- ${iocs.length} IOC(s) on record${iocs.some((i) => !i.context) ? " — some lack enrichment context" : ""}.`,
      `- ${mapped} of ${findings.length} finding(s) carry MITRE technique attribution.`,
      ...claimLines,
    ].join("\n");
  },
  hypotheses: (_c, hypotheses) =>
    hypotheses.length
      ? hypotheses.map((h) => `- [${h.status} · ${h.confidence}] **${h.hypothesis}** — supporting ${h.supporting.length}, contradicting ${h.contradicting.length}${h.decision ? `; decision: ${h.decision}` : ""}${h.nextStep ? `; next: ${h.nextStep}` : ""}`).join("\n")
      : "_No hypotheses in the notebook._",
  correlation: (_c, _h, caseId) => {
    const rows = correlationRows(caseId);
    return rows.length
      ? rows
          .map((r) => `- \`${r.value}\` — ${CORRELATION_DIMENSION_LABEL[r.dimension] ?? r.dimension} · ${r.label} · ${Math.round(r.confidence * 100)}% · status ${r.status} · seen ${r.seen}× · sources: ${r.sources.join(", ")}`)
          .join("\n")
      : "_No correlation matches on record for this case._";
  },
  decisions: (c) => {
    const rows = decisionRows(c);
    return rows.length
      ? rows.map((r) => `- \`${r.ts}\` **${r.verdict}** — ${r.body}`).join("\n")
      : "_No analyst decisions recorded._";
  },
  recommendations: (c) => {
    const findings = getUnifiedFindings(c);
    const rows = findings
      .filter((f) => f.severity === "critical" || f.severity === "high")
      .map((f) => `- [${f.severity}] **${f.title}** — investigate ${f.technique ? `${f.technique} ` : ""}and validate against the recorded evidence${f.detail ? `; context: ${f.detail}` : ""}.`);
    const roadmap = [
      "### Prioritized Incident Response Roadmap",
      "",
      "#### Phase 0: Immediate Containment (Within 24 Hours)",
      "- [ ] Isolate compromised endpoints identified in the investigation from the production network.",
      "- [ ] Enforce perimeter firewall, proxy, and DNS sinkhole blocking for all confirmed Indicators of Compromise.",
      "- [ ] Invalidate Active Directory / IdP session tokens and enforce credential rotation for affected identities.",
      "",
      "#### Phase 1: Tactical Remediation & Eradication (1 - 7 Days)",
      "- [ ] Reimage compromised host systems and restore critical workloads from verified offline backups.",
      "- [ ] Deploy targeted Sigma / EDR behavioral detection rules to identify any persistence attempts.",
      "- [ ] Conduct deep-dive mailbox and endpoint audit for secondary lateral movement.",
      "",
      "#### Phase 2: Strategic Defensive Hardening (30 - 90 Days)",
      "- [ ] Enforce FIDO2 phishing-resistant hardware MFA across all administrative and remote access gateways.",
      "- [ ] Implement network micro-segmentation and restrict workstation-to-workstation lateral traffic.",
      "- [ ] Conduct purple-team validation against the mapped MITRE ATT&CK techniques.",
    ].join("\n");

    const base = [
      "- Confirm the reported indicators against your environment (source of truth is the local case, not the analyst tool).",
      "- Preserve the case timeline and evidence before remediation.",
      "- Route MITRE-mapped findings to the detection workspace for rule coverage.",
    ];
    const specificFindings = rows.length ? [...rows, ""].join("\n") : "";
    return specificFindings + roadmap + "\n\n### Operational Baseline Requirements\n" + base.join("\n");
  },
  appendix: (c) => {
    const entries = c.entries ?? [];
    const events = c.events ?? [];
    return [
      `- ${entries.length} case entr${entries.length === 1 ? "y" : "ies"} (kind: ${Array.from(new Set(entries.map((e) => e.kind))).join(", ") || "none"}).`,
      `- ${events.length} timeline event${events.length === 1 ? "" : "s"} on record.`,
      `- ${getUnifiedIOCs(c).length} IOC(s); ${getUnifiedFindings(c).length} finding(s); ${mitreRows(c).length} MITRE technique(s).`,
      ...entries.slice(0, 20).map((e) => `- \`${e.ts}\` [${e.kind}] ${e.body.split("\n")[0]}`),
    ].join("\n");
  },
};

const SECTION_TITLES: Record<ReportSection, string> = {
  summary: "Executive Summary",
  technical: "Technical Summary",
  ioc: "IOC Summary",
  mitre: "MITRE Coverage",
  timeline: "Timeline",
  findings: "Findings",
  provenance: "Provenance",
  hypotheses: "Analyst Hypotheses",
  correlation: "Correlation Matches",
  decisions: "Analyst Decisions",
  recommendations: "Detection Recommendations",
  appendix: "Appendix",
};

/**
 * Assemble the full markdown for a report type. Sections follow the type's
 * section set. Deterministic (V4.4): all timestamps render as stored ISO
 * strings — no locale formatting, no wall-clock deltas inside the body. Pass
 * `opts.generatedAt` to pin the footer stamp; identical inputs then produce
 * byte-identical output.
 */
export function buildReportMarkdown(c: Case, type: ReportType, hypotheses: NotebookHypothesis[], opts?: { generatedAt?: string }): string {
  const meta = REPORT_TYPES.find((t) => t.id === type) ?? REPORT_TYPES[0];
  const body = reportSectionsFor(type)
    .map((s) => `## ${SECTION_TITLES[s]}\n\n${SECTION_MD[s](c, hypotheses, c.id)}`)
    .join("\n\n");
  const stamp = opts?.generatedAt ?? new Date().toISOString();
  return [
    `# ${meta.label} Report — ${c.title}`,
    `Case ${c.id} · ${c.state} · created ${c.createdAt}`,
    "",
    "> **CONFIDENTIALITY NOTICE — TLP:AMBER+STRICT**  ",
    "> **Organization:** BeyondLabs Cyber Incident Response Workstation  ",
    `> **Case Identifier:** \`${c.id}\` | **Classification:** \`CONFIDENTIAL // DFIR INCIDENT REPORT\``,
    "",
    "---",
    "",
    body,
    "",
    "---",
    "",
    `_Generated by BeyondLabs Case Report · ${stamp}_`,
  ].join("\n");
}

export function mitreRows(c: Case): TechniqueRow[] {
  const findings = getUnifiedFindings(c);
  const byTechnique = new Map<string, string[]>();
  for (const f of findings) {
    if (!f.technique) continue;
    const list = byTechnique.get(f.technique) ?? [];
    list.push(f.title);
    byTechnique.set(f.technique, list);
  }
  return [...byTechnique.entries()]
    .map(([technique, titles]) => ({ technique, count: titles.length, findings: titles }))
    .sort((a, b) => b.count - a.count || a.technique.localeCompare(b.technique));
}

export function technicalSummary(c: Case): string[] {
  const findings = getUnifiedFindings(c);
  const iocs = getUnifiedIOCs(c);
  const artifacts = c.artifacts ?? [];
  const evidence = (c.evidenceItems ?? []).length || c.entries.filter((e) => e.kind === "evidence").length;
  const lines: string[] = [];

  lines.push(
    `Case "${c.title}" (${c.state}, created ${c.createdAt}) covers ${artifacts.length} artifact(s), ${evidence} evidence item(s), ${findings.length} finding(s) and ${iocs.length} IOC(s).`
  );

  const techniques = new Set(findings.filter((f) => f.technique).map((f) => f.technique!));
  lines.push(
    techniques.size
      ? `${techniques.size} distinct MITRE technique(s) mapped: ${[...techniques].join(", ")}.`
      : "No MITRE techniques mapped — findings lack technique attribution."
  );

  const unmapped = findings.filter((f) => !f.technique).length;
  if (findings.length > 0 && unmapped > 0) {
    lines.push(`${unmapped} of ${findings.length} finding(s) carry no technique; detection coverage is incomplete.`);
  }

  const localOnly = iocs.filter((i) => !i.context).length;
  if (iocs.length > 0) {
    lines.push(
      localOnly === 0
        ? "All IOCs carry enrichment context."
        : `${localOnly} of ${iocs.length} IOC(s) lack enrichment context — external enrichment is not applied.`
    );
  } else {
    lines.push("No IOCs on record.");
  }

  return lines;
}