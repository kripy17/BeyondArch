import { describe, expect, it } from "vitest";
import {
  calculateCaseIncidentMetrics,
  buildEnterpriseDfirMarkdown,
  generateEnterprisePrintHtml,
} from "@/lib/real-world-report";
import type { Case } from "@/data/case";

function createMockCase(patch: Partial<Case> = {}): Case {
  return {
    id: "case-ir-8812",
    title: "BlackCat Ransomware Infiltration & Data Exfiltration",
    tags: ["ransomware", "blackcat", "exfiltration"],
    createdAt: new Date(Date.now() - 3600000 * 5).toISOString(), // 5h ago
    state: "active",
    entries: [
      { id: "e1", ts: new Date().toISOString(), kind: "evidence", body: "Encrypted payload and ransom note dropped" },
    ],
    events: [
      {
        id: "ev1",
        ts: new Date().toISOString(),
        kind: "finding_created",
        category: "finding",
        importance: "critical",
        actor: "analyst",
        origin: "edr",
        title: "Shadow Copy Deletion",
        detail: "vssadmin.exe delete shadows /all /quiet",
        references: [],
      },
    ],
    findings: [
      {
        id: "f1",
        severity: "critical",
        title: "Inhibit System Recovery",
        detail: "Volume shadow copies purged via vssadmin",
        source: "edr",
        technique: "T1490",
      },
      {
        id: "f2",
        severity: "high",
        title: "LSASS Memory Tampering",
        detail: "Credential access attempted via mimikatz",
        source: "sigma",
        technique: "T1003.001",
      },
    ],
    iocs: [
      {
        id: "i1",
        value: "185.220.101.5",
        type: "ipv4",
        context: "Tor Exit Node C2",
        source: "zeek",
        severity: "critical",
      },
      {
        id: "i2",
        value: "hxxps://auth-blackcat[.]org/gate",
        type: "url",
        context: "Exfiltration Gate",
        source: "logs",
        severity: "high",
      },
      {
        id: "i3",
        value: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
        type: "unknown",
        context: "Ransom Extortion Wallet",
        source: "note",
        severity: "high",
      },
    ],
    evidenceItems: [
      { id: "ev-1", title: "memory_dump.raw", type: "memory", source: "volatility", detail: "Host memory image" },
    ],
    ...patch,
  };
}

describe("calculateCaseIncidentMetrics", () => {
  it("computes maximum severity from findings and IOCs", () => {
    const mockCase = createMockCase();
    const metrics = calculateCaseIncidentMetrics(mockCase);

    expect(metrics.maxSeverity).toBe("critical");
    expect(metrics.iocsCount).toBe(3);
    expect(metrics.criticalIocsCount).toBe(1);
    expect(metrics.findingsCount).toBe(2);
    expect(metrics.mitreTechniquesCount).toBe(2);
    expect(metrics.containmentStatus).toContain("ACTIVE CONTAINMENT");
  });

  it("handles a benign or low-severity empty case cleanly", () => {
    const emptyCase: Case = {
      id: "case-clean-1",
      title: "Routine Audit",
      tags: [],
      createdAt: new Date().toISOString(),
      state: "closed",
      entries: [],
    };
    const metrics = calculateCaseIncidentMetrics(emptyCase);

    expect(metrics.maxSeverity).toBe("low");
    expect(metrics.iocsCount).toBe(0);
    expect(metrics.findingsCount).toBe(0);
    expect(metrics.containmentStatus).toBe("CONTAINED & RESOLVED");
  });
});

describe("buildEnterpriseDfirMarkdown", () => {
  it("generates publication-grade Markdown with YAML frontmatter and SANS sections", () => {
    const mockCase = createMockCase();
    const md = buildEnterpriseDfirMarkdown(mockCase, [], {
      organization: "Acme Cyber Defense Center",
      leadInvestigator: "Jane Doe (Lead IR Specialist)",
    });

    // Frontmatter
    expect(md).toContain("---");
    expect(md).toContain('case_id: "case-ir-8812"');
    expect(md).toContain('incident_severity: "CRITICAL"');
    expect(md).toContain('lead_investigator: "Jane Doe (Lead IR Specialist)"');
    expect(md).toContain('organization: "Acme Cyber Defense Center"');

    // Section 1: Executive Summary & Impact Metrics
    expect(md).toContain("## 1. Executive Summary & Operational Impact");
    expect(md).toContain("### Incident Classification & Impact Metrics");
    expect(md).toContain("| **Overall Incident Severity** | `CRITICAL` |");

    // Section 2: Attack Lifecycle & MITRE matrix
    expect(md).toContain("## 2. Attack Lifecycle & Adversary Killchain");
    expect(md).toContain("`T1490`");
    expect(md).toContain("`T1003.001`");

    // Section 3: Defensible IOC Vault
    expect(md).toContain("## 3. Defensible Indicators of Compromise (IOC Vault)");
    expect(md).toContain("185[.]220[.]101[.]5"); // Defanged

    // Section 4: Chronological Timeline
    expect(md).toContain("## 4. Chronological Forensic Timeline");
    expect(md).toContain("Shadow Copy Deletion");

    // Section 5: Evidence Chain of Custody
    expect(md).toContain("## 5. Chain of Custody & Cryptographic Evidence Ledger");

    // Section 6: 3-Phase Roadmap
    expect(md).toContain("## 6. Incident Remediation & Defensive Hardening Roadmap");
    expect(md).toContain("Phase 0: Immediate Containment (Within 24 Hours)");
    expect(md).toContain("Phase 1: Tactical Eradication & Recovery (1 - 7 Days)");
    expect(md).toContain("Phase 2: Strategic Defensive Hardening (30 - 90 Days)");

    // Section 7: Sign-off block
    expect(md).toContain("## 7. Forensic Sign-Off & Verification Block");
    expect(md).toContain("Lead Forensic Examiner");
  });
});

describe("generateEnterprisePrintHtml", () => {
  it("emits self-contained, publication-ready printable HTML document with print CSS", () => {
    const mockCase = createMockCase();
    const md = buildEnterpriseDfirMarkdown(mockCase);
    const html = generateEnterprisePrintHtml(mockCase, md);

    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("BEYONDLABS // DEFENSE OPERATIONS");
    expect(html).toContain("TLP:AMBER+STRICT");
    expect(html).toContain("kpi-grid");
    expect(html).toContain("CRITICAL");
    expect(html).toContain("@media print");
    expect(html).toContain("page-break-inside: avoid;");
    expect(html).toContain("185[.]220[.]101[.]5");
  });
});
