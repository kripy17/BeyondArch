import { describe, it, expect } from "vitest";
import { buildReportMarkdown } from "@/lib/report";
import { markdownToHtml, htmlShell, buildExportBundle } from "@/lib/export-bundle";
import type { Case } from "@/data/case";

function makeSampleCase(): Case {
  return {
    id: "case-dfir-01",
    title: "APT29 CozyBear Spearphishing Campaign",
    state: "active",
    createdAt: "2026-08-20T14:30:00.000Z",
    tags: ["apt29", "spearphishing", "lateral-movement"],
    entries: [
      { id: "e1", ts: "2026-08-20T14:32:00.000Z", kind: "evidence", body: "Malicious LNK file executed via ISO container mount" },
      { id: "e2", ts: "2026-08-20T14:40:00.000Z", kind: "ioc", body: "domain: update-microsoft-telemetry.org\nSource: DNS Log" },
      { id: "e3", ts: "2026-08-20T14:45:00.000Z", kind: "decision", body: "Verdict: Compromised. Host isolation enacted." },
      { id: "e4", ts: "2026-08-20T15:00:00.000Z", kind: "action", body: "Terminated rundll32.exe process and revoked Active Directory credentials" },
    ],
    artifacts: [
      { id: "art-1", title: "malicious_invoice.iso", kind: "file", raw: "base64payloadsample", metadata: { source: "endpoint-01" }, created: "2026-08-20T14:30:00.000Z" },
    ],
    evidenceItems: [
      { id: "ev-1", title: "PowerShell Downloader Script", type: "artifact", source: "Sysmon Event ID 1", detail: "Payload decoded from base64" },
    ],
    findings: [
      { id: "f-1", title: "Spearphishing Attachment Execution", severity: "critical", source: "EDR", technique: "T1566.001", detail: "Executed ISO mount" },
      { id: "f-2", title: "Signed Binary Proxy Execution", severity: "high", source: "Sysmon", technique: "T1218.011", detail: "rundll32 executing unsigned dll" },
    ],
    iocs: [
      { id: "ioc-1", value: "198.51.100.24", type: "ipv4", severity: "critical", source: "Firewall", context: "Command and control server" },
      { id: "ioc-2", value: "http://malicious-c2.evil.com/beacon", type: "url", severity: "high", source: "Proxy", context: "HTTP Beacon URL" },
      { id: "ioc-3", value: "44d88612fea8a8f36de82e1278abb02f", type: "md5", severity: "medium", source: "VirusTotal", context: "Trojan dropper MD5" },
    ],
    events: [
      {
        id: "ev-101",
        ts: "2026-08-20T14:32:00.000Z",
        actor: "automation",
        origin: "EDR Alert",
        kind: "alert_ingested",
        category: "artifact",
        importance: "normal",
        title: "Malicious Process Spanned from rundll32",
        detail: "Spanned rundll32 process with beacon arguments",
        references: [],
      },
    ],
  };
}

describe("Enterprise DFIR Report Engine", () => {
  it("generates publication-grade Incident Impact Assessment Matrix", () => {
    const c = makeSampleCase();
    const md = buildReportMarkdown(c, "incident-response", []);

    expect(md).toContain("| Impact Dimension | Severity Assessment | Operational Exposure / Risk Summary |");
    expect(md).toContain("| **Confidentiality** |");
    expect(md).toContain("| **Integrity** |");
    expect(md).toContain("| **Availability** |");
    expect(md).toContain("| **Legal / Compliance** |");
  });

  it("generates ingested evidence artifacts table", () => {
    const c = makeSampleCase();
    const md = buildReportMarkdown(c, "incident-response", []);

    expect(md).toContain("| Artifact ID | Category | Title / Identifier | Acquired Timestamp |");
    expect(md).toContain("malicious_invoice.iso");
  });

  it("defangs indicators in IOC summary table to prevent accidental clicks", () => {
    const c = makeSampleCase();
    const md = buildReportMarkdown(c, "incident-response", []);

    expect(md).toContain("| Indicator Type | Observable Value (Defanged) | Source / Origin | Threat Score | Remediation Action |");
    // IP defanged
    expect(md).toContain("198[.]51[.]100[.]24");
    // URL defanged
    expect(md).toContain("hxxp[:]//malicious-c2[.]evil[.]com/beacon");
  });

  it("generates MITRE ATT&CK kill-chain matrix table", () => {
    const c = makeSampleCase();
    const md = buildReportMarkdown(c, "incident-response", []);

    expect(md).toContain("| Technique ID | Attack Phase / Description | Detections / Finding Count | Correlated Case Findings |");
    expect(md).toContain("T1566.001");
    expect(md).toContain("T1218.011");
  });

  it("generates prioritized 3-phase remediation roadmap", () => {
    const c = makeSampleCase();
    const md = buildReportMarkdown(c, "incident-response", []);

    expect(md).toContain("### Prioritized Incident Response Roadmap");
    expect(md).toContain("Phase 0: Immediate Containment (Within 24 Hours)");
    expect(md).toContain("Phase 1: Tactical Remediation & Eradication (1 - 7 Days)");
    expect(md).toContain("Phase 2: Strategic Defensive Hardening (30 - 90 Days)");
  });

  it("contains confidentiality header and deterministic timestamp", () => {
    const c = makeSampleCase();
    const md = buildReportMarkdown(c, "executive", [], { generatedAt: "2026-08-25T10:00:00.000Z" });

    expect(md).toContain("CONFIDENTIALITY NOTICE — TLP:AMBER+STRICT");
    expect(md).toContain("BeyondLabs Cyber Incident Response Workstation");
    expect(md).toContain("_Generated by BeyondLabs Case Report · 2026-08-25T10:00:00.000Z_");
  });
});

describe("Markdown to HTML converter & Shell", () => {
  it("converts markdown tables to styled HTML tables with wrappers", () => {
    const mdTable = [
      "| Name | Status |",
      "| --- | --- |",
      "| Server 01 | Isolated |",
      "| Server 02 | Active |",
    ].join("\n");

    const html = markdownToHtml(mdTable);
    expect(html).toContain('<div class="report-table-wrapper"><table class="report-table">');
    expect(html).toContain("<th>Name</th>");
    expect(html).toContain("<th>Status</th>");
    expect(html).toContain("<td>Server 01</td>");
    expect(html).toContain("<td>Isolated</td>");
    expect(html).toContain("<td>Server 02</td>");
    expect(html).toContain("<td>Active</td>");
  });

  it("converts blockquotes to report callout blocks", () => {
    const quote = "> **WARNING:** Unauthorized access detected.";
    const html = markdownToHtml(quote);

    expect(html).toContain('<blockquote class="report-callout">');
    expect(html).toContain("<strong>WARNING:</strong> Unauthorized access detected.");
  });

  it("converts horizontal dividers", () => {
    const divider = "---";
    const html = markdownToHtml(divider);

    expect(html).toContain('<hr class="report-divider" />');
  });

  it("produces complete standalone HTML shell with corporate print styling", () => {
    const c = makeSampleCase();
    const md = buildReportMarkdown(c, "technical", []);
    const fullHtml = htmlShell(`${c.title} — Executive Report`, md);

    expect(fullHtml.toLowerCase()).toContain("<!doctype html>");
    expect(fullHtml).toContain("<title>APT29 CozyBear Spearphishing Campaign — Executive Report</title>");
    expect(fullHtml).toContain("@media print");
    expect(fullHtml).toContain("page-break-inside: avoid");
    expect(fullHtml).toContain("report-table");
  });

  it("builds a complete export bundle with zip, manifest, and attachments", () => {
    const c = makeSampleCase();
    const bundle = buildExportBundle({
      case: c,
      reportType: "incident-response",
      hypotheses: [],
      generatedAt: "2026-08-25T10:00:00.000Z",
    });

    expect(bundle.blob).toBeDefined();
    expect(bundle.fileCount).toBeGreaterThan(3);
    expect(bundle.manifest.some((line) => line.includes("report.md"))).toBe(true);
    expect(bundle.manifest.some((line) => line.includes("report.html"))).toBe(true);
    expect(bundle.manifest.some((line) => line.includes("case.beyondcase.json"))).toBe(true);
  });
});
