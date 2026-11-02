import { describe, expect, it } from "vitest";
import { analyzeArtifact } from "@/lib/artifact";
import { SAMPLES } from "@/data/parser";

const TS = "2026-08-07T13:00:00.000Z";

describe("analyzeArtifact — powershell artifact", () => {
  const r = analyzeArtifact(SAMPLES.powershell.text, { source: "test", ts: TS });

  it("emits a canonical command observation", () => {
    const cmd = r.observations.find((o) => o.kind === "command");
    expect(cmd?.value).toContain("powershell.exe");
    expect(cmd?.id.length).toBeGreaterThan(0);
  });

  it("runs the engine — encoded-command + hidden-execution findings", () => {
    const titles = r.findings.map((f) => f.title);
    expect(titles).toContain("Encoded PowerShell command");
    expect(titles).toContain("Hidden process execution");
  });

  it("maps findings to MITRE with confidence chain", () => {
    const m = r.mitre.find((x) => x.technique === "T1059.001");
    expect(m?.name).toBeTruthy();
    expect(m?.confidence?.level).toBeTruthy();
    expect(m?.evidenceRefs.length).toBeGreaterThan(0);
  });

  it("surfaces recommendations and quality", () => {
    expect(r.recommendations.length).toBeGreaterThan(0);
    expect(typeof r.quality.coverage.score).toBe("number");
  });

  it("runs correlation with injected (empty) history", () => {
    expect(Array.isArray(r.correlation)).toBe(true);
  });
});

describe("analyzeArtifact — email artifact", () => {
  it("extracts url/domain/ip/email + links url to its host", () => {
    const r = analyzeArtifact(SAMPLES.phishing.text, { source: "test", ts: TS });
    const kinds = r.observations.map((o) => o.kind);
    expect(kinds).toContain("url");
    expect(kinds).toContain("email");
    const link = r.relationships.find((rel) => rel.relation === "supports");
    expect(link).toBeDefined();
    expect(r.format).toBe("text");
  });
});

describe("analyzeArtifact — csv artifact", () => {
  it("routes through the CSV adapter", () => {
    const r = analyzeArtifact(SAMPLES.csv.text, { source: "test", ts: TS });
    expect(r.format).toBe("csv");
    const ip = r.observations.find((o) => o.kind === "ip");
    expect(ip?.value).toBe("198.51.100.23");
  });
});

describe("analyzeArtifact — correlation with injected history", () => {
  it("flags same-value-previous matches", () => {
    const r = analyzeArtifact(SAMPLES.csv.text, {
      source: "test",
      ts: TS,
      history: { cases: [{ id: "case-x", title: "prior case", values: ["198.51.100.23"] }] },
    });
    const prior = r.correlation.find((m) => m.dimension === "same-value-previous");
    expect(prior).toBeDefined();
    expect(prior?.matches[0]?.ref).toBe("case-x");
  });
});

describe("analyzeArtifact — determinism", () => {
  it("produces identical ids for identical input", () => {
    const a = analyzeArtifact(SAMPLES.powershell.text, { source: "test", ts: TS });
    const b = analyzeArtifact(SAMPLES.powershell.text, { source: "test", ts: TS });
    expect(a.findings.map((f) => f.id)).toEqual(b.findings.map((f) => f.id));
    expect(a.observations.map((o) => o.id)).toEqual(b.observations.map((o) => o.id));
  });
});

describe("analyzeArtifact — email-domain substrings are not domain IOCs", () => {
  const r = analyzeArtifact("contact analyst@corp.local about evil.example.com", { source: "test", ts: TS });

  it("keeps the email observation", () => {
    expect(r.observations.some((o) => o.kind === "email" && o.value === "analyst@corp.local")).toBe(true);
  });

  it("drops corp.local but keeps the standalone domain", () => {
    const domains = r.observations.filter((o) => o.kind === "domain").map((o) => o.value);
    expect(domains).not.toContain("corp.local");
    expect(domains).toContain("evil.example.com");
  });
});