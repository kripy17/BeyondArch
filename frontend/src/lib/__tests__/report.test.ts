import { describe, expect, it } from "vitest";
import type { Case } from "@/data/case";
import type { NotebookHypothesis } from "@/data/notebook";
import { mitreRows, technicalSummary, REPORT_TYPES, reportSectionsFor, isReportType, execSummaryRows, hypothesisRows, buildReportMarkdown, correlationRows, decisionRows } from "@/lib/report";

const store = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => { store.set(k, v); },
  removeItem: (k: string) => { store.delete(k); },
  clear: () => { store.clear(); },
  key: (i: number) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
};

const TS = "2026-08-07T12:30:00.000Z";

function caseWith(findings: { title: string; technique?: string }[]): Case {
  return {
    id: "c1",
    title: "Credential phishing",
    tags: [],
    state: "active",
    createdAt: TS,
    entries: [],
    events: [],
    artifacts: [{ id: "a1", kind: "file", title: "invoice.pdf", metadata: {}, created: TS }],
    findings: findings.map((f, i) => ({ id: `f${i}`, title: f.title, detail: "", severity: "high", source: "parser", ...(f.technique ? { technique: f.technique } : {}) })),
    iocs: [{ id: "i1", value: "10.0.0.9", type: "ipv4", context: "", source: "parser", severity: "high" }],
  };
}

describe("mitreRows", () => {
  it("groups findings by technique, sorted by count desc", () => {
    const c = caseWith([
      { title: "a", technique: "T1059.001" },
      { title: "b", technique: "T1059.001" },
      { title: "c", technique: "T1114" },
      { title: "d" },
    ]);
    expect(mitreRows(c)).toEqual([
      { technique: "T1059.001", count: 2, findings: ["a", "b"] },
      { technique: "T1114", count: 1, findings: ["c"] },
    ]);
  });

  it("returns empty when no techniques mapped", () => {
    expect(mitreRows(caseWith([{ title: "x" }]))).toEqual([]);
  });
});

describe("technicalSummary", () => {
  it("reports technique coverage, unmapped findings, and unenriched IOCs honestly", () => {
    const lines = technicalSummary(caseWith([
      { title: "a", technique: "T1059.001" },
      { title: "b" },
    ]));
    expect(lines[0]).toContain('"Credential phishing"');
    expect(lines[0]).toContain("1 artifact(s)");
    expect(lines[1]).toContain("T1059.001");
    expect(lines.join("\n")).toContain("1 of 2 finding(s) carry no technique");
    expect(lines.join("\n")).toContain("lack enrichment context");
  });

  it("states absence of IOCs and techniques", () => {
    const lines = technicalSummary({ ...caseWith([]), iocs: [] });
    const all = lines.join("\n");
    expect(all).toContain("No IOCs on record.");
    expect(all).toContain("No MITRE techniques mapped");
  });
});

describe("report types", () => {
  it("defines audience-scoped types with unique ids", () => {
    expect(REPORT_TYPES.map((t) => t.id)).toEqual([
      "executive", "soc", "incident-response", "technical", "customer", "ioc-annex",
    ]);
    for (const t of REPORT_TYPES) {
      expect(t.label.length).toBeGreaterThan(0);
      expect(t.audience.length).toBeGreaterThan(0);
    }
  });

  it("technical includes every section; customer stays minimal", () => {
    const technical = reportSectionsFor("technical");
    const customer = reportSectionsFor("customer");
    expect(technical).toContain("summary");
    expect(technical).toContain("technical");
    expect(technical).toContain("ioc");
    expect(technical).toContain("mitre");
    expect(technical).toContain("timeline");
    expect(technical).toContain("findings");
    expect(technical).toContain("provenance");
    expect(technical).toContain("hypotheses");
    expect(customer).toEqual(["summary", "timeline"]);
  });

  it("executive omits provenance and technical detail", () => {
    const sections = reportSectionsFor("executive");
    expect(sections).not.toContain("provenance");
    expect(sections).not.toContain("technical");
    expect(sections).not.toContain("ioc");
  });

  it("isReportType guards unknown ids with fallback to technical", () => {
    expect(isReportType("soc")).toBe(true);
    expect(isReportType("bogus")).toBe(false);
    expect(reportSectionsFor("bogus" as never)).toEqual(reportSectionsFor("technical"));
  });

  it("every type's sections are a subset of the known section set", () => {
    const known = new Set<string>(["summary", "technical", "ioc", "mitre", "timeline", "findings", "provenance", "hypotheses", "correlation", "decisions", "recommendations", "appendix"]);
    for (const t of REPORT_TYPES) {
      for (const s of reportSectionsFor(t.id)) {
        expect(known.has(s)).toBe(true);
      }
    }
  });
});

describe("execSummaryRows", () => {
  it("breaks the case down into findings/iocs/events shares", () => {
    const c = caseWith([{ title: "a" }, { title: "b" }]);
    c.iocs = [c.iocs![0], { ...c.iocs![0], id: "i2" }];
    const rows = execSummaryRows(c);
    expect(rows).toHaveLength(3);
    expect(rows[0]).toEqual({ kind: "Findings", count: 2, pct: "50.0" });
    expect(rows[1]).toEqual({ kind: "IOCs", count: 2, pct: "50.0" });
    expect(rows[2]).toEqual({ kind: "Events", count: 0, pct: "0.0" });
  });

  it("does not divide by zero on an empty case", () => {
    const empty: Case = { id: "e1", title: "empty", tags: [], state: "active", createdAt: TS, entries: [] };
    const rows = execSummaryRows(empty);
    expect(rows.map((r) => r.pct)).toEqual(["0.0", "0.0", "0.0"]);
  });
});

describe("hypothesisRows", () => {
  const hyps: NotebookHypothesis[] = [
    { id: "h1", caseId: "c1", hypothesis: "old", supporting: [], contradicting: [], confidence: "low", status: "open", decision: "", nextStep: "", createdAt: TS, updatedAt: "2026-08-07T10:00:00.000Z" },
    { id: "h2", caseId: "c1", hypothesis: "new", supporting: [], contradicting: [], confidence: "high", status: "supported", decision: "keep", nextStep: "hunt", createdAt: TS, updatedAt: "2026-08-07T12:00:00.000Z" },
    { id: "h3", caseId: "other", hypothesis: "other case", supporting: [], contradicting: [], confidence: "medium", status: "open", decision: "", nextStep: "", createdAt: TS, updatedAt: "2026-08-07T11:00:00.000Z" },
  ];

  it("filters to the case and sorts newest first", () => {
    expect(hypothesisRows(hyps, "c1").map((h) => h.id)).toEqual(["h2", "h1"]);
  });

  it("excludes other cases and returns empty when none match", () => {
    expect(hypothesisRows(hyps, "c1")).toHaveLength(2);
    expect(hypothesisRows(hyps, "missing")).toEqual([]);
  });
});

describe("buildReportMarkdown", () => {
  const c = caseWith([{ title: "a", technique: "T1059.001" }]);

  it("sections follow the report type and carry case metadata", () => {
    const md = buildReportMarkdown(c, "executive", []);
    expect(md).toContain("# Executive Report — Credential phishing");
    expect(md).toContain("## Executive Summary");
    expect(md).toContain("## MITRE Coverage");
    expect(md).not.toContain("## IOC Summary");
    expect(md).not.toContain("## Provenance");
  });

  it("includes hypothesis rows for types that carry them", () => {
    const hyps: NotebookHypothesis[] = [
      { id: "h1", caseId: "c1", hypothesis: "beaconing", supporting: ["x"], contradicting: [], confidence: "high", status: "supported", decision: "confirm", nextStep: "hunt", createdAt: TS, updatedAt: TS },
    ];
    const md = buildReportMarkdown(c, "incident-response", hyps);
    expect(md).toContain("## Analyst Hypotheses");
    expect(md).toContain("beaconing");
    expect(md).toContain("decision: confirm");
  });

  it("omits analyst hypotheses from the customer report", () => {
    const md = buildReportMarkdown(c, "customer", []);
    expect(md).not.toContain("Analyst Hypotheses");
    expect(md).toContain("## Timeline");
  });

  it("marks empty collections honestly rather than omitting them", () => {
    const empty: Case = { id: "e1", title: "empty", tags: [], state: "active", createdAt: TS, entries: [] };
    const md = buildReportMarkdown(empty, "technical", []);
    expect(md).toContain("_No findings._");
    expect(md).toContain("_No IOCs on record._");
    expect(md).toContain("_No hypotheses in the notebook._");
  });
});
describe("correlationRows", () => {
  const reset = () => localStorage.clear();

  it("projects only records attached to the case, newest lastSeen first", async () => {
    reset();
    const { rememberCorrelation } = await import("@/lib/correlation/memory");
    const mk = (dim: "same-value-previous" | "existing-detection", value: string) => ({
      dimension: dim, value, label: "L", matches: [{ ref: "r", label: "R" }], confidence: 0.8, evidenceRefs: ["r"], ts: new Date(),
    });
    await rememberCorrelation([mk("same-value-previous", "10.0.0.1")], { source: "url", caseId: "c1", ts: new Date("2026-08-13T10:00:00Z") });
    await rememberCorrelation([mk("existing-detection", "10.0.0.2")], { source: "file", caseId: "c1", ts: new Date("2026-08-13T11:00:00Z") });
    await rememberCorrelation([mk("same-value-previous", "10.0.0.9")], { source: "url", caseId: "c2", ts: new Date("2026-08-13T12:00:00Z") });
    const rows = correlationRows("c1");
    expect(rows.map((r) => r.value)).toEqual(["10.0.0.2", "10.0.0.1"]);
    expect(rows[0].confidence).toBe(0.8);
    expect(rows.every((r) => r.status === "new")).toBe(true);
  });

  it("returns empty for cases with no matches on record", () => {
    reset();
    expect(correlationRows("missing")).toEqual([]);
  });
});

describe("decisionRows", () => {
  it("extracts verdicts from decision entries, newest first", () => {
    const c = caseWith([]);
    const withEntries: Case = { ...c, entries: [
      { id: "e1", ts: "2026-08-13T09:00:00Z", kind: "decision", body: "**Verdict:** malicious — confirmed by beaconing" },
      { id: "e2", ts: "2026-08-13T10:00:00Z", kind: "decision", body: "**Verdict:** suspicious" },
      { id: "e3", ts: "2026-08-13T08:00:00Z", kind: "note", body: "not a decision" },
    ] };
    const rows = decisionRows(withEntries);
    expect(rows.map((r) => r.verdict)).toEqual(["suspicious", "malicious"]);
    expect(rows.every((r) => r.body.length > 0)).toBe(true);
  });

  it("returns empty when no decisions recorded", () => {
    expect(decisionRows(caseWith([]))).toEqual([]);
  });
});
