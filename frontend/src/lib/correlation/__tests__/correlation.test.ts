import { describe, expect, it } from "vitest";
import { makeObservation } from "@/lib/extraction";
import { analyzeAndCorrelate, correlate, type CorrelationHistory } from "@/lib/correlation";

const TS = "2026-08-07T12:30:00.000Z";

function scenario() {
  return [
    makeObservation({ kind: "ip", value: "198.51.100.23", source: "t", ts: TS }),
    makeObservation({ kind: "domain", value: "evil-example.com", source: "t", ts: TS }),
    makeObservation({ kind: "hash", value: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", source: "t", meta: { hashType: "sha256" }, ts: TS }),
  ];
}

const history: CorrelationHistory = {
  cases: [
    { id: "case-9", title: "Q3 phishing wave", values: ["198.51.100.23", "e-example.com"] },
    { id: "case-12", title: "Ransomware precursor", values: ["198.51.100.23"] },
  ],
  detections: [
    { id: "rule-3", name: "sigma phish sender tld", technique: "T1566" },
  ],
  entities: [
    { id: "ent-1", name: "evil-toolkit", observables: ["evil-example.com", "198.51.100.9"] },
  ],
};

describe("correlation engine", () => {
  it("flags values seen in prior cases, weighted by frequency", () => {
    const matches = analyzeAndCorrelate(scenario(), history, { source: "e2e", ts: TS }).correlation;
    const prior = matches.filter((m) => m.dimension === "same-value-previous");
    const ip = prior.find((m) => m.value === "198.51.100.23");
    expect(ip).toBeDefined();
    expect(ip?.confidence).toBe(0.7);
    expect(ip?.matches.map((x) => x.label)).toEqual(["Q3 phishing wave", "Ransomware precursor"]);
  });

  it("flags existing detections by technique", () => {
    const result = analyzeAndCorrelate(
      [makeObservation({ kind: "email", value: "x@phish.tk", source: "t", ts: TS })],
      { detections: [{ id: "rule-1", name: "sigma phish", technique: "T1566" }] },
      { source: "e2e", ts: TS },
    );
    const det = result.correlation.find((m) => m.dimension === "existing-detection");
    expect(det?.matches[0]?.ref).toBe("rule-1");
    expect(det?.confidence).toBe(0.8);
  });

  it("finds intel-entity observable overlap and builds ambiguous-graph edges (origin correlation)", () => {
    const result = analyzeAndCorrelate(scenario(), history, { source: "e2e", ts: TS });
    const entity = result.correlation.find((m) => m.dimension === "entity-overlap");
    expect(entity?.confidence).toBe(0.6);
    const edges = result.correlationRelationships.filter((r) => r.origin === "correlation");
    expect(edges.every((r) => r.relation === "enriched-by")).toBe(true);
    expect(edges[0]?.from.kind).toBe("ioc");
    expect(edges[0]?.to.kind).toBe("entity");
  });

  it("is deterministic for the same analysis + history", () => {
    const a = analyzeAndCorrelate(scenario(), history, { source: "e2e", ts: TS });
    const b = analyzeAndCorrelate(scenario(), history, { source: "e2e", ts: TS });
    expect(a).toEqual(b);
  });

  it("does not mutate or re-rank the analysis result", () => {
    const withoutHistory: CorrelationHistory = {};
    const base = analyzeAndCorrelate(scenario(), withoutHistory, { source: "e2e", ts: TS });
    const withHistory = analyzeAndCorrelate(scenario(), history, { source: "e2e", ts: TS });
    expect(withHistory.findings).toEqual(base.findings);
    expect(withHistory.quality).toEqual(base.quality);
    // correlation only adds analyst-reviewed data
  });

  it("returns no matches when history is empty", () => {
    const { correlation } = analyzeAndCorrelate(scenario(), {}, { source: "e2e", ts: TS });
    expect(correlation).toEqual([]);
  });
});

describe("correlate signature (§4e)", () => {
  it("emits { dimension, value, matches, confidence, evidenceRefs }", () => {
    const matches = correlate(
      [{ id: "o1", kind: "ip", value: "198.51.100.23" }],
      [],
      { cases: [{ id: "c1", title: "old", values: ["198.51.100.23"] }] },
    );
    expect(matches[0]).toMatchObject({
      dimension: "same-value-previous",
      value: "198.51.100.23",
      confidence: 0.5,
      evidenceRefs: ["o1"],
    });
    expect(matches[0].matches).toEqual([{ ref: "c1", label: "old" }]);
  });
});