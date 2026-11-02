import { describe, expect, it, beforeEach } from "vitest";
import { createCaseFromAnalysis } from "@/data/case-factory";
import { getAllEdges } from "@/lib/provenance";
import type { AnalysisResult } from "@/types/analysis";
import type { Observation, Relationship } from "@/types/objects";
import { INVESTIGATION_OBJECTS_V1 } from "@/types/objects";

const store = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => { store.set(k, v); },
  removeItem: (k: string) => { store.delete(k); },
  clear: () => { store.clear(); },
  key: (i: number) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
};

function makeResult(over: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    id: "result-1",
    analyzer: "url",
    raw: "https://evil.example/payload.exe",
    artifact: { id: "artifact-1", kind: "url", title: "test url", metadata: {}, created: "2026-08-14T10:00:00Z" },
    findings: [
      {
        id: "finding-1",
        severity: "high",
        title: "Suspicious URL",
        detail: "payload staging",
        source: "url",
        iocs: [{ value: "evil.example", type: "domain", context: "host", source: "url", severity: "high" }],
      },
    ],
    iocs: [
      { id: "ioc-evil.example", value: "evil.example", type: "domain", context: "host", source: "url", severity: "high" },
    ],
    evidenceItems: [
      { id: "ev-1", type: "finding", title: "Suspicious URL", detail: "payload staging", source: "url" },
    ],
    summary: { verdict: "malicious", score: 78, confidence: 0.72 },
    generatedAt: "2026-08-14T10:00:00Z",
    ...over,
  };
}

const OBS: Observation[] = [
  { id: "obs-domain-1", kind: "domain", value: "evil.example", meta: {}, source: "url", ts: "2026-08-14T10:00:00Z", schemaVersion: INVESTIGATION_OBJECTS_V1 },
];

const CORR_RELS: Relationship[] = [
  {
    id: "rel-enriched-1",
    relation: "enriched-by",
    from: { kind: "ioc", id: "obs-domain-1" },
    to: { kind: "entity", id: "entity-evilexample" },
    confidence: 0.6,
    evidenceRefs: ["obs-domain-1"],
    origin: "correlation",
    source: "correlation-engine",
    ts: "2026-08-14T10:00:00Z",
    schemaVersion: INVESTIGATION_OBJECTS_V1,
  },
];

describe("createCaseFromAnalysis provenance projection (§9)", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("projects correlation relationships into the graph when the observation maps to a case ioc", () => {
    createCaseFromAnalysis(makeResult({ observations: OBS, correlationRelationships: CORR_RELS }));

    const edges = getAllEdges();
    const enriched = edges.filter((e) => e.relation === "enriched-by");
    expect(enriched).toHaveLength(1);
    expect(enriched[0]!.from).toEqual({ kind: "ioc", id: "ioc-evil.example" });
    expect(enriched[0]!.to).toEqual({ kind: "entity", id: "entity-evilexample" });
    expect(enriched[0]!.confidence).toBe(0.6);
  });

  it("skips correlation relationships with no resolvable ioc node", () => {
    const orphan = CORR_RELS.map((r) => ({
      ...r,
      id: "rel-enriched-2",
      evidenceRefs: ["obs-missing"],
      from: { kind: "ioc" as const, id: "obs-missing" },
    }));
    createCaseFromAnalysis(makeResult({ observations: OBS, correlationRelationships: orphan }));

    expect(getAllEdges().filter((e) => e.relation === "enriched-by")).toHaveLength(0);
  });

  it("is idempotent: re-running with the same analysis does not duplicate edges", () => {
    createCaseFromAnalysis(makeResult({ observations: OBS, correlationRelationships: CORR_RELS }));
    const second = createCaseFromAnalysis(makeResult({ observations: OBS, correlationRelationships: CORR_RELS }));

    const edges = getAllEdges();
    expect(edges.filter((e) => e.relation === "enriched-by")).toHaveLength(1);
    expect(second.isNew).toBe(true);
  });

  it("still writes produced/supports/extracts edges without engine correlation output", () => {
    const result = makeResult();
    createCaseFromAnalysis(result);

    const edges = getAllEdges();
    expect(edges.some((e) => e.relation === "produced")).toBe(true);
    expect(edges.some((e) => e.relation === "supports")).toBe(true);
    expect(edges.some((e) => e.relation === "extracts")).toBe(true);
    expect(edges.some((e) => e.relation === "enriched-by")).toBe(false);
  });
});