import { describe, expect, it } from "vitest";
import type { Case } from "@/data/case";
import { explainObject, explainableRefs } from "@/lib/explain";
import type { Edge } from "@/lib/provenance";

const TS = "2026-08-07T12:30:00.000Z";

function caseFixture(): Case {
  return {
    id: "case-x",
    title: "Phishing wave",
    tags: [],
    state: "active",
    createdAt: TS,
    entries: [],
    events: [],
    artifacts: [{ id: "art-1", kind: "file", title: "attached.pdf", metadata: {}, created: TS }],
    evidenceItems: [],
    findings: [
      { id: "f-1", title: "EncodedCommand launch", detail: "", severity: "high", source: "parser", technique: "T1059.001", iocs: [] },
    ],
    iocs: [{ id: "ioc-1", value: "198.51.100.23", type: "ipv4", context: "", source: "parser", severity: "high" }],
  };
}

function edge(over: Partial<Edge> & { relation: Edge["relation"]; from: Edge["from"]; to: Edge["to"] }): Edge {
  return {
    id: over.id ?? `e-${over.from.id}-${over.to.id}`,
    relation: over.relation,
    from: over.from,
    to: over.to,
    source: over.source ?? "backfill",
    ts: over.ts ?? TS,
    reason: over.reason ?? `${over.relation} reason`,
    confidence: over.confidence,
  };
}

describe("explainableRefs", () => {
  it("lists findings, iocs, and evidence items", () => {
    const c = caseFixture();
    const refs = explainableRefs(c);
    expect(refs).toContainEqual({ kind: "finding", id: "f-1" });
    expect(refs).toContainEqual({ kind: "ioc", id: "ioc-1" });
  });
});

describe("explainObject", () => {
  const c = caseFixture();

  it("answers why with the origin artifact when linked", () => {
    const edges: Edge[] = [
      edge({ id: "a", relation: "produced", from: { kind: "artifact", id: "art-1" }, to: { kind: "evidence", id: "ev-1" }, source: "backfill" }),
      edge({ id: "b", relation: "supports", from: { kind: "evidence", id: "ev-1" }, to: { kind: "finding", id: "f-1" }, source: "backfill" }),
    ];
    const ex = explainObject(c, { kind: "finding", id: "f-1" }, edges);
    expect(ex.why).toContain("art-1");
    expect(ex.how).toHaveLength(2);
    expect(ex.source).toEqual(["backfill"]);
    expect(ex.confidence).toBeNull();
    expect(ex.relationships).toHaveLength(2);
  });

  it("keeps the why honest when no provenance exists", () => {
    const ex = explainObject(c, { kind: "finding", id: "f-1" }, []);
    expect(ex.why).toContain("no provenance edges found");
    expect(ex.how).toEqual([]);
    expect(ex.source).toEqual([]);
    expect(ex.confidence).toBeNull();
  });

  it("reports the strongest and weakest edge confidence", () => {
    const edges: Edge[] = [
      edge({ id: "f", relation: "extracts", from: { kind: "finding", id: "f-1" }, to: { kind: "ioc", id: "ioc-1" }, source: "parser", confidence: 0.9 }),
      edge({ id: "s", relation: "supports", from: { kind: "evidence", id: "ev-1" }, to: { kind: "finding", id: "f-1" }, source: "backfill", confidence: 0.4 }),
      edge({ id: "p", relation: "produced", from: { kind: "artifact", id: "art-1" }, to: { kind: "evidence", id: "ev-1" }, source: "backfill" }),
    ];
    const ex = explainObject(c, { kind: "finding", id: "f-1" }, edges);
    expect(ex.confidence).toBe(0.9);
    expect(ex.weakestConfidence).toBe(0.4);
    expect(ex.how).toHaveLength(3);
  });

  it("labels an ioc by type and value", () => {
    const ex = explainObject(c, { kind: "ioc", id: "ioc-1" }, []);
    expect(ex.label).toBe("ipv4 · 198.51.100.23");
  });
});