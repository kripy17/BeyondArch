import { describe, expect, it, beforeEach } from "vitest";
import type { Case, CaseEvent } from "@/data/case";
import {
  addEdge, backfillCaseEdges, backfillMitreEdges, eventDigest, explainNode,
  getAllEdges, lifecycleNodeId, path, projectTimeline, LS_PROVENANCE,
} from "@/lib/provenance";
import type { Finding, IOC } from "@/types/security";

class FakeLocalStorage {
  private store = new Map<string, string>();
  getItem(k: string): string | null { return this.store.get(k) ?? null; }
  setItem(k: string, v: string): void { this.store.set(k, v); }
  removeItem(k: string): void { this.store.delete(k); }
  clear(): void { this.store.clear(); }
  get length(): number { return this.store.size; }
  key(i: number): string | null { return [...this.store.keys()][i] ?? null; }
}

function resetStore() {
  (globalThis as unknown as { localStorage?: FakeLocalStorage }).localStorage = new FakeLocalStorage();
}
beforeEach(resetStore);

function ls(): FakeLocalStorage {
  return (globalThis as unknown as { localStorage: FakeLocalStorage }).localStorage;
}

function mkCase(partial: Partial<Case>): Case {
  return {
    id: "c-1",
    title: "Fixture",
    tags: [],
    createdAt: "2026-08-01T00:00:00.000Z",
    state: "active",
    entries: [],
    ...partial,
  };
}

function mkIoc(value: string, type: IOC["type"] = "ipv4"): IOC {
  return { value, type, context: "", source: "test", severity: "high", id: `ioc-${value}` };
}

function mkFinding(id: string, opts: Partial<Finding> = {}): Finding {
  return { id, severity: "high", title: `finding ${id}`, detail: "", source: "test", ...opts };
}

function mkArtifact(id: string) {
  return { id, kind: "email" as const, title: id, metadata: {}, created: "2026-08-01T00:00:00.000Z" };
}

function mkEvidence(id: string, title: string, type = "finding") {
  return { id, type, title, detail: "d", source: "test" };
}

describe("addEdge", () => {
  it("writes a stable idempotent edge", () => {
    const e1 = addEdge({ relation: "extracts", from: { kind: "finding", id: "f1" }, to: { kind: "ioc", id: "ioc-1" }, source: "test" });
    const e2 = addEdge({ relation: "extracts", from: { kind: "finding", id: "f1" }, to: { kind: "ioc", id: "ioc-1" }, source: "test" });
    expect(e2.id).toBe(e1.id);
    expect(getAllEdges()).toHaveLength(1);
  });

  it("keeps the original timestamp on re-assertion", () => {
    addEdge({ relation: "produced", from: { kind: "artifact", id: "a1" }, to: { kind: "evidence", id: "ev1" }, source: "test", ts: "2026-08-01T00:00:00.000Z" });
    const e2 = addEdge({ relation: "produced", from: { kind: "artifact", id: "a1" }, to: { kind: "evidence", id: "ev1" }, source: "test", ts: "2026-08-02T00:00:00.000Z" });
    expect(e2.ts).toBe("2026-08-01T00:00:00.000Z");
  });

  it("distinguishes relations between the same pair", () => {
    addEdge({ relation: "supports", from: { kind: "evidence", id: "ev1" }, to: { kind: "finding", id: "f1" }, source: "test" });
    addEdge({ relation: "creates", from: { kind: "alert", id: "al1" }, to: { kind: "case", id: "c-1" }, source: "test" });
    expect(getAllEdges()).toHaveLength(2);
  });

  it("persists via the documented storage key", () => {
    addEdge({ relation: "produced", from: { kind: "artifact", id: "a9" }, to: { kind: "evidence", id: "ev9" }, source: "test" });
    expect(ls().getItem(LS_PROVENANCE)).toContain("a9");
  });
});

describe("lifecycle ids", () => {
  it("is deterministic across calls", () => {
    expect(lifecycleNodeId("detection", "ruleA", "1.0")).toBe(lifecycleNodeId("detection", "ruleA", "1.0"));
    expect(lifecycleNodeId("detection", "ruleA", "1.0")).toMatch(/^det-/);
    expect(lifecycleNodeId("simulation", "x")).toMatch(/^sim-/);
    expect(lifecycleNodeId("deployment", "x")).toMatch(/^dep-/);
    expect(lifecycleNodeId("alert", "x")).toMatch(/^al-/);
  });

  it("derives different ids for different content keys", () => {
    expect(lifecycleNodeId("detection", "ruleA")).not.toBe(lifecycleNodeId("detection", "ruleB"));
    expect(eventDigest("  event  ")).toBe(eventDigest("event"));
    expect(eventDigest("event")).not.toBe(eventDigest("other"));
  });
});

describe("backfillCaseEdges", () => {
  const legacy = mkCase({
    artifacts: [mkArtifact("a1")],
    evidenceItems: [mkEvidence("ev1", "SPF fail"), mkEvidence("ev2", "scratch", "note")],
    findings: [mkFinding("f1", { title: "SPF fail", iocs: [mkIoc("10.0.0.5")] })],
    iocs: [mkIoc("10.0.0.5")],
  });

  it("derives produced/supports/extracts edges from embedded structure", () => {
    backfillCaseEdges(legacy);
    const edges = getAllEdges();
    expect(edges).toHaveLength(4);
    expect(edges.filter((e) => e.relation === "produced")).toHaveLength(2);
    expect(edges.some((e) => e.relation === "supports" && e.from.kind === "evidence" && e.to.kind === "finding")).toBe(true);
    expect(edges.some((e) => e.relation === "extracts" && e.from.kind === "finding" && e.to.kind === "ioc")).toBe(true);
    expect(edges.every((e) => e.source === "backfill")).toBe(true);
  });

  it("does not double-write on rerun", () => {
    backfillCaseEdges(legacy);
    backfillCaseEdges(legacy);
    expect(getAllEdges().length).toBeLessThanOrEqual(4);
  });

  it("skips evidence without a matching finding", () => {
    const noFinding = mkCase({
      artifacts: [mkArtifact("a1")],
      evidenceItems: [mkEvidence("ev1", "Nothing")],
      findings: [mkFinding("f1", { title: "SPF fail" })],
    });
    backfillCaseEdges(noFinding);
    expect(getAllEdges().some((e) => e.relation === "supports")).toBe(false);
  });
});

describe("backfillMitreEdges", () => {
  it("maps findings with a technique onto technique nodes", () => {
    const c = mkCase({ findings: [mkFinding("f1", { technique: "T1059" }), mkFinding("f2")] });
    backfillMitreEdges(c);
    const edges = getAllEdges().filter((e) => e.relation === "mapped-to");
    expect(edges).toHaveLength(1);
    expect(edges[0].to).toEqual({ kind: "mitre", id: "T1059" });
    backfillMitreEdges(c);
    expect(getAllEdges().filter((e) => e.relation === "mapped-to")).toHaveLength(1);
  });
});

describe("path", () => {
  const c = mkCase({
    artifacts: [mkArtifact("a1")],
    evidenceItems: [mkEvidence("ev1", "SPF fail")],
    findings: [mkFinding("f1", { title: "SPF fail" })],
  });

  it("finds the directed chain artifact → evidence → finding", () => {
    backfillCaseEdges(c);
    const p = path({ kind: "artifact", id: "a1" }, { kind: "finding", id: "f1" });
    expect(p).not.toBeNull();
    expect(p!.map((e) => e.relation)).toEqual(["produced", "supports"]);
  });

  it("returns null when the target is unreachable", () => {
    backfillCaseEdges(c);
    const p = path({ kind: "artifact", id: "a1" }, { kind: "finding", id: "ghost" });
    expect(p).toBeNull();
  });

  it("honors the relation whitelist", () => {
    backfillCaseEdges(c);
    const p = path({ kind: "artifact", id: "a1" }, { kind: "finding", id: "f1" }, ["extracts"]);
    expect(p).toBeNull();
  });
});

describe("explainNode", () => {
  const chained = mkCase({
    artifacts: [mkArtifact("a1")],
    evidenceItems: [mkEvidence("ev1", "Malware")],
    findings: [mkFinding("f1", { title: "Malware", iocs: [mkIoc("deadbeef", "md5")] })],
    iocs: [mkIoc("deadbeef", "md5")],
  });

  it("walks an IOC back to its artifact along the extraction spine", () => {
    backfillCaseEdges(chained);
    const { back, forward } = explainNode("ioc", "ioc-deadbeef");
    expect(back.map((e) => e.relation)).toEqual(["produced", "supports", "extracts"]);
    expect(forward).toHaveLength(0);
  });

  it("walks forward through enrichment when present", () => {
    addEdge({ relation: "enriched-by", from: { kind: "ioc", id: "ioc-deadbeef" }, to: { kind: "entity", id: "e-1" }, source: "test" });
    const { forward } = explainNode("ioc", "ioc-deadbeef", getAllEdges());
    expect(forward.map((e) => e.relation)).toEqual(["enriched-by"]);
  });

  it("stops at an artifact for finding starts", () => {
    backfillCaseEdges(chained);
    const { back } = explainNode("finding", "f1");
    expect(back.map((e) => e.relation)).toEqual(["produced", "supports"]);
  });
});

describe("projectTimeline", () => {
  const edges = [
    addEdge({ relation: "produced", from: { kind: "artifact", id: "a1" }, to: { kind: "evidence", id: "ev1" }, source: "test" }),
  ];

  it("does not crash on events without references", () => {
    const ev = { id: "ev-noref", ts: "2026-08-01T00:00:00.000Z", kind: "analyst_action" as const, category: "analyst" as const, importance: "normal" as const, actor: "analyst" as const, origin: "o", title: "t", detail: "d" };
    const out = projectTimeline([ev as unknown as CaseEvent], []);
    expect(out.get("ev-noref")!.hasProvenance).toBe(false);
    expect(out.get("ev-noref")!.edges).toEqual([]);
  });

  it("projects events whose reference participates in an edge", () => {
    const ev = { id: "ev-1", ts: "2026-08-01T00:00:00.000Z", kind: "artifact_uploaded" as const, category: "artifact" as const, importance: "normal" as const, actor: "system" as const, origin: "o", title: "t", detail: "d", references: [{ kind: "evidence" as const, id: "ev1" }] };
    const out = projectTimeline([ev], edges);
    expect(out.get("ev-1")!.hasProvenance).toBe(true);
    expect(out.get("ev-1")!.edges).toHaveLength(1);
  });

  it("marks unlinked references as no-provenance", () => {
    const ev = { id: "ev-2", ts: "2026-08-01T00:00:00.000Z", kind: "finding_created" as const, category: "finding" as const, importance: "normal" as const, actor: "system" as const, origin: "o", title: "t", detail: "d", references: [{ kind: "finding" as const, id: "ghost" }] };
    const out = projectTimeline([ev], edges);
    expect(out.get("ev-2")!.hasProvenance).toBe(false);
  });
});