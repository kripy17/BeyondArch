import { describe, expect, it, beforeEach } from "vitest";
import {
  alertNodeId,
  computeMitreCoverage,
  deploymentNodeId,
  recordAlert,
  ruleTechniques,
  type SavedRule,
} from "@/data/detection";
import { getAllEdges, type Edge } from "@/lib/provenance";

class FakeLocalStorage {
  private store = new Map<string, string>();
  getItem(k: string): string | null { return this.store.get(k) ?? null; }
  setItem(k: string, v: string): void { this.store.set(k, v); }
  removeItem(k: string): void { this.store.delete(k); }
  clear(): void { this.store.clear(); }
  get length(): number { return this.store.size; }
  key(i: number): string | null { return [...this.store.keys()][i] ?? null; }
}

beforeEach(() => {
  (globalThis as unknown as { localStorage?: FakeLocalStorage }).localStorage = new FakeLocalStorage();
});

function mkRule(partial: Partial<SavedRule> = {}): SavedRule {
  return {
    id: "rule-1",
    name: "PowerShell encode",
    format: "sigma",
    rule: "title: Suspicious PowerShell\nlevel: high",
    event: "powershell.exe -EncodedCommand",
    created: 1000,
    updated: 1000,
    tags: [],
    ruleKey: "powershell-encode-rule-1",
    state: "draft",
    stateUpdated: 1000,
    version: 0,
    ...partial,
  };
}

function mappedEdge(techniqueId: string, id = `e-${techniqueId}`): Edge {
  return {
    id,
    relation: "mapped-to",
    from: { kind: "finding", id: "f-1" },
    to: { kind: "mitre", id: techniqueId },
    source: "backfill",
    ts: "2026-08-01T00:00:00.000Z",
    reason: "finding technique mapping",
  };
}

describe("ruleTechniques", () => {
  it("reads the explicit technique field", () => {
    expect(ruleTechniques(mkRule({ technique: "T1059.001" }))).toEqual(["T1059.001"]);
  });

  it("reads attack.* tags", () => {
    expect(ruleTechniques(mkRule({ tags: ["attack.t1059.001", "nontag"] }))).toEqual(["T1059.001"]);
  });

  it("reads attack.* references inside the rule body (Sigma convention)", () => {
    const rule = "title: x\ntags:\n  - attack.t1110\n  - attack.t1003\nlevel: medium";
    const techs = ruleTechniques(mkRule({ rule }));
    expect(techs).toEqual(["T1110", "T1003"]);
  });

  it("deduplicates across field, tags, and body", () => {
    const techs = ruleTechniques(mkRule({
      technique: "T1059.001",
      tags: ["attack.t1059.001"],
      rule: "tags:\n  - attack.t1059.001",
    }));
    expect(techs).toEqual(["T1059.001"]);
  });

  it("ignores malformed technique ids", () => {
    expect(ruleTechniques(mkRule({ technique: "not-a-technique", tags: ["attack.bogus"] }))).toEqual([]);
  });
});

describe("computeMitreCoverage", () => {
  it("marks full when a rule is deployed to the technique", () => {
    const rules = [mkRule({ technique: "T1059.001", state: "deployed", version: 1 })];
    const [c] = computeMitreCoverage(rules, []);
    expect(c).toMatchObject({ id: "T1059.001", name: "PowerShell", tactic: "Execution", ruleCount: 1, deployedCount: 1, status: "full", findingMapped: false });
  });

  it("marks partial when rules exist but none deployed", () => {
    const rules = [mkRule({ technique: "T1110", state: "draft" })];
    const [c] = computeMitreCoverage(rules, []);
    expect(c.status).toBe("partial");
    expect(c.deployedCount).toBe(0);
  });

  it("marks gap when findings map to the technique but no rule targets it", () => {
    const [c] = computeMitreCoverage([], [mappedEdge("T1003")]);
    expect(c).toMatchObject({ id: "T1003", ruleCount: 0, status: "gap", findingMapped: true });
  });

  it("keeps full coverage when findings map and a deployed rule exists", () => {
    const rules = [mkRule({ technique: "T1003", state: "deployed", version: 1 })];
    const [c] = computeMitreCoverage(rules, [mappedEdge("T1003")]);
    expect(c.status).toBe("full");
    expect(c.findingMapped).toBe(true);
  });

  it("counts multiple rules and deployed rules per technique", () => {
    const rules = [
      mkRule({ id: "a", technique: "T1053", state: "deployed", version: 1 }),
      mkRule({ id: "b", technique: "T1053", state: "draft" }),
      mkRule({ id: "c", technique: "T1053", state: "deployed", version: 1 }),
    ];
    const [c] = computeMitreCoverage(rules, []);
    expect(c).toMatchObject({ ruleCount: 3, deployedCount: 2, status: "full" });
  });

  it("excludes techniques with neither rules nor mapped findings", () => {
    expect(computeMitreCoverage([], [])).toEqual([]);
  });

  it("sorts gaps first, then partial, then full", () => {
    const rules = [
      mkRule({ id: "full", technique: "T1059.001", state: "deployed", version: 1 }),
      mkRule({ id: "partial", technique: "T1110", state: "draft" }),
    ];
    const coverage = computeMitreCoverage(rules, [mappedEdge("T1003")]);
    expect(coverage.map((c) => c.status)).toEqual(["gap", "partial", "full"]);
  });

  it("resolves unknown technique ids with no tactic instead of failing", () => {
    const [c] = computeMitreCoverage([mkRule({ technique: "T9999" })], []);
    expect(c).toMatchObject({ id: "T9999", name: "T9999", tactic: "" });
  });
});

describe("fires writer", () => {
  it("alert node id is deterministic per deployment + event digest", () => {
    const dep = deploymentNodeId("rule-1", 2);
    const a = alertNodeId(dep, "abc123");
    const b = alertNodeId(dep, "abc123");
    const c = alertNodeId(dep, "other");
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a.startsWith("al-")).toBe(true);
  });

  it("recordAlert writes a fires edge from the deployment node", () => {
    const edge = recordAlert({ ruleId: "rule-1", ruleKey: "powershell-encode-rule-1", version: 2, event: "powershell.exe -EncodedCommand" });
    expect(edge.relation).toBe("fires");
    expect(edge.from).toEqual({ kind: "deployment", id: deploymentNodeId("rule-1", 2) });
    expect(edge.to.kind).toBe("alert");
    expect(edge.reason).toContain("v2");
    expect(getAllEdges()).toHaveLength(1);
  });

  it("re-asserting the same alert is idempotent", () => {
    recordAlert({ ruleId: "rule-1", ruleKey: "k", version: 2, event: "same event" });
    recordAlert({ ruleId: "rule-1", ruleKey: "k", version: 2, event: "same event" });
    expect(getAllEdges()).toHaveLength(1);
  });

  it("different events on the same deployment create distinct alerts", () => {
    recordAlert({ ruleId: "rule-1", ruleKey: "k", version: 2, event: "event one" });
    recordAlert({ ruleId: "rule-1", ruleKey: "k", version: 2, event: "event two" });
    const edges = getAllEdges();
    expect(edges).toHaveLength(2);
    expect(new Set(edges.map((e) => e.to.id)).size).toBe(2);
  });

  it("different versions produce different deployment + alert nodes", () => {
    const v1 = recordAlert({ ruleId: "rule-1", ruleKey: "k", version: 1, event: "e" });
    const v2 = recordAlert({ ruleId: "rule-1", ruleKey: "k", version: 2, event: "e" });
    expect(v1.from.id).not.toBe(v2.from.id);
    expect(v1.to.id).not.toBe(v2.to.id);
  });
});
