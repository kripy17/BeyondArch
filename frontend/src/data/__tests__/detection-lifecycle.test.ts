import { describe, expect, it } from "vitest";
import {
  canTransition,
  DETECTION_STATES,
  detectionNodeId,
  deploymentNodeId,
  normalizeRule,
  ruleFromSignal,
  simulationNodeId,
  slugRuleKey,
  transitionRule,
  validateRule,
  type DetectionState,
  type RuleSignalSource,
  type SavedRule,
} from "@/data/detection";

const HAPPY_PATH: [DetectionState, DetectionState][] = [
  ["draft", "validated"],
  ["validated", "approved"],
  ["approved", "deployed"],
  ["deployed", "retired"],
];

const FORBIDDEN: [DetectionState, DetectionState][] = [
  ["draft", "deployed"],
  ["draft", "retired"],
  ["validated", "deployed"],
  ["deployed", "validated"],
  ["approved", "retired"],
  ["retired", "deployed"],
  ["draft", "draft"],
  ["deployed", "deployed"],
  ["retired", "retired"],
];

function mkRule(state: DetectionState, version = 0): SavedRule {
  return {
    id: "rule-1",
    name: "Powershell encode",
    format: "sigma",
    rule: "title: x",
    event: "",
    created: 1000,
    updated: 1000,
    tags: [],
    ruleKey: "powershell-encode-rule-1",
    state,
    stateUpdated: 1000,
    version,
  };
}

describe("detection lifecycle", () => {
  it.each(HAPPY_PATH)("permits %s → %s and applies it", (from, to) => {
    expect(canTransition(from, to)).toBe(true);
    const next = transitionRule(mkRule(from), to);
    expect(next).not.toBeNull();
    expect(next!.state).toBe(to);
  });

  it.each(FORBIDDEN)("rejects %s → %s", (from, to) => {
    expect(canTransition(from, to)).toBe(false);
    expect(transitionRule(mkRule(from), to)).toBeNull();
  });

  it.each([["validated", "draft"], ["approved", "draft"], ["deployed", "draft"], ["retired", "draft"]] as [DetectionState, DetectionState][])(
    "returns %s → draft on revision/rollback/reactivation",
    (from, to) => {
      expect(canTransition(from, to)).toBe(true);
    },
  );

  it("covers every documented state exactly once in the order", () => {
    expect(DETECTION_STATES).toEqual(["draft", "validated", "approved", "deployed", "retired"]);
  });

  it("preserves identity and version through a transition, stamping stateUpdated", () => {
    const next = transitionRule(mkRule("draft"), "validated")!;
    expect(next.id).toBe("rule-1");
    expect(next.ruleKey).toBe("powershell-encode-rule-1");
    expect(next.version).toBe(0);
    expect(next.stateUpdated).toBeGreaterThanOrEqual(1000);
  });

  it("walks the full lifecycle end to end", () => {
    let rule = mkRule("draft");
    for (const [, to] of HAPPY_PATH) {
      rule = transitionRule(rule, to)!;
    }
    expect(rule.state).toBe("retired");
  });

  it("supports revise-deploy bumping the version per deployment", () => {
    let rule = mkRule("deployed", 2);
    rule = transitionRule(rule, "draft")!;
    expect(rule.version).toBe(2);
    rule = transitionRule(rule, "deployed")!; // draft → deployed is forbidden without revalidation
    expect(rule).toBeNull();
  });
});

describe("legacy rule normalization", () => {
  it("normalizes rules without lifecycle fields to draft", () => {
    const r = normalizeRule({ id: "r1", name: "old", format: "sigma", rule: "title: x" });
    expect(r.state).toBe("draft");
    expect(r.version).toBe(0);
    expect(r.ruleKey).toMatch(/^old-r1$/);
  });

  it("keeps explicit lifecycle fields and stable keys", () => {
    const r = normalizeRule({ ...mkRule("deployed", 3), ruleKey: "kept-key" });
    expect(r.state).toBe("deployed");
    expect(r.version).toBe(3);
    expect(r.ruleKey).toBe("kept-key");
  });
});

describe("deterministic node ids", () => {
  it("detection id is stable per rule key and differs across keys", () => {
    expect(detectionNodeId("a")).toBe(detectionNodeId("a"));
    expect(detectionNodeId("a")).not.toBe(detectionNodeId("b"));
  });

  it("simulation id varies with rule id and event digest", () => {
    const base = simulationNodeId("r1", "digest");
    expect(simulationNodeId("r1", "digest")).toBe(base);
    expect(simulationNodeId("r2", "digest")).not.toBe(base);
    expect(simulationNodeId("r1", "other")).not.toBe(base);
  });

  it("deployment id is hashed and monotonic in version", () => {
    expect(deploymentNodeId("r1", 1)).toBe(deploymentNodeId("r1", 1));
    expect(deploymentNodeId("r1", 2)).not.toBe(deploymentNodeId("r1", 1));
  });

  it("every lifecycle id is namespaced by the node kind", () => {
    expect(detectionNodeId("k")).toMatch(/^det-/);
    expect(simulationNodeId("r", "d")).toMatch(/^sim-/);
    expect(deploymentNodeId("r", 1)).toMatch(/^dep-/);
  });
});

describe("workflow drivers: ruleFromSignal", () => {
  const fromFinding: RuleSignalSource = {
    kind: "finding",
    label: "Malicious PowerShell download",
    iocs: ["evil.example.com", '"quoted" ioc'],
    severity: "high",
    technique: "T1059.001",
  };
  const fromTechnique: RuleSignalSource = { kind: "technique", id: "T1059.001", name: "PowerShell", tactic: "execution" };
  const fromIoc: RuleSignalSource = { kind: "ioc", value: "10.0.0.66", type: "ipv4" };

  it("scaffolds a finding into a named, tagged sigma draft", () => {
    const out = ruleFromSignal(fromFinding);
    expect(out.name).toContain("Malicious PowerShell download");
    expect(out.technique).toBe("T1059.001");
    expect(out.tags).toEqual(["T1059.001"]);
    expect(out.rule).toContain("title: Detection:");
    expect(out.rule).toContain("attack.t1059.001");
    expect(out.rule).toContain("evil.example.com");
  });

  it("escapes quotes and caps the keyword list", () => {
    const out = ruleFromSignal(fromFinding);
    expect(out.rule).not.toContain('"quoted"');
    expect(out.rule).toContain("'quoted'");
    expect((out.rule.match(/^\s+- /gm) ?? []).length).toBeLessThanOrEqual(8);
  });

  it("drives rules from techniques by id", () => {
    const out = ruleFromSignal(fromTechnique);
    expect(out.name).toContain("T1059.001");
    expect(out.technique).toBe("T1059.001");
    expect(out.rule).toContain("T1059.001 · PowerShell");
  });

  it("drives rules from raw iocs without a technique", () => {
    const out = ruleFromSignal(fromIoc);
    expect(out.name).toContain("ipv4 10.0.0.66");
    expect(out.technique).toBeUndefined();
    expect(out.rule).toContain("10.0.0.66");
  });

  it.each([
    { name: "finding", src: fromFinding },
    { name: "technique", src: fromTechnique },
    { name: "ioc", src: fromIoc },
  ])("scaffolded $name rules pass sigma validation with zero errors", ({ src }) => {
    const out = ruleFromSignal(src);
    const msgs = validateRule(out.rule, "sigma");
    expect(msgs.filter((m) => m.type === "error")).toEqual([]);
  });

  it("strips unsupported characters from the name", () => {
    const out = ruleFromSignal({ kind: "ioc", value: "bad:host.exe", type: "file" });
    expect(out.name).not.toContain(":");
  });
});

describe("workflow drivers: slugRuleKey", () => {
  it("is stable, slugs the name, and keeps the id suffix", () => {
    expect(slugRuleKey("WMI Persistence", "abc123")).toBe("wmi-persistence-abc123");
    expect(slugRuleKey("WMI Persistence!", "abc123")).toBe("wmi-persistence-abc123");
  });

  it("truncates long names and falls back to rule", () => {
    expect(slugRuleKey("x".repeat(120), "id9")).toHaveLength(44);
    expect(slugRuleKey("!!", "id1")).toBe("rule-id1");
  });
});