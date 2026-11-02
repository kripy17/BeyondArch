import { describe, expect, it } from "vitest";
import { normalizeRule, ruleCategory, categorizeRules, RULE_CATEGORIES, type SavedRule, type RuleCategory } from "../detection";

const mk = (over: Partial<SavedRule>): SavedRule =>
  normalizeRule({ id: "r1", name: "rule", format: "sigma", rule: "title: Test", ...over });

describe("ruleCategory", () => {
  it("prefers the explicit category field", () => {
    expect(ruleCategory({ category: "network", rule: "powershell.exe -NoP -EncodedCommand" })).toBe("network");
  });

  it("infers windows from sigma logsource product", () => {
    expect(ruleCategory({ rule: "logsource:\n  product: windows\n  category: process_creation" })).toBe("windows");
  });

  it("infers identity from kerberos", () => {
    expect(ruleCategory({ rule: "selection: Kerberos TGT request 4624" })).toBe("identity");
  });

  it("infers cloud from cloudtrail", () => {
    expect(ruleCategory({ rule: "event: CloudTrail log read" })).toBe("cloud");
  });

  it("returns undefined with no hint and no field", () => {
    expect(ruleCategory({ rule: "selection:\n  a: true" })).toBeUndefined();
  });

  it("covers every documented category", () => {
    expect(RULE_CATEGORIES).toEqual(["windows", "linux", "cloud", "identity", "email", "network", "web"]);
    const samples: Record<RuleCategory, string> = {
      windows: "powershell -Command",
      linux: "auditd execve",
      cloud: "cloudtrail GetCallerIdentity",
      identity: "Kerberos 4624",
      email: "Exchange phish sender",
      network: "dns_query answer",
      web: "nginx access log",
    };
    for (const c of RULE_CATEGORIES) {
      expect(ruleCategory({ rule: samples[c] }), c).toBe(c);
    }
  });
});

describe("categorizeRules", () => {
  it("counts explicit categories", () => {
    const rules = [
      mk({ name: "a", category: "windows" }),
      mk({ name: "b", category: "windows" }),
      mk({ name: "c", category: "network" }),
    ];
    const m = categorizeRules(rules);
    expect(m.get("windows")).toBe(2);
    expect(m.get("network")).toBe(1);
    expect(m.get(undefined)).toBeUndefined();
  });

  it("counts inferred and unfiled rules", () => {
    const rules = [mk({ name: "a" }), mk({ name: "b", rule: "logsource: product: windows" })];
    const m = categorizeRules(rules);
    expect(m.get("windows")).toBe(1);
    expect(m.get(undefined)).toBe(1);
  });
});

describe("normalizeRule", () => {
  it("round-trips an explicit category", () => {
    const r = mk({ category: "email" });
    expect(r.category).toBe("email");
  });

  it("defaults category to undefined for legacy rules", () => {
    const r = mk({});
    expect(r.category).toBeUndefined();
  });
});