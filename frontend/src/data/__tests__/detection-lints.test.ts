import { describe, expect, it } from "vitest";
import { validateRule, CONVERSION_PARITY, type ParityRow } from "@/data/detection";

const SIGMA_OK = `title: Suspicious PowerShell
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: Detects suspicious powershell
author: test
references:
  - https://example.test
level: high
falsepositives:
  - admin scripts
logsource:
  product: windows
detection:
  selection:
    CommandLine|contains: "-enc"
  condition: selection
`;

const YARA_OK = `rule test_rule
{
  meta:
    author = "test"
  strings:
    $a = "mimikatz"
  condition:
    $a
}`;

describe("sigma quality lints", () => {
  it("flags missing falsepositives, references, and description", () => {
    const msgs = validateRule("title: t\ndetection:\n  selection:\n    a: b\n  condition: selection", "sigma");
    const text = msgs.map((m) => m.msg).join("\n");
    expect(text).toContain("falsepositives");
    expect(text).toContain("references");
    expect(text).toContain("description");
  });

  it("errors when the condition references an undefined key", () => {
    const msgs = validateRule(SIGMA_OK.replace("condition: selection", "condition: selction"), "sigma");
    expect(msgs.some((m) => m.type === "error" && m.msg.includes('"selction"'))).toBe(true);
  });

  it("warns when a defined key is never referenced by the condition", () => {
    const msgs = validateRule(SIGMA_OK.replace("condition: selection", "condition: filter"), "sigma");
    expect(msgs.some((m) => m.type === "warning" && m.msg.includes('"selection" is never referenced'))).toBe(true);
  });

  it("accepts wildcard condition prefixes when matching keys exist", () => {
    const msgs = validateRule(SIGMA_OK.replace("condition: selection", "condition: 1 of select*"), "sigma");
    expect(msgs.some((m) => m.type === "error")).toBe(false);
  });

  it("errors on wildcard prefixes with no matching keys", () => {
    const msgs = validateRule(SIGMA_OK.replace("condition: selection", "condition: 1 of filter*"), "sigma");
    expect(msgs.some((m) => m.type === "error" && m.msg.includes('filter*'))).toBe(true);
  });
});

describe("yara quality lints", () => {
  it("warns on missing meta section", () => {
    const msgs = validateRule(YARA_OK.replace(/meta:\n {4}author = "test"\n/, ""), "yara");
    expect(msgs.some((m) => m.type === "warning" && m.msg.includes("meta"))).toBe(true);
  });

  it("errors when the condition references an undefined string", () => {
    const msgs = validateRule(YARA_OK.replace("$a\n}", "$a and $b\n}"), "yara");
    expect(msgs.some((m) => m.type === "error" && m.msg.includes("$b"))).toBe(true);
  });

  it("warns when a defined string is unused in the condition", () => {
    const rule = YARA_OK.replace('$a = "mimikatz"', '$a = "mimikatz"\n    $b = "unused"');
    const msgs = validateRule(rule, "yara");
    expect(msgs.some((m) => m.type === "warning" && m.msg.includes("$b") && m.msg.includes("never referenced"))).toBe(true);
  });

  it("errors on unbalanced braces", () => {
    const msgs = validateRule(YARA_OK.replace(/\}\s*$/, ""), "yara");
    expect(msgs.some((m) => m.type === "error" && m.msg.toLowerCase().includes("brace"))).toBe(true);
  });
});

describe("kql quality lints", () => {
  it("errors on unbalanced parentheses while ignoring parens inside quoted strings", () => {
    const open = validateRule("SysmonEvent | where CommandLine contains '(x'", "kql");
    expect(open.some((m) => m.type === "error" && m.msg.includes("'('"))).toBe(true);
    const closed = validateRule("SysmonEvent | where (a == 1) | take 10", "kql");
    expect(closed.some((m) => m.type === "error")).toBe(false);
  });

  it("warns on search operator and missing projection", () => {
    const msgs = validateRule("search \"mimikatz\"", "kql");
    const text = msgs.map((m) => m.msg).join("\n");
    expect(text).toContain("'search'");
    expect(text).toContain("projection/limit");
  });
});

describe("conversion parity reference", () => {
  const cells = ["sigma", "kql", "yara"] as const;

  it("covers core constructs with valid cell values", () => {
    expect(CONVERSION_PARITY.length).toBeGreaterThanOrEqual(8);
    for (const row of CONVERSION_PARITY as ParityRow[]) {
      expect(row.construct.trim().length).toBeGreaterThan(0);
      for (const c of cells) expect(["yes", "partial", "no"]).toContain(row[c]);
      expect(row.note.trim().length).toBeGreaterThan(0);
    }
  });

  it("keeps proximity yara-only and aggregation non-yara per format reality", () => {
    const proximity = CONVERSION_PARITY.find((r) => r.construct.startsWith("proximity"));
    expect(proximity?.yara).toBe("yes");
    expect(proximity?.sigma).toBe("no");
    const agg = CONVERSION_PARITY.find((r) => r.construct.startsWith("aggregations"));
    expect(agg?.yara).toBe("no");
  });
});
