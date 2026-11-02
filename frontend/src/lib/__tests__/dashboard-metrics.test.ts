import { describe, expect, it } from "vitest";
import { computeCaseLoad, severityShare, SEVERITIES, type CaseLoadStats } from "@/lib/dashboard-metrics";
import type { Case } from "@/data/case";
import type { IOC, Finding } from "@/types/security";

function mkIoc(value: string, severity: IOC["severity"]): IOC {
  return { value, type: "ipv4", context: "", source: "test", severity };
}

function mkFinding(id: string, severity: Finding["severity"]): Finding {
  return { id, severity, title: "t", detail: "d", source: "s" };
}

let seq = 0;
function mkCase(patch: Partial<Case> = {}): Case {
  seq += 1;
  return {
    id: `c-${String(seq).padStart(3, "0")}`,
    title: `Case ${seq}`,
    tags: [],
    createdAt: new Date(2026, 6, seq).toISOString(),
    state: "active",
    entries: [],
    events: [],
    artifacts: [],
    findings: [],
    iocs: [],
    evidenceItems: [],
    ...patch,
  };
}

describe("computeCaseLoad", () => {
  it("returns an honest zero rollup for an empty workspace", () => {
    const s = computeCaseLoad([]);
    expect(s.cases).toBe(0);
    expect(s.active).toBe(0);
    expect(s.closed).toBe(0);
    expect(s.indicators).toBe(0);
    expect(s.findings).toBe(0);
    expect(s.entries).toBe(0);
    expect(s.evidenceItems).toBe(0);
    for (const sev of SEVERITIES) expect(s.bySeverity[sev]).toBe(0);
    expect(s.recentCases).toEqual([]);
  });

  it("splits active vs closed and counts entries/evidence", () => {
    const cases = [
      mkCase({ state: "active", entries: [{ id: "e1" }] as Case["entries"], evidenceItems: [{ id: "ev1" }] as Case["evidenceItems"] }),
      mkCase({ state: "closed" }),
      mkCase({ state: "closed" }),
    ];
    const s = computeCaseLoad(cases);
    expect(s.cases).toBe(3);
    expect(s.active).toBe(1);
    expect(s.closed).toBe(2);
    expect(s.entries).toBe(1);
    expect(s.evidenceItems).toBe(1);
  });

  it("buckets indicator severities", () => {
    const cases = [
      mkCase({ iocs: [mkIoc("1.1.1.1", "critical"), mkIoc("2.2.2.2", "high"), mkIoc("3.3.3.3", "info")] }),
      mkCase({ iocs: [mkIoc("4.4.4.4", "critical")] }),
    ];
    const s = computeCaseLoad(cases);
    expect(s.indicators).toBe(4);
    expect(s.bySeverity.critical).toBe(2);
    expect(s.bySeverity.high).toBe(1);
    expect(s.bySeverity.info).toBe(1);
    expect(s.bySeverity.medium).toBe(0);
    expect(s.bySeverity.low).toBe(0);
  });

  it("counts findings separately and folds their severity into the same buckets", () => {
    const cases = [
      mkCase({
        iocs: [mkIoc("1.1.1.1", "high")],
        findings: [mkFinding("f1", "critical"), mkFinding("f2", "low")],
      }),
    ];
    const s = computeCaseLoad(cases);
    expect(s.findings).toBe(2);
    expect(s.indicators).toBe(1);
    expect(s.bySeverity.critical).toBe(1);
    expect(s.bySeverity.high).toBe(1);
    expect(s.bySeverity.low).toBe(1);
  });

  it("lists recent cases newest-first capped at five by createdAt string compare", () => {
    const cases = Array.from({ length: 7 }, (_, i) =>
      mkCase({ createdAt: new Date(Date.UTC(2026, 0, i + 1)).toISOString() }));
    const s = computeCaseLoad(cases);
    expect(s.recentCases).toHaveLength(5);
    const dates = s.recentCases.map((c) => c.createdAt);
    expect([...dates].sort((a, b) => b.localeCompare(a))).toEqual(dates);
    expect(dates[0]).toBe(new Date(Date.UTC(2026, 0, 7)).toISOString());
  });

  it("severityShare returns percent share and guards zero totals", () => {
    expect(severityShare(1, 4)).toBe(25);
    expect(severityShare(3, 4)).toBe(75);
    expect(severityShare(0, 0)).toBe(0);
  });

  it("keeps stats shape stable (all severity keys present)", () => {
    const s: CaseLoadStats = computeCaseLoad([mkCase()]);
    expect(Object.keys(s.bySeverity).sort()).toEqual(["critical", "high", "info", "low", "medium"]);
  });
});
