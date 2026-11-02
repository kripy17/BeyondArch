import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Case, CaseEvent } from "@/data/case";
import { computeRecommendations } from "@/components/investigation/InvestigationRecommendations";

const RULES_KEY = "ba.detection.rules.v2";

const TS = "2026-08-07T12:30:00.000Z";

function nav() {
  return { goToRoute: vi.fn(), goToTab: vi.fn(), closeCase: vi.fn() };
}

function caseWith(over: Partial<Case> = {}): Case {
  return {
    id: "c1",
    title: "Phishing",
    tags: [],
    state: "active",
    createdAt: TS,
    entries: [],
    events: [],
    artifacts: [],
    findings: [],
    iocs: [],
    ...over,
  };
}

function finding(technique?: string, source?: string) {
  return {
    id: "f1",
    title: "suspicious",
    detail: "",
    severity: "high" as const,
    source: source ?? "parser",
    ...(technique ? { technique } : {}),
  };
}

function event(kind: "report_generated" | "case_decision_made"): CaseEvent {
  return { id: kind, ts: TS, kind, category: "case", importance: "normal", actor: "analyst", origin: "test", title: kind, detail: "", references: [] };
}

const fakeStorage = () => {
  let store: Record<string, string> = {};
  (globalThis as Record<string, unknown>).localStorage = {
    getItem: (k: string) => store[k] ?? null,
    setItem: (k: string, v: string) => { store[k] = v; },
    removeItem: (k: string) => { delete store[k]; },
    clear: () => { store = {}; },
    key: (i: number) => Object.keys(store)[i] ?? null,
    get length() { return Object.keys(store).length; },
  };
  return store;
};

describe("computeRecommendations", () => {
  let store: Record<string, string>;
  beforeEach(() => { store = fakeStorage(); });

  it("recommends creating a rule when findings map to uncovered techniques", () => {
    const c = caseWith({ findings: [finding("T1059.001")] });
    const recs = computeRecommendations(c, nav());
    const rec = recs.find((r) => r.id === "create-rule");
    expect(rec).toBeDefined();
    expect(rec!.why).toContain("T1059.001");
  });

  it("skips create-rule when a saved rule already targets the technique", () => {
    store[RULES_KEY] = JSON.stringify([{
      id: "r1", name: "pwsh", format: "sigma", rule: "detection:\n  selection:\n    command: pwsh",
      tags: ["attack.execution"], technique: "T1059.001", state: "draft", category: "sigma",
      createdAt: TS, updatedAt: TS, version: 1,
    }]);
    const c = caseWith({ findings: [finding("T1059.001")] });
    expect(computeRecommendations(c, nav()).some((r) => r.id === "create-rule")).toBe(false);
  });

  it("recommends closing when report and decision exist on an active case", () => {
    const c = caseWith({
      findings: [finding("T1059.001")],
      events: [event("report_generated"), event("case_decision_made")],
    });
    const recs = computeRecommendations(c, nav());
    const rec = recs.find((r) => r.id === "close-investigation");
    expect(rec).toBeDefined();
  });

  it("does not recommend closing without report+decision, or when already closed", () => {
    const closed = caseWith({
      state: "closed",
      findings: [finding("T1059.001")],
      events: [event("report_generated"), event("case_decision_made")],
    });
    expect(computeRecommendations(closed, nav()).some((r) => r.id === "close-investigation")).toBe(false);

    const partial = caseWith({ findings: [finding("T1059.001")], events: [event("report_generated")] });
    expect(computeRecommendations(partial, nav()).some((r) => r.id === "close-investigation")).toBe(false);
  });

  it("caps at four recommendations", () => {
    const c = caseWith({ findings: [finding(undefined, "parser")], iocs: [{ id: "i1", value: "1.2.3.4", type: "ipv4", context: "", source: "", severity: "high" }] });
    expect(computeRecommendations(c, nav()).length).toBeLessThanOrEqual(4);
  });

  it("respects dismissed recommendations", () => {
    store["ba.case.recs.dismissed"] = JSON.stringify({ c1: ["no-findings"] });
    const recs = computeRecommendations(caseWith(), nav());
    expect(recs.some((r) => r.id === "no-findings")).toBe(false);
  });
});
