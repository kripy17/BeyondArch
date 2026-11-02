import { describe, expect, it, beforeEach } from "vitest";
import type { Case } from "@/data/case";
import {
  type NotebookHypothesis,
  loadHypotheses,
  saveHypotheses,
  hypothesesForCase,
  upsertHypothesis,
  deleteHypothesis,
  applyDecision,
  buildHypothesisDecisionEvent,
  attachDecision,
} from "@/data/notebook";

const ls: Record<string, string> = {};
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => ls[k] ?? null,
  setItem: (k: string, v: string) => { ls[k] = String(v); },
  removeItem: (k: string) => { delete ls[k]; },
  clear: () => { for (const k of Object.keys(ls)) delete ls[k]; },
  key: (i: number) => Object.keys(ls)[i] ?? null,
  get length() { return Object.keys(ls).length; },
};

function base(id: string, caseId: string, updatedAt: string): NotebookHypothesis {
  return {
    id, caseId,
    hypothesis: `h-${id}`,
    supporting: ["ioc-a"],
    contradicting: [],
    confidence: "low",
    status: "open",
    decision: "",
    nextStep: "pull logs",
    createdAt: updatedAt,
    updatedAt,
  };
}

beforeEach(() => { Object.keys(ls).forEach((k) => delete ls[k]); });

describe("notebook store", () => {
  it("upsert creates with id/timestamps and prepends", () => {
    const created = upsertHypothesis([], base("", "c1", ""))[0];
    expect(created.id).toMatch(/^h-/);
    expect(created.createdAt).toBeTruthy();
    expect(created.updatedAt).toBeTruthy();
    expect(created.confidence).toBe("low");
    expect(created.status).toBe("open");
  });

  it("upsert updates an existing hypothesis in place", () => {
    const original = base("h1", "c1", "2026-01-01T00:00:00.000Z");
    const [updated] = upsertHypothesis([original], { ...original, hypothesis: "revised" });
    expect(updated.hypothesis).toBe("revised");
    expect(updated.id).toBe("h1");
    expect(new Date(updated.updatedAt).getTime()).toBeGreaterThan(new Date(original.updatedAt).getTime());
  });

  it("deleteHypothesis removes only the targeted id", () => {
    const a = base("h1", "c1", "2026-01-01T00:00:00.000Z");
    const b = base("h2", "c1", "2026-01-02T00:00:00.000Z");
    const rest = deleteHypothesis([a, b], "h1");
    expect(rest).toHaveLength(1);
    expect(rest[0].id).toBe("h2");
  });

  it("hypothesesForCase filters by case and sorts by updatedAt desc", () => {
    const a = base("h1", "c1", "2026-01-01T00:00:00.000Z");
    const b = base("h2", "c1", "2026-01-03T00:00:00.000Z");
    const c = base("h3", "c2", "2026-01-02T00:00:00.000Z");
    const list = hypothesesForCase([a, b, c], "c1");
    expect(list.map((h) => h.id)).toEqual(["h2", "h1"]);
  });

  it("persists and reloads via localStorage", () => {
    saveHypotheses([base("h1", "c1", "2026-01-01T00:00:00.000Z")]);
    expect(loadHypotheses()).toHaveLength(1);
    saveHypotheses([]);
    expect(loadHypotheses()).toHaveLength(0);
  });

  it("tolerates a corrupt store", () => {
    ls["ba.notebook.hypotheses"] = "{{not json";
    expect(loadHypotheses()).toEqual([]);
  });
});

describe("notebook decisions", () => {
  it("applyDecision sets status, verdict text, confidence and bumps updatedAt", () => {
    const h = base("h1", "c1", "2026-01-01T00:00:00.000Z");
    const d = applyDecision(h, "supported", "DNS matches C2 pattern", "high");
    expect(d.status).toBe("supported");
    expect(d.decision).toBe("DNS matches C2 pattern");
    expect(d.confidence).toBe("high");
    expect(d.updatedAt > h.updatedAt).toBe(true);
  });

  it("applyDecision back to open clears the decision note", () => {
    const h = { ...base("h1", "c1", "2026-01-01T00:00:00.000Z"), decision: "old verdict" };
    const d = applyDecision(h, "open", "", "low");
    expect(d.status).toBe("open");
    expect(d.decision).toBe("");
  });

  it("buildHypothesisDecisionEvent attaches case_decision_made with analyst origin", () => {
    const c: Case = { id: "c1", title: "t", tags: [], createdAt: "", state: "active", entries: [] };
    const h = applyDecision(base("h1", "c1", "2026-01-01T00:00:00.000Z"), "refuted", "benign office traffic", "medium");
    const ev = buildHypothesisDecisionEvent(c, h, "refuted");
    expect(ev.kind).toBe("case_decision_made");
    expect(ev.category).toBe("analyst");
    expect(ev.actor).toBe("analyst");
    expect(ev.origin).toBe("notebook");
    expect(ev.detail).toContain("hypothesis refuted");
    expect(ev.detail).toContain("benign office traffic");
    expect(ev.references).toEqual([{ kind: "evidence", id: "h1" }]);
  });

  it("attachDecision appends the event to the case timeline", () => {
    const c: Case = { id: "c1", title: "t", tags: [], createdAt: "2026-01-01T00:00:00.000Z", state: "active", entries: [] };
    const h = applyDecision(base("h1", "c1", "2026-01-01T00:00:00.000Z"), "inconclusive", "", "low");
    const next = attachDecision(c, h, "inconclusive");
    expect(next?.events).toHaveLength(1);
    expect(next?.events?.[0].kind).toBe("case_decision_made");
    expect(c.events).toBeUndefined();
  });

  it("attachDecision deduplicates an identical notebook decision for the same hypothesis", () => {
    const c: Case = { id: "c1", title: "t", tags: [], createdAt: "2026-01-01T00:00:00.000Z", state: "active", entries: [] };
    const h = applyDecision(base("h1", "c1", "2026-01-01T00:00:00.000Z"), "supported", "C2 confirmed", "high");
    const attached = attachDecision(c, h, "supported");
    const repeated = attachDecision(attached ?? c, h, "supported");
    expect(repeated?.events).toHaveLength(1);
    expect(repeated?.events?.[0].detail).toContain("C2 confirmed");
  });

  it("attachDecision appends again after the decision note changes", () => {
    const c: Case = { id: "c1", title: "t", tags: [], createdAt: "2026-01-01T00:00:00.000Z", state: "active", entries: [] };
    const h1 = applyDecision(base("h1", "c1", "2026-01-01T00:00:00.000Z"), "supported", "C2 confirmed", "high");
    const c1 = attachDecision(c, h1, "supported") ?? c;
    const h2 = applyDecision(h1, "supported", "C2 confirmed after review", "high");
    const c2 = attachDecision(c1, h2, "supported");
    expect(c2?.events).toHaveLength(2);
  });
});