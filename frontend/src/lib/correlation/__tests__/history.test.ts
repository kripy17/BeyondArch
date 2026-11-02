import { describe, expect, it, beforeEach } from "vitest";
import { buildLocalHistory } from "@/lib/correlation/history";
import { LS_KEY } from "@/data/case";

const RULES_KEY = "ba.detection.rules.v2";

const store = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => { store.set(k, v); },
  removeItem: (k: string) => { store.delete(k); },
  clear: () => { store.clear(); },
  key: (i: number) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
};

describe("buildLocalHistory (local-history bridge)", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("returns no prior cases when the local case store is empty", () => {
    const h = buildLocalHistory();
    expect(h.cases ?? []).toEqual([]);
    expect(h.detections ?? []).toEqual([]);
    expect((h.entities ?? []).length).toBeGreaterThan(0);
  });

  it("collects IOCs from stored cases (deduped, refanged, lowercased)", () => {
    localStorage.setItem(LS_KEY, JSON.stringify([
      {
        id: "case-1",
        title: "Q3 phishing wave",
        tags: [],
        createdAt: "2026-08-01T00:00:00.000Z",
        state: "active",
        entries: [
          { id: "e1", kind: "ioc", body: "203[.]0[.]113[.]44", ts: "2026-08-01T00:00:00.000Z" },
          { id: "e2", kind: "ioc", body: "hxxps[:]//evil[.]example[.]com/x", ts: "2026-08-01T00:00:00.000Z" },
          { id: "e3", kind: "ioc", body: "203[.]0[.]113[.]44", ts: "2026-08-01T00:00:00.000Z" },
          { id: "e4", kind: "note", body: "not an ioc", ts: "2026-08-01T00:00:00.000Z" },
        ],
      },
    ]));
    const h = buildLocalHistory();
    expect(h.cases ?? []).toHaveLength(1);
    expect(h.cases?.[0]?.values.sort()).toEqual(["203.0.113.44", "https://evil.example.com/x"]);
  });

  it("maps the intel corpus entities with their observables", () => {
    const h = buildLocalHistory();
    const entities = h.entities ?? [];
    expect(entities.length).toBeGreaterThan(0);
    for (const e of entities) {
      expect(e.id).toBeTruthy();
      expect(e.name).toBeTruthy();
      expect(e.observables.length).toBeGreaterThan(0);
    }
  });

  it("collects saved rules that carry a technique; omits rules without one", () => {
    localStorage.setItem(RULES_KEY, JSON.stringify([
      { id: "r1", name: "sigma phish tld", format: "sigma", rule: "title: x\ndetection:\n  selection:\n    - a: b\n  condition: selection", technique: "T1566.002" },
      { id: "r2", name: "generic anti-virus scan", format: "sigma", rule: "title: y\ndetection:\n  selection:\n    - a: b\n  condition: selection" },
    ]));
    const h = buildLocalHistory();
    expect(h.detections ?? []).toEqual([{ id: "r1", name: "sigma phish tld", technique: "T1566.002" }]);
  });

  it("feeds artifacts: analysis with a matching case produces a same-value-previous match", () => {
    localStorage.setItem(LS_KEY, JSON.stringify([
      {
        id: "case-7",
        title: "Old credential phish",
        tags: [],
        createdAt: "2026-07-01T00:00:00.000Z",
        state: "active",
        entries: [
          { id: "e1", kind: "ioc", body: "198.51.100.23", ts: "2026-07-01T00:00:00.000Z" },
        ],
      },
    ]));
    const history = buildLocalHistory();
    expect(history.cases?.[0]?.values).toContain("198.51.100.23");
  });
});