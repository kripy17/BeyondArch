import { describe, expect, it, beforeEach } from "vitest";
import {
  GRAPH_VIEWS_KEY, MAX_VIEWS_PER_CASE,
  loadGraphViews, saveNamedView, deleteNamedView,
} from "@/lib/graph-views";

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
  const fake = new FakeLocalStorage();
  (globalThis as unknown as { localStorage?: FakeLocalStorage }).localStorage = fake;
  (globalThis as unknown as { window?: object }).window = { localStorage: fake };
});

const VP = { x: 10, y: -20, zoom: 0.75 };

describe("named graph views", () => {
  it("saves and loads a view per case", () => {
    saveNamedView("c-1", "lateral movement", { mode: "relationship", hops: 2 }, "ioc:ioc-x", VP);
    const views = loadGraphViews("c-1");
    expect(views).toHaveLength(1);
    expect(views[0].name).toBe("lateral movement");
    expect(views[0].state).toEqual({ mode: "relationship", hops: 2 });
    expect(views[0].focus).toBe("ioc:ioc-x");
    expect(views[0].viewport).toEqual(VP);
  });

  it("isolates views per case", () => {
    saveNamedView("c-1", "a", {}, null, null);
    saveNamedView("c-2", "b", {}, null, null);
    expect(loadGraphViews("c-1").map((v) => v.name)).toEqual(["a"]);
    expect(loadGraphViews("c-2").map((v) => v.name)).toEqual(["b"]);
  });

  it("overwrites when the same name is reused, keeping the id stable", () => {
    const first = saveNamedView("c-1", "view", {}, null, null);
    const second = saveNamedView("c-1", "view", { mode: "timeline" }, "case:c-1", VP);
    expect(second.id).toBe(first.id);
    const views = loadGraphViews("c-1");
    expect(views).toHaveLength(1);
    expect(views[0].viewport).toEqual(VP);
  });

  it("sorts by savedAt descending and caps per-case count", () => {
    for (let i = 0; i < MAX_VIEWS_PER_CASE + 5; i++) {
      saveNamedView("c-1", `v${i}`, {}, null, null, 1000 + i);
    }
    const views = loadGraphViews("c-1");
    expect(views).toHaveLength(MAX_VIEWS_PER_CASE);
    expect(views[0].name).toBe(`v${MAX_VIEWS_PER_CASE + 4}`);
  });

  it("rejects empty names on save", () => {
    expect(() => saveNamedView("c-1", "   ", {}, null, null)).toThrow();
  });

  it("drops junk entries instead of throwing", () => {
    localStorage.setItem(GRAPH_VIEWS_KEY, JSON.stringify({
      "c-1": [
        { id: "ok", caseId: "c-1", name: "good", state: {}, focus: null, viewport: VP, savedAt: 3 },
        "garbage",
        { name: "no-id" },
        { id: "bad-vp", caseId: "c-1", name: "zoomy", state: {}, focus: null, viewport: { x: 0, y: 0, zoom: 9 }, savedAt: 2 },
      ],
      broken: "not-an-array",
    }));
    const views = loadGraphViews("c-1");
    expect(views.map((v) => v.name)).toEqual(["good", "zoomy"]);
    expect(views[0].viewport).toEqual(VP);
    expect(views[1].viewport).toBeNull();
  });

  it("deletes by id only within the case", () => {
    const v = saveNamedView("c-1", "doomed", {}, null, null);
    saveNamedView("c-2", "keeper", {}, null, null);
    deleteNamedView("c-1", v.id);
    expect(loadGraphViews("c-1")).toHaveLength(0);
    expect(loadGraphViews("c-2")).toHaveLength(1);
  });
});
