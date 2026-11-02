import { describe, expect, it, beforeEach } from "vitest";
import { PINS_V2_KEY, loadPins, isPinnedIn, togglePinned } from "@/lib/pins";

const store = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => { store.set(k, v); },
  removeItem: (k: string) => { store.delete(k); },
  clear: () => { store.clear(); },
  key: (i: number) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
};

describe("namespaced pins", () => {
  beforeEach(() => {
    localStorage.removeItem(PINS_V2_KEY);
  });

  it("keeps namespaces independent and pins newest first", () => {
    expect(loadPins("detection")).toEqual([]);
    expect(togglePinned("detection", "r-1")).toBe(true);
    expect(togglePinned("entity", "r-1")).toBe(true);
    expect(isPinnedIn("detection", "r-1")).toBe(true);
    expect(loadPins("entity")).toEqual(["r-1"]);
    togglePinned("detection", "r-2");
    expect(loadPins("detection")).toEqual(["r-2", "r-1"]);
    expect(togglePinned("entity", "r-1")).toBe(false);
    expect(loadPins("detection")).toEqual(["r-2", "r-1"]);
  });

  it("survives malformed storage and unknown namespaces", () => {
    localStorage.setItem(PINS_V2_KEY, "{not-json");
    expect(loadPins("hunt")).toEqual([]);
    localStorage.setItem(PINS_V2_KEY, JSON.stringify({ detection: [1, "ok", null], bogus: ["x"] }));
    expect(loadPins("detection")).toEqual(["ok"]);
    expect(loadPins("bogus" as never)).toEqual([]);
  });
});
