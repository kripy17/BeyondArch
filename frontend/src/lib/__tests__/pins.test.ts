import { describe, expect, it, beforeEach } from "vitest";
import { PINS_KEY, loadPinnedCaseIds, isPinned, togglePin } from "@/lib/pins";

const store = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => { store.set(k, v); },
  removeItem: (k: string) => { store.delete(k); },
  clear: () => { store.clear(); },
  key: (i: number) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
};

describe("pins", () => {
  beforeEach(() => {
    localStorage.removeItem(PINS_KEY);
  });

  it("starts empty and pins to the front", () => {
    expect(loadPinnedCaseIds()).toEqual([]);
    expect(togglePin("c-1")).toBe(true);
    expect(loadPinnedCaseIds()).toEqual(["c-1"]);
    expect(togglePin("c-2")).toBe(true);
    expect(loadPinnedCaseIds()).toEqual(["c-2", "c-1"]);
    expect(isPinned("c-1")).toBe(true);
  });

  it("unpins and survives malformed storage", () => {
    togglePin("c-1");
    expect(togglePin("c-1")).toBe(false);
    expect(loadPinnedCaseIds()).toEqual([]);
    expect(isPinned("c-1")).toBe(false);
    localStorage.setItem(PINS_KEY, "{not-json");
    expect(loadPinnedCaseIds()).toEqual([]);
    localStorage.setItem(PINS_KEY, JSON.stringify([1, "c-9", null]));
    expect(loadPinnedCaseIds()).toEqual(["c-9"]);
  });
});
