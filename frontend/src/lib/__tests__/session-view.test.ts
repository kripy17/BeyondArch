import { describe, expect, it, beforeEach } from "vitest";
import {
  SESSION_VIEW_KEY, loadViewState, saveViewState, clearViewState,
} from "@/lib/session-view";

const store = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => { store.set(k, v); },
  removeItem: (k: string) => { store.delete(k); },
  clear: () => { store.clear(); },
  key: (i: number) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
};
// lib/storage guards on `window`; expose the stubbed globals to satisfy it.
(globalThis as Record<string, unknown>).window = globalThis;

describe("session view state", () => {
  beforeEach(() => {
    localStorage.removeItem(SESSION_VIEW_KEY);
  });

  it("round-trips per-key values without clobbering other keys", () => {
    expect(loadViewState<string>("graph:c-1")).toBeNull();
    saveViewState("graph:c-1", { mode: "timeline", hops: 2 });
    saveViewState("case-sidebar", { q: "lumma" });
    expect(loadViewState("graph:c-1")).toEqual({ mode: "timeline", hops: 2 });
    expect(loadViewState<{ q: string }>("case-sidebar")!.q).toBe("lumma");
    clearViewState("graph:c-1");
    expect(loadViewState("graph:c-1")).toBeNull();
    expect(loadViewState<{ q: string }>("case-sidebar")).toEqual({ q: "lumma" });
  });

  it("prunes expired entries on access", () => {
    saveViewState("old", { v: 1 });
    const raw = JSON.parse(localStorage.getItem(SESSION_VIEW_KEY)!);
    raw["old"].ts = Date.now() - 8 * 24 * 60 * 60 * 1000;
    raw["fresh"] = { v: { ok: true }, ts: Date.now() };
    localStorage.setItem(SESSION_VIEW_KEY, JSON.stringify(raw));
    expect(loadViewState("old")).toBeNull();
    expect(loadViewState("fresh")).toEqual({ ok: true });
  });

  it("survives malformed storage", () => {
    localStorage.setItem(SESSION_VIEW_KEY, "{broken");
    expect(loadViewState("x")).toBeNull();
    saveViewState("x", true);
    expect(loadViewState("x")).toBe(true);
  });
});
