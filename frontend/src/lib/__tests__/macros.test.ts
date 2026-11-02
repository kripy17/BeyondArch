import { describe, expect, it, beforeEach } from "vitest";
import {
  MACROS_KEY, MACRO_STEPS_LIMIT, macroId, loadMacros,
  createMacroFromRecent, deleteMacro, type Macro,
} from "@/lib/palette/macros";

const store = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => { store.set(k, v); },
  removeItem: (k: string) => { store.delete(k); },
  clear: () => { store.clear(); },
  key: (i: number) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
};

const recents = [
  { id: "nav-/case", title: "Case", ts: 3 },
  { id: "nav-/detection", title: "Detection workspace", ts: 2 },
  { id: "nav-/siem", title: "SIEM", ts: 1 },
];

describe("palette macros", () => {
  beforeEach(() => {
    localStorage.removeItem(MACROS_KEY);
    localStorage.removeItem("ba.palette.recent.v1");
  });

  it("deterministic id per normalized name", () => {
    expect(macroId("Daily Sweep")).toBe(macroId("daily sweep "));
    expect(macroId("a")).not.toBe(macroId("b"));
  });

  it("returns null for empty name or no recents — never fabricates empty macros", () => {
    expect(createMacroFromRecent("")).toBeNull();
    expect(createMacroFromRecent("solo")).toBeNull();
  });

  it("builds from recents in order, dedupes ids, caps at limit", () => {
    const m = createMacroFromRecent("Morning sweep", recents);
    expect(m).not.toBeNull();
    expect(m!.steps.map((s) => s.id)).toEqual(["nav-/case", "nav-/detection", "nav-/siem"]);
    const duped = createMacroFromRecent("Dupe run", [
      { id: "x", title: "X", ts: 2 },
      { id: "x", title: "X again", ts: 1 },
      ...Array.from({ length: MACRO_STEPS_LIMIT + 3 }, (_, i) => ({ id: `k${i}`, title: `K${i}`, ts: 0 - i })),
    ]);
    expect(duped!.steps.length).toBe(MACRO_STEPS_LIMIT);
    expect(duped!.steps[0].id).toBe("x");
  });

  it("re-saving a name replaces the macro; list sorts newest first; delete works", () => {
    const first = createMacroFromRecent("Sweep", [recents[0]]);
    const second = createMacroFromRecent("Sweep", recents.slice(1));
    expect(second!.id).toBe(first!.id);
    expect(loadMacros().length).toBe(1);
    expect(loadMacros()[0].steps.length).toBe(2);

    const other = createMacroFromRecent("Other", [recents[2]]);
    const listed = loadMacros();
    expect(listed.map((m: Macro) => m.id)).toEqual([other!.id, second!.id]);

    deleteMacro(second!.id);
    expect(loadMacros().map((m: Macro) => m.id)).toEqual([other!.id]);
  });

  it("survives malformed storage", () => {
    localStorage.setItem(MACROS_KEY, "{nope");
    expect(loadMacros()).toEqual([]);
    localStorage.setItem(MACROS_KEY, JSON.stringify([{ id: 1 }, null, { id: "mac-x", name: "ok", createdAt: 5, steps: [{ id: "a", title: "A" }] }]));
    expect(loadMacros().length).toBe(1);
    expect(loadMacros()[0].name).toBe("ok");
  });
});
