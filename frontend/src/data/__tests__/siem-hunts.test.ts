import { describe, expect, it, beforeEach } from "vitest";
import { loadHunts, saveHunts, huntAgeLabel, huntIsStale, type SavedHunt } from "@/data/siem";

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
  (globalThis as unknown as { localStorage?: FakeLocalStorage }).localStorage = new FakeLocalStorage();
});

const T0 = 1_700_000_000_000;

function mkHunt(partial: Partial<SavedHunt> = {}): SavedHunt {
  return {
    id: "hunt-1",
    name: "SSH brute",
    text: "line one\nline two",
    q: "svc_db",
    chips: [{ field: "sev", value: "high" }],
    range: "15m",
    pinned: false,
    updatedAt: T0,
    ...partial,
  };
}

describe("saved hunts persistence", () => {
  it("round-trips a hunt through localStorage", () => {
    const hunts = [mkHunt(), mkHunt({ id: "hunt-2", name: "C2 beacon", pinned: true, updatedAt: T0 + 5 })];
    saveHunts(hunts);
    const loaded = loadHunts();
    expect(loaded).toHaveLength(2);
    expect(loaded[0]).toMatchObject(hunts[1]);
    expect(loaded[1]).toMatchObject(hunts[0]);
  });

  it("returns an empty list for missing or non-array storage", () => {
    expect(loadHunts()).toEqual([]);
    localStorage.setItem("beyondlabs.siem.hunts.v1", '{"not":"an array"}');
    expect(loadHunts()).toEqual([]);
    localStorage.setItem("beyondlabs.siem.hunts.v1", "not json");
    expect(loadHunts()).toEqual([]);
  });

  it("drops malformed entries instead of crashing", () => {
    localStorage.setItem("beyondlabs.siem.hunts.v1", JSON.stringify([
      mkHunt(),
      { id: "no-name" },
      "junk",
      null,
    ]));
    const loaded = loadHunts();
    expect(loaded).toHaveLength(1);
    expect(loaded[0].id).toBe("hunt-1");
  });

  it("clamps unknown ranges to all and tolerates missing optional fields", () => {
    localStorage.setItem("beyondlabs.siem.hunts.v1", JSON.stringify([
      { id: "h1", name: "n", text: "t", range: "decade" },
    ]));
    const loaded = loadHunts();
    expect(loaded[0].range).toBe("all");
    expect(loaded[0].q).toBe("");
    expect(loaded[0].chips).toEqual([]);
    expect(loaded[0].pinned).toBe(false);
    expect(loaded[0].updatedAt).toBe(0);
  });

  it("sorts pinned hunts to the front, newest first", () => {
    saveHunts([
      mkHunt({ id: "a", pinned: false, updatedAt: T0 + 10 }),
      mkHunt({ id: "b", pinned: true, updatedAt: T0 + 1 }),
      mkHunt({ id: "c", pinned: true, updatedAt: T0 + 9 }),
    ]);
    const loaded = loadHunts();
    expect(loaded.map((h) => h.id)).toEqual(["c", "b", "a"]);
  });

  it("round-trips lastRunAt alongside the rest of the hunt", () => {
    saveHunts([mkHunt({ lastRunAt: T0 - 5_000 })]);
    expect(loadHunts()[0].lastRunAt).toBe(T0 - 5_000);
  });
});

describe("hunt re-run reminders", () => {
  it("labels relative ages", () => {
    const now = 1_700_000_000_000;
    expect(huntAgeLabel(now, now)).toBe("just now");
    expect(huntAgeLabel(now - 90_000, now)).toBe("1m ago");
    expect(huntAgeLabel(now - 45 * 60_000, now)).toBe("45m ago");
    expect(huntAgeLabel(now - 3 * 3_600_000, now)).toBe("3h ago");
    expect(huntAgeLabel(now - 2 * 86_400_000, now)).toBe("2d ago");
  });

  it("treats never-run hunts as stale and fresh runs under a day as not stale", () => {
    const now = 1_700_000_000_000;
    expect(huntIsStale(mkHunt(), now)).toBe(true);
    expect(huntIsStale(mkHunt({ lastRunAt: now - 23 * 3_600_000 }), now)).toBe(false);
    expect(huntIsStale(mkHunt({ lastRunAt: now - 25 * 3_600_000 }), now)).toBe(true);
    expect(huntIsStale(mkHunt({ lastRunAt: Number.NaN }), now)).toBe(true);
  });
});
