import { beforeEach, describe, expect, it } from "vitest";
import { seenBeforeForCase } from "@/lib/correlation/seen-before";
import type { Case } from "@/data/case";

class FakeLocalStorage {
  private store = new Map<string, string>();
  getItem(k: string) { return this.store.get(k) ?? null; }
  setItem(k: string, v: string) { this.store.set(k, String(v)); }
  removeItem(k: string) { this.store.delete(k); }
  clear() { this.store.clear(); }
}

function resetStore() {
  (globalThis as any).window = { localStorage: new FakeLocalStorage() };
  Object.defineProperty(globalThis, "localStorage", { value: (globalThis as any).window.localStorage, configurable: true });
}

function seedCases(cases: Case[]) {
  localStorage.setItem("ba.cases.v2", JSON.stringify(cases));
}

function mkCase(partial: Partial<Case> & { id: string }): Case {
  return {
    title: partial.id,
    tags: [],
    createdAt: "2026-08-01T00:00:00Z",
    state: "active",
    entries: [],
    ...partial,
  };
}

beforeEach(() => {
  resetStore();
  localStorage.removeItem("ba.cases.v2");
});

describe("seenBeforeForCase", () => {
  it("returns empty when no other cases exist", () => {
    seedCases([mkCase({ id: "c1", iocs: [{ id: "i1", value: "10.0.0.1", type: "ipv4" }] as any })]);
    const r = seenBeforeForCase(JSON.parse(localStorage.getItem("ba.cases.v2")!)[0]);
    expect(r.cards).toEqual([]);
    expect(r.priorCaseIds).toEqual([]);
  });

  it("returns empty when values never overlap", () => {
    seedCases([
      mkCase({ id: "c1", iocs: [{ id: "i1", value: "10.0.0.1", type: "ipv4" }] as any }),
      mkCase({ id: "c2", iocs: [{ id: "i2", value: "10.0.0.9", type: "ipv4" }] as any }),
    ]);
    const [a] = JSON.parse(localStorage.getItem("ba.cases.v2")!) as Case[];
    expect(seenBeforeForCase(a).cards).toEqual([]);
  });

  it("excludes the active case itself and finds shared values", () => {
    seedCases([
      mkCase({
        id: "c1",
        title: "Current",
        iocs: [{ id: "i1", value: "203.0.113.5", type: "ipv4", context: "C2 beacon" }] as any,
      }),
      mkCase({ id: "c2", title: "Prior A", iocs: [{ id: "i3", value: "203.0.113.5", type: "ipv4" }] as any }),
      mkCase({ id: "c3", title: "Unrelated", iocs: [{ id: "i4", value: "198.51.100.7", type: "ipv4" }] as any }),
    ]);
    const [a] = JSON.parse(localStorage.getItem("ba.cases.v2")!) as Case[];
    const r = seenBeforeForCase(a);
    expect(r.cards).toHaveLength(1);
    expect(r.cards[0].value).toBe("203.0.113.5");
    expect(r.cards[0].kind).toBe("ipv4");
    expect(r.cards[0].context).toBe("C2 beacon");
    expect(r.priorCaseIds).toEqual(["c2"]);
  });

  it("normalizes defanged and case variants to the same value", () => {
    seedCases([
      mkCase({ id: "c1", entries: [{ id: "e1", ts: "", kind: "ioc", body: "hxxp://evil.example[.]com/p" } as any], iocs: [{ id: "i1", value: "hxxp://evil.example[.]com/p", type: "url" }] as any }),
      mkCase({ id: "c2", entries: [{ id: "e2", ts: "", kind: "ioc", body: "HTTP://EVIL.EXAMPLE.COM/P" } as any] }),    ]);
    const [a, b] = JSON.parse(localStorage.getItem("ba.cases.v2")!) as Case[];
    const fromA = seenBeforeForCase(a);
    const fromB = seenBeforeForCase(b);
    expect(fromA.cards[0]?.value).toBe("http://evil.example.com/p");
    expect(fromB.priorCaseIds).toEqual(["c1"]);
  });

  it("collects ioc-entry bodies and dedupes repeated values", () => {
    seedCases([
      mkCase({
        id: "c1",
        entries: [
          { id: "e1", ts: "", kind: "ioc", body: "8.8.8.8" } as any,
          { id: "e2", ts: "", kind: "ioc", body: "8.8.8.8" } as any,
        ],
      }),
      mkCase({ id: "c2", entries: [{ id: "e3", ts: "", kind: "ioc", body: "8.8.8.8" } as any] }),
    ]);
    const [a] = JSON.parse(localStorage.getItem("ba.cases.v2")!) as Case[];
    const r = seenBeforeForCase(a);
    expect(r.cards).toHaveLength(1);
    expect(r.cards[0].priorCases.map((p) => p.id)).toEqual(["c2"]);
  });

  it("sorts cards by prior-case count desc, then value asc; refs newest case first", () => {
    seedCases([
      mkCase({ id: "c1", iocs: [
        { id: "i1", value: "shared-one.example.com", type: "domain" },
        { id: "i2", value: "10.1.1.1", type: "ipv4" },
      ] as any }),
      mkCase({ id: "c2", title: "Older", createdAt: "2026-07-01T00:00:00Z", iocs: [
        { id: "i3", value: "shared-one.example.com", type: "domain" },
        { id: "i4", value: "10.1.1.1", type: "ipv4" },
        { id: "i5", value: "only-b.example.com", type: "domain" },
      ] as any }),
      mkCase({ id: "c3", title: "Newest", createdAt: "2026-08-20T00:00:00Z", iocs: [
        { id: "i6", value: "shared-one.example.com", type: "domain" },
      ] as any }),
    ]);
    const [a] = JSON.parse(localStorage.getItem("ba.cases.v2")!) as Case[];
    const r = seenBeforeForCase(a);
    expect(r.cards.map((c) => c.value)).toEqual(["shared-one.example.com", "10.1.1.1"]);
    expect(r.cards[0].priorCases.map((p) => p.title)).toEqual(["Newest", "Older"]);
    expect(r.priorCaseIds.sort()).toEqual(["c2", "c3"]);
  });

  it("falls back to generic kind for entry-only shared values", () => {
    seedCases([
      mkCase({ id: "c1", entries: [{ id: "e1", ts: "", kind: "ioc", body: "9.9.9.9" } as any] }),
      mkCase({ id: "c2", entries: [{ id: "e2", ts: "", kind: "ioc", body: "9.9.9.9" } as any] }),
    ]);
    const [a] = JSON.parse(localStorage.getItem("ba.cases.v2")!) as Case[];
    expect(seenBeforeForCase(a).cards[0]).toMatchObject({ value: "9.9.9.9", kind: "ioc", context: "" });
  });
});
