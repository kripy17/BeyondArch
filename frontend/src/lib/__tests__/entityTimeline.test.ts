import { beforeEach, describe, expect, it } from "vitest";
import { entityTimeline, normalizeEntityValue } from "@/lib/timeline/entity-timeline";

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

beforeEach(() => {
  resetStore();
});

describe("normalizeEntityValue", () => {
  it("refangs and lowercases", () => {
    expect(normalizeEntityValue("hxxp://EVIL.example[.]com")).toBe("http://evil.example.com");
  });
});

describe("entityTimeline", () => {
  it("returns empty for blank values", () => {
    expect(entityTimeline("   ").appearances).toEqual([]);
  });

  it("collects case appearances from iocs and ioc entries with state", () => {
    localStorage.setItem("ba.cases.v2", JSON.stringify([
      {
        id: "c1", title: "Case One", tags: [], createdAt: "2026-08-01T00:00:00Z", state: "active",
        entries: [],
        iocs: [{ id: "i1", value: "203.0.113.9", type: "ipv4", context: "beacon dst" }],
      },
      {
        id: "c2", title: "Case Two", tags: [], createdAt: "2026-07-01T00:00:00Z", state: "closed",
        entries: [{ id: "e1", ts: "", kind: "ioc", body: "203.0.113.9" }],
      },
      {
        id: "c3", title: "Unrelated", tags: [], createdAt: "2026-06-01T00:00:00Z", state: "active", entries: [],
      },
    ]));
    const r = entityTimeline("203.0.113.9");
    expect(r.surfacesCovered).toEqual(["case"]);
    expect(r.appearances.map(a => a.refId)).toEqual(["c1", "c2"]);
    expect(r.appearances[0]).toMatchObject({ surface: "case", state: "active", detail: "beacon dst" });
    expect(r.appearances[1].state).toBe("closed");
  });

  it("collects triage alert appearances and merges surfaces sorted desc by ts", () => {
    localStorage.setItem("ba.cases.v2", JSON.stringify([
      { id: "c1", title: "Older case", tags: [], createdAt: "2026-08-01T00:00:00Z", state: "active", entries: [], iocs: [{ id: "i1", value: "evil.example.com", type: "domain" }] },
    ]));
    localStorage.setItem("ba.triage.v1", JSON.stringify([
      { id: "g1", ts: "2026-08-20T10:00:00Z", title: "Sigma hit", status: "escalated", iocs: [{ type: "domain", value: "evil.example.com" }] },
      { id: "g2", ts: "2026-08-10T10:00:00Z", title: "Other alert", status: "open", iocs: [{ type: "domain", value: "other.example.com" }] },
    ]));
    const r = entityTimeline("Evil.Example.Com");
    expect(r.appearances.map(a => a.refId)).toEqual(["g1", "c1"]);
    expect(r.appearances[0]).toMatchObject({ surface: "alert", state: "escalated", title: "Sigma hit" });
    expect(r.surfacesCovered).toEqual(["alert", "case"]);
  });

  it("matches defanged variants across stores", () => {
    localStorage.setItem("ba.cases.v2", JSON.stringify([
      { id: "c1", title: "Defanged source", tags: [], createdAt: "2026-08-01T00:00:00Z", state: "active", entries: [], iocs: [{ id: "i1", value: "hxxp://bad.example[.]net/x", type: "url" }] },
    ]));
    const r = entityTimeline("http://bad.example.net/x");
    expect(r.appearances.map(a => a.refId)).toEqual(["c1"]);
  });

  it("reports empty timeline honestly when nothing observed the value", () => {
    localStorage.setItem("ba.cases.v2", "[]");
    localStorage.setItem("ba.triage.v1", "[]");
    const r = entityTimeline("10.9.9.9");
    expect(r.appearances).toEqual([]);
    expect(r.surfacesCovered).toEqual([]);
  });
});
