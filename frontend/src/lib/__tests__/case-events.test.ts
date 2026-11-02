import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { addCaseEvent, removeCaseEvent, loadCases, type Case, type CaseEvent } from "@/data/case";

function stubStorage(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
    clear: () => void map.clear(),
  });
}

function mkEvent(id: string, title: string): CaseEvent {
  return {
    id,
    ts: "2026-03-01T10:00:00.000Z",
    kind: "analyst_action",
    category: "analyst",
    importance: "normal",
    actor: "integration",
    origin: "/parser timeline-import",
    title,
    detail: "",
    references: [],
  };
}

function seedCase(events: CaseEvent[]): Case {
  const c: Case = {
    id: "c-test",
    title: "Test Case",
    tags: [],
    createdAt: "2026-01-01T00:00:00.000Z",
    state: "active",
    entries: [],
    events,
    artifacts: [],
    findings: [],
    iocs: [],
    evidenceItems: [],
  };
  stubStorage({ "ba.cases.v2": JSON.stringify([c]) });
  return c;
}

beforeEach(() => stubStorage());
afterEach(() => vi.unstubAllGlobals());

describe("removeCaseEvent", () => {
  it("returns a case without the target event", () => {
    const c = seedCase([mkEvent("evt-a", "first"), mkEvent("evt-b", "second")]);
    const next = removeCaseEvent(c, "evt-a");
    expect(next).not.toBeNull();
    expect(next!.events!.map((e) => e.id)).toEqual(["evt-b"]);
  });

  it("returns null when the event id does not exist", () => {
    const c = seedCase([mkEvent("evt-a", "first")]);
    expect(removeCaseEvent(c, "evt-missing")).toBeNull();
  });

  it("returns null for legacy cases without events", () => {
    const c = seedCase([]);
    const legacy = { ...c, events: undefined };
    expect(removeCaseEvent(legacy, "evt-a")).toBeNull();
  });

  it("round-trips through persistence via loadCases", () => {
    const c = seedCase([mkEvent("evt-a", "first"), mkEvent("evt-b", "second")]);
    const removed = removeCaseEvent(c, "evt-b");
    localStorage.setItem("ba.cases.v2", JSON.stringify([removed]));
    const list = loadCases();
    expect(list[0]!.events!.map((e) => e.id)).toEqual(["evt-a"]);
  });

  it("composes with addCaseEvent (delete then re-add)", () => {
    const c = seedCase([mkEvent("evt-a", "first")]);
    const next = addCaseEvent(removeCaseEvent(c, "evt-a")!, mkEvent("evt-c", "again"));
    expect(next.events!.map((e) => e.id)).toEqual(["evt-c"]);
  });
});
