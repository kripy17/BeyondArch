import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createEvidenceItem, findDuplicateEvidence, appendEvidence, evidenceLinks } from "@/lib/evidence";
import { loadCases, saveCases, type Case } from "@/data/case";

function stubStorage(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
    clear: () => void map.clear(),
  });
}

function blankCase(): Case {
  return {
    id: "c-test",
    title: "Test Case",
    tags: [],
    createdAt: "2026-01-01T00:00:00.000Z",
    state: "active",
    entries: [],
    events: [],
    artifacts: [],
    findings: [],
    iocs: [],
    evidenceItems: [],
  };
}

beforeEach(() => stubStorage());
afterEach(() => vi.unstubAllGlobals());

describe("createEvidenceItem", () => {
  it("trims fields and defaults source to manual", () => {
    const ev = createEvidenceItem({ type: "log", title: "  auth.log slice  ", detail: " collected via kibana ", source: "" });
    expect(ev.title).toBe("auth.log slice");
    expect(ev.detail).toBe("collected via kibana");
    expect(ev.source).toBe("manual");
    expect(ev.id).toMatch(/^ev-[0-9a-f]{8}$/);
  });

  it("is deterministic — same inputs, same id", () => {
    const a = createEvidenceItem({ type: "file", title: "sample.exe", detail: "", source: "sandbox" });
    const b = createEvidenceItem({ type: "file", title: "sample.exe", detail: "", source: "sandbox" });
    expect(a.id).toBe(b.id);
  });

  it("coerces unknown types to other", () => {
    expect(createEvidenceItem({ type: "floppy", title: "x", detail: "", source: "" }).type).toBe("other");
  });
});

describe("findDuplicateEvidence", () => {
  it("detects identical filings and ignores distinct ones", () => {
    const first = createEvidenceItem({ type: "url", title: "hxxp://evil", detail: "", source: "" });
    expect(findDuplicateEvidence([first], createEvidenceItem({ type: "url", title: "hxxp://evil", detail: "", source: "" }))).not.toBeNull();
    expect(findDuplicateEvidence([first], createEvidenceItem({ type: "url", title: "hxxp://other", detail: "", source: "" }))).toBeNull();
  });
});

describe("appendEvidence", () => {
  it("appends the item and a vocabulary-conformant case event referencing it", () => {
    const c = blankCase();
    const ev = createEvidenceItem({ type: "pcap", title: "capture.pcap", detail: "from sensor-3", source: "sensor" });
    const next = appendEvidence(c, ev);
    expect(next.evidenceItems).toHaveLength(1);
    const event = next.events!.at(-1)!;
    expect(event.kind).toBe("analyst_action");
    expect(event.category).toBe("artifact");
    expect(event.actor).toBe("analyst");
    expect(event.origin).toBe("/case evidence-intake");
    expect(event.references).toEqual([{ kind: "evidence", id: ev.id! }]);
  });

  it("persists through the canonical cases store", () => {
    const c = blankCase();
    const next = appendEvidence(c, createEvidenceItem({ type: "note", title: "handoff note", detail: "", source: "" }));
    saveCases([next]);
    expect(loadCases()[0]!.evidenceItems![0]!.title).toBe("handoff note");
  });
});

describe("evidenceLinks", () => {
  const ev = createEvidenceItem({ type: "log", title: "t", detail: "", source: "" });

  it("emits no edges without selections", () => {
    expect(evidenceLinks(ev, {})).toEqual([]);
  });

  it("emits produced for artifact and supports for finding", () => {
    expect(evidenceLinks(ev, { artifactId: "a-1" })).toEqual([
      { relation: "produced", from: { kind: "artifact", id: "a-1" }, to: { kind: "evidence", id: ev.id! } },
    ]);
    expect(evidenceLinks(ev, { findingId: "f-1" })).toEqual([
      { relation: "supports", from: { kind: "evidence", id: ev.id! }, to: { kind: "finding", id: "f-1" } },
    ]);
    expect(evidenceLinks(ev, { artifactId: "a-1", findingId: "f-1" })).toHaveLength(2);
  });
});
