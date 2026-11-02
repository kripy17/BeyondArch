import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  detectTimelineFields,
  effectiveTimelineMapping,
  loadStoredTimelineMapping,
  makeImportedEvent,
  normalizeTimestamp,
  parseTimelineRows,
  saveTimelineMapping,
  TIMELINE_IMPORT_CAP,
  importCaseTimeline,
  type ParsedTimelineRow,
} from "@/lib/timeline-import";
import { getTimelineEvents } from "@/lib/timeline";
import { loadCases } from "@/data/case";

function stubStorage(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
    clear: () => void map.clear(),
  });
}

function seedCase(events: unknown[] = []) {
  stubStorage({
    "ba.cases.v2": JSON.stringify([
      {
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
      },
    ]),
  });
}

const CSV = [
  "timestamp,name,message",
  '2026-03-01T10:00:00Z,"Suspicious logon","Failed logon for admin"',
  '"not-a-date","Bad row","should be skipped"',
].join("\n");

const JSONL = [
  '{"event":{"time":"2026-03-01T11:30:00.000Z","name":"Malware alert"},"message":"Emotet beacon observed"}',
  '{"event":{"time":1772338200,"name":"Epoch event"},"message":"epoch seconds row"}',
].join("\n");

beforeEach(() => {
  stubStorage();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("detectTimelineFields", () => {
  it("guesses ts/title/detail from csv and jsonl columns", () => {
    const g1 = detectTimelineFields(CSV);
    expect(g1?.source).toBe("csv");
    expect(g1?.guess.ts).toBe("timestamp");
    expect(g1?.confidence.ts).toBe("high");

    const g2 = detectTimelineFields(JSONL);
    expect(g2?.source).toBe("json");
    expect(g2?.guess.ts).toBe("event.time");
    expect(g2?.guess.title).toBe("event.name");
    expect(g2?.guess.detail).toBe("message");
  });

  it("guesses generic event/description/message headers at medium confidence", () => {
    const g = detectTimelineFields("timestamp,event,message\n2026-03-01T10:00:00Z,Beacon seen,C2 traffic observed");
    expect(g?.guess.ts).toBe("timestamp");
    expect(g?.guess.title).toBe("event");
    expect(g?.confidence.title).toBe("medium");
    expect(g?.guess.detail).toBe("message");
  });

  it("returns null for non-columnar input", () => {
    expect(detectTimelineFields("just some plain text\nno structure here")).toBeNull();
    expect(detectTimelineFields("")).toBeNull();
  });
});

describe("timeline mapping store", () => {
  it("corrections win over auto-guess and persist per source", () => {
    const guess = detectTimelineFields(CSV)!;
    expect(effectiveTimelineMapping(guess, null).ts).toBe("timestamp");

    saveTimelineMapping("csv", "title", "message");
    const stored = loadStoredTimelineMapping("csv");
    expect(stored?.fields.title).toBe("message");

    const merged = effectiveTimelineMapping(guess, stored);
    expect(merged.title).toBe("message");
    expect(merged.ts).toBe("timestamp");

    saveTimelineMapping("csv", "title", null);
    expect(loadStoredTimelineMapping("csv")?.fields.title).toBeUndefined();
  });
});

describe("normalizeTimestamp", () => {
  it("accepts ISO strings and epoch values, rejects garbage honestly", () => {
    expect(normalizeTimestamp("2026-03-01T10:00:00Z")).toBe("2026-03-01T10:00:00.000Z");
    expect(normalizeTimestamp("1772338200")).toBe(new Date(1772338200 * 1000).toISOString());
    expect(normalizeTimestamp("1772338200000")).toBe(new Date(1772338200000).toISOString());
    expect(normalizeTimestamp("not-a-date")).toBeNull();
    expect(normalizeTimestamp("")).toBeNull();
    expect(normalizeTimestamp(null)).toBeNull();
  });
});

describe("parseTimelineRows", () => {
  it("parses csv rows, skips bad timestamps with row numbers", () => {
    const r = parseTimelineRows(CSV, "csv", { ts: "timestamp", title: "name", detail: "message" });
    expect(r.rows).toHaveLength(1);
    expect(r.rows[0]).toMatchObject({
      index: 1,
      ts: "2026-03-01T10:00:00.000Z",
      title: "Suspicious logon",
      detail: "Failed logon for admin",
    });
    expect(r.skipped).toEqual([{ row: 2, reason: expect.stringContaining('unparseable timestamp "not-a-date"') }]);
  });

  it("falls back to a derived title and empty detail when unmapped", () => {
    const r = parseTimelineRows(CSV, "csv", { ts: "timestamp" });
    expect(r.rows[0]?.title).toBe("Imported timeline event");
    expect(r.rows[0]?.detail).toBe("");
  });

  it("handles jsonl dot-path keys including epoch seconds", () => {
    const r = parseTimelineRows(JSONL, "json", { ts: "event.time", title: "event.name", detail: "message" });
    expect(r.rows).toHaveLength(2);
    expect(r.rows[1]?.ts).toBe(new Date(1772338200 * 1000).toISOString());
    expect(r.skipped).toHaveLength(0);
  });

  it("reports an honest block when no timestamp column is mapped", () => {
    const r = parseTimelineRows(CSV, "csv", { title: "name" });
    expect(r.rows).toHaveLength(0);
    expect(r.skipped[0]?.reason).toContain("no timestamp column mapped");
  });
});

describe("makeImportedEvent", () => {
  it("builds deterministic vocabulary-conformant case events", () => {
    const row: ParsedTimelineRow = { index: 1, ts: "2026-03-01T10:00:00.000Z", title: "T", detail: "D" };
    const a = makeImportedEvent("c-1", row);
    const b = makeImportedEvent("c-1", row);
    expect(a.id).toBe(b.id);
    expect(a).toMatchObject({
      ts: "2026-03-01T10:00:00.000Z",
      kind: "analyst_action",
      category: "analyst",
      importance: "normal",
      actor: "integration",
      origin: "/parser timeline-import",
      references: [],
    });
  });
});

describe("importCaseTimeline", () => {
  it("appends events to the case, logs to the workbench feed, and dedupes re-imports", () => {
    seedCase();
    const report = importCaseTimeline("c-test", CSV, { ts: "timestamp", title: "name", detail: "message" });
    expect(report.imported).toBe(1);
    expect(report.skipped).toHaveLength(1);

    const c = loadCases().find((x) => x.id === "c-test")!;
    expect(c.events).toHaveLength(1);
    expect(c.events![0]).toMatchObject({ kind: "analyst_action", actor: "integration", title: "Suspicious logon" });

    const feed = getTimelineEvents();
    expect(feed[0]?.verb).toBe("imported");
    expect(feed[0]?.detail).toContain("Imported 1 timeline events into Test Case");

    const again = importCaseTimeline("c-test", CSV, { ts: "timestamp", title: "name", detail: "message" });
    expect(again.imported).toBe(0);
    expect(again.skipped.some((s) => s.reason.startsWith("duplicate"))).toBe(true);
    expect(loadCases().find((x) => x.id === "c-test")!.events).toHaveLength(1);
  });

  it("enforces the per-import cap instead of silently truncating", () => {
    seedCase();
    const lines = Array.from({ length: TIMELINE_IMPORT_CAP + 25 }, (_, i) =>
      `{"event":{"time":"2026-01-01T00:${String(Math.floor(i / 60)).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}Z","name":"E${i}"}}`,
    ).join("\n");
    const report = importCaseTimeline("c-test", lines, { ts: "event.time", title: "event.name" });
    expect(report.imported).toBe(TIMELINE_IMPORT_CAP);
    expect(report.skipped.filter((s) => s.reason.includes("cap"))).toHaveLength(25);
  });

  it("reports a missing target case instead of throwing", () => {
    seedCase();
    const report = importCaseTimeline("c-missing", CSV, { ts: "timestamp" });
    expect(report.imported).toBe(0);
    expect(report.skipped[0]?.reason).toBe("target case not found");
  });
});
