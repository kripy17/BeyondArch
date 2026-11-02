import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  backupFilename,
  collectWorkspace,
  parseBackup,
  restoreBackup,
  serializeBackup,
} from "@/lib/workspace-backup";

function stubStorage(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
    clear: () => void map.clear(),
    key: (i: number) => Array.from(map.keys())[i] ?? null,
    get length() {
      return map.size;
    },
  });
}

beforeEach(() => stubStorage({ "ba.cases.v2": "[]", "other-app.key": "keep-me-out" }));
afterEach(() => vi.unstubAllGlobals());

describe("collectWorkspace", () => {
  it("captures only ba.* keys, sorted", () => {
    const b = collectWorkspace();
    expect(b.format).toBe("beyondlabs-workspace");
    expect(b.entries.map((e) => e.key)).toEqual(["ba.cases.v2"]);
  });
});

describe("parseBackup", () => {
  it("round-trips through serialize", () => {
    const b = collectWorkspace();
    const parsed = parseBackup(serializeBackup(b));
    expect(parsed.entries).toEqual(b.entries);
  });

  it("rejects invalid JSON, foreign formats, and future versions honestly", () => {
    expect(() => parseBackup("{nope")).toThrow("Not valid JSON");
    expect(() => parseBackup(JSON.stringify({ hello: true }))).toThrow(/Not a BeyondLabs workspace backup/);
    expect(() => parseBackup(JSON.stringify({ format: "beyondlabs-workspace", version: 999, entries: [] }))).toThrow(/newer than this app/);
    expect(() => parseBackup(JSON.stringify({ format: "beyondlabs-workspace", version: 1 }))).toThrow(/no entries/);
  });
});

describe("restoreBackup", () => {
  it("overwrites ba.* keys and never writes foreign keys", () => {
    const donor = { "ba.cases.v2": '[{"id":"c-1"}]', "ba.timeline.v1": "{}" };
    const parsed = parseBackup(
      JSON.stringify({
        format: "beyondlabs-workspace",
        version: 1,
        exportedAt: "2026-08-25T00:00:00.000Z",
        entries: [
          { key: "ba.cases.v2", value: donor["ba.cases.v2"] },
          { key: "ba.timeline.v1", value: donor["ba.timeline.v1"] },
          { key: "evil.key", value: "nope" },
        ],
      }),
    );
    const report = restoreBackup(parsed);
    expect(report.restored).toEqual(["ba.cases.v2", "ba.timeline.v1"]);
    expect(report.skippedForeign).toEqual(["evil.key"]);
    expect(localStorage.getItem("ba.cases.v2")).toBe(donor["ba.cases.v2"]);
    expect(localStorage.getItem("other-app.key")).toBe("keep-me-out");
  });

  it("full round-trip: export → wipe → import restores the workspace", () => {
    localStorage.setItem("ba.attachments.v1", '{"att-1":"data"}');
    const snapshot = serializeBackup(collectWorkspace());
    stubStorage({});
    expect(localStorage.getItem("ba.cases.v2")).toBeNull();
    const report = restoreBackup(parseBackup(snapshot));
    expect(report.restored.length).toBe(2);
    expect(localStorage.getItem("ba.attachments.v1")).toBe('{"att-1":"data"}');
  });
});

describe("backupFilename", () => {
  it("uses the export date stamp", () => {
    expect(backupFilename({ format: "beyondlabs-workspace", version: 1, exportedAt: "2026-08-25T10:00:00.000Z", entries: [] })).toBe(
      "beyondlabs-workspace-2026-08-25.json",
    );
  });
});
