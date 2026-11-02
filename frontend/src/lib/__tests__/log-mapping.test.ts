import { describe, expect, it, beforeEach } from "vitest";
import {
  detectLogFields, loadStoredMapping, saveFieldMapping, effectiveMapping,
  extractValue, LOG_MAPPINGS_KEY,
} from "@/lib/log-mapping";
import { autoDetectInputType } from "@/data/parser";

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
  const fake = new FakeLocalStorage();
  (globalThis as unknown as { localStorage?: FakeLocalStorage }).localStorage = fake;
  (globalThis as unknown as { window?: object }).window = { localStorage: fake };
});

const ZEEK = [
  "#separator\\x09",
  "#fields\tts\tuid\tid.orig_h\tid.resp_h",
  "1745574720.0\tCXYZ123\t198.51.100.23\t10.0.0.5",
].join("\n");

const CSV = [
  "src_ip,dst_ip,user_name,rule_name,severity",
  '198.51.100.23,10.0.0.5,jdoe,"SQL injection",2',
].join("\n");

const JSON_LINE = '{"timestamp":"2026-04-25T10:12:00Z","event_type":"alert","src_ip":"198.51.100.23","dest_ip":"10.0.0.5","alert":{"signature":"ET SQLi","severity":2}}';

describe("detectLogFields", () => {
  it("returns null for empty or non-columnar text", () => {
    expect(detectLogFields("")).toBeNull();
    expect(detectLogFields("just some free text\nmore text")).toBeNull();
  });

  it("detects zeek TSV and guesses orig/resp hosts", () => {
    const g = detectLogFields(ZEEK)!;
    expect(g.source).toBe("zeek-tsv");
    expect(g.guess.src).toBe("id.orig_h");
    expect(g.guess.dst).toBe("id.resp_h");
    expect(g.confidence.src).toBe("medium");
    expect(g.guess.user).toBeUndefined();
  });

  it("detects CSV with canonical header matches at high confidence", () => {
    const g = detectLogFields(CSV)!;
    expect(g.source).toBe("csv");
    expect(g.guess).toMatchObject({ src: "src_ip", dst: "dst_ip", user: "user_name", sig: "rule_name", sev: "severity" });
    expect(g.confidence.src).toBe("high");
  });

  it("flattens nested JSON keys for guesses", () => {
    const g = detectLogFields(JSON_LINE)!;
    expect(g.source).toBe("json");
    expect(g.columns).toContain("alert.signature");
    expect(g.guess.sig).toBe("alert.signature");
    expect(g.guess.sev).toBe("alert.severity");
    expect(g.guess.dst).toBe("dest_ip");
  });
});

describe("extractValue", () => {
  it("reads zeek columns by index from the data line", () => {
    expect(extractValue(ZEEK, "zeek-tsv", "id.orig_h")).toBe("198.51.100.23");
    expect(extractValue(ZEEK, "zeek-tsv", "uid")).toBe("CXYZ123");
  });

  it("resolves dotted JSON paths", () => {
    expect(extractValue(JSON_LINE, "json", "alert.signature")).toBe("ET SQLi");
    expect(extractValue(JSON_LINE, "json", "missing.key")).toBeNull();
  });

  it("reads CSV rows honoring quoted values", () => {
    expect(extractValue(CSV, "csv", "rule_name")).toBe("SQL injection");
    expect(extractValue(CSV, "csv", "user_name")).toBe("jdoe");
  });
});

describe("mapping persistence", () => {
  it("stores a correction per source and merges it over the guess", () => {
    const g = detectLogFields(ZEEK)!;
    saveFieldMapping("zeek-tsv", "user", "uid");
    const stored = loadStoredMapping("zeek-tsv");
    const merged = effectiveMapping(g, stored);
    expect(merged.user).toBe("uid");
    expect(merged.src).toBe("id.orig_h");
  });

  it("clearing a field reverts to auto guess (or unmaps)", () => {
    saveFieldMapping("zeek-tsv", "src", "uid");
    saveFieldMapping("zeek-tsv", "src", null);
    const g = detectLogFields(ZEEK)!;
    const merged = effectiveMapping(g, loadStoredMapping("zeek-tsv"));
    expect(merged.src).toBe("id.orig_h");
  });

  it("keeps sources isolated under one storage key", () => {
    saveFieldMapping("csv", "sev", "level_x");
    saveFieldMapping("zeek-tsv", "src", "uid");
    const raw = JSON.parse((globalThis as unknown as { localStorage: FakeLocalStorage }).localStorage.getItem(LOG_MAPPINGS_KEY)!) as Record<string, unknown>;
    expect(Object.keys(raw)).toHaveLength(2);
    expect(loadStoredMapping("csv")?.fields.sev).toBe("level_x");
    expect(loadStoredMapping("zeek-tsv")?.fields.src).toBe("uid");
  });
});

describe("autoDetectInputType confidence", () => {
  it("labels strong anchors high with evidence listed", () => {
    const r = autoDetectInputType('#separator\\x09\n#fields\tts\tuid')!;
    expect(r.label).toBe("Zeek log");
    expect(r.level).toBe("high");
    expect(r.evidence.length).toBeGreaterThan(0);
  });

  it("returns medium for single-signal detections", () => {
    const r = autoDetectInputType('{"event_type":"alert","src_ip":"1.2.3.4"}')!;
    expect(r.level).toBe("medium");
  });

  it("returns null for empty input", () => {
    expect(autoDetectInputType("   ")).toBeNull();
  });
});
