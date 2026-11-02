import { describe, expect, it, beforeEach } from "vitest";
import { correlationRelationships, type CorrelationMatch } from "@/lib/correlation/engine";
import {
  correlationRecordId,
  L_CORRELATION,
  loadCorrelationMemory,
  rememberCorrelation,
  setCorrelationStatus,
  getCorrelationRecord,
  countCorrelationMemory,
  projectCorrelationEdges,
} from "@/lib/correlation/memory";
import { getAllEdges } from "@/lib/provenance";

const store = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => { store.set(k, v); },
  removeItem: (k: string) => { store.delete(k); },
  clear: () => { store.clear(); },
  key: (i: number) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
};

const MATCH = (over: Partial<CorrelationMatch> = {}): CorrelationMatch => ({
  dimension: "entity-overlap",
  value: "Raccoon Stealer",
  label: "observable of Raccoon Stealer",
  matches: [{ ref: "entity-raccoon", label: "Raccoon Stealer" }],
  confidence: 0.6,
  evidenceRefs: ["obs-1"],
  ...over,
});

describe("correlation memory (ba.correlation.v1)", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("remembers new matches as untriaged records with deterministic ids", () => {
    const records = rememberCorrelation([MATCH()], { source: "analyze:parser" });
    expect(records).toHaveLength(1);
    const r = records[0];
    expect(r.status).toBe("new");
    expect(r.seen).toBe(1);
    expect(r.sources).toEqual(["analyze:parser"]);
    expect(r.caseIds ?? []).toEqual([]);
    expect(r.id).toBe(correlationRecordId("entity-overlap", "Raccoon Stealer"));
    expect(r.firstSeen).toBe(r.lastSeen);
  });

  it("is idempotent: re-observation merges instead of duplicating", () => {
    const t1 = new Date("2026-08-14T00:00:00Z");
    rememberCorrelation([MATCH()], { source: "analyze:parser", ts: t1 });
    const t2 = new Date("2026-08-14T01:00:00Z");
    const records = rememberCorrelation([MATCH()], { source: "analyze:parser", ts: t2 });
    expect(records).toHaveLength(1);
    expect(records[0].seen).toBe(2);
    expect(records[0].firstSeen).toBe(t1.toISOString());
    expect(records[0].lastSeen).toBe(t2.toISOString());
    expect(records[0].sources).toEqual(["analyze:parser"]);
  });

  it("merges distinct surfaces and alert case ids on the same value", () => {
    rememberCorrelation([MATCH()], { source: "analyze:parser" });
    const records = rememberCorrelation([MATCH()], { source: "alert-ingest:al-1", caseId: "case-9" });
    expect(records).toHaveLength(1);
    expect(records[0].sources).toEqual(["analyze:parser", "alert-ingest:al-1"]);
    expect(records[0].caseIds).toEqual(["case-9"]);
  });

  it("keys each (dimension, value) separately", () => {
    const same = MATCH({ dimension: "same-value-previous", value: "evil.example.com", label: "seen in prior case" });
    const det = MATCH({ dimension: "existing-detection", value: "T1059.001", label: "covered by existing detection" });
    const records = rememberCorrelation([same, det], { source: "analyze:parser" });
    expect(records).toHaveLength(2);
    expect(new Set(records.map((r) => r.dimension))).toEqual(new Set(["same-value-previous", "existing-detection"]));
  });

  it("never resets analyst status on re-observation", () => {
    const [r] = rememberCorrelation([MATCH()], { source: "analyze:parser" });
    setCorrelationStatus(r.id, "dismissed");
    rememberCorrelation([MATCH()], { source: "analyze:url" });
    expect(getCorrelationRecord(r.id)?.status).toBe("dismissed");
  });

  it("setCorrelationStatus transitions and ignores unknown ids", () => {
    const [r] = rememberCorrelation([MATCH()], { source: "analyze:parser" });
    expect(setCorrelationStatus(r.id, "confirmed")?.status).toBe("confirmed");
    expect(getCorrelationRecord(r.id)?.status).toBe("confirmed");
    expect(setCorrelationStatus("no-such-record", "confirmed")).toBeUndefined();
  });

  it("loads records sorted by lastSeen descending", () => {
    rememberCorrelation([MATCH({ dimension: "same-value-previous", value: "a.test", label: "seen in prior case" })], { source: "s1", ts: new Date("2026-08-01T00:00:00Z") });
    rememberCorrelation([MATCH({ dimension: "same-value-previous", value: "b.test", label: "seen in prior case" })], { source: "s2", ts: new Date("2026-08-03T00:00:00Z") });
    const records = loadCorrelationMemory();
    expect(records.map((x) => x.value)).toEqual(["b.test", "a.test"]);
    expect(countCorrelationMemory()).toBe(2);
  });

  it("persists under the ledger key with a schema version", () => {
    rememberCorrelation([MATCH()], { source: "analyze:parser" });
    const raw = JSON.parse(store.get(L_CORRELATION)!);
    expect(raw).toHaveLength(1);
    expect(raw[0].schemaVersion).toBe(1);
    expect(raw[0].status).toBe("new");
  });

  it("projectCorrelationEdges writes enriched-by edges via canonical ioc ids and skips unresolvable", () => {
    const matches = [
      MATCH(),
      MATCH({
        dimension: "entity-overlap",
        value: "APT-41",
        label: "observable of APT-41",
        matches: [{ ref: "entity-apt41", label: "APT-41" }],
        evidenceRefs: ["obs-2"],
      }),
    ];
    const rels = correlationRelationships(matches, "test-source", "2026-08-14T00:00:00Z");
    const count = projectCorrelationEdges({
      relationships: rels,
      iocNodeFor: (obsId) => (obsId === "obs-1" ? "ioc-canonical-1" : undefined),
    });
    expect(count).toBe(1);
    const edges = getAllEdges();
    const enriched = edges.filter((e) => e.relation === "enriched-by");
    expect(enriched).toHaveLength(1);
    expect(enriched[0].from).toEqual({ kind: "ioc", id: "ioc-canonical-1" });
    expect(enriched[0].to).toEqual({ kind: "entity", id: "entity-raccoon" });
    expect(enriched[0].source).toBe("correlation");
  });
});