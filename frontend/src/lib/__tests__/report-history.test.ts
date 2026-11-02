import { beforeEach, describe, expect, it } from "vitest";
import type { Case, CaseEvent } from "@/data/case";
import type { Finding } from "@/types/security";
import type { Severity } from "@/lib/severity";
import {
  MAX_VERSIONS, attachVersionEvent, deltaBetween, diffSavedVersions, loadReportHistory,
  sameInputs, saveReportVersion, snapshotFrom, type ReportVersion,
} from "@/lib/report-history";

const TS = "2026-08-07T12:30:00.000Z";
const TS2 = "2026-08-08T12:30:00.000Z";

const fakeStorage = () => {
  let store: Record<string, string> = {};
  (globalThis as Record<string, unknown>).localStorage = {
    getItem: (k: string) => store[k] ?? null,
    setItem: (k: string, v: string) => { store[k] = v; },
    removeItem: (k: string) => { delete store[k]; },
    clear: () => { store = {}; },
    key: (i: number) => Object.keys(store)[i] ?? null,
    get length() { return Object.keys(store).length; },
  };
  return store;
};

function finding(over: Partial<Finding> & Pick<Finding, "id" | "title">): Finding {
  return { severity: "high", detail: "", source: "parser", ...over };
}

function version(over: Partial<ReportVersion> = {}): ReportVersion {
  return {
    id: `c1:${TS}`,
    caseId: "c1",
    generatedAt: TS,
    reportType: "technical",
    summary: { findings: 1, iocs: 1, events: 2, techniques: 1, hypotheses: 1 },
    findings: [{ id: "f1", title: "beacon", severity: "high", technique: "T1059.001" }],
    iocs: [{ value: "evil.com", type: "domain", source: "manual" }],
    hypotheses: [{ id: "h1", hypothesis: "opportunistic", status: "open", confidence: "low" }],
    techniques: ["T1059.001"],
    eventCount: 2,
    ...over,
  };
}

const FAKE_CASE: Case = {
  id: "c1", title: "Phishing", tags: [], state: "active", createdAt: TS,
  entries: [], events: [], artifacts: [], findings: [], iocs: [],
};

describe("snapshotFrom", () => {
  it("captures cells and summary counts with a deterministic id", () => {
    const snap = snapshotFrom({
      caseId: "c1",
      reportType: "executive",
      findings: [finding({ id: "f1", title: "beacon", severity: "high", technique: "T1059.001" })],
      iocs: [{ value: "evil.com", type: "domain", context: "", source: "manual", severity: "unknown" as Severity }],
      hypotheses: [{ id: "h1", caseId: "c1", hypothesis: "opportunistic", supporting: [], contradicting: [], confidence: "low", status: "open", decision: "", nextStep: "", createdAt: TS, updatedAt: TS }],
      techniques: ["T1059.001"],
      eventCount: 4,
      generatedAt: TS,
    });
    expect(snap.id).toBe("c1:" + TS);
    expect(snap.reportType).toBe("executive");
    expect(snap.summary).toEqual({ findings: 1, iocs: 1, events: 4, techniques: 1, hypotheses: 1 });
    expect(snap.findings).toEqual([{ id: "f1", title: "beacon", severity: "high", technique: "T1059.001" }]);
    expect(snap.iocs).toEqual([{ value: "evil.com", type: "domain", source: "manual" }]);
  });

  it("omits absent technique fields on findings", () => {
    const snap = snapshotFrom({ caseId: "c1", reportType: "technical", findings: [finding({ id: "f1", title: "beacon" })], iocs: [], hypotheses: [], techniques: [], eventCount: 0, generatedAt: TS });
    expect(snap.findings[0].technique).toBeUndefined();
  });

  it("embeds a repro block whose hash is stable across key order and timestamps", () => {
    const base = { caseId: "c1", reportType: "technical" as const, findings: [finding({ id: "f1", title: "beacon" })], iocs: [], hypotheses: [], techniques: ["T1059.001"], eventCount: 2 };
    const a = snapshotFrom({ ...base, generatedAt: TS });
    const b = snapshotFrom({ generatedAt: TS2, techniques: [...base.techniques], findings: [...base.findings], hypotheses: base.hypotheses, iocs: base.iocs, eventCount: 2, reportType: base.reportType, caseId: "c1" });
    expect(a.repro).toBeDefined();
    expect(a.repro?.algorithm).toBe("fnv1a-64");
    expect(b.repro?.inputHash).toBe(a.repro?.inputHash);
    expect(sameInputs(a, b)).toBe(true);
  });

  it("produces different hashes when inputs differ, and sameInputs requires both blocks", () => {
    const a = snapshotFrom({ caseId: "c1", reportType: "technical", findings: [finding({ id: "f1", title: "beacon" })], iocs: [], hypotheses: [], techniques: [], eventCount: 0, generatedAt: TS });
    const b = snapshotFrom({ caseId: "c1", reportType: "technical", findings: [finding({ id: "f2", title: "other" })], iocs: [], hypotheses: [], techniques: [], eventCount: 0, generatedAt: TS2 });
    expect(a.repro?.inputHash).not.toBe(b.repro?.inputHash);
    expect(sameInputs(a, b)).toBe(false);
    expect(sameInputs(a, version())).toBe(false); // legacy version without repro
  });

  it("diffs two saved versions in timestamp order regardless of argument order", () => {
    const old = version({ id: "c1:" + TS, generatedAt: TS, eventCount: 2 });
    const neu = version({ id: "c1:" + TS2, generatedAt: TS2, eventCount: 5 });
    const ab = diffSavedVersions(old, neu);
    const ba = diffSavedVersions(neu, old);
    expect(ab.older.id).toBe(old.id);
    expect(ab.newer.id).toBe(neu.id);
    expect(ab.deltas.map((d) => d.detail)).toEqual(ba.deltas.map((d) => d.detail));
    expect(ab.deltas.some((d) => d.kind === "events")).toBe(true);
  });
});

describe("save/load report history", () => {
  let store: Record<string, string>;
  beforeEach(() => { store = fakeStorage(); });

  it("round-trips and returns newest first", () => {
    saveReportVersion(version());
    saveReportVersion(version({ id: `c1:${TS2}`, generatedAt: TS2 }));
    const list = loadReportHistory("c1");
    expect(list.map(v => v.generatedAt)).toEqual([TS2, TS]);
  });

  it("replaces a version with the same id instead of duplicating", () => {
    saveReportVersion(version());
    saveReportVersion(version({ reportType: "soc" }));
    const list = loadReportHistory("c1");
    expect(list).toHaveLength(1);
    expect(list[0].reportType).toBe("soc");
  });

  it("caps at MAX_VERSIONS and drops the oldest", () => {
    for (let i = 0; i < MAX_VERSIONS + 3; i++) {
      const ts = new Date(Date.parse(TS) + i * 60000).toISOString();
      saveReportVersion(version({ id: `c1:${ts}`, generatedAt: ts, eventCount: i }));
    }
    const list = loadReportHistory("c1");
    expect(list).toHaveLength(MAX_VERSIONS);
    expect(list[list.length - 1].eventCount).toBe(3);
  });

  it("returns [] on corrupt storage and isolates per-case lists", () => {
    store["ba.reports.v1"] = "{not json";
    expect(loadReportHistory("c1")).toEqual([]);
    store["ba.reports.v1"] = JSON.stringify({ c1: [version()], c2: "junk", c3: [version({ id: "c3:x", caseId: "c3", generatedAt: "junk" })] });
    expect(loadReportHistory("c1")).toHaveLength(1);
    expect(loadReportHistory("c2")).toEqual([]);
    expect(loadReportHistory("c3")).toEqual([]);
  });
});

describe("deltaBetween", () => {
  it("reports no changes for identical snapshots", () => {
    expect(deltaBetween(version(), version())).toEqual([]);
  });

  it("flags new findings, severity changes, new IOCs, techniques, hypotheses, and timeline growth", () => {
    const prev = version();
    const curr = version({
      generatedAt: TS2,
      findings: [
        { id: "f1", title: "beacon", severity: "critical", technique: "T1059.001" },
        { id: "f2", title: "exfil", severity: "high" },
      ],
      iocs: [
        { value: "evil.com", type: "domain", source: "manual" },
        { value: "192.168.1.2", type: "ipv4", source: "parser" },
      ],
      hypotheses: [
        { id: "h1", hypothesis: "opportunistic", status: "supported", confidence: "high" },
      ],
      techniques: ["T1059.001", "T1041"],
      eventCount: 7,
    });
    const deltas = deltaBetween(prev, curr);
    const byKind = Object.fromEntries(deltas.map(d => [d.kind, d]));
    expect(byKind["finding-severity"].detail).toBe("beacon: high → critical");
    expect(byKind["finding-new"].detail).toBe("exfil");
    expect(byKind["ioc-new"].detail).toContain("192.168.1.2");
    expect(byKind["hypothesis-status"].detail).toBe("opportunistic: open → supported");
    expect(byKind["hypothesis-confidence"]).toBeUndefined();
    expect(byKind["technique-new"].detail).toBe("T1041");
    expect(byKind["events"].detail).toBe("+5 events since the previous version");
  });

  it("reports confidence changes only when status is unchanged", () => {
    const prev = version({ hypotheses: [{ id: "h1", hypothesis: "opportunistic", status: "open", confidence: "low" }] });
    const curr = version({ hypotheses: [{ id: "h1", hypothesis: "opportunistic", status: "open", confidence: "high" }] });
    const deltas = deltaBetween(prev, curr);
    expect(deltas.map(d => d.kind)).toEqual(["hypothesis-confidence"]);
    expect(deltas[0].detail).toBe("opportunistic: low → high");
  });

  it("caps long detail lists", () => {
    const prev = version({ iocs: [{ value: "a.com", type: "domain", source: "x" }] });
    const curr = version({
      iocs: [
        { value: "a.com", type: "domain", source: "x" },
        ...["b.com", "c.com", "d.com", "e.com"].map((value) => ({ value, type: "domain" as const, source: "x" })),
      ],
    });
    const [delta] = deltaBetween(prev, curr);
    expect(delta.kind).toBe("ioc-new");
    expect(delta.detail).toBe("b.com, c.com, d.com (+1 more)");
  });
});

describe("attachVersionEvent", () => {
  it("appends a report_generated event once per version id", () => {
    const v = version();
    let c = attachVersionEvent(FAKE_CASE, v);
    c = attachVersionEvent(c, v);
    const reportEvents = (c.events as CaseEvent[]).filter(e => e.origin === "report-versions");
    expect(reportEvents).toHaveLength(1);
    expect(reportEvents[0].kind).toBe("report_generated");
    expect(reportEvents[0].title).toContain("technical");
    expect(reportEvents[0].references).toEqual([{ kind: "report", id: v.id }]);
  });
});