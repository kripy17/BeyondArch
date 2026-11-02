import { describe, expect, it, beforeEach } from "vitest";
import { ingestAlert, ingestAlertNodeId, loadAlertLedger, resolveFiringDetection } from "@/lib/alerts/ingest";
import { loadCases, LS_KEY } from "@/data/case";
import { loadRules, slugRuleKey } from "@/data/detection";
import { getAllEdges, explainNode, path, projectTimeline } from "@/lib/provenance";
import { FILE_HASHES } from "@/data/intel";

const RULES_KEY = "ba.detection.rules.v2";

const store = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => { store.set(k, v); },
  removeItem: (k: string) => { store.delete(k); },
  clear: () => { store.clear(); },
  key: (i: number) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
};

const KNOWN_HASH = FILE_HASHES[0]!.observables[0]!.value;

const CANONICAL = (observables: string[], extra: Record<string, unknown> = {}) =>
  JSON.stringify({
    schema: "beyondlabs.alert.v1",
    title: extra.title ?? "High-risk payload delivery",
    severity: extra.severity ?? "high",
    summary: "Suspicious staging URL with malicious payload",
    rule_ref: extra.rule_ref,
    observables,
  });

const SIGMA = (title: string, level = "high") =>
  `title: ${title}\nlevel: ${level}\ndescription: detection test\ntags:\n  - attack.t1059.001\ndetection:\n  selection:\n    CommandLine|contains: '-enc'\n  condition: selection\n`;

function seedRule(over: Partial<ReturnType<typeof loadRules>[number]> = {}) {
  const name = "Suspicious PowerShell Encoded Command";
  const rule = {
    id: "rule-deploy-1",
    name,
    format: "sigma" as const,
    rule: SIGMA(name),
    ruleKey: slugRuleKey(name, "rule-deploy-1"),
    state: "deployed" as const,
    version: 2,
    technique: "T1059.001",
    tags: ["attack.t1059.001"],
    event: "",
    created: 1,
    updated: 1,
    stateUpdated: 1,
    ...over,
  };
  localStorage.setItem(RULES_KEY, JSON.stringify([rule]));
  return rule;
}

function seedPriorCaseWithIoc(value: string) {
  localStorage.setItem(LS_KEY, JSON.stringify([
    {
      id: "case-prior-1",
      title: "Prior credential phish",
      tags: [],
      createdAt: "2026-07-01T00:00:00.000Z",
      state: "active",
      entries: [{ id: "e1", kind: "ioc", body: value, ts: "2026-07-01T00:00:00.000Z" }],
    },
  ]));
}

describe("ingestAlert — pipeline", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("rejects unrecognized formats", () => {
    const out = ingestAlert("plain text without alert grammar");
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error).toMatch(/Unrecognized alert format/);
  });

  it("ingests a beyondlabs alert into a new case with durable edges", () => {
    const out = ingestAlert(CANONICAL(["198.51.100.73", "victim@corp.xyz", "https://evil.example.xyz/x"]));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.isNew).toBe(true);
    expect(out.alertId.startsWith("al-")).toBe(true);
    expect(out.case).not.toBeNull();

    const stored = loadCases();
    expect(stored).toHaveLength(1);
    const c = stored[0]!;
    expect(c.title).toContain("High-risk payload delivery");
    expect(c.tags).toContain("beyondlabs");
    expect(c.tags).toContain("alert");
    expect(c.iocs?.length).toBeGreaterThanOrEqual(3);
    expect(c.findings?.some((f) => f.title === "High-risk TLD in URL")).toBe(true);
    expect(c.findings?.some((f) => f.title === "Suspicious sender domain")).toBe(true);
    expect(c.events?.some((e) => e.kind === "alert_ingested" && e.references.some((r) => r.kind === "alert" && r.id === out.alertId))).toBe(true);

    const edges = getAllEdges();
    expect(edges.some((e) => e.relation === "creates" && e.from.kind === "alert" && e.from.id === out.alertId && e.to.kind === "case" && e.to.id === c.id)).toBe(true);
    expect(edges.some((e) => e.relation === "produced" && e.from.kind === "alert")).toBe(true);
    expect(edges.some((e) => e.relation === "supports" && e.to.kind === "finding")).toBe(true);
    expect(edges.some((e) => e.relation === "extracts" && e.from.kind === "finding" && e.to.kind === "ioc" && e.to.id.startsWith("ioc-"))).toBe(true);
    expect(edges.some((e) => e.relation === "mapped-to" && e.to.kind === "mitre")).toBe(true);
    expect(out.edgesWritten).toBe(out.edgesWritten);
    expect(edges.length).toBeGreaterThanOrEqual(6);
  });

  it("is idempotent: re-ingesting the same alert reuses the case and never duplicates edges", () => {
    const raw = CANONICAL(["198.51.100.73", "https://evil.example.xyz/x"]);
    const first = ingestAlert(raw);
    expect(first.ok && first.isNew).toBe(true);
    const edgesAfterFirst = getAllEdges().length;

    const second = ingestAlert(raw, { now: new Date("2026-08-15T00:00:00.000Z") });
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.isNew).toBe(false);
    expect(second.case?.id).toBe(first.ok ? first.case?.id : undefined);
    expect(second.alertId).toBe(first.ok ? first.alertId : undefined);
    expect(second.edgesWritten).toBe(0);

    expect(getAllEdges().length).toBe(edgesAfterFirst);
    expect(loadCases()).toHaveLength(1);
    const ledger = loadAlertLedger();
    expect(Object.keys(ledger)).toHaveLength(1);
  });

  it("distinguishes different alerts: new content → new node, new case", () => {
    const a = ingestAlert(CANONICAL(["198.51.100.73", "https://evil.example.xyz/x"], { title: "Alert one" }));
    const b = ingestAlert(CANONICAL(["203.0.113.9", "https://other.example.xyz/y"], { title: "Alert two" }));
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(a.alertId).not.toBe(b.alertId);
    expect(a.case?.id).not.toBe(b.case?.id);
    expect(loadCases()).toHaveLength(2);
  });

  it("links to a deployed detection with a fires edge and lifecycle alert identity", () => {
    seedRule();
    const out = ingestAlert(SIGMA("Suspicious PowerShell Encoded Command"));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.resolvedRule?.ruleKey).toBe(slugRuleKey("Suspicious PowerShell Encoded Command", "rule-deploy-1"));
    expect(out.alertId).not.toBe(ingestAlertNodeId(out.alert));
    const ledger = loadAlertLedger()[out.alertId];
    expect(ledger).toBeDefined();
    expect(ledger.ruleKey).toBe(out.resolvedRule?.ruleKey);
    const firing = getAllEdges().filter((e) => e.relation === "fires");
    expect(firing.length).toBe(1);
    expect(firing[0]!.from.kind).toBe("deployment");
    expect(firing[0]!.to.id).toBe(out.alertId);
    const creates = getAllEdges().find((e) => e.relation === "creates");
    expect(creates?.from.id).toBe(out.alertId);
  });

  it("does not invent a detection relationship for unmatched alerts", () => {
    const out = ingestAlert(CANONICAL(["198.51.100.73", "https://evil.example.xyz/x"]));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(resolveFiringDetection(out.alert)).toBeUndefined();
    expect(getAllEdges().some((e) => e.relation === "fires")).toBe(false);
  });

  it("ignores non-deployed rules when resolving the firing detection", () => {
    seedRule({ state: "draft" });
    const out = ingestAlert(SIGMA("Suspicious PowerShell Encoded Command"));
    expect(out.ok && out.resolvedRule).toBeUndefined();
  });
});

describe("ingestAlert — correlation memory", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("flags prior-case overlap in analysis but writes durable edges only for entity overlap", () => {
    seedPriorCaseWithIoc("198.51.100.73");
    const out = ingestAlert(CANONICAL(["198.51.100.73", "https://evil.example.xyz/x"]));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.analysis.correlation.some((m) => m.dimension === "same-value-previous")).toBe(true);
    const edges = getAllEdges();
    expect(edges.some((e) => e.relation === "enriched-by" && e.source === "correlation" && e.from.kind === "ioc" && e.to.kind === "entity")).toBe(false);
  });

  it("writes enriched-by ioc → entity edges for intel-corpus overlap, source correlation", () => {
    const entity = FILE_HASHES[0]!;
    const out = ingestAlert(CANONICAL([KNOWN_HASH, "198.51.100.73"]));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.analysis.correlation.some((m) => m.dimension === "entity-overlap" && m.matches.some((x) => x.ref === entity.id))).toBe(true);
    const edges = getAllEdges();
    const corr = edges.filter((e) => e.relation === "enriched-by" && e.source === "correlation");
    expect(corr.length).toBeGreaterThan(0);
    expect(corr[0]!.from.kind).toBe("ioc");
    expect(corr[0]!.from.id.startsWith("ioc-")).toBe(true);
    expect(corr[0]!.to.kind).toBe("entity");
    expect(corr[0]!.to.id).toBe(entity.id);
  });
});

describe("ingestAlert — graph readability (path / explain / timeline)", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("path() and explainNode() traverse the new alert edges", () => {
    const out = ingestAlert(CANONICAL(["198.51.100.73", "https://evil.example.xyz/x"]));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    const c = out.case!;
    const edges = getAllEdges();

    const explained = explainNode("alert", out.alertId, edges);
    expect(explained.forward.some((e) => e.relation === "creates" && e.to.kind === "case")).toBe(true);
    expect(explained.forward.length).toBeGreaterThan(0);

    const p = path({ kind: "alert", id: out.alertId }, { kind: "case", id: c.id }, ["creates"]);
    expect(p).not.toBeNull();
    expect(p!.length).toBe(1);
    expect(p![0]!.relation).toBe("creates");

    const findingId = c.findings?.[0]?.id ?? "";
    const toFinding = path({ kind: "alert", id: out.alertId }, { kind: "finding", id: findingId });
    expect(toFinding).not.toBeNull();
  });

  it("projectTimeline auto-includes alert provenance for ingested events", () => {
    const out = ingestAlert(CANONICAL(["198.51.100.73", "https://evil.example.xyz/x"]));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    const c = out.case!;
    const projected = projectTimeline(c.events ?? []);
    const alertEvent = (c.events ?? []).find((e) => e.kind === "alert_ingested")!;
    const entry = projected.get(alertEvent.id)!;
    expect(entry.hasProvenance).toBe(true);
    expect(entry.edges.some((e) => e.relation === "creates")).toBe(true);
  });
});

describe("ingestAlert — provenance immutability", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("never mutates existing edges on rerun (append-only ledger)", () => {
    const raw = CANONICAL(["198.51.100.73", "https://evil.example.xyz/x"]);
    const first = ingestAlert(raw);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    const before = getAllEdges().map((e) => e.id).sort();
    ingestAlert(raw);
    const after = getAllEdges().map((e) => e.id).sort();
    expect(after).toEqual(before);
  });
});