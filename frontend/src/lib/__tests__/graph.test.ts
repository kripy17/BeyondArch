import { describe, expect, it, beforeEach } from "vitest";
import type { Case } from "@/data/case";
import { addEdge, backfillCaseEdges, backfillMitreEdges, getAllEdges } from "@/lib/provenance";
import { LS_ENRICHMENT, type EnrichmentRecord } from "@/lib/enrichment";
import { buildGraphData, expandHops, modeRankOf, nodeTime } from "@/components/investigation/InvestigationGraph";
import type { Finding, IOC } from "@/types/security";

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
  (globalThis as unknown as { localStorage?: FakeLocalStorage }).localStorage = new FakeLocalStorage();
});

const T0 = "2026-08-01T00:00:00.000Z";
const T1 = "2026-08-01T00:01:00.000Z";
const T2 = "2026-08-01T00:02:00.000Z";

function mkCase(partial: Partial<Case>): Case {
  return {
    id: "c-1",
    title: "Graph Fixture",
    tags: [],
    createdAt: T0,
    state: "active",
    entries: [],
    ...partial,
  };
}

function mkIoc(value: string, type: IOC["type"] = "ipv4"): IOC {
  return { value, type, context: "", source: "test", severity: "high", id: `ioc-${value}` };
}

function mkFinding(id: string, opts: Partial<Finding> = {}): Finding {
  return { id, severity: "high", title: `finding ${id}`, detail: "detail", source: "test", ...opts };
}

const spineCase = mkCase({
  artifacts: [{ id: "a1", kind: "file", title: "payload.bin", metadata: {}, created: T0 }],
  evidenceItems: [{ id: "ev1", type: "finding", title: "Malware", detail: "d", source: "test" }],
  findings: [mkFinding("f1", { title: "Malware", iocs: [mkIoc("deadbeef", "md5")], technique: "T1059" })],
  iocs: [mkIoc("deadbeef", "md5")],
});

const ref = (kind: string, id: string) => ({ kind, id } as never);

function seedEnrichment(records: EnrichmentRecord[]): void {
  localStorage.setItem(LS_ENRICHMENT, JSON.stringify(Object.fromEntries(records.map((r) => [r.id, r]))));
}

function mkEnr(id: string): EnrichmentRecord {
  return { id, adapter: "dns", query: "203.0.113.9", queryType: "ip", ok: true, source: "local backend", method: "dnspython DNS/PTR lookup", confidence: "measured", limitations: [], collectedAt: T1, fields: [] };
}

describe("buildGraphData", () => {
  it("renders every backed node with a label and coherent edges", () => {
    backfillCaseEdges(spineCase);
    backfillMitreEdges(spineCase);
    const { nodes, edges } = buildGraphData(spineCase);
    expect(nodes.length).toBeGreaterThanOrEqual(5);
    for (const e of edges) {
      const from = `${e.from.kind}:${e.from.id}`;
      const to = `${e.to.kind}:${e.to.id}`;
      expect(nodes.some((n) => `${n.ref.kind}:${n.ref.id}` === from)).toBe(true);
      expect(nodes.some((n) => `${n.ref.kind}:${n.ref.id}` === to)).toBe(true);
    }
    const ioc = nodes.find((n) => n.ref.kind === "ioc");
    expect(ioc?.label).toBe("deadbeef");
    const mitre = nodes.find((n) => n.ref.kind === "mitre");
    expect(mitre?.label).toContain("T1059");
  });

  it("drops edges whose endpoint is unknown to the case", () => {
    addEdge({ relation: "produced", from: ref("artifact", "ghost"), to: ref("evidence", "ev1"), source: "test" });
    const { edges } = buildGraphData(spineCase);
    expect(edges.some((e) => e.from.id === "ghost")).toBe(false);
  });

  it("drops edges that go against the layer ranking", () => {
    addEdge({ relation: "supports", from: ref("finding", "f1"), to: ref("artifact", "a1"), source: "test" });
    const { edges } = buildGraphData(spineCase);
    expect(edges.some((e) => e.relation === "supports" && e.from.kind === "finding")).toBe(false);
  });

  it("surfaces triage origin and case state on the case node", () => {
    addEdge({ relation: "creates", from: ref("alert", "alert-x"), to: ref("case", "c-1"), source: "triage:siem", reason: "triage escalation opened the investigation" });
    const triaged = mkCase({
      tags: ["triage"],
      events: [{ id: "e1", ts: T0, kind: "case_created", category: "case", importance: "normal", actor: "analyst", origin: "triage-escalation", title: "", detail: "", references: [{ kind: "alert", id: "alert-x" }] }],
    });
    const { nodes } = buildGraphData(triaged);
    const caseNode = nodes.find((n) => n.ref.kind === "case");
    expect(caseNode?.sub).toBe("triage escalation · active");
  });

  it("renders enrichment nodes behind enriched-by edges", () => {
    seedEnrichment([mkEnr("enr-1")]);
    addEdge({ relation: "enriched-by", from: ref("ioc", "ioc-deadbeef"), to: ref("enrichment", "enr-1"), source: "/intel enrichment" });
    const { nodes, edges } = buildGraphData(spineCase);
    const enr = nodes.find((n) => n.ref.kind === "enrichment");
    expect(enr?.label).toBe("DNS / PTR · 203.0.113.9");
    expect(enr?.sub).toBe("measured · 2026-08-01");
    expect(edges.some((e) => e.relation === "enriched-by" && e.to.kind === "enrichment")).toBe(true);
  });

  it("drops enriched-by edges whose enrichment record no longer exists", () => {
    addEdge({ relation: "enriched-by", from: ref("ioc", "ioc-deadbeef"), to: ref("enrichment", "enr-gone"), source: "/intel enrichment" });
    const { nodes, edges } = buildGraphData(spineCase);
    expect(nodes.some((n) => n.ref.kind === "enrichment")).toBe(false);
    expect(edges.some((e) => e.relation === "enriched-by")).toBe(false);
  });

  it("leaves cases without a triage origin unannotated", () => {
    addEdge({ relation: "creates", from: ref("alert", "alert-y"), to: ref("case", "c-1"), source: "alert-ingest:cef", reason: "alert opened the investigation" });
    const { nodes } = buildGraphData(mkCase({}));
    const caseNode = nodes.find((n) => n.ref.kind === "case");
    expect(caseNode?.sub).toBeUndefined();
  });
});

describe("modeRankOf", () => {
  it("ranks kinds inside a mode's layer order", () => {
    expect(modeRankOf("relationship", "artifact")).toBe(0);
    expect(modeRankOf("campaign", "finding")).toBe(0);
    expect(modeRankOf("campaign", "mitre")).toBe(2);
  });

  it("maps out-of-mode kinds to 99", () => {
    expect(modeRankOf("detection", "entity")).toBe(99);
    expect(modeRankOf("infrastructure", "detection")).toBe(99);
    expect(modeRankOf("campaign", "evidence")).toBe(99);
  });
});

describe("expandHops", () => {
  const chain = [
    addEdge({ relation: "produced", from: ref("artifact", "a1"), to: ref("evidence", "ev1"), source: "test", ts: T0 }),
    addEdge({ relation: "supports", from: ref("evidence", "ev1"), to: ref("finding", "f1"), source: "test", ts: T1 }),
    addEdge({ relation: "extracts", from: ref("finding", "f1"), to: ref("ioc", "ioc-1"), source: "test", ts: T2 }),
  ];

  it("expands to the configured hop distance", () => {
    expect(expandHops(chain, "artifact:a1", 1)).toEqual(new Set(["artifact:a1", "evidence:ev1"]));
    expect(expandHops(chain, "artifact:a1", 2)).toEqual(new Set(["artifact:a1", "evidence:ev1", "finding:f1"]));
    expect(expandHops(chain, "artifact:a1", 3)).toEqual(new Set(["artifact:a1", "evidence:ev1", "finding:f1", "ioc:ioc-1"]));
  });

  it("keeps the focus node when no neighbors exist", () => {
    expect(expandHops(chain, "case:c-1", 2)).toEqual(new Set(["case:c-1"]));
  });

  it("returns null without a focus", () => {
    expect(expandHops(chain, "", 1)).toBeNull();
  });
});

describe("nodeTime", () => {
  const chain = [
    addEdge({ relation: "produced", from: ref("artifact", "a1"), to: ref("evidence", "ev1"), source: "test", ts: T1 }),
    addEdge({ relation: "supports", from: ref("evidence", "ev1"), to: ref("finding", "f1"), source: "test", ts: T2 }),
  ];

  it("uses the earliest incident edge timestamp", () => {
    expect(nodeTime({ kind: "evidence", id: "ev1" }, spineCase, chain)).toBe(T1);
    expect(nodeTime({ kind: "finding", id: "f1" }, spineCase, chain)).toBe(T2);
  });

  it("falls back to the case creation time", () => {
    expect(nodeTime({ kind: "mitre", id: "T1059" }, spineCase, getAllEdges())).toBe(T0);
  });
});

describe("graph input integrity", () => {
  it("stays empty for a case with no provenance", () => {
    const { nodes, edges } = buildGraphData(spineCase);
    expect(edges).toHaveLength(0);
    expect(nodes).toHaveLength(0);
  });

  it("never emits edges for a case whose nodes carry no labels", () => {
    const bare = mkCase({});
    addEdge({ relation: "produced", from: ref("artifact", "a1"), to: ref("evidence", "ev1"), source: "test", ts: T0 });
    const { nodes, edges } = buildGraphData(bare);
    expect(edges).toHaveLength(0);
    expect(nodes).toHaveLength(0);
  });
});