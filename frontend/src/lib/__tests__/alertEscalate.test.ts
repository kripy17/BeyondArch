import { describe, expect, it, beforeEach } from "vitest";
import {
  extractIocsFromText, escalateToCase, escalateItems,
} from "@/lib/alerts/escalate";
import { LS_KEY as CASES_KEY, loadCases, type Case } from "@/data/case";
import { getAllEdges, LS_PROVENANCE } from "@/lib/provenance";
import type { TriageItem } from "@/data/triage";

class FakeLocalStorage {
  private store = new Map<string, string>();
  getItem(k: string): string | null { return this.store.get(k) ?? null; }
  setItem(k: string, v: string): void { this.store.set(k, v); }
  removeItem(k: string): void { this.store.delete(k); }
  clear(): void { this.store.clear(); }
  get length(): number { return this.store.size; }
  key(i: number): string | null { return [...this.store.keys()][i] ?? null; }
}

function resetStore() {
  (globalThis as unknown as { localStorage?: FakeLocalStorage }).localStorage = new FakeLocalStorage();
}
beforeEach(resetStore);

const NOW = "2026-08-23T10:00:00.000Z";

function mkItem(partial: Partial<TriageItem>): TriageItem {
  return {
    id: "t-1",
    ts: NOW,
    title: "Suspicious login",
    description: "",
    severity: "high",
    source: "siem",
    status: "in_review",
    notes: "",
    tags: [],
    updated: 1,
    ...partial,
  };
}

describe("extractIocsFromText", () => {
  it("extracts supported observable types and dedupes", () => {
    const out = extractIocsFromText(
      "Beacon to 10.0.0.5 and evil.example.com via http://evil.example.com/payload — hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    const values = out.map((i) => i.value);
    expect(values).toContain("10.0.0.5");
    expect(values).toContain("evil.example.com");
    expect(out.filter((i) => i.type === "url")).toHaveLength(1);
    expect(values).toContain("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(new Set(values).size).toBe(values.length);
  });

  it("skips noisy kinds and short-label prose domains", () => {
    const out = extractIocsFromText("See CVE-2024-12345 technique T1566 e.g. around 12:30 event id 4625");
    expect(out).toHaveLength(0);
  });

  it("carries email observables", () => {
    const out = extractIocsFromText("Phishing from attacker@bad-actor.net");
    expect(out).toEqual([{ type: "email", value: "attacker@bad-actor.net" }]);
  });
});

describe("escalateToCase", () => {
  it("creates a structured case with carried IOCs and no fabricated alert edge", () => {
    const item = mkItem({
      description: "Login from 203.0.113.9 against vpn.corp.example.com",
      notes: "Analyst reviewed source logs",
    });
    const res = escalateToCase(item, NOW);
    expect(res.ok).toBe(true);
    expect(res.existing).toBe(false);
    expect(res.edgeWritten).toBe(false);

    const cases = loadCases();
    expect(cases).toHaveLength(1);
    const c = cases[0];
    expect(c.id).toBe(res.caseId);
    expect(c.title).toBe("Suspicious login");
    expect(c.tags).toContain("triage");
    expect(c.iocs?.map((i) => i.value).sort()).toEqual(["203.0.113.9", "vpn.corp.example.com"]);
    expect(c.entries.some((e) => e.kind === "decision" && e.body.includes("Escalated from Triage"))).toBe(true);
    expect(c.entries.some((e) => e.kind === "note" && e.body.includes("Analyst reviewed source logs"))).toBe(true);
    const created = c.events?.find((e) => e.kind === "case_created");
    expect(created?.references ?? []).toHaveLength(0);
    expect(created?.detail).toContain("2 IOC(s) carried");
    expect(JSON.parse(localStorage.getItem(LS_PROVENANCE) ?? "{}")).toEqual({});
  });

  it("writes a creates edge when the item carries an alert node id", () => {
    const item = mkItem({ alertNodeId: "alert-node-1", description: "hit 198.51.100.7" });
    const res = escalateToCase(item, NOW);
    expect(res.edgeWritten).toBe(true);
    const edges = getAllEdges();
    expect(edges).toHaveLength(1);
    expect(edges[0].relation).toBe("creates");
    expect(edges[0].from).toEqual({ kind: "alert", id: "alert-node-1" });
    expect(edges[0].to).toEqual({ kind: "case", id: res.caseId });
  });

  it("links to an existing case instead of duplicating", () => {
    const existing: Case = {
      id: "case-existing",
      title: "Prior investigation",
      tags: [],
      createdAt: NOW,
      state: "active",
      entries: [],
    };
    localStorage.setItem(CASES_KEY, JSON.stringify([existing]));
    const res = escalateToCase(mkItem({ caseId: "case-existing" }), NOW);
    expect(res.existing).toBe(true);
    expect(loadCases()).toHaveLength(1);
  });

  it("prefers stored item IOCs over re-extraction", () => {
    const item = mkItem({ iocs: [{ type: "ipv4", value: "192.0.2.44" }], description: "unrelated text with no ioc" });
    const res = escalateToCase(item, NOW);
    expect(loadCases()[0].iocs?.map((i) => i.value)).toEqual(["192.0.2.44"]);
    expect(res.iocCount).toBe(1);
  });
});

describe("escalateItems", () => {
  it("aggregates honest counts across new, linked, and already-escalated items", () => {
    localStorage.setItem(
      CASES_KEY,
      JSON.stringify([{
        id: "case-a", title: "A", tags: [], createdAt: NOW, state: "active", entries: [],
      } satisfies Case]),
    );
    const items = [
      mkItem({ id: "t-new", caseId: undefined, description: "ip 192.0.2.1" }),
      mkItem({ id: "t-link", caseId: "case-a" }),
      mkItem({ id: "t-second", caseId: undefined, description: "domain bad.io" }),
    ];
    const { summary, updated } = escalateItems(items, Date.parse(NOW));
    expect(summary.created).toBe(2);
    expect(summary.linked).toBe(1);
    expect(summary.failed).toBe(0);
    expect(summary.iocsCarried).toBe(2);
    expect(updated.map((u) => u.status)).toEqual(["escalated", "escalated", "escalated"]);
    expect(updated.find((u) => u.id === "t-link")?.caseId).toBe("case-a");
    expect(loadCases()).toHaveLength(3);
  });
});

import { clusterItems, extractTechniques } from "@/lib/alerts/clusters";

describe("extractTechniques", () => {
  it("finds and dedupes MITRE technique ids case-insensitively", () => {
    expect(extractTechniques("Mapped to T1566.001 then t1110 again T1566.001")).toEqual(["T1566.001", "T1110"]);
  });
});

describe("clusterItems", () => {
  const base = { ts: NOW, severity: "high" as const, source: "siem", notes: "", tags: [], updated: 1 };

  it("groups items sharing an IOC value across sources", () => {
    const items = [
      mkItem({ id: "a", title: "Beacon seen", description: "C2 at 203.0.113.50", status: "open", ...base }),
      mkItem({ id: "b", title: "Firewall drop", description: "Blocked 203.0.113.50", status: "in_review", ...base, severity: "medium" as const }),
      mkItem({ id: "c", title: "Unrelated", description: "nothing here", status: "open", ...base }),
    ];
    const clusters = clusterItems(items);
    expect(clusters).toHaveLength(2);
    expect(clusters[0].label).toBe("203.0.113.50");
    expect(clusters[0].items.map((i) => i.id)).toEqual(["a", "b"]);
    expect(clusters[1].kind).toBe("unclustered");
    expect(clusters[1].items.map((i) => i.id)).toEqual(["c"]);
  });

  it("builds technique clusters and excludes escalated/dismissed items", () => {
    const items = [
      mkItem({ id: "t1", title: "Phish T1566 campaign", description: "", status: "open", ...base }),
      mkItem({ id: "t2", title: "Also t1566 related", description: "", status: "open", ...base }),
      mkItem({ id: "gone", title: "Old T1566 noise", description: "", status: "dismissed", ...base }),
    ];
    const clusters = clusterItems(items);
    expect(clusters).toHaveLength(1);
    expect(clusters[0].kind).toBe("technique");
    expect(clusters[0].label).toBe("T1566");
    expect(clusters[0].items.map((i) => i.id)).toEqual(["t1", "t2"]);
  });

  it("prefers stored item IOCs over re-extraction", () => {
    const items = [
      mkItem({ id: "s1", title: "Hash hit", description: "unrelated text", iocs: [{ type: "md5", value: "d41d8cd98f00b204e9800998ecf8427e" }], status: "open", ...base }),
    ];
    const clusters = clusterItems(items);
    expect(clusters[0].iocType).toBe("md5");
    expect(clusters[0].items.map((i) => i.id)).toEqual(["s1"]);
  });

  it("returns empty for empty input", () => {
    expect(clusterItems([])).toEqual([]);
  });
});
