import { describe, expect, it, beforeEach } from "vitest";
import { matchesQualifier, parseQualifiers, searchIndex } from "@/lib/search-engine";
import type { SearchItem, SearchItemType } from "@/lib/search-index";

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

function mkItem(partial: Partial<SearchItem> & { type: SearchItemType; label: string }): SearchItem {
  return {
    id: `item-${partial.label}`,
    description: "",
    tags: "",
    caseId: null,
    caseTitle: "",
    scoreWeight: 5,
    ...partial,
  };
}

describe("parseQualifiers", () => {
  it("extracts a single qualifier and returns the residual text", () => {
    expect(parseQualifiers("severity:high powershell")).toEqual({
      qualifiers: [{ key: "severity", value: "high" }],
      text: "powershell",
    });
  });

  it("extracts multiple qualifiers regardless of position", () => {
    expect(parseQualifiers("type:ioc tag:lumma evil.com")).toEqual({
      qualifiers: [{ key: "type", value: "ioc" }, { key: "tag", value: "lumma" }],
      text: "evil.com",
    });
  });

  it("treats keys outside the whitelist as plain text", () => {
    expect(parseQualifiers("CVE-2024-1234").text).toBe("CVE-2024-1234");
    expect(parseQualifiers("foo:bar baz").qualifiers).toEqual([]);
    expect(parseQualifiers("foo:bar baz").text).toBe("foo:bar baz");
  });

  it("keeps qualifier-only queries empty of residual text", () => {
    expect(parseQualifiers("state:active").text).toBe("");
    expect(parseQualifiers("state:active type:case")).toMatchObject({ text: "" });
  });

  it("is case-insensitive on the key", () => {
    expect(parseQualifiers("TYPE:ioc")).toEqual({ qualifiers: [{ key: "type", value: "ioc" }], text: "" });
  });
});

describe("matchesQualifier", () => {
  it("filters by type", () => {
    const ioc = mkItem({ type: "ioc", label: "10.0.0.1", metadata: { iocType: "ipv4", severity: "high" } });
    expect(matchesQualifier(ioc, { key: "type", value: "ioc" })).toBe(true);
    expect(matchesQualifier(ioc, { key: "type", value: "case" })).toBe(false);
  });

  it("filters by severity against findings, iocs, and alerts", () => {
    const high = mkItem({ type: "finding", label: "bad", metadata: { severity: "high" } });
    expect(matchesQualifier(high, { key: "severity", value: "high" })).toBe(true);
    expect(matchesQualifier(high, { key: "severity", value: "low" })).toBe(false);
    const generic = mkItem({ type: "note", label: "n" });
    expect(matchesQualifier(generic, { key: "severity", value: "high" })).toBe(false);
  });

  it("normalizes technique ids for matching", () => {
    const f = mkItem({ type: "finding", label: "ps", metadata: { technique: "T1059.001" } });
    expect(matchesQualifier(f, { key: "technique", value: "t1059" })).toBe(true);
    expect(matchesQualifier(f, { key: "technique", value: "T1059.001" })).toBe(true);
    expect(matchesQualifier(f, { key: "technique", value: "T1566" })).toBe(false);
  });

  it("matches tags in the tag field and detection metadata", () => {
    const caseItem = mkItem({ type: "case", label: "Lumma stealer", tags: "Lumma stealer active" });
    expect(matchesQualifier(caseItem, { key: "tag", value: "lumma" })).toBe(true);
    const rule = mkItem({ type: "detection", label: "r", metadata: { format: "sigma", tags: "lumma, powershell" } });
    expect(matchesQualifier(rule, { key: "tag", value: "lumma" })).toBe(true);
    expect(matchesQualifier(rule, { key: "tag", value: "wannacry" })).toBe(false);
  });

  it("filters actors against entity text", () => {
    const actor = mkItem({
      type: "entity",
      label: "APT29",
      description: "Russian espionage group (Cozy Bear) — SolarWinds, diplomatic targets",
      tags: "APT29 Russia espionage",
    });
    expect(matchesQualifier(actor, { key: "actor", value: "apt29" })).toBe(true);
    expect(matchesQualifier(actor, { key: "actor", value: "cozy" })).toBe(true);
    const cve = mkItem({ type: "entity", label: "CVE-2024-6387", tags: "openssh" });
    expect(matchesQualifier(cve, { key: "actor", value: "apt29" })).toBe(false);
  });

  it("restricts report qualifiers to report items", () => {
    const rep = mkItem({ type: "report", label: "Credential theft report", tags: "credential" });
    const ioc = mkItem({ type: "ioc", label: "x" });
    expect(matchesQualifier(rep, { key: "report", value: "credential" })).toBe(true);
    expect(matchesQualifier(ioc, { key: "report", value: "credential" })).toBe(false);
  });
});

describe("searchIndex with qualifiers", () => {
  beforeEach(() => {
    localStorage.setItem("ba.cases.v2", JSON.stringify([
      {
        id: "c-1",
        title: "Phishing Ops",
        tags: ["lumma"],
        createdAt: "2026-08-01T00:00:00.000Z",
        state: "active",
        entries: [],
        findings: [
          { id: "f1", severity: "high", title: "Malicious PowerShell", detail: "T1059.001", source: "analyzer", technique: "T1059.001" },
          { id: "f2", severity: "low", title: "Noisy Port Scan", detail: "lateral", source: "analyzer" },
        ],
        iocs: [
          { id: "i1", value: "203.0.113.44", type: "ipv4", context: "", source: "analyzer", severity: "high" },
          { id: "i2", value: "evil.example.com", type: "domain", context: "", source: "analyzer", severity: "medium" },
        ],
      },
    ]));
  });

  it("returns only high-severity results for severity:high", () => {
    const out = searchIndex("severity:high", { log: false });
    expect(out.length).toBeGreaterThan(0);
    for (const r of out) {
      const sev = r.metadata?.severity;
      expect(["high", "critical"]).toContain(sev);
    }
    expect(out.some((r) => r.metadata?.severity === "high")).toBe(true);
    expect(out.some((r) => r.metadata?.severity === "low")).toBe(false);
  });

  it("scopes to a single type with type:ioc", () => {
    const out = searchIndex("type:ioc", { log: false });
    expect(out.length).toBeGreaterThan(0);
    expect(out.every((r) => r.type === "ioc")).toBe(true);
    expect(out.some((r) => r.label === "203.0.113.44")).toBe(true);
  });

  it("combines text search with qualifiers", () => {
    const out = searchIndex("type:case lumma", { log: false });
    expect(out.length).toBeGreaterThan(0);
    expect(out.every((r) => r.type === "case")).toBe(true);
    expect(out.some((r) => r.label.includes("Phishing Ops"))).toBe(true);
  });

  it("matches techniques case-insensitively without dots", () => {
    const out = searchIndex("technique:t1059", { log: false });
    expect(out.some((r) => r.label === "Malicious PowerShell")).toBe(true);
    expect(out.some((r) => r.label === "Noisy Port Scan")).toBe(false);
  });

  it("lets tag qualifiers filter by case tags", () => {
    const out = searchIndex("tag:lumma", { log: false });
    expect(out.some((r) => r.type === "case" && r.label.includes("Phishing Ops"))).toBe(true);
  });

  it("does not treat unknown prefixes as qualifiers", () => {
    const { qualifiers, text } = parseQualifiers("CVE-2024-6387");
    expect(qualifiers).toEqual([]);
    expect(text).toBe("CVE-2024-6387");
    const out = searchIndex("CVE-2024-6387", { log: false });
    expect(out.some((r) => r.label === "CVE-2024-6387")).toBe(true);
  });
});