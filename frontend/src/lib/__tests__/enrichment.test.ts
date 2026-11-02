import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  detectEnrichmentQueryType,
  enrichmentHistory,
  LS_ENRICHMENT,
  runEnrichment,
} from "@/lib/enrichment";
import { getAllEdges } from "@/lib/provenance";

function stubStorage(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
    clear: () => void map.clear(),
  });
}

function stubFetch(routes: Record<string, unknown>) {
  const calls: { url: string; body: unknown }[] = [];
  vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
    calls.push({ url, body: init?.body ? JSON.parse(init.body as string) : null });
    for (const [match, payload] of Object.entries(routes)) {
      if (url.includes(match)) return new Response(JSON.stringify(payload), { status: 200 });
    }
    return new Response(JSON.stringify({ detail: "not found" }), { status: 404 });
  });
  return calls;
}

beforeEach(() => {
  stubStorage();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("detectEnrichmentQueryType", () => {
  it("classifies hashes, IPs, domains, and rejects the rest", () => {
    expect(detectEnrichmentQueryType("44d88612fea8a8f36de82e1278abb02f")).toBe("hash");
    expect(detectEnrichmentQueryType("203.0.113.9")).toBe("ip");
    expect(detectEnrichmentQueryType("evil.example.com")).toBe("domain");
    expect(detectEnrichmentQueryType("not a domain")).toBeNull();
    expect(detectEnrichmentQueryType("https://evil.example.com")).toBeNull();
  });
});

describe("dns adapter", () => {
  it("measures DNS records and always carries source/method/limitations/collectedAt", async () => {
    const calls = stubFetch({
      "/api/recon/dns": {
        target: { type: "domain", hostname: "evil.example.com", root_domain: "example.com" },
        dns: { domain: "example.com", records: { A: ["203.0.113.9"], MX: ["10 mail.example.com."] } },
        whois: {},
        meta: { source: "local backend", method: "dnspython DNS/PTR lookup", limitations: "resolver-dependent availability." },
      },
    });
    const r = await runEnrichment("dns", "evil.example.com");
    expect(r.ok).toBe(true);
    expect(r.confidence).toBe("measured");
    expect(r.source).toBe("local backend");
    expect(r.method).toBe("DNS record lookup");
    expect(r.limitations).toHaveLength(1);
    expect(r.collectedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(r.fields.map((f) => f.label)).toEqual(["A", "MX"]);
    // gate flag was explicitly sent
    expect(calls[0].body).toEqual({ target: "evil.example.com", confirm_permission: true });
    // persisted to history
    expect(enrichmentHistory()[0].id).toBe(r.id);
  });

  it("labels each record with only the method that adapter consumed", async () => {
    stubFetch({
      "/api/recon/dns": {
        dns: { records: { A: ["203.0.113.9"] } },
        whois: { registrar: "Example Registrar" },
        meta: { source: "local backend", method: "dnspython DNS/PTR lookup with WHOIS/RDAP", limitations: "l" },
      },
    });
    const dnsRec = await runEnrichment("dns", "example.com");
    const whoisRec = await runEnrichment("whois", "example.com");
    expect(dnsRec.method).not.toContain("WHOIS");
    expect(whoisRec.method).toBe("WHOIS + RDAP registration lookup");
  });

  it("reports no-data honestly when a section comes back empty", async () => {
    stubFetch({
      "/api/recon/dns": {
        dns: { domain: "example.com", records: {} },
        whois: {},
        meta: { source: "local backend", method: "m", limitations: "l" },
      },
    });
    const r = await runEnrichment("whois", "example.org");
    expect(r.ok).toBe(true);
    expect(r.confidence).toBe("no-data");
    expect(r.fields).toEqual([]);
  });

  it("captures backend failures as failed records without throwing", async () => {
    stubFetch({});
    const r = await runEnrichment("whois", "unreachable.invalid");
    expect(r.ok).toBe(false);
    expect(r.confidence).toBe("failed");
    expect(r.error).toMatch(/not found/);
    expect(r.limitations[0]).toMatch(/never completed/);
  });
});

describe("hash reputation adapter", () => {
  it("maps findings and surfaces the no-external-provider limitation", async () => {
    stubFetch({
      "/api/malware/hash/reputation": {
        indicator: "44d88612fea8a8f36de82e1278abb02f",
        checked_at: "2026-08-25T00:00:00Z",
        summary: { total_findings: 1, note: "Deterministic local checks only — no external provider queried." },
        findings: [
          { severity: "info", title: "Well-known test hash", detail: "Matches EICAR pattern.", guidance: "Verify context." },
        ],
      },
    });
    const r = await runEnrichment("hash-reputation", "44d88612fea8a8f36de82e1278abb02f");
    expect(r.ok).toBe(true);
    expect(r.confidence).toBe("measured");
    expect(r.fields[0].label).toContain("Well-known test hash");
    expect(r.limitations.join(" ")).toMatch(/no external/i);
    expect(r.limitations.length).toBeGreaterThanOrEqual(2);
  });
});

describe("provenance linkage", () => {
  it("writes an enriched-by edge when the query matches a case IOC", async () => {
    stubFetch({
      "/api/recon/dns": {
        dns: { records: { A: ["203.0.113.9"] } },
        whois: {},
        meta: { source: "local backend", method: "m", limitations: "l" },
      },
    });
    const cases = [{
      id: "c1", title: "t", tags: [], createdAt: "", state: "active",
      entries: [], iocs: [{ id: "ioc-abc", value: "203.0.113.9", type: "ip", context: "", source: "siem", severity: "high" }],
    }];
    localStorage.setItem("ba.cases.v2", JSON.stringify(cases));
    await runEnrichment("dns", "203.0.113.9");
    const edges = getAllEdges();
    expect(edges.some((e) => e.relation === "enriched-by" && e.to.kind === "enrichment")).toBe(true);
  });

  it("stores failed lookups without writing provenance edges", async () => {
    stubFetch({});
    await runEnrichment("dns", "203.0.113.10");
    expect(getAllEdges().some((e) => e.to.kind === "enrichment")).toBe(false);
    expect(enrichmentHistory()).toHaveLength(1);
    expect(localStorage.getItem(LS_ENRICHMENT)).toBeTruthy();
  });
});
