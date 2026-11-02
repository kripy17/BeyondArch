import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  BATCH_ENRICHMENT_CAP,
  enrichmentHistory,
  LS_ENRICHMENT,
  runBatchEnrichment,
  type BatchSkippedItem,
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

function batchPayload() {
  return {
    results: [
      {
        indicator: "44d88612fea8a8f36de82e1278abb02f",
        normalized: "44d88612fea8a8f36de82e1278abb02f",
        type: "hash",
        checked_at: "2026-08-25T00:00:00Z",
        summary: { total_findings: 1, note: "Deterministic backend/local checks only." },
        findings: [
          { severity: "medium", title: "Hash format identified", detail: "MD5 digest.", guidance: "Correlate with case evidence." },
        ],
      },
    ],
    summary: {
      requested: 1,
      processed: 1,
      skipped_count: 0,
      skipped: [] as BatchSkippedItem[],
      verdict_counts: { unknown: 1 },
      note: "cap-25 · auto-detected types",
    },
  };
}

describe("runBatchEnrichment", () => {
  it("maps each backend report into an honest persisted record", async () => {
    const calls = stubFetch({ "/api/reputation/enrich-batch": batchPayload() });
    const result = await runBatchEnrichment(["44D88612FEA8A8F36DE82E1278ABB02F"]);

    expect(calls[0].body).toEqual({ indicators: [{ value: "44D88612FEA8A8F36DE82E1278ABB02F" }] });
    expect(result.processed).toBe(1);
    expect(result.requested).toBe(1);
    expect(result.skipped).toEqual([]);

    const record = result.records[0];
    expect(record.ok).toBe(true);
    expect(record.adapter).toBe("batch-reputation");
    expect(record.confidence).toBe("measured");
    expect(record.collectedAt).toBe("2026-08-25T00:00:00Z");
    expect(record.fields[0].label).toBe("medium: Hash format identified");
    expect(record.fields[0].value).toContain("MD5 digest.");
    expect(record.limitations.join(" ")).toMatch(/not verdicts/i);
    // persisted like single lookups
    expect(enrichmentHistory()[0].id).toBe(record.id);
    expect(localStorage.getItem(LS_ENRICHMENT)).toBeTruthy();
  });

  it("falls back to the summary note when a report carries no findings", async () => {
    const payload = batchPayload();
    payload.results[0].findings = [];
    stubFetch({ "/api/reputation/enrich-batch": payload });
    const result = await runBatchEnrichment(["203.0.113.9"]);
    expect(result.records[0].confidence).toBe("no-data");
    expect(result.records[0].fields[0].value).toMatch(/deterministic/i);
  });

  it("surfaces skipped entries from the backend verbatim", async () => {
    const payload = batchPayload();
    payload.results = [];
    payload.summary.skipped = [{ index: 1, reason: "ValueError while enriching 'junk'." }];
    payload.summary.processed = 0;
    stubFetch({ "/api/reputation/enrich-batch": payload });
    const result = await runBatchEnrichment(["junk"]);
    expect(result.processed).toBe(0);
    expect(result.skipped).toEqual([{ index: 1, reason: expect.stringMatching(/ValueError/) }]);
    expect(result.records).toHaveLength(0);
  });

  it("refuses batches over the cap before any request is made", async () => {
    const calls = stubFetch({});
    const tooMany = Array.from({ length: BATCH_ENRICHMENT_CAP + 1 }, (_, i) => `host${i}.example.com`);
    await expect(runBatchEnrichment(tooMany)).rejects.toThrow(/limited to 25/);
    expect(calls).toHaveLength(0);
  });

  it("refuses empty input without contacting the backend", async () => {
    const calls = stubFetch({});
    await expect(runBatchEnrichment([])).rejects.toThrow(/No indicators/);
    await expect(runBatchEnrichment(["   ", ""])).rejects.toThrow(/No indicators/);
    expect(calls).toHaveLength(0);
  });

  it("dedupes case-insensitively and preserves first-seen order", async () => {
    const calls = stubFetch({ "/api/reputation/enrich-batch": batchPayload() });
    await runBatchEnrichment(["Evil.example.com", "evil.example.com", "203.0.113.9"]);
    expect(calls[0].body).toEqual({
      indicators: [{ value: "Evil.example.com" }, { value: "203.0.113.9" }],
    });
  });

  it("writes enriched-by provenance edges when a batch value matches a case IOC", async () => {
    stubFetch({
      "/api/reputation/enrich-batch": (() => {
        const p = batchPayload();
        p.results = [];
        return p;
      })(),
    });
    // seed a second payload that includes the matching ip so finish() runs
    vi.stubGlobal("fetch", vi.fn(async (url: string) =>
      url.includes("/api/reputation/enrich-batch")
        ? new Response(JSON.stringify(batchPayload()), { status: 200 })
        : new Response(JSON.stringify({ detail: "not found" }), { status: 404 }),
    ));
    const cases = [{
      id: "c1", title: "t", tags: [], createdAt: "", state: "active",
      entries: [], iocs: [{ id: "ioc-x", value: "44d88612fea8a8f36de82e1278abb02f", type: "hash", context: "", source: "manual", severity: "high" }],
    }];
    localStorage.setItem("ba.cases.v2", JSON.stringify(cases));
    await runBatchEnrichment(["44d88612fea8a8f36de82e1278abb02f"]);
    expect(getAllEdges().some((e) => e.relation === "enriched-by" && e.to.kind === "enrichment")).toBe(true);
  });
});
