import { crc32 } from "@/lib/zip";
import { getBackendUrl } from "@/lib/backend";
import { addEdge } from "@/lib/provenance";
import { loadCases } from "@/data/case";

/** Opt-in external enrichment adapters (WHOIS, DNS, hash reputation).
 *  Same gate philosophy as Safe Fetch: nothing leaves the machine until the
 *  analyst explicitly consents per lookup. Every record permanently carries
 *  source, method, confidence, limitations, and collection time — readers
 *  render all of them, always. */

export const LS_ENRICHMENT = "ba.enrichment.v1";

export type EnrichmentAdapterId = "whois" | "dns" | "hash-reputation" | "batch-reputation";

export type EnrichmentQueryType = "domain" | "ip" | "hash";

export type EnrichmentConfidence = "measured" | "no-data" | "failed";

export type EnrichmentField = { label: string; value: string };

export type EnrichmentRecord = {
  id: string;
  adapter: EnrichmentAdapterId;
  query: string;
  queryType: EnrichmentQueryType;
  ok: boolean;
  source: string;
  method: string;
  confidence: EnrichmentConfidence;
  limitations: string[];
  collectedAt: string;
  fields: EnrichmentField[];
  error?: string;
};

export const ADAPTER_META: Record<EnrichmentAdapterId, { label: string; appliesTo: EnrichmentQueryType[] }> = {
  whois: { label: "WHOIS / RDAP", appliesTo: ["domain", "ip"] },
  dns: { label: "DNS / PTR", appliesTo: ["domain", "ip"] },
  "hash-reputation": { label: "Hash reputation", appliesTo: ["hash"] },
  "batch-reputation": { label: "Reputation (batch)", appliesTo: ["hash", "ip", "domain"] },
};

/** Backend /enrich-batch accepts at most 25 indicators per call. */
export const BATCH_ENRICHMENT_CAP = 25;

type Store = Record<string, EnrichmentRecord>;

function loadStore(): Store {
  try {
    const raw = localStorage.getItem(LS_ENRICHMENT);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Store;
    return typeof parsed === "object" && parsed ? parsed : {};
  } catch { return {}; }
}

function saveStore(store: Store) {
  try { localStorage.setItem(LS_ENRICHMENT, JSON.stringify(store)); } catch { /* quota */ }
}

/** Newest first; capped so the store cannot grow unbounded across sessions. */
const HISTORY_CAP = 200;

export function enrichmentHistory(): EnrichmentRecord[] {
  return Object.values(loadStore()).sort((a, b) => (a.collectedAt < b.collectedAt ? 1 : -1)).slice(0, HISTORY_CAP);
}

export function detectEnrichmentQueryType(query: string): EnrichmentQueryType | null {
  const q = query.trim().toLowerCase();
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(q)) return "hash";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(q)) return "ip";
  // Registrable-domain-ish: letters/tld, no scheme, no spaces.
  if (/^(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(q) && q.includes(".")) return "domain";
  return null;
}

function recordId(adapter: string, query: string, collectedAt: string): string {
  return `enr-${crc32(new TextEncoder().encode(`${adapter}|${query.toLowerCase()}|${collectedAt}`)).toString(16).padStart(8, "0")}`;
}

async function post(path: string, body: unknown): Promise<Record<string, unknown>> {
  const res = await fetch(`${getBackendUrl()}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const err = (await res.json()) as { detail?: string };
      if (err?.detail) detail = String(err.detail);
    } catch { /* keep status line */ }
    throw new Error(detail);
  }
  return (await res.json()) as Record<string, unknown>;
}

function pushField(fields: EnrichmentField[], label: string, value: unknown) {
  if (value === null || value === undefined) return;
  const v = Array.isArray(value) ? value.join(", ") : String(value);
  if (!v.trim()) return;
  fields.push({ label, value: v });
}

function sectionConfidence(fields: EnrichmentField[], error?: string): EnrichmentConfidence {
  if (error) return "failed";
  return fields.length > 0 ? "measured" : "no-data";
}

async function runDnsWhois(adapter: "whois" | "dns", query: string): Promise<EnrichmentRecord> {
  const queryType: EnrichmentQueryType = detectEnrichmentQueryType(query) === "ip" ? "ip" : "domain";
  const collectedAt = new Date().toISOString();
  const base = { id: "", adapter, query, queryType, collectedAt };
  try {
    // confirm_permission is the opt-in gate — only ever true from an explicit click.
    const resp = await post("/api/recon/dns", { target: query, confirm_permission: true });
    const meta = (resp.meta ?? {}) as { source?: string; method?: string; limitations?: string };
    const fields: EnrichmentField[] = [];
    let error: string | undefined;

    if (queryType === "domain") {
      if (adapter === "dns") {
        const dns = (resp.dns ?? {}) as { records?: Record<string, string[]>; error?: string };
        for (const [rt, vals] of Object.entries(dns.records ?? {})) pushField(fields, rt, vals);
        error = dns.error;
      } else {
        const whois = (resp.whois ?? {}) as Record<string, unknown>;
        pushField(fields, "Registrar", whois.registrar);
        pushField(fields, "Organization", whois.organization);
        pushField(fields, "Created", whois.creation_date);
        pushField(fields, "Expires", whois.expiry_date);
        pushField(fields, "Name servers", whois.name_servers);
        pushField(fields, "Status", whois.status);
        error = typeof whois.error === "string" ? whois.error : undefined;
        if (!error && !fields.length && typeof whois.raw === "string" && whois.raw.trim()) {
          fields.push({ label: "Raw WHOIS", value: `${whois.raw.length} chars` });
        }
      }
    } else {
      if (adapter === "dns") {
        const rev = (resp.reverse_dns ?? {}) as { records?: Record<string, string[]>; error?: string };
        for (const [rt, vals] of Object.entries(rev.records ?? {})) if (vals.length) pushField(fields, rt, vals);
        error = rev.error;
      } else {
        const rdap = (resp.rdap ?? {}) as Record<string, unknown>;
        pushField(fields, "Handle", rdap.handle);
        pushField(fields, "Name", rdap.name);
        pushField(fields, "Organization", rdap.organization ?? rdap.org);
        pushField(fields, "Country", rdap.country);
        pushField(fields, "Registered", rdap.start_address ?? rdap.registration_date ?? rdap.created);
        pushField(fields, "Last changed", rdap.last_changed_date ?? rdap.updated);
        error = typeof rdap.error === "string" ? rdap.error : undefined;
      }
    }

    const record: EnrichmentRecord = {
      ...base,
      id: recordId(adapter, query, collectedAt),
      ok: !error,
      source: meta.source ?? "local backend",
      // The backend response bundles dns/whois/rdap sections regardless of
      // adapter; the record must describe only what THIS adapter consumed.
      method:
        adapter === "dns"
          ? "DNS record lookup" + (queryType === "ip" ? " with PTR reverse resolution" : "")
          : "WHOIS + RDAP registration lookup",
      limitations: meta.limitations
        ? [meta.limitations]
        : ["Availability depends on network, resolver, registry, and target type."],
      confidence: sectionConfidence(fields, error),
      fields,
      ...(error ? { error } : {}),
    };
    return finish(record);
  } catch (e) {
    return finish({
      ...base,
      id: recordId(adapter, query, collectedAt),
      ok: false,
      source: "local backend",
      method: adapter === "dns" ? "backend DNS/PTR lookup" : "backend WHOIS/RDAP lookup",
      limitations: ["Lookup never completed — no data was collected."],
      confidence: "failed",
      fields: [],
      error: e instanceof Error ? e.message : String(e),
    });
  }
}

async function runHashReputation(query: string): Promise<EnrichmentRecord> {
  const queryType: EnrichmentQueryType = "hash";
  const collectedAt = new Date().toISOString();
  const base = { id: "", adapter: "hash-reputation" as const, query, queryType, collectedAt };
  try {
    const resp = await post("/api/malware/hash/reputation", { hash_value: query });
    const findings = (Array.isArray(resp.findings) ? resp.findings : []) as Array<Record<string, unknown>>;
    const summary = (resp.summary ?? {}) as { note?: string; total_findings?: number };
    const fields: EnrichmentField[] = [];
    for (const f of findings) {
      const title = [f.severity, f.title].filter(Boolean).join(": ");
      const detail = [f.detail, f.guidance].filter(Boolean).join(" — ");
      if (title) fields.push({ label: title, value: detail || "-" });
    }
    if (typeof resp.checked_at === "string") pushField(fields, "Backend checked at", resp.checked_at);
    const record: EnrichmentRecord = {
      ...base,
      id: recordId("hash-reputation", query, collectedAt),
      ok: true,
      source: "local backend deterministic checks",
      method: "local hash heuristics (structure/entropy/format), no external provider queried",
      limitations: [
        summary.note ?? "Deterministic local checks only — no external reputation provider was queried.",
        "Absence of findings is not a verdict of safety.",
      ],
      confidence: fields.length > 0 ? "measured" : "no-data",
      fields,
    };
    return finish(record);
  } catch (e) {
    return finish({
      ...base,
      id: recordId("hash-reputation", query, collectedAt),
      ok: false,
      source: "local backend",
      method: "local hash reputation checks",
      limitations: ["Lookup never completed — no data was collected."],
      confidence: "failed",
      fields: [],
      error: e instanceof Error ? e.message : String(e),
    });
  }
}

/** Persist + link into provenance when the queried observable matches a case IOC. */
function finish(record: EnrichmentRecord): EnrichmentRecord {
  const store = loadStore();
  store[record.id] = record;
  saveStore(store);
  const q = record.query.trim().toLowerCase();
  const iocMatch = loadCases()
    .flatMap((c) => c.iocs ?? [])
    .find((i) => i.id && i.value.trim().toLowerCase() === q);
  if (iocMatch?.id && record.ok) {
    addEdge({
      relation: "enriched-by",
      from: { kind: "ioc", id: iocMatch.id },
      to: { kind: "enrichment", id: record.id },
      source: "/intel enrichment",
      confidence: 0.6,
      reason: `${ADAPTER_META[record.adapter].label} via ${record.source}`,
    });
  }
  return record;
}

export function runEnrichment(adapter: EnrichmentAdapterId, query: string): Promise<EnrichmentRecord> {
  if (adapter === "hash-reputation") return runHashReputation(query);
  if (adapter === "batch-reputation") {
    return Promise.reject(new Error("batch-reputation is list-based — use runBatchEnrichment() instead of runEnrichment()."));
  }
  return runDnsWhois(adapter, query);
}

export type BatchSkippedItem = { index: number; reason: string };

export type BatchEnrichmentResult = {
  records: EnrichmentRecord[];
  requested: number;
  processed: number;
  skipped: BatchSkippedItem[];
  note?: string;
};

/** One opt-in call enriches up to 25 indicators (hash/ip/domain/email/url).
 *  Every per-indicator report becomes its own record with the full honesty
 *  header, and provenance edges fire exactly like single lookups. */
export async function runBatchEnrichment(values: string[]): Promise<BatchEnrichmentResult> {
  const cleaned: string[] = [];
  for (const raw of values) {
    const v = raw.trim();
    if (v && !cleaned.some((c) => c.toLowerCase() === v.toLowerCase())) cleaned.push(v);
  }
  if (cleaned.length > BATCH_ENRICHMENT_CAP) {
    throw new Error(`Batch is limited to ${BATCH_ENRICHMENT_CAP} indicators (got ${cleaned.length}).`);
  }
  if (cleaned.length === 0) throw new Error("No indicators to enrich.");

  // confirm_permission-equivalent: this function is only ever called from an
  // explicit user click after the panel's opt-in checkbox — the batch endpoint
  // runs local deterministic checks only.
  const resp = await post("/api/reputation/enrich-batch", {
    indicators: cleaned.map((value) => ({ value })),
  });

  const reports = (Array.isArray(resp.results) ? resp.results : []) as Array<Record<string, unknown>>;
  const batchSummary = (resp.summary ?? {}) as {
    requested?: number;
    processed?: number;
    skipped?: BatchSkippedItem[];
    note?: string;
  };
  const skipped = Array.isArray(batchSummary.skipped) ? batchSummary.skipped : [];

  const records = reports.map((report) => {
    const indicator = String(report.indicator ?? "");
    const collectedAt = typeof report.checked_at === "string" ? report.checked_at : new Date().toISOString();
    const reportType = String(report.type ?? "");
    const queryType: EnrichmentQueryType =
      detectEnrichmentQueryType(indicator) ?? (["ip", "domain", "hash"].includes(reportType) ? (reportType as EnrichmentQueryType) : "domain");
    const findings = (Array.isArray(report.findings) ? report.findings : []) as Array<Record<string, unknown>>;
    const summary = (report.summary ?? {}) as { note?: string };
    const fields: EnrichmentField[] = [];
    for (const f of findings) {
      const title = [f.severity, f.title].filter(Boolean).join(": ");
      const detail = [f.detail, f.guidance].filter(Boolean).join(" — ");
      if (title) fields.push({ label: title, value: detail || "-" });
    }
    const measured = findings.length > 0;
    if (!measured && typeof summary.note === "string" && summary.note) {
      fields.push({ label: "summary", value: summary.note });
    }
    return finish({
      id: recordId("batch-reputation", indicator, collectedAt),
      adapter: "batch-reputation",
      query: indicator,
      queryType,
      ok: true,
      source: "local backend deterministic checks",
      method: `batch reputation enrichment · type inferred: ${reportType || "unknown"}`,
      confidence: measured ? "measured" : "no-data",
      limitations: [
        summary.note || "Deterministic backend/local checks only.",
        "Heuristic findings are not verdicts of safety or malice.",
      ],
      collectedAt,
      fields,
    });
  });

  return {
    records,
    requested: batchSummary.requested ?? cleaned.length,
    processed: batchSummary.processed ?? records.length,
    skipped,
    note: batchSummary.note,
  };
}
