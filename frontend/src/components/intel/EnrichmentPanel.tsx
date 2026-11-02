import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Globe, ShieldAlert, RefreshCw } from "lucide-react";
import {
  ADAPTER_META,
  BATCH_ENRICHMENT_CAP,
  detectEnrichmentQueryType,
  enrichmentHistory,
  runBatchEnrichment,
  runEnrichment,
  type BatchSkippedItem,
  type EnrichmentAdapterId,
  type EnrichmentRecord,
} from "@/lib/enrichment";

const CONFIDENCE_STYLE: Record<EnrichmentRecord["confidence"], string> = {
  measured: "border-success/40 bg-success/10 text-success",
  "no-data": "border-border bg-surface-1 text-muted-foreground",
  failed: "border-destructive/40 bg-destructive/10 text-destructive",
};

/** Opt-in external enrichment behind an explicit per-lookup gate — the same
 *  consent philosophy as Safe Fetch. Source, method, confidence, limitations,
 *  and collection time are always rendered, for every record, forever. */
export function EnrichmentPanel({ query }: { query: string }) {
  const queryType = useMemo(() => detectEnrichmentQueryType(query), [query]);
  const [consent, setConsent] = useState(false);
  const [running, setRunning] = useState<EnrichmentAdapterId | null>(null);
  const [records, setRecords] = useState<EnrichmentRecord[]>([]);
  const [batchText, setBatchText] = useState("");
  const [batchRunning, setBatchRunning] = useState(false);
  const [batchSkipped, setBatchSkipped] = useState<BatchSkippedItem[]>([]);

  const batchValues = useMemo(() => {
    const seen: string[] = [];
    for (const raw of batchText.split(/[\n,]+/)) {
      const v = raw.trim();
      if (v && !seen.some((c) => c.toLowerCase() === v.toLowerCase())) seen.push(v);
    }
    return seen;
  }, [batchText]);
  const batchOverCap = batchValues.length > BATCH_ENRICHMENT_CAP;

  useEffect(() => {
    setConsent(false);
    setRecords(enrichmentHistory().filter((r) => r.query.toLowerCase() === query.trim().toLowerCase()));
  }, [query]);

  if (!query.trim() || !queryType) return null;

  const adapters = (Object.keys(ADAPTER_META) as EnrichmentAdapterId[]).filter((id) =>
    ADAPTER_META[id].appliesTo.includes(queryType),
  );

  async function run(adapter: EnrichmentAdapterId) {
    setRunning(adapter);
    try {
      const record = await runEnrichment(adapter, query);
      setRecords((prev) => [record, ...prev.filter((r) => r.id !== record.id)]);
      if (record.ok) toast.success(`${ADAPTER_META[adapter].label}: ${record.confidence}`);
      else toast.error(`${ADAPTER_META[adapter].label} failed: ${record.error ?? record.confidence}`);
    } catch {
      toast.error("Enrichment request could not be completed");
    } finally {
      setRunning(null);
    }
  }

  async function runBatch() {
    setBatchRunning(true);
    try {
      const result = await runBatchEnrichment(batchValues);
      setRecords((prev) => [...result.records, ...prev.filter((p) => !result.records.some((n) => n.id === p.id))]);
      setBatchSkipped(result.skipped);
      toast.success(`batch reputation: ${result.processed} enriched · ${result.skipped.length} skipped`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Batch enrichment failed");
    } finally {
      setBatchRunning(false);
    }
  }

  return (
    <div className="mb-4 rounded border border-subtle bg-surface-1/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Globe className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="text-mono ba-text-2xs font-semibold uppercase tracking-wide text-muted-foreground">
          External enrichment · {queryType}
        </span>
        <label className="ml-auto inline-flex cursor-pointer items-center gap-1.5 text-mono ba-text-2xs text-muted-foreground">
          <input
            type="checkbox"
            checked={consent}
            onChange={(e) => setConsent(e.target.checked)}
            className="accent-[var(--primary)]"
          />
          opt in: contact backend live lookup
        </label>
      </div>
      {!consent ? (
        <p className="mt-2 flex items-start gap-1.5 text-mono ba-text-2xs text-fg-dim">
          <ShieldAlert className="mt-0.5 h-3 w-3 shrink-0 text-warning" />
          Nothing has been requested. Adapters only run after you opt in below — same gate as Safe Fetch.
        </p>
      ) : (
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          {adapters.map((id) => (
            <button
              key={id}
              onClick={() => void run(id)}
              disabled={running !== null}
              className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:border-primary/40 hover:text-foreground disabled:opacity-50"
            >
              {running === id && <RefreshCw className="h-3 w-3 animate-spin" />}
              {ADAPTER_META[id].label}
            </button>
          ))}
        </div>
      )}
      {consent && (
        <div className="mt-2 border-t border-subtle pt-2">
          <p className="text-mono ba-text-2xs uppercase tracking-wide text-muted-foreground">
            batch reputation · local deterministic checks (max {BATCH_ENRICHMENT_CAP})
          </p>
          <textarea
            rows={3}
            value={batchText}
            onChange={(e) => setBatchText(e.target.value)}
            placeholder="one indicator per line or comma-separated — hashes, IPs, domains"
            aria-label="Batch enrichment indicators"
            className="mt-1.5 w-full rounded border border-border bg-surface-0 p-2 font-mono ba-text-2xs text-foreground placeholder:text-fg-dim focus-visible:outline-[var(--ring)]"
          />
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <button
              onClick={() => void runBatch()}
              disabled={batchRunning || running !== null || !batchValues.length || batchOverCap}
              className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:border-primary/40 hover:text-foreground disabled:opacity-50"
            >
              {batchRunning && <RefreshCw className="h-3 w-3 animate-spin" />}
              enrich {batchValues.length} indicator{batchValues.length === 1 ? "" : "s"}
            </button>
            {batchOverCap && (
              <span className="text-mono ba-text-2xs text-destructive">
                {batchValues.length} indicators exceeds the {BATCH_ENRICHMENT_CAP} limit
              </span>
            )}
          </div>
          {batchSkipped.length > 0 && (
            <ul className="mt-1.5 space-y-0.5">
              {batchSkipped.map((s) => (
                <li key={s.index} className="text-mono ba-text-2xs text-warning/90">
                  skipped · index {s.index}: {s.reason}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {records.map((r) => (
        <div key={r.id} data-testid="enrichment-record" className="mt-3 rounded border border-divider-strong bg-surface-0 p-2.5">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-mono ba-text-2xs">
            <span className="font-semibold uppercase text-foreground">{ADAPTER_META[r.adapter].label}</span>
            <span className="text-fg-dim">source: {r.source}</span>
            <span className="text-fg-dim">method: {r.method}</span>
            <span className={"rounded border px-1.5 py-0 " + CONFIDENCE_STYLE[r.confidence]}>{r.confidence}</span>
            <span className="text-fg-dim">collected: {r.collectedAt}</span>
          </div>
          {r.error && (
            <p className="mt-1.5 text-mono ba-text-2xs text-destructive">{r.error}</p>
          )}
          <ul className="mt-1.5 space-y-0.5">
            {r.limitations.map((l, i) => (
              <li key={i} className="text-mono ba-text-2xs text-warning/90">limitation: {l}</li>
            ))}
          </ul>
          {r.fields.length > 0 ? (
            <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5">
              {r.fields.map((f, i) => (
                <div key={i} className="col-span-2 grid grid-cols-subgrid">
                  <dt className="font-mono ba-text-2xs uppercase text-muted-foreground">{f.label}</dt>
                  <dd className="break-all font-mono ba-text-2xs text-foreground/90">{f.value}</dd>
                </div>
              ))}
            </dl>
          ) : r.ok ? (
            <p className="mt-2 text-mono ba-text-2xs text-muted-foreground">No records returned for this target.</p>
          ) : null}
        </div>
      ))}
    </div>
  );
}
