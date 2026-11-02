import type { Case, CaseEvent } from "@/data/case";
import { loadCases, saveCases, newId, ensureIocId, ensureEvidenceId } from "@/data/case";
import { loadRules, recordAlert, slugRuleKey, alertNodeId, deploymentNodeId, type SavedRule } from "@/data/detection";
import { addEdge, eventDigest, lifecycleNodeId } from "@/lib/provenance";
import { analyzeAndCorrelate, type CorrelatedAnalysis } from "@/lib/correlation";
import { rememberCorrelation, projectCorrelationEdges } from "@/lib/correlation/memory";
import { buildLocalHistory } from "@/lib/correlation/history";
import { parseAlert, iocObservations, type ParsedAlert } from "./parse";
import type { IOC as SecurityIOC } from "@/types/security";
import type { EvidenceItem } from "@/types/analysis";

export const L_ALERTS = "ba.alerts.v1";

export interface AlertLedgerEntry {
  alertId: string;
  format: ParsedAlert["format"];
  title: string;
  ingestedAt: string;
  caseId: string;
  ruleKey?: string;
}

export interface IngestResult {
  ok: true;
  alert: ParsedAlert;
  alertId: string;
  analysis: CorrelatedAnalysis;
  case: Case | null;
  isNew: boolean;
  ledger: AlertLedgerEntry;
  resolvedRule?: SavedRule;
  edgesWritten: number;
}

export interface IngestError {
  ok: false;
  error: string;
}

export type IngestOutcome = IngestResult | IngestError;

/**
 * Deterministic alert node id for alerts that resolved to no deployed
 * detection: keyed on (format|ruleRef?|digest) so re-ingesting the same raw
 * alert always lands on the same node. Alerts that DO resolve to a deployed
 * rule use the lifecycle-canonical identity (deploymentId|eventDigest) via
 * recordAlert — one node per deployment firing, never two.
 */
export function ingestAlertNodeId(alert: ParsedAlert): string {
  return lifecycleNodeId("alert", `${alert.format}|${alert.ruleName ?? "ingest"}|${eventDigest(alert.raw)}`);
}

export function loadAlertLedger(): Record<string, AlertLedgerEntry> {
  try {
    const raw = localStorage.getItem(L_ALERTS);
    return raw ? (JSON.parse(raw) as Record<string, AlertLedgerEntry>) : {};
  } catch {
    return {};
  }
}

function saveAlertLedger(ledger: Record<string, AlertLedgerEntry>) {
  try {
    localStorage.setItem(L_ALERTS, JSON.stringify(ledger));
  } catch {
    /* best-effort */
  }
}

/**
 * Resolve the detection the alert fires from: a saved rule in state
 * "deployed", matched by rule name (case-insensitive) or stored rule-key
 * slug. Rule-fired alerts gain the `fires` edge; unmatched alerts stay
 * standalone graph nodes (no synthetic detection relationship).
 */
export function resolveFiringDetection(alert: ParsedAlert): SavedRule | undefined {
  if (alert.format !== "sigma" && !(alert.format === "beyondlabs" && alert.ruleName)) return undefined;
  if (!alert.ruleName) return undefined;
  const rules = loadRules();
  const deployed = rules.filter((r) => r.state === "deployed");
  const byName = deployed.find((r) => r.name.toLowerCase() === alert.ruleName!.toLowerCase());
  if (byName) return byName;
  const slug = slugRuleKey(alert.ruleName, "").replace(/-$/, "");
  return deployed.find((r) => r.ruleKey === `${slug}-` || r.ruleKey.startsWith(`${slug}-`));
}

/* ── case assembly ────────────────────────────────────────── */

function iocTypeFor(o: { kind: ParsedAlert["observations"][number]["kind"]; meta: Record<string, string> }): SecurityIOC["type"] {
  if (o.kind === "ip") return "ipv4";
  if (o.kind === "domain") return "domain";
  if (o.kind === "url") return "url";
  if (o.kind === "email") return "email";
  if (o.kind === "hash") return (o.meta.hashType as SecurityIOC["type"]) || "sha256";
  return "unknown";
}

function iocsFromObservations(alert: ParsedAlert, alertId: string): SecurityIOC[] {
  return iocObservations(alert.observations).map((o) =>
    ensureIocId({
      value: o.value,
      type: iocTypeFor(o),
      context: `Alert ${alert.format} ${alertId}`,
      source: o.source,
      severity: alert.severity,
    }),
  );
}

function evidenceFromFindings(analysis: CorrelatedAnalysis, source: string): EvidenceItem[] {
  return analysis.findings.map((f) =>
    ensureEvidenceId({
      type: "finding",
      title: f.title,
      detail: f.detail,
      source: typeof f.source === "string" ? f.source : source,
    }),
  );
}

function confidencePercent(analysis: CorrelatedAnalysis): number {
  return Math.round((analysis.quality.confidence ?? 0) * 100);
}

function entriesFrom(alert: ParsedAlert, analysis: CorrelatedAnalysis, iocs: SecurityIOC[], now: string) {
  const entries = [
    {
      id: newId("entry"),
      ts: now,
      kind: "decision" as const,
      body: `Alert: ${alert.title}\nSource: ${alert.format}\nSeverity: ${alert.severity}\nTechniques: ${analysis.mitre.length ? analysis.mitre.map((m) => m.technique).join(", ") : "none mapped"}\nConfidence: ${confidencePercent(analysis)}%`,
    },
    ...analysis.findings.map((f) => ({
      id: newId("entry"),
      ts: now,
      kind: (f.severity === "critical" || f.severity === "high" ? "evidence" : "note") as "evidence" | "note",
      body: `[${(f.severity ?? "medium").toUpperCase()}] ${f.title} (from: ${alert.format} alert)\n${f.detail}`,
    })),
    ...iocs.map((i) => ({
      id: newId("entry"),
      ts: now,
      kind: "ioc" as const,
      body: `${i.type}: ${i.value}\nSource: ${i.context}`,
    })),
  ];
  return entries;
}

function eventsFrom(alert: ParsedAlert, analysis: CorrelatedAnalysis, iocs: SecurityIOC[], now: string, alertId: string): CaseEvent[] {
  const alertRef: CaseEvent["references"][number] = { kind: "alert", id: alertId };
  const events: CaseEvent[] = [
    {
      id: newId("evt"), ts: now, kind: "alert_ingested", category: "detection",
      importance: alert.severity === "critical" || alert.severity === "high" ? "high" : "normal",
      actor: "integration", origin: "alert-ingest",
      title: alert.title,
      detail: `${alert.format} alert ingested (severity: ${alert.severity})${alert.ruleName ? ` — rule: ${alert.ruleName}` : ""}`,
      references: [alertRef],
    },
    {
      id: newId("evt"), ts: now, kind: "case_created", category: "case", importance: "high",
      actor: "system", origin: "alert-ingest",
      title: alert.title,
      detail: `Investigation opened by ${alert.format} alert (severity: ${alert.severity})`,
      references: [alertRef],
    },
  ];
  for (const f of analysis.findings) {
    events.push({
      id: newId("evt"), ts: now, kind: "finding_created", category: "finding",
      importance: f.severity === "critical" || f.severity === "high" ? "high" : "normal",
      actor: "system", origin: "alert-ingest",
      title: `[${(f.severity ?? "medium").toUpperCase()}] ${f.title}`,
      detail: f.detail,
      references: [alertRef, { kind: "finding", id: f.id }],
    });
  }
  for (const ioc of iocs) {
    events.push({
      id: newId("evt"), ts: now, kind: "ioc_created", category: "ioc", importance: "normal",
      actor: "system", origin: "alert-ingest",
      title: `${ioc.type}: ${ioc.value}`,
      detail: ioc.context,
      references: [alertRef, { kind: "ioc", id: ioc.id! }],
    });
  }
  return events;
}

function buildCase(alert: ParsedAlert, analysis: CorrelatedAnalysis, iocs: SecurityIOC[], now: string, alertId: string): Case {
  const caseId = newId("case");
  const c: Case = {
    id: caseId,
    title: `${alert.title} — Alert Investigation`,
    tags: [alert.format, alert.severity, "alert", ...(alert.ruleName ? ["detection-linked"] : [])],
    createdAt: now,
    state: "active",
    entries: entriesFrom(alert, analysis, iocs, now),
    events: eventsFrom(alert, analysis, iocs, now, alertId),
    iocs,
    findings: analysis.findings.map((f) => ({
      id: f.id,
      severity: f.severity ?? "medium",
      title: f.title,
      detail: f.detail,
      source: typeof f.source === "string" ? f.source : `alert-ingest:${alertId}`,
      ...(f.technique ? { technique: f.technique } : {}),
    })),
    evidenceItems: evidenceFromFindings(analysis, `alert-ingest:${alertId}`),
  };
  return c;
}

/* ── provenance writers ───────────────────────────────────── */

type Ref = { kind: "alert" | "case" | "evidence" | "finding" | "ioc" | "mitre" | "entity"; id: string };

function writeIngestEdges(opts: {
  alertId: string;
  alert: ParsedAlert;
  analysis: CorrelatedAnalysis;
  c: Case;
  resolvedRule?: SavedRule;
}): number {
  const { alertId, alert, analysis, c, resolvedRule } = opts;
  const source = `alert-ingest:${alert.format}`;
  let count = 0;
  const alertRef: Ref = { kind: "alert", id: alertId };

  if (resolvedRule) {
    recordAlert({ ruleId: resolvedRule.id, ruleKey: resolvedRule.ruleKey, version: resolvedRule.version, event: alert.raw, source });
    count += 1;
  }

  addEdge({ relation: "creates", from: alertRef, to: { kind: "case", id: c.id }, source, reason: `${alert.format} alert opened the investigation` });
  count += 1;

  const iocByValue = new Map((c.iocs ?? []).map((i) => [i.value, i.id!]));
  const valueByObs = new Map(analysis.observations.map((o) => [o.id, o.value]));

  for (const f of analysis.findings) {
    const evidence = c.evidenceItems?.find((e) => e.title === f.title && e.detail === f.detail);
    if (evidence?.id) {
      addEdge({ relation: "produced", from: alertRef, to: { kind: "evidence", id: evidence.id }, source, reason: "alert produced the evidence item" });
      addEdge({
        relation: "supports",
        from: { kind: "evidence", id: evidence.id },
        to: { kind: "finding", id: f.id },
        source,
        confidence: analysis.quality.confidence,
        reason: "evidence backs the finding",
      });
      count += 2;
    }
    for (const obs of f.observations ?? []) {
      const iocId = iocByValue.get(obs.value);
      if (iocId) {
        addEdge({ relation: "extracts", from: { kind: "finding", id: f.id }, to: { kind: "ioc", id: iocId }, source, reason: "finding produced the observable" });
        count += 1;
      }
    }
    if (f.technique) {
      addEdge({ relation: "mapped-to", from: { kind: "finding", id: f.id }, to: { kind: "mitre", id: f.technique }, source, reason: "behaviour maps to technique" });
      count += 1;
    }
  }

  count += projectCorrelationEdges({
    relationships: analysis.correlationRelationships,
    iocNodeFor: (obsId) => {
      const obsValue = valueByObs.get(obsId);
      return obsValue ? iocByValue.get(obsValue) : undefined;
    },
  });

  return count;
}

/* ── pipeline ─────────────────────────────────────────────── */

/**
 * Alert → Investigation → Graph (DETECTION_LIFECYCLE §5, ANALYSIS_ENGINE §4).
 * Structured alert → parse → observations → runAnalysis → correlation →
 * case create → provenance writes. Idempotent per alert content: the alert
 * ledger records the node, and re-ingesting the same raw alert returns the
 * existing investigation without duplicating edges (deterministic node ids +
 * append-only addEdge keep history immutable).
 */
export function ingestAlert(raw: string, opts: { now?: Date } = {}): IngestOutcome {
  const now = (opts.now ?? new Date()).toISOString();
  const alert = parseAlert(raw);
  if (!alert) {
    return { ok: false, error: "Unrecognized alert format — expected beyondlabs.alert.v1, Sigma, Suricata EVE, or Sysmon XML" };
  }

  const resolvedRule = resolveFiringDetection(alert);
  const alertId = resolvedRule
    ? alertNodeId(deploymentNodeId(resolvedRule.id, resolvedRule.version), eventDigest(alert.raw))
    : ingestAlertNodeId(alert);
  const ledger = loadAlertLedger();

  const prior = ledger[alertId];
  if (prior) {
    const existing = loadCases().find((c) => c.id === prior.caseId) ?? null;
    return {
      ok: true,
      alert,
      alertId,
      analysis: analyzeAndCorrelate(alert.observations, buildLocalHistory(), { source: `alert-ingest:${alertId}`, ts: now }),
      case: existing,
      isNew: false,
      ledger: prior,
      edgesWritten: 0,
    };
  }

  const analysis = analyzeAndCorrelate(alert.observations, buildLocalHistory(), { source: `alert-ingest:${alertId}`, ts: now });
  const iocs = iocsFromObservations(alert, alertId);
  const c = buildCase(alert, analysis, iocs, now, alertId);

  const cases = loadCases();
  cases.push(c);
  saveCases(cases);

  const entry: AlertLedgerEntry = {
    alertId,
    format: alert.format,
    title: alert.title,
    ingestedAt: now,
    caseId: c.id,
    ...(resolvedRule ? { ruleKey: resolvedRule.ruleKey } : {}),
  };
  const nextLedger = { ...ledger, [alertId]: entry };
  saveAlertLedger(nextLedger);

  const edgesWritten = writeIngestEdges({ alertId, alert, analysis, c, resolvedRule });

  rememberCorrelation(analysis.correlation, { source: `alert-ingest:${alertId}`, caseId: c.id, ts: opts.now });

  return { ok: true, alert, alertId, analysis, case: c, isNew: true, ledger: entry, resolvedRule, edgesWritten };
}