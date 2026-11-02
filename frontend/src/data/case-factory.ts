import type { AnalysisResult, EvidenceItem } from "@/types/analysis";
import type { Finding, IOC } from "@/types/security";
import type { Investigation, InvestigationTimelineEvent, InvestigationResult } from "@/types/investigation";
import type { Case, Entry, EntryKind, CaseEvent, EventReference } from "@/data/case";
import { newId, newCaseTitle, loadCases, saveCases, setActiveCaseId, ensureIocId, ensureEvidenceId } from "@/data/case";
import { addEdge } from "@/lib/provenance";
import { projectCorrelationEdges } from "@/lib/correlation/memory";

function genId(): string {
  return crypto.randomUUID();
}

function findingToEntry(f: Finding, result: AnalysisResult): Entry {
  const kind: EntryKind = f.severity === "critical" || f.severity === "high" ? "evidence" : "note";
  return {
    id: newId("entry"),
    ts: result.generatedAt,
    kind,
    body: `[${f.severity.toUpperCase()}] ${f.title} (from: ${result.analyzer})\n${f.detail}`,
  };
}

function iocToEntry(ioc: IOC, result: AnalysisResult): Entry {
  return {
    id: newId("entry"),
    ts: result.generatedAt,
    kind: "ioc" as EntryKind,
    body: `${ioc.type}: ${ioc.value}\nSource: ${ioc.context} (from: ${result.analyzer})`,
  };
}

function evidenceItemToEntry(item: EvidenceItem, result: AnalysisResult): Entry {
  const kind: EntryKind = item.type === "secret" ? "evidence" : "note";
  return {
    id: newId("entry"),
    ts: result.generatedAt,
    kind,
    body: `[${item.type}] ${item.title} (from: ${item.source})\n${item.detail}`,
  };
}

function buildTimeline(result: AnalysisResult): InvestigationTimelineEvent[] {
  const events: InvestigationTimelineEvent[] = [
    {
      id: genId(),
      ts: result.generatedAt,
      kind: "analysis",
      title: `${result.analyzer} analysis completed`,
      detail: `Verdict: ${result.summary.verdict} (score: ${result.summary.score}, confidence: ${Math.round(result.summary.confidence * 100)}%)`,
      source: result.analyzer,
    },
  ];

  for (const f of result.findings) {
    if (f.severity === "critical" || f.severity === "high") {
      events.push({
        id: genId(),
        ts: result.generatedAt,
        kind: "finding",
        title: f.title,
        detail: f.detail,
        source: result.analyzer,
      });
    }
  }

  return events;
}

function buildEvents(result: AnalysisResult, caseTitle: string, ts: string): CaseEvent[] {
  const artRef: EventReference = { kind: "artifact", id: result.artifact.id };
  const events: CaseEvent[] = [
    {
      id: newId("evt"), ts, kind: "case_created", category: "case", importance: "high",
      actor: "system", origin: result.analyzer,
      title: `${caseTitle}`,
      detail: `Investigation created from ${result.analyzer} analysis`,
      references: [artRef],
    },
    {
      id: newId("evt"), ts, kind: "artifact_uploaded", category: "artifact", importance: "normal",
      actor: "system", origin: result.analyzer,
      title: result.artifact.title,
      detail: `${result.artifact.kind} artifact submitted for analysis`,
      references: [artRef],
    },
    {
      id: newId("evt"), ts, kind: "analysis_completed", category: "analysis", importance: "high",
      actor: "system", origin: result.analyzer,
      title: `${result.analyzer} analysis completed`,
      detail: `${result.summary.verdict} (score: ${result.summary.score}, confidence: ${Math.round(result.summary.confidence * 100)}%)`,
      references: [artRef],
    },
  ];
  for (const f of result.findings) {
    const refs: EventReference[] = [artRef, { kind: "finding", id: f.id }];
    events.push({
      id: newId("evt"), ts, kind: "finding_created", category: "finding", importance: f.severity === "critical" || f.severity === "high" ? "high" : "normal",
      actor: "system", origin: result.analyzer,
      title: `[${f.severity.toUpperCase()}] ${f.title}`,
      detail: f.detail,
      references: refs,
    });
  }
  for (const ioc of result.iocs) {
    const refs: EventReference[] = [artRef, { kind: "ioc", id: ensureIocId(ioc).id! }];
    events.push({
      id: newId("evt"), ts, kind: "ioc_created", category: "ioc", importance: "normal",
      actor: "system", origin: result.analyzer,
      title: `${ioc.type}: ${ioc.value}`,
      detail: ioc.context,
      references: refs,
    });
  }
  return events;
}

export function createCaseFromAnalysis(result: AnalysisResult): InvestigationResult {
  const now = new Date().toISOString();
  const analyzerLabel = result.analyzer === "phishing" ? "Phishing" : result.analyzer === "url" ? "URL" : result.analyzer;
  const caseTitle = `${newCaseTitle()} — ${analyzerLabel} Analysis`;

  const entries: Entry[] = [
    {
      id: newId("entry"),
      ts: now,
      kind: "decision",
      body: `Verdict: ${result.summary.verdict}\nScore: ${result.summary.score}/100\nConfidence: ${Math.round(result.summary.confidence * 100)}%\nAnalyzer: ${result.analyzer}`,
    },
    ...result.findings.map(f => findingToEntry(f, result)),
    ...result.iocs.map(i => iocToEntry(i, result)),
    ...result.evidenceItems.map(e => evidenceItemToEntry(e, result)),
  ];

  const events = buildEvents(result, caseTitle, now);

  const c: Case = {
    id: newId("case"),
    title: caseTitle,
    tags: [result.analyzer, result.summary.verdict],
    createdAt: now,
    state: "active",
    entries,
    events,
    artifacts: [result.artifact],
    findings: result.findings,
    iocs: result.iocs.map(ensureIocId),
    evidenceItems: result.evidenceItems.map(ensureEvidenceId),
    analysisSummary: result.summary,
  };

  const timeline = buildTimeline(result);

  const investigation: Investigation = {
    case: c,
    analysisResults: [result],
    timeline,
  };

  const existing = loadCases();
  existing.push(c);
  saveCases(existing);
  setActiveCaseId(c.id);

  writeAnalysisEdges(c, result);

  return { investigation, isNew: true };
}

/* ── provenance writers (§9 step 3) ── */

function writeAnalysisEdges(c: Case, result: AnalysisResult) {
  const artifactRef = { kind: "artifact" as const, id: result.artifact.id };
  const iocsById = new Map((c.iocs ?? []).map((i) => [`${i.type}|${i.value}`, i.id!]));

  for (const ev of c.evidenceItems ?? []) {
    addEdge({ relation: "produced", from: artifactRef, to: { kind: "evidence", id: ev.id! }, source: result.analyzer, reason: `${result.analyzer} analysis` });
    if (ev.type === "finding") {
      const finding = (c.findings ?? []).find((f) => f.title === ev.title);
      if (finding) {
        addEdge({ relation: "supports", from: { kind: "evidence", id: ev.id! }, to: { kind: "finding", id: finding.id }, source: result.analyzer, confidence: result.summary.confidence, reason: "evidence backs the finding" });
      }
    }
  }

  for (const f of c.findings ?? []) {
    for (const ioc of f.iocs ?? []) {
      const id = iocsById.get(`${ioc.type}|${ioc.value}`);
      if (id) {
        addEdge({ relation: "extracts", from: { kind: "finding", id: f.id }, to: { kind: "ioc", id }, source: result.analyzer, confidence: result.summary.confidence, reason: "finding produced the observable" });
      }
    }
  }

  const corr = result.correlationRelationships ?? [];
  if (corr.length > 0 && (result.observations?.length ?? 0) > 0) {
    const iocByValue = new Map((c.iocs ?? []).map((i) => [i.value, i.id!]));
    const valueByObs = new Map((result.observations ?? []).map((o) => [o.id, o.value]));
    projectCorrelationEdges({
      relationships: corr,
      iocNodeFor: (obsId) => {
        const obsValue = valueByObs.get(obsId);
        return obsValue ? iocByValue.get(obsValue) : undefined;
      },
    });
  }
}

/* ── event builders for analyst/case actions ── */

export function buildCaseCreatedEvent(title: string): CaseEvent {
  const ts = new Date().toISOString();
  return {
    id: newId("evt"), ts, kind: "case_created", category: "case", importance: "normal",
    actor: "analyst", origin: "case",
    title: `Case created: ${title}`,
    detail: "",
    references: [],
  };
}

export function buildNoteAddedEvent(body: string, origin: string): CaseEvent {
  const ts = new Date().toISOString();
  return {
    id: newId("evt"), ts, kind: "case_note_added", category: "analyst", importance: "low",
    actor: "analyst", origin,
    title: "Note added",
    detail: body.slice(0, 200),
    references: [],
  };
}

export function buildDecisionMadeEvent(decision: string, origin: string): CaseEvent {
  const ts = new Date().toISOString();
  return {
    id: newId("evt"), ts, kind: "case_decision_made", category: "case", importance: "critical",
    actor: "analyst", origin,
    title: "Decision recorded",
    detail: decision.slice(0, 200),
    references: [],
  };
}

export function buildStatusChangedEvent(from: string, to: string, origin: string): CaseEvent {
  const ts = new Date().toISOString();
  return {
    id: newId("evt"), ts, kind: "case_status_changed", category: "case", importance: "high",
    actor: "analyst", origin,
    title: `Case ${to}`,
    detail: `Status changed from "${from}" to "${to}"`,
    references: [],
  };
}

export function buildAnalystActionEvent(action: string, detail: string, origin: string): CaseEvent {
  const ts = new Date().toISOString();
  return {
    id: newId("evt"), ts, kind: "analyst_action", category: "analyst", importance: "normal",
    actor: "analyst", origin,
    title: action,
    detail: detail.slice(0, 200),
    references: [],
  };
}

export function findInvestigationsForArtifact(artifactValue: string): Investigation[] {
  const cases = loadCases();
  return cases
    .filter(c => c.entries.some(e => e.body.includes(artifactValue)))
    .map(c => ({
      case: c,
      analysisResults: [],
      timeline: [],
    }));
}
