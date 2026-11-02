import type { Case, CaseEvent } from "@/data/case";
import { addCaseEvent, newId } from "@/data/case";

export type HypothesisConfidence = "low" | "medium" | "high";
export type HypothesisStatus = "open" | "supported" | "refuted" | "inconclusive";

export type NotebookHypothesis = {
  id: string;
  caseId: string;
  hypothesis: string;
  supporting: string[];
  contradicting: string[];
  confidence: HypothesisConfidence;
  status: HypothesisStatus;
  decision: string;
  nextStep: string;
  createdAt: string;
  updatedAt: string;
};

export const LS_KEY = "ba.notebook.hypotheses";

export const HYPOTHESIS_CONFIDENCE_ORDER: HypothesisConfidence[] = ["low", "medium", "high"];
export const HYPOTHESIS_STATUS_ORDER: HypothesisStatus[] = ["open", "supported", "refuted", "inconclusive"];

export const STATUS_TO_EVENT: Record<Exclude<HypothesisStatus, "open">, string> = {
  supported: "hypothesis supported",
  refuted: "hypothesis refuted",
  inconclusive: "hypothesis inconclusive",
};

export function loadHypotheses(): NotebookHypothesis[] {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as NotebookHypothesis[];
  } catch {
    return [];
  }
}

export function saveHypotheses(list: NotebookHypothesis[]) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(list));
  } catch {
    /* noop */
  }
}

export function hypothesesForCase(list: NotebookHypothesis[], caseId: string): NotebookHypothesis[] {
  return list
    .filter((h) => h.caseId === caseId)
    .sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
}

export function upsertHypothesis(list: NotebookHypothesis[], input: NotebookHypothesis): NotebookHypothesis[] {
  const now = new Date().toISOString();
  if (input.id) {
    return list.map((h) => (h.id === input.id ? { ...h, ...input, updatedAt: now } : h));
  }
  const created: NotebookHypothesis = {
    ...input,
    id: newId("h"),
    createdAt: now,
    updatedAt: now,
    confidence: input.confidence || "low",
    status: input.status || "open",
  };
  return [...list, created];
}

export function deleteHypothesis(list: NotebookHypothesis[], id: string): NotebookHypothesis[] {
  return list.filter((h) => h.id !== id);
}

export function applyDecision(
  h: NotebookHypothesis,
  status: HypothesisStatus,
  decision: string,
  confidence: HypothesisConfidence,
): NotebookHypothesis {
  return {
    ...h,
    status,
    decision: status === "open" ? "" : decision || h.decision,
    confidence,
    updatedAt: new Date().toISOString(),
  };
}

export function buildHypothesisDecisionEvent(c: Case, h: NotebookHypothesis, verdict: Exclude<HypothesisStatus, "open">): CaseEvent {
  return {
    id: newId("ev"),
    ts: new Date().toISOString(),
    kind: "case_decision_made",
    category: "analyst",
    importance: verdict === "supported" ? "high" : "normal",
    actor: "analyst",
    origin: "notebook",
    title: `Hypothesis ${verdict}`,
    detail: h.decision ? `${STATUS_TO_EVENT[verdict]} — ${h.decision}` : STATUS_TO_EVENT[verdict],
    references: [{ kind: "evidence", id: h.id }],
  };
}

export function attachDecision(c: Case, h: NotebookHypothesis, verdict: Exclude<HypothesisStatus, "open">): Case | null {
  if (!c) return null;
  const expected = buildHypothesisDecisionEvent(c, h, verdict);
  const events = c.events ?? [];
  if (events.some((e) => e.kind === "case_decision_made" && e.origin === "notebook"
    && e.detail === expected.detail && e.references.some((r) => r.id === h.id))) {
    return c;
  }
  return addCaseEvent(c, expected);
}