import type { Case } from "@/data/case";
import type { AnalysisResult } from "./analysis";


export type InvestigationState = "active" | "closed";

/**
 * A domain object representing the analyst's complete work on one artifact.
 * Bridges AnalysisResult → Case workspace.
 */
export interface Investigation {
  case: Case;
  analysisResults: AnalysisResult[];
  timeline: InvestigationTimelineEvent[];
}

export interface InvestigationTimelineEvent {
  id: string;
  ts: string;
  kind: "analysis" | "finding" | "ioc" | "note" | "action" | "decision";
  title: string;
  detail: string;
  source: string;
}

/** Returned by createCaseFromAnalysis — either new or appended to existing case */
export interface InvestigationResult {
  investigation: Investigation;
  isNew: boolean;
}
