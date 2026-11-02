import type { Artifact, Finding, IOC } from "./security";
import type { Observation, Relationship } from "./objects";

export interface AnalysisSummary {
  verdict: string;
  score: number;
  confidence: number;
}

export interface EvidenceItem {
  id?: string;
  type: string;
  title: string;
  detail: string;
  source: string;
}

/**
 * Common contract satisfied by every analyzer result.
 * TypeScript structural typing — any object with these fields IS an AnalysisResult.
 */
export interface AnalysisResult {
  id: string;
  analyzer: string;
  artifact: Artifact;
  raw: string;
  findings: Finding[];
  iocs: IOC[];
  evidenceItems: EvidenceItem[];
  summary: AnalysisSummary;
  generatedAt: string;
  /** Engine output (ANALYSIS_ENGINE §4) — present on analyzer-backed results. */
  observations?: Observation[];
  /** Engine relationship objects (origin "analysis" | "correlation"), projected when a case is created. */
  relationships?: Relationship[];
  /** Correlation-origin relationships (ANALYSIS_ENGINE §4e) — projected into the graph when a case is created. */
  correlationRelationships?: Relationship[];
}
