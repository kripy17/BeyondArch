import type { MitreMapping } from "./mitre";
import type { DetectionOpportunity, Finding, Observation, Recommendation, Relationship, AnalysisQuality } from "@/types/objects";
import { attachConfidence } from "./confidence";
import { assessQuality } from "./quality";
import { buildOpportunities, type OpportunityContext } from "./opportunities";
import { buildRecommendations } from "./recommendations";
import { reason } from "./reasoning";
import { mapFindings } from "./mitre";
import { discoverFindingEdges, discoverUrlHostLinks } from "./relationships";
import { weightObservations, type WeightedObservation } from "./weighting";

export * from "./weighting";
export * from "./reasoning";
export * from "./confidence";
export * from "./mitre";
export * from "./opportunities";
export * from "./recommendations";
export * from "./quality";
export * from "./relationships";
export type { MitreMapping };
export type { OpportunityContext };

/**
 * Analysis Engine v1 (ANALYSIS_ENGINE §4c). Consumes canonical Observations,
 * emits investigation objects. Pure pipeline — no UI state, no storage access
 * (stores are injected via context). Correlation runs post-analysis elsewhere (§4e).
 */

export interface AnalysisContext {
  source?: string;
  ts?: string;
  opportunity?: OpportunityContext;
}

export interface AnalysisEngineResult {
  observations: Observation[];
  weighted: WeightedObservation[];
  findings: Finding[];
  relationships: Relationship[];
  mitre: MitreMapping[];
  opportunities: DetectionOpportunity[];
  recommendations: Recommendation[];
  quality: AnalysisQuality;
}

export function runAnalysis(observations: Observation[], ctx: AnalysisContext = {}): AnalysisEngineResult {
  const source = ctx.source ?? "analysis-engine";
  const ts = ctx.ts ?? new Date().toISOString();

  const weighted = weightObservations(observations);
  const findings = attachConfidence(reason(weighted, source), weighted);
  const mitre = mapFindings(findings);
  const opportunities = buildOpportunities(findings, ctx.opportunity);
  const recommendations = buildRecommendations(observations, findings, opportunities);
  const quality = assessQuality(observations, weighted, findings, opportunities, recommendations);

  const observationsById = new Map(observations.map((o) => [o.id, o]));
  const relationships: Relationship[] = [
    ...discoverUrlHostLinks(observations, source, ts),
    ...discoverFindingEdges(
      findings.map((f) => ({
        id: f.id,
        technique: f.technique,
        observationIds: (f.observations ?? []).map((o) => o.id),
      })),
      observationsById,
      source,
      ts,
    ),
  ];

  return { observations, weighted, findings, relationships, mitre, opportunities, recommendations, quality };
}