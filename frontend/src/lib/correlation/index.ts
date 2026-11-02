import { runAnalysis, type AnalysisContext, type AnalysisEngineResult } from "@/lib/analysis";
import { correlate, correlationRelationships, type CorrelationHistory, type CorrelationMatch } from "./engine";

export * from "./engine";
export * from "./memory";
export type { AnalysisContext, AnalysisEngineResult, CorrelationHistory, CorrelationMatch };

/**
 * Analysis → Correlation main path (ANALYSIS_ENGINE §4e). Analysis runs first,
 * deterministically; correlation then flags history matches for analyst review.
 */

export interface CorrelatedAnalysis extends AnalysisEngineResult {
  correlation: CorrelationMatch[];
  correlationRelationships: ReturnType<typeof correlationRelationships>;
}

export function analyzeAndCorrelate(
  observations: Parameters<typeof runAnalysis>[0],
  history: CorrelationHistory,
  ctx: AnalysisContext = {},
): CorrelatedAnalysis {
  const result = runAnalysis(observations, ctx);
  const ts = ctx.ts ?? new Date().toISOString();
  const correlation = correlate(
    result.observations.map((o) => ({ id: o.id, kind: o.kind, value: o.value })),
    result.findings.map((f) => ({
      id: f.id,
      technique: f.technique,
      observationIds: (f.observations ?? []).map((o) => o.id),
    })),
    history,
  );
  const correlationRelationshipsResult = correlationRelationships(correlation, ctx.source ?? "correlation-engine", ts);
  return { ...result, correlation, correlationRelationships: correlationRelationshipsResult };
}