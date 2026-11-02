import type { ConfidenceExplanation, Finding } from "@/types/objects";
import type { WeightedObservation } from "./weighting";
import { STRONG, MEDIUM, WEAK } from "./weighting";

/**
 * Confidence (ANALYSIS_ENGINE §4c module 5, Principles 5 & 7).
 * Never a bare percentage: level + contributors, recomputed from the weighted
 * observation set. Same input → same explanation.
 */

export function levelFromWeights(scores: number[]): ConfidenceExplanation["level"] {
  const strong = scores.filter((s) => s >= STRONG).length;
  const medium = scores.filter((s) => s >= MEDIUM && s < STRONG).length;
  const weak = scores.filter((s) => s >= WEAK && s < MEDIUM).length;
  if (strong >= 1 && medium >= 1) return "high";
  if (strong >= 2) return "high";
  if (strong >= 1 || medium >= 2) return "medium";
  if (medium >= 1 || weak >= 2) return "low";
  return "unknown";
}

export function explanationFor(weighted: WeightedObservation[]): ConfidenceExplanation {
  const contributing = weighted
    .filter((w) => w.score >= WEAK)
    .map((w) => w.observation.id);
  const levels = weighted.map((w) => w.score);
  const strong = levels.filter((s) => s >= STRONG).length;
  const medium = levels.filter((s) => s >= MEDIUM && s < STRONG).length;
  const weak = levels.filter((s) => s >= WEAK && s < MEDIUM).length;
  const contributors: string[] = [];
  if (strong >= 1) contributors.push(`${strong} strong indicator${strong > 1 ? "s" : ""}`);
  if (medium >= 1) contributors.push(`${medium} medium signal${medium > 1 ? "s" : ""}`);
  if (weak >= 1) contributors.push(`${weak} weak signal${weak > 1 ? "s" : ""}`);
  if (contributors.length === 0) contributors.push("no scoring observations");
  contributors.push(...contributing);
  return { level: levelFromWeights(levels), contributors };
}

export function attachConfidence(findings: Finding[], weighted: WeightedObservation[]): Finding[] {
  const overall = explanationFor(weighted);
  return findings.map((f) => {
    if (f.confidence && f.confidence.level !== "unknown") return f;
    const refs = f.observations ?? [];
    const perFinding = weighted.filter((w) => refs.some((o) => o.id === w.observation.id));
    const explanation = refs.length > 0 ? explanationFor(perFinding) : overall;
    return { ...f, confidence: explanation };
  });
}