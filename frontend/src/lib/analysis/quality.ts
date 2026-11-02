import type { AnalysisQuality, DetectionOpportunity, Finding, Observation, Recommendation } from "@/types/objects";
import { INVESTIGATION_OBJECTS_V1 } from "@/types/objects";
import type { WeightedObservation } from "./weighting";
import { WEAK, MEDIUM } from "./weighting";

/**
 * Quality Checker (ANALYSIS_ENGINE §4d, module 9).
 * Answers "How complete is this investigation?" — not "malicious 87%".
 * Deterministic: coverage proportions, weak/conflicting signals, next step.
 */

const COVERAGE_CATEGORIES: { kind: Observation["kind"]; label: string }[] = [
  { kind: "url", label: "URL content" },
  { kind: "domain", label: "domain context" },
  { kind: "ip", label: "network indicator" },
  { kind: "hash", label: "file hash" },
  { kind: "command", label: "process/command context" },
  { kind: "email", label: "sender identity" },
];

export function assessQuality(
  observations: Observation[],
  weighted: WeightedObservation[],
  findings: Finding[],
  opportunities: DetectionOpportunity[],
  recommendations: Recommendation[],
): AnalysisQuality {
  const kinds = new Set(observations.map((o) => o.kind));
  const covered = COVERAGE_CATEGORIES.filter((c) => kinds.has(c.kind));
  const gaps = COVERAGE_CATEGORIES.filter((c) => !kinds.has(c.kind)).map((c) => `missing ${c.label}`);
  const score = covered.length / COVERAGE_CATEGORIES.length;

  const weakSignals = weighted
    .filter((w) => w.score >= WEAK && w.score < MEDIUM)
    .map((w) => `${w.observation.kind}:${w.observation.value}`);

  const unexplained = findings.filter((f) => !f.confidence || f.confidence.level === "unknown").length;
  const missing = [...gaps];
  if (unexplained) missing.push(`${unexplained} finding(s) without confidence explanation`);

  const topOpportunity = [...opportunities].sort((a, b) => PRIORITY[a.priority] - PRIORITY[b.priority])[0];
  const topRecommendation = [...recommendations].sort((a, b) => PRIORITY[a.priority] - PRIORITY[b.priority]).find((r) => r.kind !== "next-step");

  let recommendedNextStep: string;
  if (topOpportunity && topOpportunity.coverage !== "detected") {
    recommendedNextStep = `Create or verify detection for ${topOpportunity.technique}`;
  } else if (topRecommendation) {
    recommendedNextStep = topRecommendation.statement;
  } else if (gaps.length) {
    recommendedNextStep = `Collect ${gaps[0]}`;
  } else {
    recommendedNextStep = "Review findings and document a decision";
  }

  const anyExplained = findings.some((f) => f.confidence && f.confidence.level !== "unknown");

  return {
    coverage: { score, gaps },
    confidence: anyExplained ? undefined : computeLevel(findings),
    weakSignals,
    conflictingSignals: [],
    recommendedNextStep,
    missing,
    notes: findings.length ? ["correlation engine not run (deferred)"] : ["no findings to grade"],
    schemaVersion: INVESTIGATION_OBJECTS_V1,
  };
}

const PRIORITY: Record<"low" | "medium" | "high", number> = { high: 0, medium: 1, low: 2 };

function computeLevel(findings: Finding[]): number | undefined {
  const levels = findings.map((f) => f.confidence?.level).filter((l) => l && l !== "unknown");
  if (!levels.length) return undefined;
  if (levels.some((l) => l === "high")) return 0.85;
  if (levels.some((l) => l === "medium")) return 0.65;
  return 0.45;
}