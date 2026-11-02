import { objectId } from "@/lib/ids";
import type { DetectionOpportunity, Finding, Observation, Recommendation } from "@/types/objects";
import { INVESTIGATION_OBJECTS_V1 } from "@/types/objects";

/**
 * Recommendations (ANALYSIS_ENGINE §4c module 8, Principle 6).
 * Every recommendation references evidence (observation ids). Kinds per
 * INVESTIGATION_OBJECTS §12. Never reads storage directly.
 */

export function buildRecommendations(
  observations: Observation[],
  findings: Finding[],
  opportunities: DetectionOpportunity[],
): Recommendation[] {
  const out: Recommendation[] = [];
  const ids = observations.map((o) => o.id);
  const kinds = new Set(observations.map((o) => o.kind));

  for (const opp of opportunities) {
    if (opp.coverage === "detected") continue;
    const findingObsIds = findings
      .filter((f) => f.technique === opp.technique)
      .flatMap((f) => (f.observations ?? []).map((o) => o.id));
    const refs = findingObsIds.length ? findingObsIds : [opp.id];
    if (opp.coverage === "unknown") {
      out.push({
        id: objectId("recommendation", "map-coverage", opp.technique),
        kind: "next-step",
        priority: opp.priority,
        statement: `Assess detection coverage for ${opp.technique}`,
        reason: `${opp.technique} surfaced with no rule-coverage check.`,
        evidenceRefs: refs,
        target: { route: "/detection" },
        status: "open",
        schemaVersion: INVESTIGATION_OBJECTS_V1,
      });
    } else {
      out.push({
        id: objectId("recommendation", "create-rule", opp.technique),
        kind: "create-rule",
        priority: opp.priority,
        statement: `Create a Sigma rule for ${opp.technique}`,
        reason: `No existing rule covers ${opp.technique} (${opp.behavior}).`,
        evidenceRefs: refs,
        target: { route: "/detection" },
        status: "open",
        schemaVersion: INVESTIGATION_OBJECTS_V1,
      });
    }
  }

  const enrichable = observations.filter((o) => o.kind === "ip" || o.kind === "domain" || o.kind === "url" || o.kind === "hash");
  if (enrichable.length) {
    const highRisk = enrichable.find((o) => o.kind === "url" && o.meta.host && /\.(tk|ml|ga|cf|gq|ru|cn)$/.test(o.meta.host)) ?? enrichable[0];
    out.push({
      id: objectId("recommendation", "enrich-ioc", highRisk.value),
      kind: "enrich-ioc",
      priority: highRisk === enrichable[0] && enrichable.length > 1 && (enrichable[0].kind === "ip" || enrichable[0].kind === "domain") ? "medium" : "medium",
      statement: `Enrich ${highRisk.kind} ${highRisk.value}`,
      reason: `${enrichable.length} network indicator(s) available for reputation lookups.`,
      evidenceRefs: [highRisk.id],
      target: { route: "/intel" },
      status: "open",
      schemaVersion: INVESTIGATION_OBJECTS_V1,
    });
  }

  const unmapped = findings.some((f) => !f.technique);
  if (unmapped) {
    out.push({
      id: objectId("recommendation", "add-mitre", "map"),
      kind: "add-mitre",
      priority: "low",
      statement: "Map remaining findings to MITRE ATT&CK",
      reason: "At least one finding has no technique mapping.",
      evidenceRefs: findings.filter((f) => !f.technique).flatMap((f) => (f.observations ?? []).map((o) => o.id)),
      target: { route: "/mitre" },
      status: "open",
      schemaVersion: INVESTIGATION_OBJECTS_V1,
    });
  }

  if (!kinds.has("ip") && (kinds.has("url") || kinds.has("email") || kinds.has("command"))) {
    out.push({
      id: objectId("recommendation", "collect-logs", "network"),
      kind: "collect-logs",
      priority: "low",
      statement: "Collect network connection logs for the investigated hosts",
      reason: "No IP observation present to anchor correlation.",
      evidenceRefs: ids,
      status: "open",
      schemaVersion: INVESTIGATION_OBJECTS_V1,
    });
  }

  if (ids.length) {
    out.push({
      id: objectId("recommendation", "next-step", "top"),
      kind: "next-step",
      priority: out.some((r) => r.priority === "high" && r.kind !== "next-step") ? "high" : "medium",
      statement: "Proceed with the highest-priority open recommendation",
      reason: `${out.length} open recommendation(s) await analyst action.`,
      evidenceRefs: ids,
      target: { route: "/investigation" },
      status: "open",
      schemaVersion: INVESTIGATION_OBJECTS_V1,
    });
  }

  return out;
}