import type { IntelEntity, Relationship } from "./types";
import { ALL_ENTITIES } from "./sources";

/* ── Relationship discovery ───────────────────────────────
 *
 * Currently all relationships are derived from string matching
 * (no formal foreign keys). Known overlaps:
 *
 *   Actor.tools  ↔  Malware.title  (e.g. "Cobalt Strike")
 *   Actor.tools  ↔  FileHash.malware
 *   Actor.tools  ↔  TlsFingerprint.malware
 *   Malware.title ↔  TlsFingerprint.malware
 *   Malware.title ↔  FileHash.malware
 *   Actor.techniques  ↔  MITRE (internal only, no separate index)
 *
 * Future: explicit relationship data layer.
 */

export function discoverRelationships(entity: IntelEntity): Relationship[] {
  const rels: Relationship[] = [];

  if (entity.type === "threat-actor") {
    const actor = entity as import("./types").ThreatActorEntity;

    /* Actor → Malware via shared tools */
    for (const tool of actor.tools) {
      for (const other of ALL_ENTITIES) {
        if (other.id === entity.id) continue;
        if (other.type === "malware" && other.title.toLowerCase() === tool.toLowerCase()) {
          rels.push({
            sourceId: entity.id,
            targetId: other.id,
            targetType: "malware",
            relationshipType: "uses-tool",
            confidence: "high",
            source: "Intel data (exact match)",
            reason: `Actor ${entity.title} uses malware ${other.title}`,
          });
        }
      }
    }

    /* Actor → TlsFingerprint via shared malware */
    for (const tool of actor.tools) {
      for (const other of ALL_ENTITIES) {
        if (other.id === entity.id) continue;
        if (other.type === "tls-fingerprint") {
          const fp = other as import("./types").TlsFingerprintEntity;
          if (fp.malware.toLowerCase() === tool.toLowerCase()) {
            rels.push({
              sourceId: entity.id,
              targetId: other.id,
              targetType: "tls-fingerprint",
              relationshipType: "associated-with",
              confidence: "medium",
              source: "Intel data (string match)",
              reason: `Actor ${entity.title} associated with ${fp.malware} TLS fingerprint`,
            });
          }
        }
      }
    }

    /* Actor → FileHash via shared malware */
    for (const tool of actor.tools) {
      for (const other of ALL_ENTITIES) {
        if (other.id === entity.id) continue;
        if (other.type === "file-hash") {
          const h = other as import("./types").FileHashEntity;
          if (h.malware.toLowerCase() === tool.toLowerCase()) {
            rels.push({
              sourceId: entity.id,
              targetId: other.id,
              targetType: "file-hash",
              relationshipType: "associated-with",
              confidence: "medium",
              source: "Intel data (string match)",
              reason: `Actor ${entity.title} associated with ${h.malware} file hash`,
            });
          }
        }
      }
    }
    /* Actor → Vulnerability via targeted CVEs */
    if (actor.targetedCves?.length) {
      for (const cve of actor.targetedCves) {
        for (const other of ALL_ENTITIES) {
          if (other.id === entity.id) continue;
          if (other.type === "vulnerability" && other.title.toLowerCase() === cve.toLowerCase()) {
            rels.push({
              sourceId: entity.id,
              targetId: other.id,
              targetType: "vulnerability",
              relationshipType: "targets-cve",
              confidence: "high",
              source: "Adversary intelligence",
              reason: `Actor ${entity.title} observed exploiting ${cve}`,
            });
          }
        }
      }
    }
  }

  if (entity.type === "vulnerability") {
    /* Vulnerability → Threat Actor that targets it */
    for (const other of ALL_ENTITIES) {
      if (other.id === entity.id) continue;
      if (other.type === "threat-actor") {
        const actor = other as import("./types").ThreatActorEntity;
        if (actor.targetedCves?.some((c) => c.toLowerCase() === entity.title.toLowerCase())) {
          rels.push({
            sourceId: entity.id,
            targetId: other.id,
            targetType: "threat-actor",
            relationshipType: "exploited-by",
            confidence: "high",
            source: "Threat telemetry",
            reason: `Exploited in operations by ${actor.title}`,
          });
        }
      }
    }
  }

  if (entity.type === "malware") {
    const malware = entity as import("./types").MalwareEntity;

    /* Malware → Threat Actor that uses it */
    for (const other of ALL_ENTITIES) {
      if (other.id === entity.id) continue;
      if (other.type === "threat-actor") {
        const actor = other as import("./types").ThreatActorEntity;
        if (actor.tools.some((t) => t.toLowerCase() === malware.title.toLowerCase())) {
          rels.push({
            sourceId: entity.id,
            targetId: other.id,
            targetType: "threat-actor",
            relationshipType: "used-by",
            confidence: "high",
            source: "Tooling telemetry",
            reason: `Employed in intrusions by ${actor.title}`,
          });
        }
      }
    }

    /* Malware → TlsFingerprint */
    for (const other of ALL_ENTITIES) {
      if (other.id === entity.id) continue;
      if (other.type === "tls-fingerprint") {
        const fp = other as import("./types").TlsFingerprintEntity;
        if (fp.malware.toLowerCase() === malware.title.toLowerCase()) {
          rels.push({
            sourceId: entity.id,
            targetId: other.id,
            targetType: "tls-fingerprint",
            relationshipType: "linked-to",
            confidence: "medium",
            source: "Intel data (string match)",
            reason: `Malware ${malware.title} linked to TLS fingerprint`,
          });
        }
      }
      if (other.type === "file-hash") {
        const h = other as import("./types").FileHashEntity;
        if (h.malware.toLowerCase() === malware.title.toLowerCase()) {
          rels.push({
            sourceId: entity.id,
            targetId: other.id,
            targetType: "file-hash",
            relationshipType: "linked-to",
            confidence: "medium",
            source: "Intel data (string match)",
            reason: `Malware ${malware.title} linked to file hash`,
          });
        }
      }
    }
  }

  if (entity.type === "tls-fingerprint") {
    const fp = entity as import("./types").TlsFingerprintEntity;

    /* TlsFingerprint → Malware */
    for (const other of ALL_ENTITIES) {
      if (other.id === entity.id) continue;
      if (other.type === "malware" && other.title.toLowerCase() === fp.malware.toLowerCase()) {
        rels.push({
          sourceId: entity.id,
          targetId: other.id,
          targetType: "malware",
          relationshipType: "linked-to",
          confidence: "medium",
          source: "Intel data (string match)",
          reason: `TLS fingerprint linked to malware ${other.title}`,
        });
      }
    }
  }

  if (entity.type === "file-hash") {
    const hash = entity as import("./types").FileHashEntity;

    /* FileHash → Malware */
    for (const other of ALL_ENTITIES) {
      if (other.id === entity.id) continue;
      if (other.type === "malware" && other.title.toLowerCase() === hash.malware.toLowerCase()) {
        rels.push({
          sourceId: entity.id,
          targetId: other.id,
          targetType: "malware",
          relationshipType: "linked-to",
          confidence: "medium",
          source: "Intel data (string match)",
          reason: `File hash linked to malware ${other.title}`,
        });
      }
    }
  }

  /* Deduplicate by targetId + type */
  const seen = new Set<string>();
  return rels.filter((r) => {
    const key = `${r.targetId}:${r.relationshipType}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  isCenter?: boolean;
  score?: number;
  sublabel?: string;
}

export interface GraphLink {
  source: string;
  target: string;
  label: string;
  confidence: string;
}

export function buildGraphElements(centerEntity: IntelEntity, relationships: Relationship[]): {
  nodes: GraphNode[];
  links: GraphLink[];
} {
  const nodes: GraphNode[] = [
    {
      id: centerEntity.id,
      label: centerEntity.title,
      type: centerEntity.type,
      isCenter: true,
      score: centerEntity.score,
      sublabel: centerEntity.type.replace("-", " "),
    },
  ];

  const links: GraphLink[] = [];
  const addedNodeIds = new Set<string>([centerEntity.id]);

  for (const rel of relationships) {
    const target = ALL_ENTITIES.find((e) => e.id === rel.targetId);
    if (target && !addedNodeIds.has(target.id)) {
      addedNodeIds.add(target.id);
      nodes.push({
        id: target.id,
        label: target.title,
        type: target.type,
        score: target.score,
        sublabel: target.type.replace("-", " "),
      });
    }

    links.push({
      source: rel.sourceId,
      target: rel.targetId,
      label: rel.relationshipType.replace(/-/g, " "),
      confidence: rel.confidence,
    });
  }

  // Also include direct observables for the center entity as satellite leaf nodes if under 6
  if (centerEntity.observables.length > 0 && centerEntity.observables.length <= 8) {
    for (const obs of centerEntity.observables) {
      const obsNodeId = `obs-${obs.id}`;
      if (!addedNodeIds.has(obsNodeId)) {
        addedNodeIds.add(obsNodeId);
        nodes.push({
          id: obsNodeId,
          label: obs.value.length > 28 ? obs.value.slice(0, 26) + "…" : obs.value,
          type: "observable",
          sublabel: obs.type,
        });
        links.push({
          source: centerEntity.id,
          target: obsNodeId,
          label: "observable",
          confidence: "high",
        });
      }
    }
  }

  return { nodes, links };
}
