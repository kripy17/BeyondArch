import { objectId } from "@/lib/ids";
import type { NodeRef, ProvenanceRelation } from "@/lib/provenance";
import type { Observation, Relationship } from "@/types/objects";
import { INVESTIGATION_OBJECTS_V1 } from "@/types/objects";

/**
 * Relationship Discovery (ANALYSIS_ENGINE §4c module 2).
 * Finds factual links between observations: a URL's host, observations
 * referenced by a finding, findings mapped to techniques. Emits Relationship
 * objects with deterministic ids (hash of relation, from, to — PROVENANCE §4).
 */

export function observationRef(o: Observation): NodeRef {
  return { kind: "ioc", id: o.id };
}

export function findingRef(id: string): NodeRef {
  return { kind: "finding", id };
}

export function techniqueRef(id: string): NodeRef {
  return { kind: "mitre", id };
}

export function relationshipId(relation: ProvenanceRelation, from: NodeRef, to: NodeRef): string {
  return objectId("relationship", relation, from.kind, from.id, to.kind, to.id);
}

function edge(
  relation: ProvenanceRelation,
  from: NodeRef,
  to: NodeRef,
  source: string,
  evidenceRefs: string[],
  ts: string,
): Relationship {
  return {
    id: relationshipId(relation, from, to),
    relation,
    from,
    to,
    evidenceRefs,
    origin: "analysis",
    source,
    ts,
    schemaVersion: INVESTIGATION_OBJECTS_V1,
  };
}

/** Links each URL to its extracted host domain/ip observation (meta.from = "url"). */
export function discoverUrlHostLinks(observations: Observation[], source: string, ts: string): Relationship[] {
  const out: Relationship[] = [];
  const byValue = new Map<string, Observation[]>();
  for (const o of observations) {
    if (o.kind !== "domain" && o.kind !== "ip") continue;
    const list = byValue.get(o.value) ?? [];
    list.push(o);
    byValue.set(o.value, list);
  }
  for (const url of observations.filter((o) => o.kind === "url")) {
    const host = url.meta.host;
    if (!host) continue;
    const linked = byValue.get(host);
    if (linked) {
      for (const hostObs of linked) {
        out.push(edge("supports", observationRef(url), observationRef(hostObs), source, [url.id, hostObs.id], ts));
      }
    }
  }
  return out;
}

/** Links findings to the observations that support them (extracts) and techniques they map to. */
export function discoverFindingEdges(
  findings: { id: string; technique?: string; observationIds: string[] }[],
  observationsById: Map<string, Observation>,
  source: string,
  ts: string,
): Relationship[] {
  const out: Relationship[] = [];
  for (const f of findings) {
    const obsNodes: NodeRef[] = [];
    for (const oid of f.observationIds) {
      const o = observationsById.get(oid);
      if (!o) continue;
      const n = observationRef(o);
      if (obsNodes.every((x) => x.id !== n.id)) obsNodes.push(n);
      out.push(edge("extracts", findingRef(f.id), n, source, [f.id, oid], ts));
    }
    if (f.technique) {
      out.push(edge("mapped-to", findingRef(f.id), techniqueRef(f.technique), source, f.observationIds, ts));
    }
  }
  return out;
}