import { describe, it, expect } from "vitest";
import {
  getThreatActors,
  getThreatActorById,
  getThreatActorByTitleOrAlias,
  discoverRelationships,
  buildGraphElements,
  searchIntel,
  ALL_ENTITIES,
} from "@/data/intel";

describe("Threat Intelligence & Threat Actors Suite", () => {
  it("loads catalog of 24 tracked threat actors", () => {
    const actors = getThreatActors();
    expect(actors.length).toBe(24);
    expect(actors.some((a) => a.title === "APT28")).toBe(true);
    expect(actors.some((a) => a.title === "APT29")).toBe(true);
    expect(actors.some((a) => a.title === "Lazarus Group")).toBe(true);
    expect(actors.some((a) => a.title === "UNC1878")).toBe(true);
  });

  it("resolves threat actors by title, alias, or id", () => {
    const apt28 = getThreatActorByTitleOrAlias("APT28");
    expect(apt28).toBeDefined();
    expect(apt28?.title).toBe("APT28");

    // Case-insensitive alias matching
    const fancyBear = getThreatActorByTitleOrAlias("fancy bear");
    expect(fancyBear?.title).toBe("APT28");

    const cozyBear = getThreatActorByTitleOrAlias("Midnight Blizzard");
    expect(cozyBear?.title).toBe("APT29");

    const scatteredSpider = getThreatActorByTitleOrAlias("scattered spider");
    expect(scatteredSpider?.title).toBe("UNC1878");

    // ID lookup
    if (apt28) {
      const byId = getThreatActorById(apt28.id);
      expect(byId?.title).toBe("APT28");
    }

    expect(getThreatActorByTitleOrAlias("NonExistentActor12345")).toBeUndefined();
  });

  it("populates concrete observed infrastructure observables on actors", () => {
    const apt28 = getThreatActorByTitleOrAlias("APT28")!;
    expect(apt28.observables.length).toBeGreaterThan(0);
    const hasProxyIp = apt28.observables.some((o) => o.value === "185.220.101.4" && o.type === "ipv4");
    expect(hasProxyIp).toBe(true);

    const lazarus = getThreatActorByTitleOrAlias("Lazarus Group")!;
    expect(lazarus.observables.length).toBeGreaterThan(0);
    const hasCryptoDomain = lazarus.observables.some((o) => o.value === "crypto-trade-wallet.io");
    expect(hasCryptoDomain).toBe(true);
  });

  it("discovers bi-directional adversary relationships (tools and CVE targeting)", () => {
    const apt28 = getThreatActorByTitleOrAlias("APT28")!;
    const rels = discoverRelationships(apt28);

    // Actor -> Tool (Cobalt Strike)
    const usesCs = rels.some(
      (r) => r.relationshipType === "uses-tool" && r.reason.includes("Cobalt Strike")
    );
    expect(usesCs).toBe(true);

    // Actor -> Targeted CVE (e.g. CVE-2024-21413)
    const targetsCve = rels.some(
      (r) => r.relationshipType === "targets-cve" && r.reason.includes("CVE-2024-21413")
    );
    expect(targetsCve).toBe(true);

    // Reverse test: CVE-2024-21413 -> Actor (exploited-by)
    const cve = ALL_ENTITIES.find((e) => e.title === "CVE-2024-21413")!;
    const cveRels = discoverRelationships(cve);
    const exploitedByApt28 = cveRels.some(
      (r) => r.relationshipType === "exploited-by" && r.reason.includes("APT28")
    );
    expect(exploitedByApt28).toBe(true);

    // Reverse test: Cobalt Strike -> Actor (used-by)
    const cs = ALL_ENTITIES.find((e) => e.title === "Cobalt Strike")!;
    const csRels = discoverRelationships(cs);
    const usedByApt28 = csRels.some(
      (r) => r.relationshipType === "used-by" && r.reason.includes("APT28")
    );
    expect(usedByApt28).toBe(true);
  });

  it("builds structured graph elements for STIX relationship graph", () => {
    const apt28 = getThreatActorByTitleOrAlias("APT28")!;
    const rels = discoverRelationships(apt28);
    const graph = buildGraphElements(apt28, rels);

    expect(graph.nodes.length).toBeGreaterThan(1);
    expect(graph.links.length).toBeGreaterThan(0);

    const center = graph.nodes.find((n) => n.isCenter);
    expect(center).toBeDefined();
    expect(center?.id).toBe(apt28.id);
    expect(center?.label).toBe("APT28");

    // Peripheral nodes contain connected entities and leaf observables
    expect(graph.nodes.some((n) => n.label === "Cobalt Strike")).toBe(true);
  });

  it("scores search queries matching aliases and observed infrastructure", () => {
    // Search by alias
    const aliasHits = searchIntel("Fancy Bear");
    expect(aliasHits.totalHits).toBeGreaterThan(0);
    const topActor = aliasHits.entityGroups
      .find((g) => g.entityType === "threat-actor")
      ?.entities[0];
    expect(topActor?.title).toBe("APT28");

    // Search by concrete observable IP
    const ipHits = searchIntel("185.220.101.4");
    expect(ipHits.totalHits).toBeGreaterThan(0);
    const actorMatch = ipHits.entityGroups
      .find((g) => g.entityType === "threat-actor")
      ?.entities.find((e) => e.title === "APT28");
    expect(actorMatch).toBeDefined();
  });
});
