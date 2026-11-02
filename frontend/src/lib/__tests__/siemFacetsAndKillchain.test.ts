import { describe, expect, it } from "vitest";
import { computeFieldFacets } from "@/lib/siem/field-facets";
import { classifyEventPhase, reconstructKillChain } from "@/lib/siem/killchain-reconstruction";
import type { SiemEvent } from "@/data/siem";

const sampleEvents: SiemEvent[] = [
  {
    ts: "10:00:00",
    min: 600,
    src: "45.33.32.156",
    dst: "10.0.0.5",
    user: "-",
    sig: "GET /.env HTTP/1.1 404 (sqlmap scanner)",
    sev: "medium",
  },
  {
    ts: "10:05:00",
    min: 605,
    src: "45.33.32.156",
    dst: "10.0.0.5",
    user: "root",
    sig: "Failed password for root from 45.33.32.156 port 22",
    sev: "high",
  },
  {
    ts: "10:10:00",
    min: 610,
    src: "10.0.0.5",
    dst: "10.0.0.5",
    user: "Administrator",
    sig: "powershell.exe -EncodedCommand SQBFAFgA...",
    sev: "high",
  },
  {
    ts: "10:15:00",
    min: 615,
    src: "10.0.0.5",
    dst: "10.0.0.5",
    user: "Administrator",
    sig: "EventID: 1102 The audit log was cleared by Administrator",
    sev: "high",
  },
  {
    ts: "10:20:00",
    min: 620,
    src: "10.0.0.5",
    dst: "51.15.0.100",
    user: "Administrator",
    sig: "HTTPS outbound to 51.15.0.100:443 periodic beacon",
    sev: "high",
  },
];

describe("siem field facets", () => {
  it("computes field facets coverage and top values", () => {
    const facets = computeFieldFacets(sampleEvents);
    expect(facets).toHaveLength(5);

    const srcFacet = facets.find((f) => f.field === "src");
    expect(srcFacet).toBeDefined();
    expect(srcFacet?.coverage).toBe(100);
    expect(srcFacet?.uniqueCount).toBe(2);
    expect(srcFacet?.topValues[0].value).toBe("10.0.0.5");
    expect(srcFacet?.topValues[0].count).toBe(3);

    const userFacet = facets.find((f) => f.field === "user");
    expect(userFacet).toBeDefined();
    expect(userFacet?.coverage).toBe(80); // 4 out of 5 have user != '-'
    expect(userFacet?.topValues[0].value).toBe("Administrator");
  });

  it("handles empty event lists gracefully", () => {
    const facets = computeFieldFacets([]);
    expect(facets).toHaveLength(5);
    expect(facets[0].coverage).toBe(0);
    expect(facets[0].topValues).toEqual([]);
  });
});

describe("siem kill-chain reconstruction", () => {
  it("classifies individual events into correct kill-chain phases", () => {
    expect(classifyEventPhase(sampleEvents[0])).toBe("recon");
    expect(classifyEventPhase(sampleEvents[1])).toBe("initial_access");
    expect(classifyEventPhase(sampleEvents[2])).toBe("execution");
    expect(classifyEventPhase(sampleEvents[3])).toBe("persistence_evasion");
    expect(classifyEventPhase(sampleEvents[4])).toBe("c2_exfil");
  });

  it("reconstructs full kill chain progression and assigns high progression score", () => {
    const result = reconstructKillChain(sampleEvents);
    expect(result.activePhaseCount).toBe(5);
    expect(result.progressionScore).toBe(100);
    expect(result.highestPhase?.id).toBe("c2_exfil");
    expect(result.threatNarrative).toContain("Critical breach progression observed");
  });

  it("handles early-stage reconnaissance only datasets", () => {
    const reconOnly = [sampleEvents[0]];
    const result = reconstructKillChain(reconOnly);
    expect(result.activePhaseCount).toBe(1);
    expect(result.progressionScore).toBe(20);
    expect(result.highestPhase?.id).toBe("recon");
    expect(result.threatNarrative).toContain("Early reconnaissance");
  });
});
