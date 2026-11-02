import { describe, expect, it } from "vitest";
import {
  lookupTechniqueMeta,
  calculateAdversaryAttribution,
  profileC2Traffic,
  attributeActiveCase,
  generateAttributionMarkdown,
} from "@/lib/adversary-attribution";
import { type IOC } from "@/types/security";
import { type Case } from "@/data/case";

describe("Adversary Attribution & MITRE C2 Profiling Engine", () => {
  it("looks up technique metadata from the MITRE dataset", () => {
    const t1 = lookupTechniqueMeta("T1566");
    expect(t1.id).toBe("T1566");
    expect(t1.name).toBeDefined();

    const t2 = lookupTechniqueMeta("T1059.001");
    expect(t2.id).toBe("T1059.001");
    expect(t2.tactic).toBeDefined();
  });

  it("attributes threat actor with high confidence when infrastructure matches", () => {
    // Volt Typhoon known proxy IP from threat intel dataset: 45.154.255.101
    const observables: IOC[] = [
      {
        value: "45.154.255.101",
        type: "ipv4",
        context: "C2 ingress hop",
        source: "siem",
        severity: "critical",
      },
    ];
    const techniques = ["T1059.003", "T1078", "T1047"];

    const report = calculateAdversaryAttribution(observables, techniques, "Energy");

    expect(report.primaryCandidate).toBeDefined();
    expect(report.primaryCandidate?.actor.title).toBe("Volt Typhoon");
    expect(report.primaryCandidate?.confidenceScore).toBeGreaterThanOrEqual(70);
    expect(report.primaryCandidate?.confidenceLevel).toBe("High Confidence");
    expect(report.primaryCandidate?.evidence.matchedIocs.length).toBe(1);
    expect(report.primaryCandidate?.evidence.matchedTargeting).toBe(true);
  });

  it("profiles C2 traffic accurately via JA3 and JA4 TLS fingerprints", () => {
    // Known Cobalt Strike JA3
    const csProfile = profileC2Traffic({
      ja3: "7e12c4a7c2e1e5c6c8d4f7a0b3c5d8e1",
      beaconIntervalSec: 30,
      jitterPct: 5,
    });

    expect(csProfile.framework).toBe("Cobalt Strike");
    expect(csProfile.confidence).toBeGreaterThanOrEqual(80);
    expect(csProfile.profileType).toBe("TLS JA3/JA4 Fingerprint");
    expect(csProfile.recommendedMitigations.length).toBeGreaterThan(0);
    expect(csProfile.sigmaRuleMatches.length).toBeGreaterThan(0);

    // Known Sliver JA4
    const sliverProfile = profileC2Traffic({
      ja4: "ja4_b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
      beaconIntervalSec: 15,
      jitterPct: 10,
    });

    expect(sliverProfile.framework).toBe("Sliver");
    expect(sliverProfile.confidence).toBeGreaterThanOrEqual(85);
  });

  it("attributes an active case automatically based on its findings and observables", () => {
    const mockCase: Case = {
      id: "case-attrib-01",
      title: "Critical Infrastructure Infiltration",
      tags: ["energy", "critical", "incident"],
      createdAt: new Date().toISOString(),
      state: "active",
      entries: [
        {
          id: "e1",
          ts: new Date().toISOString(),
          kind: "action",
          body: "Detected living-off-the-land techniques T1059.003 and T1078",
        },
      ],
      findings: [
        {
          id: "f1",
          title: "Proxy Tunneling",
          source: "siem",
          severity: "critical",
          detail: "Fast Reverse Proxy FRP observed contacting 45.154.255.101",
          technique: "T1090",
        },
      ],
      iocs: [
        {
          id: "i1",
          value: "45.154.255.101",
          type: "ipv4",
          context: "Cisco router proxy",
          source: "siem",
          severity: "critical",
        },
      ],
    };

    const report = attributeActiveCase(mockCase);

    expect(report.primaryCandidate).toBeDefined();
    expect(report.primaryCandidate?.actor.title).toBe("Volt Typhoon");
    expect(report.primaryCandidate?.evidence.matchedIocs.length).toBe(1);
    expect(report.primaryCandidate?.evidence.matchedTechniques.length).toBeGreaterThan(0);
  });

  it("generates structured markdown dossier with evidence breakdown", () => {
    const observables: IOC[] = [
      {
        value: "45.154.255.101",
        type: "ipv4",
        context: "C2 ingress hop",
        source: "siem",
        severity: "critical",
      },
    ];
    const techniques = ["T1059.003", "T1078"];
    const report = calculateAdversaryAttribution(observables, techniques, "Energy");
    const c2 = profileC2Traffic({ ja3: "7e12c4a7c2e1e5c6c8d4f7a0b3c5d8e1" });

    const md = generateAttributionMarkdown(report, c2);

    expect(md).toContain("# THREAT ACTOR ATTRIBUTION & C2 PROFILE DOSSIER");
    expect(md).toContain("Volt Typhoon");
    expect(md).toContain("Attribution Evidence Matrix");
    expect(md).toContain("45.154.255.101");
    expect(md).toContain("Command & Control (C2) Architecture Profiling");
    expect(md).toContain("Cobalt Strike");
    expect(md).toContain("Alternative Threat Actor Contenders");
  });
});
