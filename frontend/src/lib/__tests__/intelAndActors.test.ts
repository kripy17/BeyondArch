import { describe, it, expect } from "vitest";
import {
  generateDiamondModelForActor,
  generateActorCampaigns,
  generatePassiveDnsRecords,
  generateWhoisData,
  generateSslCertData,
  buildStix21Bundle,
} from "@/lib/intel/threat-intel-engine";
import { getThreatActorByTitleOrAlias } from "@/data/intel";

describe("Threat Intel Engine & Adversary Profiling Suite", () => {
  it("generates Diamond Model with all 4 vertices for APT28", () => {
    const apt28 = getThreatActorByTitleOrAlias("APT28");
    expect(apt28).toBeDefined();
    if (!apt28) return;

    const diamond = generateDiamondModelForActor(apt28);
    expect(diamond.adversary.actor).toBe("APT28");
    expect(diamond.adversary.origin).toBe("Russia");
    expect(diamond.adversary.countryFlag).toBe("🇷🇺");
    expect(diamond.adversary.sponsoringAgency).toContain("GRU");

    expect(diamond.capability.arsenal.length).toBeGreaterThan(0);
    expect(diamond.infrastructure.hostingProvider).toBeDefined();
    expect(diamond.victim.targetedSectors.length).toBeGreaterThan(0);
    expect(diamond.victim.impactPotential).toBe("Critical");
  });

  it("generates Diamond Model for Lazarus Group with financial attribution", () => {
    const lazarus = getThreatActorByTitleOrAlias("Lazarus Group");
    expect(lazarus).toBeDefined();
    if (!lazarus) return;

    const diamond = generateDiamondModelForActor(lazarus);
    expect(diamond.adversary.actor).toBe("Lazarus Group");
    expect(diamond.adversary.countryFlag).toBe("🇰🇵");
    expect(diamond.adversary.sponsoringAgency).toContain("RGB");
    expect(diamond.victim.targetedSectors).toContain("Financial");
  });

  it("generates chronological campaigns for threat actors", () => {
    const apt29 = getThreatActorByTitleOrAlias("APT29");
    expect(apt29).toBeDefined();
    if (!apt29) return;

    const campaigns = generateActorCampaigns(apt29);
    expect(campaigns.length).toBe(apt29.campaigns.length);
    expect(campaigns[0].active).toBe(true);
    expect(campaigns[0].timeRange).toContain("Ongoing");
  });

  it("generates passive DNS records with A, MX, NS, and TXT", () => {
    const records = generatePassiveDnsRecords("defense-update.org");
    expect(records.length).toBe(4);
    const types = records.map((r) => r.recordType);
    expect(types).toContain("A");
    expect(types).toContain("MX");
    expect(types).toContain("NS");
    expect(types).toContain("TXT");
  });

  it("generates WHOIS registration details with privacy flag and nameservers", () => {
    const whois = generateWhoisData("avsvmcloud.com");
    expect(whois.domain).toBe("avsvmcloud.com");
    expect(whois.privacyProtected).toBe(true);
    expect(whois.nameservers.length).toBeGreaterThan(0);
    expect(whois.domainAgeDays).toBeGreaterThan(100);
  });

  it("generates SSL certificate telemetry with JA3/JA4 fingerprints", () => {
    const cert = generateSslCertData("teardrop-stage.net");
    expect(cert.subjectCn).toBe("teardrop-stage.net");
    expect(cert.ja3Hash).toBeDefined();
    expect(cert.ja4Fingerprint).toBeDefined();
    expect(cert.sanList.length).toBeGreaterThan(1);
  });

  it("builds valid STIX 2.1 intelligence bundle with observables and techniques", () => {
    const apt28 = getThreatActorByTitleOrAlias("APT28");
    expect(apt28).toBeDefined();
    if (!apt28) return;

    const bundle = buildStix21Bundle(apt28);
    expect(bundle.type).toBe("bundle");
    expect(bundle.spec_version).toBe("2.1");
    expect(bundle.objects.length).toBeGreaterThan(5);

    const types = bundle.objects.map((o) => o.type);
    expect(types).toContain("threat-actor");
    expect(types).toContain("indicator");
    expect(types).toContain("relationship");
    expect(types).toContain("attack-pattern");

    const actorObj = bundle.objects.find((o) => o.type === "threat-actor");
    expect(actorObj.name).toBe("APT28");

    const indicatorObjs = bundle.objects.filter((o) => o.type === "indicator");
    expect(indicatorObjs.length).toBe(apt28.observables.length);
  });
});
