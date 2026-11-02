import { describe, expect, it } from "vitest";
import { analyzePcapBackend, analyzePcapText } from "@/lib/pcapArtifact";
import { SAMPLE_OUTPUTS, type PcapBackendResult } from "@/data/pcap";

const TCPDUMP = SAMPLE_OUTPUTS["tcpdump sample"] ?? "";
const TSHARK = SAMPLE_OUTPUTS["tshark HTTP sample"] ?? "";

function sampleBackend(overrides: Partial<PcapBackendResult> = {}): PcapBackendResult {
  return {
    status: "ok",
    filename: "capture.pcap",
    sha256: "ab" + "1".repeat(62),
    summary: { packets: 100, unique_ips: 4, dns_queries: 2, http_requests: 1, tls_sni: 1, findings: 4 },
    top_ips: [{ ip: "192.168.1.10", packets: 40 }, { ip: "185.220.101.44", packets: 30 }],
    dns_queries: ["evil-payload.ru"],
    http_requests: [{ src: "192.168.1.10", dst: "203.0.113.9", method: "GET", path: "/a", host: "legit.example.com" }],
    tls_server_names: ["evil-payload.ru"],
    beaconing_candidates: [{ src: "192.168.1.10", dst: "185.220.101.44", packets: 12 }],
    findings: [
      { severity: "critical", title: "Beaconing C2 detected", detail: "Repeating short-interval connections to a known C2 endpoint.", recommendation: "Block the C2 endpoint." },
      { severity: "high", title: "Connection to suspicious host in 185.220.101.44", detail: "Unusual connection pattern detected.", recommendation: "Review connection and block if confirmed malicious." },
      { severity: "medium", title: "Suspicious DNS query", detail: "DNS query to suspicious destination.", recommendation: "Sinkhole the queried domain." },
      { severity: "low", title: "Unusual TLS SNI", detail: "TLS Client Hello used an unexpected server name.", recommendation: "Verify the SNI against baseline." },
    ],
    iocs: { ips: ["185.220.101.44"], domains: ["evil-payload.ru"], urls: [] },
    limitations: [],
    ...overrides,
  };
}

describe("analyzePcapText — tcpdump sample", () => {
  const r = analyzePcapText(TCPDUMP);

  it("summarizes as suspicious with legacy score cadence", () => {
    expect(r.summary.verdict).toBe("suspicious");
    expect(r.summary.score).toBe(60);
  });

  it("emits one finding per parsed suspicious indicator", () => {
    expect(r.findings.filter((f) => f.severity === "high").length).toBe(5);
    expect(r.displayFindings.length).toBe(5);
    expect(r.displayFindings[0].severity).toBe("high");
    expect(r.displayFindings[0].technique).toBe("T1105");
  });

  it("keeps capture-level page fields", () => {
    expect(r.inputMode).toBe("text");
    expect(r.totalPackets).toBe(14);
    expect(r.uniqueIPs).toBeGreaterThan(0);
    expect(r.artifact.title).toBe("Pasted output");
    expect(r.textAnalysis).toBeDefined();
  });

  it("extracts IP IOCs with verdict-derived severity", () => {
    expect(r.iocs.some((i) => i.type === "ipv4" && i.value === "185.220.101.44")).toBe(true);
    expect(r.iocs.every((i) => i.severity === "medium")).toBe(true);
  });

  it("produces MITRE mapping from engine findings", () => {
    const ids = r.mitre.map((m) => m.technique);
    expect(ids.length).toBeGreaterThan(0);
    expect(ids).toContain("T1105");
    expect(r.mitre[0].evidenceRefs.length).toBeGreaterThan(0);
  });

  it("fills the engine sections", () => {
    expect(Array.isArray(r.recommendations)).toBe(true);
    expect(r.quality.coverage.score).toBeGreaterThan(0);
    expect(Array.isArray(r.observations)).toBe(true);
    expect(r.observations.length).toBeGreaterThan(0);
    expect(r.relationships).toBeDefined();
  });

  it("is fully deterministic", () => {
    const a = analyzePcapText(TCPDUMP);
    const b = analyzePcapText(TCPDUMP);
    expect(a.findings.map((f) => f.id)).toEqual(b.findings.map((f) => f.id));
    expect(a.observations.map((o) => o.id)).toEqual(b.observations.map((o) => o.id));
    expect(a.id).toBe(b.id);
    const t = analyzePcapText(TSHARK);
    expect(t.id).not.toBe(a.id);
  });

  it("returns a blank clean result for empty input", () => {
    const blank = analyzePcapText("   \n");
    expect(blank.summary.verdict).toBe("clean");
    expect(blank.findings.length).toBe(0);
    expect(blank.iocs.length).toBe(0);
    expect(blank.displayFindings.length).toBe(0);
    expect(blank.mitre[0].technique).toBe("T1071");
    expect(blank.artifact.title).toBe("Pasted output");
  });
});

describe("analyzePcapText — clean input falls back to low informational finding", () => {
  const clean = `12:00:00.000001 IP 192.168.1.10.443 > 8.8.8.8.53: Flags [P.]
12:00:00.000002 IP 8.8.8.8.53 > 192.168.1.10.443: Flags [P.]`;
  const r = analyzePcapText(clean);

  it("scores clean with a single low finding", () => {
    expect(r.summary.verdict).toBe("clean");
    expect(r.summary.score).toBe(0);
    expect(r.findings.length).toBe(1);
    expect(r.findings[0].severity).toBe("low");
    expect(r.findings[0].title).toBe("No suspicious indicators detected");
    expect(r.displayFindings[0].action).toBe("Monitor for any unusual outbound connections.");
  });
});

describe("analyzePcapText — tshark sample", () => {
  const r = analyzePcapText(TSHARK);

  it("detects encrypted suspicious indicators", () => {
    expect(r.summary.verdict).toBe("suspicious");
    expect(r.summary.score).toBe(36);
    expect(r.displayFindings.every((f) => f.technique === "T1573.001")).toBe(true);
    expect(r.displayFindings[0].title).toContain("185.220.101.44");
  });

  it("keeps verdict-derived IOC severity", () => {
    expect(r.iocs.every((i) => i.severity === "medium")).toBe(true);
  });
});

describe("analyzePcapBackend", () => {
  const r = analyzePcapBackend(sampleBackend());

  it("preserves the legacy verdict/score cadence", () => {
    expect(r.summary.verdict).toBe("malicious");
    expect(r.summary.score).toBe(42);
  });

  it("keeps backend display 1:1 with actions and techniques", () => {
    expect(r.displayFindings.length).toBe(4);
    expect(r.displayFindings[0].title).toBe("Beaconing C2 detected");
    expect(r.displayFindings[0].action).toBe("Block the C2 endpoint.");
    expect(r.displayFindings[0].technique).toBe("T1071.001");
    expect(r.displayFindings.find((f) => f.title === "Suspicious DNS query")?.technique).toBe("T1572");
    expect(r.displayFindings.find((f) => f.title === "Unusual TLS SNI")?.technique).toBe("T1573.001");
    expect(r.displayFindings[3].severity).toBe("low");
  });

  it("keeps page fields and IOCs", () => {
    expect(r.inputMode).toBe("file");
    expect(r.fileName).toBe("capture.pcap");
    expect(r.totalPackets).toBe(100);
    expect(r.uniqueIPs).toBe(4);
    expect(r.backendResult?.status).toBe("ok");
    expect(r.iocs.some((i) => i.type === "ipv4" && i.value === "185.220.101.44")).toBe(true);
    expect(r.iocs.some((i) => i.type === "domain" && i.value === "evil-payload.ru" && i.context === "DNS query")).toBe(true);
  });

  it("maps extracted payload hashes to typed hash IOCs", () => {
    const withHashes = analyzePcapBackend(sampleBackend({
      iocs: {
        ips: [],
        domains: [],
        urls: [],
        hashes: [
          "44d88612fea8a8f36de82e1278abb02f",
          "b" + "1".repeat(39),
          "c".repeat(64),
        ],
      },
    }));
    const byValue = new Map(withHashes.iocs.map((i) => [i.value, i]));
    expect(byValue.get("44d88612fea8a8f36de82e1278abb02f")?.type).toBe("md5");
    expect(byValue.get("b" + "1".repeat(39))?.type).toBe("sha1");
    expect(byValue.get("c".repeat(64))?.type).toBe("sha256");
    expect([...byValue.values()].every((i) => i.context === "PCAP payload")).toBe(true);
  });

  it("tolerates backend results without a hashes field", () => {
    const legacy = analyzePcapBackend(sampleBackend());
    expect(legacy.iocs.some((i) => i.type === "md5" || i.type === "sha256")).toBe(false);
  });
});

describe("correlation", () => {
  it("returns no matches with empty history", () => {
    const r = analyzePcapText(TCPDUMP, { history: {} });
    expect(r.correlation.length).toBe(0);
  });
});