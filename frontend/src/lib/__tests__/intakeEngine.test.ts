import { describe, it, expect } from "vitest";
import {
  computeMd5Hex,
  computeSha256Hex,
  computeShannonEntropy,
  classifyEntropy,
  detectArtifactKind,
  extractArtifactObservables,
  digestArtifact,
  INTAKE_PRESETS,
} from "../intake-engine";

describe("Intake Engine", () => {
  it("computes MD5 and SHA-256 hashes accurately", async () => {
    const data = "BeyondLabs SOC Analyst Platform";
    const md5 = computeMd5Hex(data);
    expect(md5).toMatch(/^[a-f0-9]{32}$/);

    const sha256 = await computeSha256Hex(data);
    expect(sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it("calculates Shannon entropy and classifies risk", () => {
    // Low entropy: repeated characters
    const low = computeShannonEntropy("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    expect(low).toBeLessThan(1.0);
    expect(classifyEntropy(low).risk).toBe("low");

    // High entropy: random byte stream
    const randomBytes = new Uint8Array(256);
    for (let i = 0; i < 256; i++) randomBytes[i] = i;
    const high = computeShannonEntropy(randomBytes);
    expect(high).toBeGreaterThan(7.5);
    expect(classifyEntropy(high).risk).toBe("high");
  });

  it("detects artifact kinds from filenames and content", () => {
    expect(detectArtifactKind("alert.eml", "message/rfc822", "")).toBe("email");
    expect(detectArtifactKind("capture.pcap", "application/vnd.tcpdump.pcap", "")).toBe("pcap");
    expect(detectArtifactKind("syslog.json", "application/json", "{}")).toBe("log");
    expect(detectArtifactKind("malware.exe", "application/octet-stream", "")).toBe("binary");
    expect(detectArtifactKind("payload.ps1", "text/plain", "")).toBe("script");
  });

  it("extracts and defangs observables from artifact content", () => {
    const sample = `
      Malicious IP: 185.220.101.5
      Staging URL: https://evil.example.com/drop
      Phishing sender: attacker@malicious-domain.xyz
      Hash: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
      Command: powershell.exe -enc SQBFAFgA
    `;
    const obs = extractArtifactObservables(sample);
    expect(obs.some((o) => o.kind === "ip" && o.defanged === "185[.]220[.]101[.]5")).toBe(true);
    expect(obs.some((o) => o.kind === "url" && o.defanged.startsWith("hxxps://"))).toBe(true);
    expect(obs.some((o) => o.kind === "email" && o.defanged === "attacker[at]malicious-domain.xyz")).toBe(true);
    expect(obs.some((o) => o.kind === "hash" && o.meta === "SHA-256")).toBe(true);
    expect(obs.some((o) => o.kind === "command")).toBe(true);
  });

  it("digests presets correctly", async () => {
    const preset = INTAKE_PRESETS[0];
    const digest = await digestArtifact(preset.fileName, preset.content);
    expect(digest.kind).toBe("email");
    expect(digest.recommendedRoute.path).toBe("/phishing");
    expect(digest.observables.length).toBeGreaterThan(0);
    expect(digest.sha256).toMatch(/^[a-f0-9]{64}$/);
  });
});
