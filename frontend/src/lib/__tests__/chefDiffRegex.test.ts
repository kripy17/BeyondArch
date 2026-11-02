import { describe, it, expect } from "vitest";
import { calculateEntropy } from "../chef/entropy";
import { detectMagicBytes } from "../chef/magic-bytes";
import { xorBruteForce } from "../chef/xor-bruteforce";
import { computeIocDelta } from "../diff/ioc-delta";
import { OP_BY_ID } from "../chef-ops";

describe("Shannon Entropy Engine (calculateEntropy)", () => {
  it("computes 0 entropy for empty input", () => {
    const res = calculateEntropy("");
    expect(res.entropy).toBe(0);
    expect(res.classification).toBe("empty");
    expect(res.isSuspicious).toBe(false);
  });

  it("classifies repetitive text as low entropy", () => {
    const res = calculateEntropy("AAAAAAAAAAAAAAAAAAAAAAAA");
    expect(res.entropy).toBe(0);
    expect(res.classification).toBe("low");
  });

  it("classifies natural English text as normal entropy", () => {
    const res = calculateEntropy("The quick brown fox jumps over the lazy dog in the SOC workstation.");
    expect(res.entropy).toBeGreaterThan(3.5);
    expect(res.entropy).toBeLessThan(5.2);
    expect(res.classification).toBe("normal");
  });

  it("classifies high-entropy encrypted/packed bytes as very_high", () => {
    // Generate pseudorandom byte spread
    let str = "";
    for (let i = 0; i < 256; i++) str += String.fromCharCode(i);
    const res = calculateEntropy(str);
    expect(res.entropy).toBeGreaterThanOrEqual(7.0);
    expect(res.classification).toBe("very_high");
    expect(res.isSuspicious).toBe(true);
  });

  it("extracts top byte frequencies", () => {
    const res = calculateEntropy("AAAABBBCC");
    expect(res.topBytes.length).toBeGreaterThanOrEqual(3);
    expect(res.topBytes[0].char).toBe("A");
    expect(res.topBytes[0].count).toBe(4);
  });
});

describe("Magic Bytes & File Signature Detection (detectMagicBytes)", () => {
  it("detects Windows PE binary from hex prefix", () => {
    const res = detectMagicBytes("4d5a900003000000");
    expect(res.detected).toBe(true);
    expect(res.category).toBe("executable");
    expect(res.signature).toContain("PE");
  });

  it("detects GZIP compressed stream from hex prefix", () => {
    const res = detectMagicBytes("1f8b080000000000");
    expect(res.detected).toBe(true);
    expect(res.category).toBe("archive");
    expect(res.recommendedRecipe.opIds).toContain("gunzip");
  });

  it("detects Base64-encoded GZIP stream", () => {
    const res = detectMagicBytes("H4sIC9vY8VwCA3Rlc3QudHh0APNLzE1VSEvMzAUAU9+MggcAAAA=");
    expect(res.detected).toBe(true);
    expect(res.category).toBe("archive");
  });

  it("detects JSON Web Token (JWT)", () => {
    const res = detectMagicBytes("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNrvP5rQj1wGvR6QqVvX5J7kLxQm4vN3bG8FhYI");
    expect(res.detected).toBe(true);
    expect(res.category).toBe("token");
    expect(res.recommendedRecipe.opIds).toContain("jwt-dissect");
  });

  it("detects PowerShell UTF-16LE Base64 (-EncodedCommand)", () => {
    // "cwBhAG0AcABsAGUA" is "sample" in UTF-16LE Base64
    const res = detectMagicBytes("cwBhAG0AcABsAGUA");
    expect(res.detected).toBe(true);
    expect(res.category).toBe("encoded");
    expect(res.recommendedRecipe.opIds).toContain("powershell-decode-utf16");
  });
});

describe("XOR Brute Force Engine (xorBruteForce)", () => {
  it("recovers plaintext and ranks candidate key using needle matching", () => {
    const plaintext = "powershell.exe -NoProfile -ExecutionPolicy Bypass";
    const key = 0x42;
    // XOR with 0x42
    let hex = "";
    for (let i = 0; i < plaintext.length; i++) {
      const b = plaintext.charCodeAt(i) ^ key;
      hex += b.toString(16).padStart(2, "0");
    }

    const results = xorBruteForce(hex, 5, "powershell");
    expect(results.length).toBeGreaterThan(0);
    const top = results[0];
    expect(top.key).toBe(key);
    expect(top.hasNeedle).toBe(true);
    expect(top.preview).toContain("powershell.exe");
  });
});

describe("IOC Delta Extraction (computeIocDelta)", () => {
  it("isolates net-new IOCs between baseline and incident texts", () => {
    const baseline = `Baseline firewall rules:
Allowed web server: 10.0.0.1
Management domain: corp.internal
Clean file: d41d8cd98f00b204e9800998ecf8427e`;

    const incident = `Compromised firewall rules:
Allowed web server: 10.0.0.1
Management domain: corp.internal
Inbound C2 connection from 185.220.101.5 on port 443
Attacker payload URL: http://evil-threat.org/stage2.exe
Ransomware hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Exploited vulnerability: CVE-2024-3400`;

    const delta = computeIocDelta(baseline, incident);
    expect(delta.totalAdded).toBeGreaterThanOrEqual(4);
    expect(delta.hasThreats).toBe(true);

    const addedValues = delta.added.map((i) => i.value);
    expect(addedValues).toContain("185.220.101.5");
    expect(addedValues).toContain("CVE-2024-3400");
    expect(addedValues).toContain("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // Unchanged IP 10.0.0.1 should be in unchanged list, not added
    expect(delta.unchanged.map((i) => i.value)).toContain("10.0.0.1");
    expect(addedValues).not.toContain("10.0.0.1");
  });
});

describe("CyberChef Extended Operations (OP_BY_ID)", () => {
  it("encodes and decodes PowerShell UTF-16LE Base64 round-trip", async () => {
    const script = "Write-Output 'SOC Workstation Ready'";
    const encodeOp = OP_BY_ID["powershell-encode-utf16"];
    const decodeOp = OP_BY_ID["powershell-decode-utf16"];
    expect(encodeOp).toBeDefined();
    expect(decodeOp).toBeDefined();

    const encoded = await encodeOp.run(script);
    expect(encoded).not.toContain("Write-Output");

    const decoded = await decodeOp.run(encoded);
    expect(decoded).toBe(script);
  });

  it("generates canonical hex dump and parses it back", async () => {
    const text = "Hello CyberChef!";
    const hexdumpOp = OP_BY_ID["hexdump"];
    const fromHexdumpOp = OP_BY_ID["from-hexdump"];

    const dump = await hexdumpOp.run(text);
    expect(dump).toContain("00000000");
    expect(dump).toContain("|Hello CyberChef!|");

    const restored = await fromHexdumpOp.run(dump);
    expect(restored).toBe(text);
  });

  it("rotates and decodes ROT47", async () => {
    const text = "Incident-Response-2026";
    const rot47Op = OP_BY_ID["rot47"];
    const encrypted = await rot47Op.run(text);
    expect(encrypted).not.toBe(text);

    const decrypted = await rot47Op.run(encrypted);
    expect(decrypted).toBe(text);
  });

  it("dissects JWT header and claims", async () => {
    const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTg5MzQ1NjAwMH0.testSig";
    const jwtOp = OP_BY_ID["jwt-dissect"];
    const output = await jwtOp.run(token);
    expect(output).toContain("HEADER");
    expect(output).toContain("HS256");
    expect(output).toContain("CLAIMS SUMMARY");
    expect(output).toContain("Subject (sub):   admin");
  });
});
