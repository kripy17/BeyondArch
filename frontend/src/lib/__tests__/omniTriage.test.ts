import { describe, expect, it } from "vitest";
import {
  classifyOmniInput,
  calculateSubnet,
  parseTimestamp,
  generateShiftHandoffReport,
  isPrivateIPv4,
  tryDecodeBase64,
} from "@/lib/omni-triage";
import type { Case } from "@/data/case";

describe("classifyOmniInput", () => {
  it("classifies public and private IPv4 addresses", () => {
    const pub = classifyOmniInput("185.220.101.5");
    expect(pub.kind).toBe("ipv4");
    expect(pub.defanged).toBe("185[.]220[.]101[.]5");
    expect(pub.metadata?.Scope).toContain("Public");

    const priv = classifyOmniInput("192.168.1.100");
    expect(priv.kind).toBe("ipv4");
    expect(priv.metadata?.Scope).toContain("Private");
  });

  it("classifies file hashes (MD5, SHA-1, SHA-256)", () => {
    const md5 = classifyOmniInput("d41d8cd98f00b204e9800998ecf8427e");
    expect(md5.kind).toBe("hash-md5");

    const sha1 = classifyOmniInput("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect(sha1.kind).toBe("hash-sha1");

    const sha256 = classifyOmniInput("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(sha256.kind).toBe("hash-sha256");
  });

  it("classifies CVE IDs", () => {
    const cve = classifyOmniInput("cve-2024-21413");
    expect(cve.kind).toBe("cve");
    expect(cve.refanged).toBe("CVE-2024-21413");
    expect(cve.pivots.some((p) => p.to === "/intel")).toBe(true);
  });

  it("classifies URLs and defangs them", () => {
    const url = classifyOmniInput("https://evil-phish.com/login?token=abc");
    expect(url.kind).toBe("url");
    expect(url.defanged).toContain("[.]");
    expect(url.metadata?.Host).toBe("evil-phish.com");
  });

  it("classifies email addresses", () => {
    const email = classifyOmniInput("attacker@bad-domain.xyz");
    expect(email.kind).toBe("email");
    expect(email.metadata?.Domain).toBe("bad-domain.xyz");
  });

  it("classifies domains while filtering auth tokens", () => {
    const dom = classifyOmniInput("malware-c2.org");
    expect(dom.kind).toBe("domain");
    expect(dom.defanged).toBe("malware-c2[.]org");

    const authParam = classifyOmniInput("smtp.mailfrom");
    expect(authParam.kind).not.toBe("domain");
  });

  it("decodes base64 commands and previews content", () => {
    const b64 = "cG93ZXJzaGVsbCAtZXhlYyBieXBhc3MgLWMgIndnZXQgaHR0cDovL2V2aWwueHl6Ig==";
    const res = classifyOmniInput(b64);
    expect(res.kind).toBe("base64");
    expect(res.decodedPreview).toContain("powershell");
  });

  it("classifies JSON event logs", () => {
    const jsonStr = JSON.stringify({ src_ip: "10.0.0.1", event_id: 4688, user: "admin" });
    const res = classifyOmniInput(jsonStr);
    expect(res.kind).toBe("json-log");
    expect(res.metadata?.Keys).toContain("src_ip");
  });
});

describe("calculateSubnet", () => {
  it("computes /24 subnet boundaries", () => {
    const sub = calculateSubnet("192.168.1.50/24");
    expect(sub).not.toBeNull();
    expect(sub!.network).toBe("192.168.1.0");
    expect(sub!.broadcast).toBe("192.168.1.255");
    expect(sub!.firstUsable).toBe("192.168.1.1");
    expect(sub!.lastUsable).toBe("192.168.1.254");
    expect(sub!.usableHosts).toBe(254);
    expect(sub!.isPrivate).toBe(true);
  });

  it("computes public /16 subnet boundaries", () => {
    const sub = calculateSubnet("8.8.8.8/16");
    expect(sub).not.toBeNull();
    expect(sub!.network).toBe("8.8.0.0");
    expect(sub!.broadcast).toBe("8.8.255.255");
    expect(sub!.isPrivate).toBe(false);
  });

  it("rejects invalid inputs", () => {
    expect(calculateSubnet("invalid")).toBeNull();
    expect(calculateSubnet("10.0.0.1/35")).toBeNull();
  });
});

describe("parseTimestamp", () => {
  it("converts 10-digit epoch seconds", () => {
    const ts = parseTimestamp("1725470000");
    expect(ts).not.toBeNull();
    expect(ts!.unixSeconds).toBe(1725470000);
    expect(ts!.iso).toContain("2024-09-04");
  });

  it("converts 13-digit epoch milliseconds", () => {
    const ts = parseTimestamp("1725470000000");
    expect(ts).not.toBeNull();
    expect(ts!.unixSeconds).toBe(1725470000);
  });

  it("converts ISO strings", () => {
    const ts = parseTimestamp("2026-08-15T12:00:00Z");
    expect(ts).not.toBeNull();
    expect(ts!.utc).toContain("15 Aug 2026");
  });

  it("rejects invalid date strings", () => {
    expect(parseTimestamp("not-a-date")).toBeNull();
  });
});

describe("generateShiftHandoffReport", () => {
  it("generates markdown with operational metrics and case details", () => {
    const mockCases: Case[] = [
      {
        id: "case-01",
        title: "Executive Phishing Investigation",
        tags: ["phishing", "bec"],
        createdAt: "2026-09-04T10:00:00Z",
        state: "active",
        entries: [],
        findings: [
          {
            id: "f1",
            severity: "high",
            title: "Display-name spoofing detected",
            detail: "Spoofed CEO identity",
            source: "phishing",
          },
        ],
        iocs: [
          {
            id: "i1",
            value: "185.220.101.5",
            type: "ipv4",
            context: "sender IP",
            source: "phishing",
            severity: "high",
          },
        ],
      },
    ];

    const report = generateShiftHandoffReport(mockCases, 3, 12);
    expect(report).toContain("# SOC Shift Handoff Briefing");
    expect(report).toContain("Active Investigations:** 1");
    expect(report).toContain("case-01");
    expect(report).toContain("Executive Phishing Investigation");
    expect(report).toContain("185[.]220[.]101[.]5");
  });
});
