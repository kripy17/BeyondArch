import { describe, expect, it } from "vitest";
import { analyzeUrl, tlsValidity, measuredRedirectSignals } from "@/lib/urlArtifact";

const PUNY = "https://xn--80ak6aa92e.com";
const HTTP = "http://evil-host.ru";
const BANK = "https://bank.example.com/login?utm_source=x&id=abc123";
const IPHOST = "http://185.220.101.161/wp-content/payload.ps1";

describe("analyzeUrl — punycode sample", () => {
  const r = analyzeUrl({ raw: PUNY, committed: true })!;

  it("scores malicious with legacy cadence", () => {
    expect(r.summary.verdict).toBe("malicious");
    expect(r.summary.score).toBe(25);
  });

  it("keeps page-level display findings and techniques", () => {
    expect(r.displayFindings.length).toBe(1);
    expect(r.displayFindings[0].severity).toBe("destructive");
    expect(r.displayFindings[0].title).toBe("Punycode host (IDN homograph risk)");
    expect(r.findings[0].severity).toBe("critical");
    expect(r.findings[0].technique).toBe("T1566");
  });

  it("maps MITRE from engine findings", () => {
    expect(r.mitre).toContainEqual({ id: "T1566", name: "Phishing" });
  });

  it("emits only the detection fact (no self-references)", () => {
    expect(r.observations.length).toBe(1);
    expect(r.observations[0].kind).toBe("string");
    expect(r.observations[0].meta.attr).toBe("url-detection");
  });

  it("keeps URL/domain IOCs with verdict-derived severity", () => {
    expect(r.iocs.some((i) => i.type === "url" && i.value === "https://xn--80ak6aa92e.com/")).toBe(true);
    expect(r.iocs.some((i) => i.type === "domain" && i.value === "xn--80ak6aa92e.com")).toBe(true);
    expect(r.iocs.every((i) => i.severity === "high")).toBe(true);
  });

  it("fills the engine sections", () => {
    expect(Array.isArray(r.recommendations)).toBe(true);
    expect(Array.isArray(r.relationships)).toBe(true);
    expect(Array.isArray(r.opportunities)).toBe(true);
    expect(r.quality).toBeDefined();
    expect(r.generatedAt).toBeTruthy();
  });
});

describe("analyzeUrl — plain http host", () => {
  const r = analyzeUrl({ raw: HTTP, committed: true })!;

  it("verdicts suspicious with medium signals", () => {
    expect(r.summary.verdict).toBe("suspicious");
    expect(r.summary.score).toBe(10);
    expect(r.displayFindings.length).toBe(2);
    expect(r.displayFindings.map((f) => f.severity)).toEqual(["warning", "warning"]);
  });

  it("maps http + suspicious TLD techniques", () => {
    expect(r.findings.map((f) => f.technique)).toContain("T1573");
    expect(r.findings.map((f) => f.technique)).toContain("T1583.001");
    expect(r.mitre.map((m) => m.id)).toEqual(expect.arrayContaining(["T1573", "T1583.001"]));
  });
});

describe("analyzeUrl — sample bank page", () => {
  const r = analyzeUrl({ raw: BANK, committed: true })!;

  it("detects suspicious path + tracking info", () => {
    expect(r.summary.verdict).toBe("suspicious");
    expect(r.summary.score).toBe(5);
    expect(r.suspiciousPaths).toEqual(["login"]);
    expect(r.trackingParams).toEqual([["utm_source", "x"]]);
    expect(r.displayFindings.map((f) => [f.severity, f.title])).toEqual([
      ["warning", "Suspicious path segment"],
      ["info", "Tracking parameters present"],
    ]);
  });

  it("maps T1204 and keeps clean secrets list", () => {
    expect(r.mitre).toContainEqual({ id: "T1204", name: "User Execution" });
    expect(r.secrets.length).toBe(0);
  });

  it("keeps knowledge graph for the page", () => {
    expect(r.knowledge.canonicalUrl.value).toContain("bank.example.com");
    expect(r.knowledge.relatedDomains.length).toBeGreaterThan(0);
    expect(r.knowledge.passiveDns.configured).toBe(false);
  });
});

describe("analyzeUrl — direct IP host", () => {
  const r = analyzeUrl({ raw: IPHOST, committed: true })!;

  it("flags IP host, http, file download", () => {
    expect(r.summary.verdict).toBe("suspicious");
    expect(r.isNumericDomain).toBe(true);
    expect(r.fileExt).toBe("ps1");
    expect(r.displayFindings.map((f) => f.title)).toEqual(
      expect.arrayContaining(["Direct IP address as hostname", "Direct file download (.ps1)"]),
    );
  });

  it("keeps ipv4 IOC and T1071 mapping", () => {
    expect(r.iocs.some((i) => i.type === "ipv4" && i.value === "185.220.101.161")).toBe(true);
    expect(r.mitre.map((m) => m.id)).toContain("T1071");
  });
});

describe("analyzeUrl — clean control", () => {
  const r = analyzeUrl({ raw: "https://example.com", committed: true })!;

  it("verdicts clean with no findings", () => {
    expect(r.summary.verdict).toBe("clean");
    expect(r.summary.score).toBe(0);
    expect(r.displayFindings.length).toBe(0);
    expect(r.findings.length).toBe(0);
    expect(r.iocs.every((i) => i.severity === "info")).toBe(true);
  });

  it("returns null for blank, whitespace, and unparseable input", () => {
    expect(analyzeUrl({ raw: "", committed: true })).toBeNull();
    expect(analyzeUrl({ raw: "   \n", committed: true })).toBeNull();
    expect(analyzeUrl({ raw: "not a url", committed: true })).toBeNull();
    expect(analyzeUrl({ raw: "https://example.com", committed: false })).toBeNull();
  });
});

describe("analyzeUrl — determinism", () => {
  it("maps identical input to identical ids", () => {
    const a = analyzeUrl({ raw: PUNY, committed: true })!;
    const b = analyzeUrl({ raw: PUNY, committed: true })!;
    expect(a.id).toBe(b.id);
    expect(a.artifact.id).toBe(b.artifact.id);
    expect(a.findings.map((f) => f.id)).toEqual(b.findings.map((f) => f.id));
    expect(a.observations.map((o) => o.id)).toEqual(b.observations.map((o) => o.id));
    const other = analyzeUrl({ raw: HTTP, committed: true })!;
    expect(other.id).not.toBe(a.id);
  });

  it("returns no correlation matches with empty history", () => {
    const r = analyzeUrl({ raw: PUNY, committed: true }, { history: {} })!;
    expect(r.correlation.length).toBe(0);
    expect(r.correlationRelationships.length).toBe(0);
  });
});

describe("analyzeUrl — defanged intake", () => {
  const r = analyzeUrl({ raw: "hxxps[:]//login.example-bank[.]com.evil-host[.]ru/reset?session=abc123", committed: true })!;

  it("refangs and flags defanged origin", () => {
    expect(r.parsed.hostname).toBe("login.example-bank.com.evil-host.ru");
    expect(r.defangedOriginal).toBe(true);
    expect(r.displayFindings.map((f) => f.title)).toEqual(
      expect.arrayContaining(["Originally defanged", "Excessive subdomain depth", "Suspicious TLD (.ru)"]),
    );
  });
});
describe("analyzeUrl — payload depth signals (§4a)", () => {
  it("names a direct executable download", () => {
    const r = analyzeUrl({ raw: "https://evil.example/files/Setup%20Payload.exe", committed: true })!;
    expect(r.downloadName).toBe("Setup Payload.exe");
    expect(r.displayFindings.map((f) => f.title)).toEqual(expect.arrayContaining(["Named download: Setup Payload.exe"]));
    expect(r.pathSignals).toContain("Named download: Setup Payload.exe");
    expect(r.mitre.map((m) => m.id)).toContain("T1105");
    expect(r.mitre.find((m) => m.id === "T1105")?.name).toBe("Ingress Tool Transfer");
  });

  it("flags a script download cradle as critical", () => {
    const r = analyzeUrl({ raw: "https://evil.example/drop?cmd=bitsadmin%2Ftransfer%20payload", committed: true })!;
    expect(r.displayFindings.map((f) => f.title)).toContain("Script download cradle");
    const cradle = r.displayFindings.find((f) => f.title === "Script download cradle")!;
    expect(cradle.severity).toBe("destructive");
    expect(r.pathSignals.some((s) => s.startsWith("Script download cradle markers"))).toBe(true);
    expect(r.mitre.map((m) => m.id)).toContain("T1059.001");
  });

  it("flags obfuscated client-side script markers", () => {
    const r = analyzeUrl({ raw: "https://evil.example/payload.js?c=eval(atob('ZQ=='))", committed: true })!;
    expect(r.displayFindings.map((f) => f.title)).toContain("Obfuscated script markers in URL");
    expect(r.pathSignals.some((s) => s.startsWith("Obfuscated script markers"))).toBe(true);
    expect(r.mitre.map((m) => m.id)).toContain("T1059.007");
  });

  it("derives a named download from a query argument", () => {
    const r = analyzeUrl({ raw: "https://evil.example/get?filename=invoice.docm", committed: true })!;
    expect(r.downloadName).toBe("invoice.docm");
    expect(r.displayFindings.map((f) => f.title)).toEqual(expect.arrayContaining(["Named download: invoice.docm"]));
  });

  it("stays silent on benign URLs", () => {
    const r = analyzeUrl({ raw: "https://docs.example.com/guide.pdf", committed: true })!;
    expect(r.displayFindings.map((f) => f.title)).not.toEqual(expect.arrayContaining(["Script download cradle", "Obfuscated script markers in URL"]));
  });
});

describe("tlsValidity", () => {
  const now = new Date("2026-08-23T12:00:00Z");

  it("returns null for blank or unparseable dates", () => {
    expect(tlsValidity("", now)).toBeNull();
    expect(tlsValidity("not a date", now)).toBeNull();
  });

  it("labels past dates expired with negative day count", () => {
    expect(tlsValidity("May 24 12:00:00 2026 GMT", now)).toEqual({ label: "expired", days: -91 });
  });

  it("labels dates within 30 days expiring soon", () => {
    expect(tlsValidity("Sep 15 00:00:00 2026 GMT", now)!.label).toBe("expiring soon");
  });

  it("labels distant future dates valid", () => {
    expect(tlsValidity("May 24 12:00:00 2027 GMT", now)).toMatchObject({ label: "valid" });
    expect(tlsValidity("May 24 12:00:00 2027 GMT", now)!.days).toBeGreaterThan(30);
  });
});

describe("measuredRedirectSignals", () => {
  it("returns empty for empty chain", () => {
    expect(measuredRedirectSignals([])).toEqual([]);
  });

  it("flags domain hand-off as destructive with hop count", () => {
    const out = measuredRedirectSignals([
      { hop: 1, host: "bit.ly", status_code: 301 },
      { hop: 2, host: "phish.example.ru", status_code: 200 },
    ]);
    expect(out.length).toBe(1);
    expect(out[0].severity).toBe("destructive");
    expect(out[0].title).toContain("2 hops, measured");
    expect(out[0].reason).toContain("phish.example.ru");
  });

  it("reports same-domain multi-hop as info", () => {
    const out = measuredRedirectSignals([
      { hop: 1, host: "www.example.com" },
      { hop: 2, host: "example.com" },
    ]);
    expect(out.length).toBe(1);
    expect(out[0].severity).toBe("info");
    expect(out[0].title).toContain("same domain");
  });

  it("flags Set-Cookie on any measured hop", () => {
    const out = measuredRedirectSignals([{ hop: 1, host: "example.com", set_cookie_present: true }]);
    expect(out.length).toBe(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].title).toContain("Set-Cookie");
  });

  it("ignores non-object entries and missing hosts safely", () => {
    expect(measuredRedirectSignals([null, "x", { hop: 1 }])).toEqual([]);
  });
});
