import { describe, expect, it } from "vitest";
import { analyzeUrls, detectDisplaySpoof } from "@/data/phishing";
import { analyzePhishing } from "@/lib/emailArtifact";

describe("detectDisplaySpoof", () => {
  it("flags display-name brand spoof on unrelated domain", () => {
    const out = detectDisplaySpoof("Microsoft Support <helpdesk@it-support.xyz>", "it-support.xyz");
    expect(out.some((d) => d.kind === "brand" && d.brand === "microsoft")).toBe(true);
  });

  it("flags BEC tell: personal name from free webmail", () => {
    const out = detectDisplaySpoof("Jane Doe <jane.doe.cfo@gmail.com>", "gmail.com");
    expect(out.some((d) => d.kind === "bec")).toBe(true);
  });

  it("stays quiet on legit senders", () => {
    expect(detectDisplaySpoof("Newsletter <newsletter@sendgrid.net>", "sendgrid.net")).toEqual([]);
    expect(detectDisplaySpoof("SOC Alert <soc@siem.corp.internal>", "siem.corp.internal")).toEqual([]);
  });
});

describe("analyzeUrls trust badges", () => {
  it("flags open-redirect parameters", () => {
    const [r] = analyzeUrls(["https://legit.example.com/out?url=https://evil.tk/login"]);
    expect(r.badges.some((b) => b.label === "open redirect")).toBe(true);
    expect(r.suspicious).toBe(true);
  });

  it("flags abused-host delivery infrastructure", () => {
    const [r] = analyzeUrls(["https://docs.google.com/forms/d/e/abc123/viewform"]);
    expect(r.badges.some((b) => b.label === "abused host")).toBe(true);
  });
});

describe("analyzePhishing identity + trust wiring", () => {
  const BEC = `From: Jane Doe <jane.doe.cfo@gmail.com>
To: finance@acme-corp.com
Subject: Re: Wire transfer for vendor onboarding
Reply-To: jane.doe.cfo@gmail.com
Authentication-Results: spf=pass; dkim=pass; dmarc=pass

Quick request — please process the wire for our new vendor today.`;

  it("surfaces BEC signal and breakdown row on auth-passing mail", () => {
    const res = analyzePhishing(BEC);
    expect(res).not.toBeNull();
    expect(res!.displayFindings.some((f) => f.title === "Possible BEC impersonation")).toBe(true);
    const row = res!.breakdown.find((b) => b.signal === "Display-name spoof");
    expect(row).toBeDefined();
    expect(row!.weight).toBe(15);
  });

  it("surfaces redirect signal and breakdown row", () => {
    const res = analyzePhishing(`From: Alerts <alerts@example.org>
Subject: shared a document with you

Open https://legit.example.com/out?next=https://evil.tk/docs now.`);
    expect(res).not.toBeNull();
    expect(res!.displayFindings.some((f) => f.title === "Redirect / abused-host URLs")).toBe(true);
    const row = res!.breakdown.find((b) => b.signal === "URL redirect / abused host");
    expect(row).toBeDefined();
    expect(row!.weight).toBe(10);
  });
});
