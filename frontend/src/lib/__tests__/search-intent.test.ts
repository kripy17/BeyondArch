import { describe, expect, it } from "vitest";
import { applyIntent, detectIntent } from "@/lib/search-intent";
import type { SearchItemType } from "@/lib/search-index";

describe("detectIntent", () => {
  it("maps 'Show phishing investigations' to case scope with cleaned term", () => {
    const i = detectIntent("Show phishing investigations");
    expect(i.scope).toEqual(["case"]);
    expect(i.term).toBe("phishing");
    expect(i.note).toContain("cases only");
  });

  it("maps 'Cases involving APT29' to case scope with the group as term", () => {
    const i = detectIntent("Cases involving APT29");
    expect(i.scope).toEqual(["case"]);
    expect(i.term).toBe("APT29");
  });

  it("maps 'PowerShell detections' to detection scope", () => {
    const i = detectIntent("PowerShell detections");
    expect(i.scope).toEqual(["detection"]);
    expect(i.term).toBe("PowerShell");
  });

  it("maps 'Recent credential theft' to recency without scope", () => {
    const i = detectIntent("Recent credential theft");
    expect(i.recentDays).toBe(7);
    expect(i.scope).toBeNull();
    expect(i.term).toBe("credential theft");
  });

  it("maps 'recent iocs' to ioc scope and empty term", () => {
    const i = detectIntent("recent iocs");
    expect(i.scope).toEqual(["ioc"]);
    expect(i.term).toBe("");
  });

  it("passes plain queries through unscoped", () => {
    const i = detectIntent("APT29");
    expect(i.scope).toBeNull();
    expect(i.term).toBe("APT29");
  });
});

describe("applyIntent", () => {
  const items: { type: SearchItemType; metadata?: Record<string, string> }[] = [
    { type: "case", metadata: { age: "2" } },
    { type: "case", metadata: { age: "40" } },
    { type: "detection", metadata: {} },
  ];

  it("filters by scope and recency together", () => {
    const out = applyIntent(items, { scope: ["case"], term: "", recentDays: 7 });
    expect(out).toHaveLength(1);
    expect(out[0].metadata?.age).toBe("2");
  });

  it("keeps everything when intent is open", () => {
    const out = applyIntent(items, { scope: null, term: "x" });
    expect(out).toHaveLength(3);
  });

  it("drops items with no age when recency window is set", () => {
    const out = applyIntent(items, { scope: null, term: "", recentDays: 7 });
    expect(out).toHaveLength(1);
  });
});