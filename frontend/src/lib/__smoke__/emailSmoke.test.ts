import { describe, it, expect } from "vitest";
import { analyzePhishing } from "@/lib/emailArtifact";
import { SAMPLES } from "@/data/phishing";

describe("emailArtifact parity smoke", () => {
  it("handles all built-in samples and produces deterministic ids", () => {
    for (const s of Object.values(SAMPLES)) {
      const r = analyzePhishing(s);
      expect(r).not.toBeNull();
      if (r) {
        expect(r.findings.length).toBeGreaterThanOrEqual(1);
        expect(r.observations.length).toBeGreaterThan(0);
        expect(r.relationships.length).toBeGreaterThan(0);
        expect(r.summary).toBeDefined();
        expect(r.verdict.tone).toBeTruthy();
        const r2 = analyzePhishing(s);
        expect(r.id).toBe(r2!.id);
      }
    }
  });

  it("returns null on empty input", () => {
    expect(analyzePhishing("")).toBeNull();
    expect(analyzePhishing("   ")).toBeNull();
  });
});
