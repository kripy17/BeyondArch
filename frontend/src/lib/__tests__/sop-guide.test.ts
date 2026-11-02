import { describe, it, expect } from "vitest";
import {
  SOP_RUNBOOKS,
  calculateSopCatalogMetrics,
  instantiateCaseFromSop,
  exportSopRunbookMarkdown,
  type SopRunbook,
} from "../sop-guide";

describe("sop-guide library", () => {
  it("should contain at least 12 production-grade SOP runbooks", () => {
    expect(SOP_RUNBOOKS.length).toBeGreaterThanOrEqual(12);
  });

  it("every runbook should have valid NIST phases, MITRE techniques, and guardrails", () => {
    for (const r of SOP_RUNBOOKS) {
      expect(r.id).toBeTruthy();
      expect(r.title).toBeTruthy();
      expect(r.severity).toMatch(/^P[1-3]$/);
      expect(r.steps.length).toBeGreaterThanOrEqual(5);
      expect(r.attack.length).toBeGreaterThan(0);
      expect(r.alwaysRules.length).toBeGreaterThan(0);
      expect(r.neverRules.length).toBeGreaterThan(0);

      // Verify each step has valid phase and criticality
      for (const step of r.steps) {
        expect(step.id).toBeTruthy();
        expect(["preparation", "detection", "containment", "eradication", "recovery", "post_incident"]).toContain(step.phase);
        expect(["mandatory", "recommended", "optional"]).toContain(step.criticality);
        expect(step.text.length).toBeGreaterThan(5);
      }
    }
  });

  it("calculates accurate catalog metrics", () => {
    const metrics = calculateSopCatalogMetrics(SOP_RUNBOOKS);
    expect(metrics.totalRunbooks).toBe(SOP_RUNBOOKS.length);
    expect(metrics.p1Count).toBeGreaterThan(0);
    expect(metrics.p2Count).toBeGreaterThan(0);
    expect(metrics.avgMtrMinutes).toBeGreaterThan(0);
    expect(metrics.uniqueMitreTechniques).toBeGreaterThan(10);
    expect(metrics.totalSteps).toBeGreaterThan(50);
  });

  it("instantiates an authentic incident case from a SOP runbook", () => {
    const runbook = SOP_RUNBOOKS.find((r) => r.id === "ransomware-outbreak")!;
    const newCase = instantiateCaseFromSop(runbook);

    expect(newCase.id).toMatch(/^case-/);
    expect(newCase.title).toContain("Ransomware");
    expect(newCase.state).toBe("active");
    expect(newCase.tags).toContain("sop:ransomware-outbreak");
    expect(newCase.tags).toContain("severity:p1");
    expect(newCase.tags).toContain("nist-sp-800-61");
    expect(newCase.entries.length).toBeGreaterThanOrEqual(3);

    // Initial decision entry contains SOP initiation info
    const decisionEntry = newCase.entries.find((e) => e.kind === "decision");
    expect(decisionEntry).toBeDefined();
    expect(decisionEntry?.body).toContain("[INITIATED FROM SOP]");

    // Check action entries contain checklists
    const actionEntries = newCase.entries.filter((e) => e.kind === "action");
    expect(actionEntries.length).toBeGreaterThan(0);
  });

  it("exports formatted NIST SP 800-61 Markdown checklist", () => {
    const runbook = SOP_RUNBOOKS[0];
    const doneStepIds = new Set<string>([runbook.steps[0].id, runbook.steps[1].id]);

    const md = exportSopRunbookMarkdown(runbook, doneStepIds);
    expect(md).toContain(`# SOC Incident Response SOP: ${runbook.title}`);
    expect(md).toContain("NIST SP 800-61r2 Execution Progress");
    expect(md).toContain("Operational Guardrails");
    expect(md).toContain("Incident Response Checklist");
    expect(md).toContain("[x]");
    expect(md).toContain("[ ]");
  });
});
