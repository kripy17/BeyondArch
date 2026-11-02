import { describe, it, expect, beforeEach } from "vitest";
import {
  SOAR_PLAYBOOKS,
  calculatePlaybookTelemetry,
  generatePlaybookRunMarkdown,
  loadPlaybookRuns,
  savePlaybookRuns,
  recordPlaybookRun,
  LS_PLAYBOOK_RUNS,
  type PlaybookRunRecord,
} from "../playbooks";

const store = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => { store.set(k, v); },
  removeItem: (k: string) => { store.delete(k); },
  clear: () => { store.clear(); },
  key: (i: number) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
};

describe("SOAR Playbooks", () => {
  beforeEach(() => {
    store.clear();
  });

  describe("Playbook Catalog", () => {
    it("defines 5 core enterprise SOAR playbooks", () => {
      expect(SOAR_PLAYBOOKS.length).toBe(5);
    });

    it("ensures each playbook has non-empty steps, valid runtime, and MITRE tactics", () => {
      for (const pb of SOAR_PLAYBOOKS) {
        expect(pb.id).toBeTruthy();
        expect(pb.title).toBeTruthy();
        expect(pb.steps.length).toBeGreaterThan(0);
        expect(pb.mitreTactics.length).toBeGreaterThan(0);
        expect(pb.requiredInputs.length).toBeGreaterThan(0);

        for (const step of pb.steps) {
          expect(step.id).toBeTruthy();
          expect(step.title).toBeTruthy();
          expect(step.description).toBeTruthy();
          expect(step.estimatedSeconds).toBeGreaterThan(0);
        }
      }
    });

    it("contains expected categories", () => {
      const categories = SOAR_PLAYBOOKS.map((p) => p.category);
      expect(categories).toContain("email");
      expect(categories).toContain("endpoint");
      expect(categories).toContain("network");
      expect(categories).toContain("cloud");
      expect(categories).toContain("forensics");
    });
  });

  describe("calculatePlaybookTelemetry", () => {
    it("computes aggregate metrics across run records", () => {
      const mockRuns: PlaybookRunRecord[] = [
        {
          id: "run-1",
          playbookId: "phishing-purge",
          playbookTitle: "Phishing Purge",
          status: "completed",
          startedAt: "2026-09-01T10:00:00Z",
          completedAt: "2026-09-01T10:00:30Z",
          analyst: "Analyst A",
          inputs: {},
          stepsCompleted: 6,
          totalSteps: 6,
          logs: ["Done"],
        },
        {
          id: "run-2",
          playbookId: "c2-perimeter-blackhole",
          playbookTitle: "C2 Blackhole",
          status: "failed",
          startedAt: "2026-09-01T11:00:00Z",
          completedAt: "2026-09-01T11:00:15Z",
          analyst: "Analyst B",
          inputs: {},
          stepsCompleted: 2,
          totalSteps: 5,
          logs: ["Failed"],
        },
      ];

      const telemetry = calculatePlaybookTelemetry(mockRuns);
      expect(telemetry.totalPlaybooks).toBe(5);
      expect(telemetry.totalRuns).toBe(2);
      expect(telemetry.completedRuns).toBe(1);
      expect(telemetry.successRate).toBe(50);
      expect(telemetry.totalAutomatedActions).toBeGreaterThan(5);
    });

    it("handles empty run arrays gracefully", () => {
      const telemetry = calculatePlaybookTelemetry([]);
      expect(telemetry.totalPlaybooks).toBe(5);
      expect(telemetry.totalRuns).toBe(0);
      expect(telemetry.completedRuns).toBe(0);
      expect(telemetry.successRate).toBe(100);
    });
  });

  describe("generatePlaybookRunMarkdown", () => {
    it("formats execution details and logs into markdown", () => {
      const pb = SOAR_PLAYBOOKS[0];
      const run: PlaybookRunRecord = {
        id: "run-test-01",
        playbookId: pb.id,
        playbookTitle: pb.title,
        status: "completed",
        startedAt: "2026-09-01T10:00:00Z",
        completedAt: "2026-09-01T10:00:35Z",
        analyst: "Test Analyst",
        inputs: {
          sender: "evil@malicious.com",
          subject: "Test Subject",
        },
        stepsCompleted: 6,
        totalSteps: 6,
        logs: ["[00:05] Header analyzed.", "[00:30] Remediation finished."],
      };

      const md = generatePlaybookRunMarkdown(run, pb);
      expect(md).toContain(`### SOAR Playbook Execution: ${pb.title}`);
      expect(md).toContain("**Run ID:** `run-test-01`");
      expect(md).toContain("COMPLETED");
      expect(md).toContain("evil@malicious.com");
      expect(md).toContain("[00:05] Header analyzed.");
    });
  });

  describe("persistence", () => {
    it("loads default runs when localStorage is empty", () => {
      const runs = loadPlaybookRuns();
      expect(runs.length).toBeGreaterThanOrEqual(2);
    });

    it("persists new runs via recordPlaybookRun", () => {
      const newRun: PlaybookRunRecord = {
        id: "run-custom-99",
        playbookId: "cloud-iam-revocation",
        playbookTitle: "Cloud Revocation",
        status: "completed",
        startedAt: new Date().toISOString(),
        analyst: "SecOps Lead",
        inputs: { user: "arn:aws:iam::123:user/test" },
        stepsCompleted: 5,
        totalSteps: 5,
        logs: ["Revocation completed."],
      };

      recordPlaybookRun(newRun);
      const reloaded = loadPlaybookRuns();
      expect(reloaded[0].id).toBe("run-custom-99");
    });
  });
});
