import { describe, it, expect } from "vitest";
import type { Case } from "@/data/case";
import {
  calculateQueueMetrics,
  findCrossCaseObservables,
  computeCaseSeverity,
  computeContainmentStage,
  filterCaseQueue,
  exportCaseQueueCsv,
  exportCaseQueueJson,
  instantiateCaseFromTemplate,
  IR_TEMPLATES,
} from "../case-desk";

describe("case-desk", () => {
  const mockCases: Case[] = [
    {
      id: "case-001",
      title: "Phishing Campaign Alpha",
      state: "active",
      tags: ["phishing", "critical"],
      createdAt: "2026-09-01T10:00:00.000Z",
      entries: [
        { id: "e1", ts: "2026-09-01T10:05:00.000Z", kind: "note", body: "Initial notice" },
        { id: "e2", ts: "2026-09-01T10:10:00.000Z", kind: "ioc", body: "ipv4: 198.51.100.44\nSource: Mail Gateway" },
        { id: "e3", ts: "2026-09-01T10:15:00.000Z", kind: "ioc", body: "url: https://evil-login.example.com/test\nSource: Email Lure" },
      ],
    },
    {
      id: "case-002",
      title: "Lateral Movement Beta",
      state: "active",
      tags: ["lateral-movement", "high"],
      createdAt: "2026-09-02T12:00:00.000Z",
      entries: [
        { id: "e4", ts: "2026-09-02T12:05:00.000Z", kind: "ioc", body: "ipv4: 198.51.100.44\nSource: Firewall Drop" },
        { id: "e5", ts: "2026-09-02T12:10:00.000Z", kind: "action", body: "Isolate endpoint SRV-BETA-01 immediately." },
      ],
    },
    {
      id: "case-003",
      title: "Resolved Incident Gamma",
      state: "closed",
      tags: ["malware", "resolved"],
      createdAt: "2026-09-03T08:00:00.000Z",
      entries: [
        { id: "e6", ts: "2026-09-03T08:30:00.000Z", kind: "ioc", body: "ipv4: 198.51.100.44\nSource: Endpoint Log" },
        { id: "e7", ts: "2026-09-03T09:00:00.000Z", kind: "action", body: "Recovery completed: system restored from clean snapshot." },
      ],
    },
  ];

  describe("computeCaseSeverity", () => {
    it("detects severity from tags", () => {
      expect(computeCaseSeverity(mockCases[0])).toBe("critical");
      expect(computeCaseSeverity(mockCases[1])).toBe("high");
    });

    it("detects severity from entry text tokens", () => {
      const caseWithCritText: Case = {
        id: "case-crit",
        title: "Test Case",
        state: "active",
        tags: [],
        createdAt: "2026-09-01T10:00:00.000Z",
        entries: [{ id: "e1", ts: "2026-09-01T10:00:00.000Z", kind: "note", body: "[CRITICAL] Zero-day exploited" }],
      };
      expect(computeCaseSeverity(caseWithCritText)).toBe("critical");
    });
  });

  describe("computeContainmentStage", () => {
    it("marks closed cases as Closed", () => {
      expect(computeContainmentStage(mockCases[2])).toBe("Closed");
    });

    it("detects Containment actions", () => {
      expect(computeContainmentStage(mockCases[1])).toBe("Containment");
    });

    it("defaults to Triage when no actions are taken", () => {
      expect(computeContainmentStage(mockCases[0])).toBe("Triage");
    });

    it("detects Recovery stage when open case has recovery actions", () => {
      const openRecoveryCase: Case = {
        ...mockCases[2],
        state: "active",
      };
      expect(computeContainmentStage(openRecoveryCase)).toBe("Recovery");
    });
  });

  describe("findCrossCaseObservables", () => {
    it("identifies observables occurring across multiple cases", () => {
      const correlated = findCrossCaseObservables(mockCases);
      expect(correlated.length).toBe(1);
      expect(correlated[0].type).toBe("ipv4");
      expect(correlated[0].value).toBe("198.51.100.44");
      expect(correlated[0].count).toBe(3);
      expect(correlated[0].caseIds).toEqual(["case-001", "case-002", "case-003"]);
    });

    it("omits single-occurrence observables", () => {
      const correlated = findCrossCaseObservables(mockCases);
      const urlObs = correlated.find((o) => o.value.includes("evil-login"));
      expect(urlObs).toBeUndefined();
    });
  });

  describe("calculateQueueMetrics", () => {
    it("computes accurate aggregate metrics across cases", () => {
      const metrics = calculateQueueMetrics(mockCases);
      expect(metrics.totalCases).toBe(3);
      expect(metrics.activeCases).toBe(2);
      expect(metrics.closedCases).toBe(1);
      expect(metrics.criticalCases).toBe(1);
      expect(metrics.highCases).toBe(1);
      expect(metrics.totalCorrelatedIocs).toBe(1);
      expect(metrics.totalEvidenceCount).toBeGreaterThan(0);
      expect(metrics.avgMttcMinutes).toBeGreaterThan(0);
    });

    it("handles empty case lists gracefully", () => {
      const metrics = calculateQueueMetrics([]);
      expect(metrics.totalCases).toBe(0);
      expect(metrics.activeCases).toBe(0);
      expect(metrics.avgMttcMinutes).toBe(0);
      expect(metrics.totalCorrelatedIocs).toBe(0);
    });
  });

  describe("filterCaseQueue", () => {
    it("filters by status", () => {
      const activeOnly = filterCaseQueue(mockCases, { search: "", status: "active", severity: "all", tag: "" });
      expect(activeOnly.length).toBe(2);

      const closedOnly = filterCaseQueue(mockCases, { search: "", status: "closed", severity: "all", tag: "" });
      expect(closedOnly.length).toBe(1);
      expect(closedOnly[0].id).toBe("case-003");
    });

    it("filters by severity", () => {
      const criticalOnly = filterCaseQueue(mockCases, { search: "", status: "all", severity: "critical", tag: "" });
      expect(criticalOnly.length).toBe(1);
      expect(criticalOnly[0].id).toBe("case-001");
    });

    it("filters by tag", () => {
      const phishingTag = filterCaseQueue(mockCases, { search: "", status: "all", severity: "all", tag: "phishing" });
      expect(phishingTag.length).toBe(1);
      expect(phishingTag[0].id).toBe("case-001");
    });

    it("filters by search query across titles and entry bodies", () => {
      const titleSearch = filterCaseQueue(mockCases, { search: "lateral", status: "all", severity: "all", tag: "" });
      expect(titleSearch.length).toBe(1);
      expect(titleSearch[0].id).toBe("case-002");

      const entrySearch = filterCaseQueue(mockCases, { search: "SRV-BETA-01", status: "all", severity: "all", tag: "" });
      expect(entrySearch.length).toBe(1);
      expect(entrySearch[0].id).toBe("case-002");
    });
  });

  describe("export utilities", () => {
    it("exports CSV with correct header and formatted rows", () => {
      const csv = exportCaseQueueCsv(mockCases);
      expect(csv).toContain("Case ID,Title,Status,Severity,Stage");
      expect(csv).toContain('"case-001","Phishing Campaign Alpha","active","CRITICAL"');
    });

    it("exports JSON structure with valid metadata", () => {
      const jsonStr = exportCaseQueueJson(mockCases);
      const parsed = JSON.parse(jsonStr);
      expect(parsed.totalCases).toBe(3);
      expect(parsed.generator).toBe("BeyondLabs Incident Operations Desk");
      expect(parsed.cases.length).toBe(3);
      expect(parsed.cases[0].id).toBe("case-001");
    });
  });

  describe("instantiateCaseFromTemplate", () => {
    it("creates a well-formed enterprise case from an IR template", () => {
      const template = IR_TEMPLATES[0]; // Spear-phishing
      const created = instantiateCaseFromTemplate(template, "Custom Executive Spear Phish");

      expect(created.id).toMatch(/^case-/);
      expect(created.title).toBe("Custom Executive Spear Phish");
      expect(created.state).toBe("active");
      expect(created.tags).toContain("phishing");
      expect(created.tags).toContain("high");
      expect(created.tags).toContain("incident");

      // Verify entries structure
      expect(created.entries.length).toBeGreaterThanOrEqual(4);
      const intakeEntry = created.entries[0];
      expect(intakeEntry.body).toContain("[INITIAL INTAKE]");

      const checklistEntry = created.entries.find((e) => e.body.includes("Incident Response Checklist"));
      expect(checklistEntry).toBeDefined();
    });
  });
});
