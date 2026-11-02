import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  getShiftWindowTimes,
  calculateShiftMetrics,
  buildShiftBriefing,
  generateShiftBriefingMarkdown,
  recordShiftHandoverToTimeline,
} from "@/lib/shift-handover";
import { type Case } from "@/data/case";
import { getTimelineEvents } from "@/lib/timeline";

function stubStorage(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
    clear: () => void map.clear(),
  });
}

function mockCase(id: string, title: string, severity: "critical" | "high" | "low", state: "active" | "closed" = "active"): Case {
  return {
    id,
    title,
    tags: [severity, "incident"],
    createdAt: new Date().toISOString(),
    state,
    entries: [
      {
        id: `entry-${id}-1`,
        ts: new Date().toISOString(),
        kind: "action",
        body: severity === "critical" ? "Host isolated and dropped connection" : "Reviewed alert log",
      },
    ],
    events: [
      {
        id: `ev-${id}-1`,
        ts: new Date(Date.now() - 3600000).toISOString(),
        kind: "alert_ingested",
        category: "detection",
        importance: "high",
        actor: "system",
        origin: "siem",
        title: "Initial Alert",
        detail: "Alert triggered",
        references: [],
      },
      {
        id: `ev-${id}-2`,
        ts: new Date(Date.now() - 1800000).toISOString(),
        kind: "alert_ingested",
        category: "detection",
        importance: "high",
        actor: "system",
        origin: "detection",
        title: "Confirmed Detection",
        detail: "Correlation matched",
        references: [],
      },
    ],
    artifacts: [],
    findings: [
      {
        id: `find-${id}-1`,
        title: `${title} Primary Threat Vector`,
        source: "siem",
        severity,
        detail: "Malicious command execution identified",
      },
    ],
    iocs: [
      {
        id: `ioc-${id}-1`,
        type: "ipv4",
        value: "51.15.0.100",
        context: "Hostile C2 endpoint",
        source: "siem",
        severity,
      },
    ],
  };
}

describe("SOC Shift Handover & Incident Briefing Engine", () => {
  beforeEach(() => {
    stubStorage();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("calculates shift window boundaries accurately", () => {
    const w8 = getShiftWindowTimes("current_8h");
    expect(w8.label).toContain("8 Hours");
    expect(w8.end.getTime() - w8.start.getTime()).toBeGreaterThanOrEqual(7.9 * 3600 * 1000);

    const w12 = getShiftWindowTimes("past_12h");
    expect(w12.label).toContain("12 Hours");

    const w24 = getShiftWindowTimes("past_24h");
    expect(w24.label).toContain("24 Hours");

    const wAll = getShiftWindowTimes("all_active");
    expect(wAll.label).toContain("All Active");
  });

  it("calculates MTTA, MTTD, MTTR and DEFCON levels correctly", () => {
    const cases: Case[] = [
      mockCase("case-001", "Ransomware Infiltration", "critical", "active"),
      mockCase("case-002", "Phishing Credential Access", "high", "active"),
      mockCase("case-003", "Port Scan Reconnaissance", "low", "closed"),
    ];

    const metrics = calculateShiftMetrics(cases, "current_8h");

    expect(metrics.totalIncidents).toBe(3);
    expect(metrics.activeIncidents).toBe(2);
    expect(metrics.closedIncidents).toBe(1);
    expect(metrics.criticalIncidents).toBe(1);
    expect(metrics.highIncidents).toBe(1);
    expect(metrics.mttaMinutes).toBeGreaterThan(0);
    expect(metrics.mttaFormatted).toBeDefined();
    expect(metrics.mttdMinutes).toBeGreaterThan(0);
    expect(metrics.mttrMinutes).toBeGreaterThan(0);
    expect(metrics.containmentVelocity).toBeGreaterThan(0);
    expect(metrics.defconLevel).toBe("DEFCON 2 (ELEVATED)");
    expect(metrics.newObservablesCount).toBe(1);
    expect(metrics.isolatedEndpointsCount).toBeGreaterThan(0);
  });

  it("builds structured shift briefing data with classified case tiers", () => {
    const cases: Case[] = [
      mockCase("case-p1", "Active Cobalt Strike C2", "critical", "active"),
      mockCase("case-p2", "Suspicious Execution", "high", "active"),
      mockCase("case-p3", "Closed Phish", "low", "closed"),
    ];

    const briefing = buildShiftBriefing({
      cases,
      shiftWindow: "current_8h",
      outgoingLead: "Analyst Alice",
      incomingLead: "Analyst Bob",
      shiftNotes: "Critical isolation active on WS-SEC-092",
    });

    expect(briefing.outgoingLead).toBe("Analyst Alice");
    expect(briefing.incomingLead).toBe("Analyst Bob");
    expect(briefing.p1Blockers.length).toBe(2);
    expect(briefing.resolvedCases.length).toBe(1);
    expect(briefing.infrastructure.length).toBeGreaterThan(0);
    expect(briefing.infrastructure[0].value).toBe("51.15.0.100");
  });

  it("generates publication-ready Markdown with all operational sections", () => {
    const cases: Case[] = [
      mockCase("case-p1", "Active Cobalt Strike C2", "critical", "active"),
    ];

    const briefing = buildShiftBriefing({
      cases,
      shiftWindow: "current_8h",
      outgoingLead: "Officer Stark",
      incomingLead: "Officer Rogers",
      shiftNotes: "Perimeter firewall rule active. Tier 3 notified.",
    });

    const md = generateShiftBriefingMarkdown(briefing);

    expect(md).toContain("# BEYONDARCH SOC SHIFT HANDOVER DOSSIER");
    expect(md).toContain("THREAT CONDITION:");
    expect(md).toContain("Officer Stark");
    expect(md).toContain("Officer Rogers");
    expect(md).toContain("Core SOC Performance & Dwell Metrics");
    expect(md).toContain("MTTA");
    expect(md).toContain("MTTD");
    expect(md).toContain("MTTR");
    expect(md).toContain("High-Priority Case Handover Matrix");
    expect(md).toContain("51.15.0.100");
    expect(md).toContain("Operational Sign-Off & Verification");
  });

  it("records shift handover to master timeline as an official audit milestone", () => {
    const cases: Case[] = [mockCase("case-001", "Test Incident", "high", "active")];
    const briefing = buildShiftBriefing({ cases });

    const event = recordShiftHandoverToTimeline(briefing);

    expect(event.id).toBeDefined();
    expect(event.source).toBe("analyst");
    expect(event.verb).toBe("SOC Shift Handover Completed");
    expect(event.tags).toContain("shift-handover");
    expect(event.tags).toContain("audit");

    const events = getTimelineEvents();
    expect(events.some((e) => e.verb === "SOC Shift Handover Completed")).toBe(true);
  });
});
