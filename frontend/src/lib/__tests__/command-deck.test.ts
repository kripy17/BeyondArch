import { describe, expect, it } from "vitest";
import {
  evaluateThreatPosture,
  extractActiveSentinel,
  aggregateChronicle,
  generateShiftHandoverReport,
  exportDeckTelemetryJson,
  formatElapsedTime,
} from "@/lib/command-deck";
import type { Case } from "@/data/case";
import type { AlertLedgerEntry } from "@/lib/alerts/ingest";
import type { TimelineEvent } from "@/lib/timeline";

function createMockCase(patch: Partial<Case> = {}): Case {
  return {
    id: "case-test-1",
    title: "Cobalt Strike C2 Beaconing",
    tags: ["apt29", "c2", "ransomware"],
    createdAt: new Date(Date.now() - 3600000 * 4).toISOString(), // 4h ago
    state: "active",
    entries: [
      { id: "e1", ts: new Date().toISOString(), kind: "evidence", body: "Malicious payload observed" },
    ],
    events: [
      {
        id: "ev1",
        ts: new Date().toISOString(),
        kind: "finding_created",
        category: "finding",
        importance: "critical",
        actor: "analyst",
        origin: "sentinel",
        title: "Injected DLL Detected",
        detail: "lsass.exe memory tampering",
        references: [],
      },
    ],
    findings: [
      { id: "f1", severity: "critical", title: "C2 Infiltration", detail: "Active beaconing", source: "pcap", technique: "T1071.001" },
      { id: "f2", severity: "high", title: "Credential Dumping", detail: "LSASS read", source: "sigma", technique: "T1003.001" },
    ],
    iocs: [
      { id: "i1", value: "198.51.100.23", type: "ipv4", context: "C2 Server", source: "pcap", severity: "critical" },
      { id: "i2", value: "evil-c2.net", type: "domain", context: "Beacon Host", source: "logs", severity: "high" },
      { id: "i3", value: "d41d8cd98f00b204e9800998ecf8427e", type: "md5", context: "Dropper", source: "file", severity: "medium" },
    ],
    evidenceItems: [
      { id: "ev-1", title: "traffic.pcap", type: "pcap", source: "suricata", detail: "Packet capture payload" },
    ],
    ...patch,
  };
}

function createMockAlert(patch: Partial<AlertLedgerEntry> = {}): AlertLedgerEntry {
  return {
    alertId: "alert-99",
    format: "crowdstrike",
    title: "Suspicious Powershell EncodedCommand",
    ingestedAt: new Date(Date.now() - 600000).toISOString(),
    caseId: "case-test-1",
    ruleKey: "sigma_ps_encoded",
    ...patch,
  };
}

function createMockTimelineEvent(patch: Partial<TimelineEvent> = {}): TimelineEvent {
  return {
    id: "tl-101",
    ts: new Date(Date.now() - 120000).toISOString(),
    source: "detection",
    verb: "matched",
    detail: "Rule Sigma: PowerShell Execution Match",
    severity: "critical",
    ...patch,
  };
}

describe("formatElapsedTime", () => {
  it("formats minutes, hours, and days cleanly", () => {
    const now = 1700000000000;
    // 30 seconds ago
    expect(formatElapsedTime(new Date(now - 30000).toISOString(), now)).toBe("30s");
    // 15 minutes ago
    expect(formatElapsedTime(new Date(now - 15 * 60000).toISOString(), now)).toBe("15m");
    // 2 hours 30 mins ago
    expect(formatElapsedTime(new Date(now - (2 * 3600 + 30 * 60) * 1000).toISOString(), now)).toBe("2h 30m");
    // 3 days 5 hours ago
    expect(formatElapsedTime(new Date(now - (3 * 86400 + 5 * 3600) * 1000).toISOString(), now)).toBe("3d 5h");
  });

  it("handles malformed timestamps safely", () => {
    expect(formatElapsedTime("invalid-date")).toBe("—");
  });
});

describe("evaluateThreatPosture", () => {
  it("evaluates an empty workspace as DEFCON 5 Low Threat", () => {
    const readiness = evaluateThreatPosture([], [], []);
    expect(readiness.threatScore).toBe(0);
    expect(readiness.threatLevel).toBe("low");
    expect(readiness.defconLevel).toBe(5);
    expect(readiness.activeCasesCount).toBe(0);
    expect(readiness.criticalIocsCount).toBe(0);
  });

  it("evaluates a high/critical scenario with active cases, alerts, and critical IOCs", () => {
    const mockCase = createMockCase();
    const alerts = [createMockAlert(), createMockAlert({ alertId: "alert-100" })];
    const timeline = [createMockTimelineEvent(), createMockTimelineEvent({ id: "tl-102", severity: "high" })];

    const readiness = evaluateThreatPosture([mockCase], alerts, timeline);
    expect(readiness.activeCasesCount).toBe(1);
    expect(readiness.criticalIocsCount).toBe(1);
    expect(readiness.highIocsCount).toBe(1);
    expect(readiness.mitreTechniquesCount).toBe(2);
    expect(readiness.unhandledAlertsCount).toBe(2);
    expect(readiness.threatScore).toBeGreaterThanOrEqual(40);
    expect(["elevated", "high", "critical"]).toContain(readiness.threatLevel);
    expect(readiness.defconLevel).toBeLessThanOrEqual(3);
  });

  it("caps threat score at 100", () => {
    const manyCriticalCases: Case[] = Array.from({ length: 10 }, (_, idx) =>
      createMockCase({
        id: `case-${idx}`,
        iocs: Array.from({ length: 5 }, (__, j) => ({
          value: `10.0.${idx}.${j}`,
          type: "ipv4",
          context: "c2",
          source: "test",
          severity: "critical",
        })),
      })
    );
    const readiness = evaluateThreatPosture(manyCriticalCases, [createMockAlert()], [createMockTimelineEvent()]);
    expect(readiness.threatScore).toBe(100);
    expect(readiness.threatLevel).toBe("critical");
    expect(readiness.defconLevel).toBe(1);
  });
});

describe("extractActiveSentinel", () => {
  it("returns null when no active case exists", () => {
    expect(extractActiveSentinel(null)).toBeNull();
  });

  it("extracts active case with prioritized IOCs and MITRE techniques", () => {
    const mockCase = createMockCase();
    const sentinel = extractActiveSentinel(mockCase, Date.now());
    expect(sentinel).not.toBeNull();
    expect(sentinel?.id).toBe("case-test-1");
    expect(sentinel?.leadIocs[0].severity).toBe("critical");
    expect(sentinel?.leadIocs[0].value).toBe("198.51.100.23");
    expect(sentinel?.mitreTechniques).toContain("T1071.001");
    expect(sentinel?.mitreTechniques).toContain("T1003.001");
    expect(sentinel?.findingsCount).toBe(2);
    expect(sentinel?.evidenceCount).toBe(1);
  });
});

describe("aggregateChronicle", () => {
  it("aggregates timeline events, alerts, and case milestones into a sorted feed", () => {
    const timeline = [
      createMockTimelineEvent({ id: "tl-1", ts: "2026-09-06T09:00:00.000Z", source: "parser", verb: "extracted" }),
      createMockTimelineEvent({ id: "tl-2", ts: "2026-09-06T10:00:00.000Z", source: "detection", verb: "alerted" }),
    ];
    const alerts = [
      createMockAlert({ alertId: "a1", ingestedAt: "2026-09-06T09:30:00.000Z", title: "C2 traffic" }),
    ];
    const cases = [
      createMockCase({
        events: [
          {
            id: "ce-1",
            ts: "2026-09-06T09:45:00.000Z",
            kind: "case_created",
            category: "case",
            importance: "high",
            actor: "analyst",
            origin: "deck",
            title: "Incident opened",
            detail: "Opened for C2 investigation",
            references: [],
          },
        ],
      }),
    ];

    const all = aggregateChronicle(timeline, alerts, cases, "all");
    expect(all.length).toBe(4);
    // Ordered newest first
    expect(all[0].id).toBe("ev-tl-2"); // 10:00
    expect(all[1].id).toBe("case-ev-ce-1"); // 09:45
    expect(all[2].id).toBe("alert-a1"); // 09:30
    expect(all[3].id).toBe("ev-tl-1"); // 09:00
  });

  it("filters accurately by category and query", () => {
    const timeline = [
      createMockTimelineEvent({ id: "tl-1", source: "parser", detail: "Parsed apache access log" }),
      createMockTimelineEvent({ id: "tl-2", source: "detection", detail: "Sigma rule match on mimikatz" }),
    ];
    const alerts = [createMockAlert({ alertId: "a1", title: "Ransomware canary file changed" })];
    const cases = [createMockCase()];

    // Filter alerts only
    const alertsOnly = aggregateChronicle(timeline, alerts, cases, "alert");
    expect(alertsOnly.length).toBe(1);
    expect(alertsOnly[0].sourceBadge).toBe("alert");

    // Filter detections only
    const detectionsOnly = aggregateChronicle(timeline, alerts, cases, "detection");
    expect(detectionsOnly.length).toBe(1);
    expect(detectionsOnly[0].detail).toContain("mimikatz");

    // Query search
    const searched = aggregateChronicle(timeline, alerts, cases, "all", "mimikatz");
    expect(searched.length).toBe(1);
    expect(searched[0].detail).toContain("mimikatz");
  });
});

describe("generateShiftHandoverReport & exportDeckTelemetryJson", () => {
  it("formats a comprehensive markdown shift handover report", () => {
    const mockCase = createMockCase();
    const readiness = evaluateThreatPosture([mockCase], [createMockAlert()], [createMockTimelineEvent()]);
    const report = generateShiftHandoverReport(
      readiness,
      mockCase,
      [createMockAlert()],
      [createMockTimelineEvent()]
    );

    expect(report).toContain("# BeyondLabs SOC Shift Handover Report");
    expect(report).toContain("## 1. Executive Operations Summary");
    expect(report).toContain("## 2. Active Incident Sentinel");
    expect(report).toContain("198.51.100.23");
    expect(report).toContain("## 3. Ingested Alert Ledger");
    expect(report).toContain("## 4. Notable Analyst Chronology");
  });

  it("exports valid JSON telemetry payload", () => {
    const mockCase = createMockCase();
    const readiness = evaluateThreatPosture([mockCase], [createMockAlert()], []);
    const jsonStr = exportDeckTelemetryJson(readiness, mockCase, [mockCase], [createMockAlert()]);
    const parsed = JSON.parse(jsonStr);

    expect(parsed.exportedAt).toBeDefined();
    expect(parsed.readiness.threatLevel).toBeDefined();
    expect(parsed.activeCase.id).toBe("case-test-1");
    expect(parsed.casesSummary.active).toBe(1);
    expect(parsed.alertsCount).toBe(1);
  });
});
