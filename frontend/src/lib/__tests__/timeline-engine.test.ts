import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  pushTimelineEvent,
  getTimelineEvents,
  clearTimeline,
  deleteTimelineEvent,
  addAnalystMilestone,
  bucketEventsByTime,
  filterTimelineEvents,
  exportTimelineCsv,
  exportTimelineJsonl,
  exportTimelineMarkdown,
  promoteEventToCase,
  inferEventSeverity,
  inferEventActor,
  type TimelineEvent,
} from "../timeline";
import { loadCases, saveCases, type Case } from "@/data/case";

function stubStorage(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
    clear: () => void map.clear(),
  });
  if (typeof window === "undefined") {
    vi.stubGlobal("window", {
      dispatchEvent: () => true,
      addEventListener: () => {},
      removeEventListener: () => {},
    });
  }
}

describe("timeline-engine", () => {
  beforeEach(() => {
    stubStorage();
  });

  describe("heuristics", () => {
    it("infers severity correctly based on keywords and verbs", () => {
      expect(inferEventSeverity({ verb: "quarantined", detail: "Host isolation executed" })).toBe("critical");
      expect(inferEventSeverity({ verb: "detected", detail: "Potential ransomware note found" })).toBe("critical");
      expect(inferEventSeverity({ verb: "flagged", detail: "Phishing lure detected in email" })).toBe("high");
      expect(inferEventSeverity({ verb: "analyzed", detail: "Unusual registry modification" })).toBe("medium");
      expect(inferEventSeverity({ verb: "parsed", detail: "Clean file sample" })).toBe("low");
      expect(inferEventSeverity({ verb: "scanned", detail: "Routine asset discovery" })).toBe("info");
      // Explicit severity is honored
      expect(inferEventSeverity({ severity: "low", verb: "quarantined" })).toBe("low");
    });

    it("infers actor correctly based on source and action", () => {
      expect(inferEventActor({ source: "analyst", verb: "note added" })).toBe("analyst");
      expect(inferEventActor({ source: "case", verb: "decision documented" })).toBe("analyst");
      expect(inferEventActor({ source: "detection", verb: "sigma matched" })).toBe("system");
      expect(inferEventActor({ source: "parser", verb: "extracted" })).toBe("automation");
    });
  });

  describe("storage and mutation", () => {
    it("pushes, retrieves, and clears timeline events with enrichment", () => {
      expect(getTimelineEvents()).toHaveLength(0);

      const ev1 = pushTimelineEvent({
        source: "parser",
        verb: "extracted",
        detail: "Found 4 IOCs in auth.log",
        target: "auth.log",
      });

      expect(ev1.id).toBeDefined();
      expect(ev1.ts).toBeDefined();
      expect(ev1.severity).toBe("info");
      expect(ev1.actor).toBe("automation");

      const events = getTimelineEvents();
      expect(events).toHaveLength(1);
      expect(events[0].id).toBe(ev1.id);

      // Add analyst milestone
      const milestone = addAnalystMilestone({
        title: "Containment Completed",
        detail: "Egress firewall rules applied to isolate subnet 10.0.4.0/24",
        severity: "critical",
        target: "10.0.4.0/24",
      });

      expect(milestone.source).toBe("analyst");
      expect(milestone.actor).toBe("analyst");
      expect(milestone.severity).toBe("critical");
      expect(getTimelineEvents()).toHaveLength(2);

      // Delete milestone
      deleteTimelineEvent(milestone.id);
      expect(getTimelineEvents()).toHaveLength(1);
      expect(getTimelineEvents()[0].id).toBe(ev1.id);

      // Clear all
      clearTimeline();
      expect(getTimelineEvents()).toHaveLength(0);
    });
  });

  describe("bucketing and histogram", () => {
    it("handles empty events safely", () => {
      expect(bucketEventsByTime([])).toEqual([]);
    });

    it("buckets events into intervals with accurate severity and counts", () => {
      const baseMs = 1725600000000;
      const testEvents: TimelineEvent[] = [
        {
          id: "1",
          ts: new Date(baseMs).toISOString(),
          source: "parser",
          verb: "extracted",
          detail: "IOC parse",
          severity: "low",
        },
        {
          id: "2",
          ts: new Date(baseMs + 10 * 60 * 1000).toISOString(),
          source: "detection",
          verb: "flagged",
          detail: "Malicious beacon",
          severity: "critical",
        },
        {
          id: "3",
          ts: new Date(baseMs + 12 * 60 * 1000).toISOString(),
          source: "url",
          verb: "analyzed",
          detail: "Phishing landing page",
          severity: "high",
        },
        {
          id: "4",
          ts: new Date(baseMs + 50 * 60 * 1000).toISOString(),
          source: "analyst",
          verb: "quarantined",
          detail: "Analyst isolated workstation",
          severity: "critical",
        },
      ];

      // 15-minute interval buckets (900,000 ms)
      const buckets = bucketEventsByTime(testEvents, { intervalMs: 15 * 60 * 1000 });
      expect(buckets.length).toBeGreaterThanOrEqual(4);

      // First bucket (0-15m) should contain events 1, 2, 3
      expect(buckets[0].count).toBe(3);
      expect(buckets[0].peakSeverity).toBe("critical");
      expect(buckets[0].severityCounts.critical).toBe(1);
      expect(buckets[0].severityCounts.high).toBe(1);
      expect(buckets[0].severityCounts.low).toBe(1);
      expect(buckets[0].heightPercent).toBe(100); // peak count is 3

      // Later bucket should contain event 4
      const laterBucket = buckets.find((b) => b.events.some((e) => e.id === "4"));
      expect(laterBucket).toBeDefined();
      expect(laterBucket?.count).toBe(1);
      expect(laterBucket?.heightPercent).toBe(33);
    });
  });

  describe("filtering", () => {
    const testEvents: TimelineEvent[] = [
      {
        id: "e1",
        ts: "2026-09-06T04:00:00.000Z",
        source: "parser",
        verb: "extracted",
        detail: "Found IP 198.51.100.4 in auth.log",
        target: "198.51.100.4",
        severity: "info",
        actor: "automation",
      },
      {
        id: "e2",
        ts: "2026-09-06T04:15:00.000Z",
        source: "detection",
        verb: "flagged",
        detail: "Suspicious PowerShell invocation detected",
        target: "powershell.exe",
        severity: "high",
        actor: "system",
      },
      {
        id: "e3",
        ts: "2026-09-06T04:30:00.000Z",
        source: "analyst",
        verb: "quarantined",
        detail: "Analyst confirmed active C2 beaconing and quarantined host",
        severity: "critical",
        actor: "analyst",
      },
    ];

    it("filters by search query across multiple fields", () => {
      expect(filterTimelineEvents(testEvents, { searchQuery: "powershell" })).toHaveLength(1);
      expect(filterTimelineEvents(testEvents, { searchQuery: "198.51.100.4" })).toHaveLength(1);
      expect(filterTimelineEvents(testEvents, { searchQuery: "analyst" })).toHaveLength(1);
      expect(filterTimelineEvents(testEvents, { searchQuery: "nonexistent" })).toHaveLength(0);
    });

    it("filters by source and severity", () => {
      expect(filterTimelineEvents(testEvents, { sources: ["parser"] })).toHaveLength(1);
      expect(filterTimelineEvents(testEvents, { severities: ["high", "critical"] })).toHaveLength(2);
      expect(filterTimelineEvents(testEvents, { actors: ["analyst"] })).toHaveLength(1);
    });

    it("filters by explicit time window", () => {
      const windowed = filterTimelineEvents(testEvents, {
        timeRange: {
          start: "2026-09-06T04:10:00.000Z",
          end: "2026-09-06T04:20:00.000Z",
        },
      });
      expect(windowed).toHaveLength(1);
      expect(windowed[0].id).toBe("e2");
    });
  });

  describe("exporters", () => {
    const testEvents: TimelineEvent[] = [
      {
        id: "e1",
        ts: "2026-09-06T04:00:00.000Z",
        source: "parser",
        verb: "extracted",
        detail: 'Extracted IOCs, with "quotes" & commas',
        target: "198.51.100.4",
        result: "flagged",
        severity: "high",
        actor: "analyst",
        tags: ["c2", "revshell"],
      },
    ];

    it("generates RFC 4180 compliant Timesketch CSV", () => {
      const csv = exportTimelineCsv(testEvents);
      expect(csv).toContain("datetime,timestamp_desc,message,source,verb,severity,actor,target,result,tags");
      expect(csv).toContain('"Extracted IOCs, with ""quotes"" & commas"');
      expect(csv).toContain("c2;revshell");
    });

    it("generates valid newline-delimited JSONL", () => {
      const jsonl = exportTimelineJsonl(testEvents);
      const lines = jsonl.split("\n");
      expect(lines).toHaveLength(1);
      const parsed = JSON.parse(lines[0]);
      expect(parsed.id).toBe("e1");
      expect(parsed.target).toBe("198.51.100.4");
    });

    it("generates publication-grade DFIR Markdown table", () => {
      const md = exportTimelineMarkdown(testEvents, "Incident Incident Timeline");
      expect(md).toContain("# Incident Incident Timeline");
      expect(md).toContain("| Timestamp (UTC) | Severity | Source | Actor | Verb | Detail | Target / Result |");
      expect(md).toContain("| 2026-09-06 04:00:00 UTC | HIGH | parser | analyst | extracted |");
    });
  });

  describe("case promotion", () => {
    it("promotes a timeline event into a defensible CaseEvent on the active case", () => {
      const initialCase: Case = {
        id: "case-alpha-123",
        title: "Phishing Attack Investigation",
        tags: ["incident", "phishing"],
        createdAt: new Date().toISOString(),
        state: "active",
        entries: [],
        events: [],
      };
      saveCases([initialCase]);

      const eventToPromote: TimelineEvent = {
        id: "tel-999",
        ts: "2026-09-06T04:30:00.000Z",
        source: "detection",
        verb: "flagged",
        detail: "C2 beacon detected to cobalt strike listener",
        target: "evil-c2.com",
        result: "malicious (score 95)",
        severity: "critical",
        actor: "system",
      };

      const success = promoteEventToCase(eventToPromote, "case-alpha-123");
      expect(success).toBe(true);

      const cases = loadCases();
      const updatedCase = cases.find((c) => c.id === "case-alpha-123");
      expect(updatedCase?.events).toHaveLength(1);

      const caseEvt = updatedCase!.events![0];
      expect(caseEvt.ts).toBe("2026-09-06T04:30:00.000Z");
      expect(caseEvt.importance).toBe("critical");
      expect(caseEvt.origin).toContain("/timeline (detection)");
      expect(caseEvt.references[0].id).toBe("evil-c2.com");

      // Idempotency: promoting again shouldn't duplicate
      const secondAttempt = promoteEventToCase(eventToPromote, "case-alpha-123");
      expect(secondAttempt).toBe(true);
      expect(loadCases().find((c) => c.id === "case-alpha-123")?.events).toHaveLength(1);
    });
  });
});
