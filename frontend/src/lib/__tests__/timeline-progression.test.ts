import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_TIMELINE_SCENARIO,
  classifyEventIntrusionStage,
  computeIntrusionProgression,
  computeAttackVelocity,
  getTimelineEvents,
  restoreDefaultTimelineScenario,
  type TimelineEvent,
} from "@/lib/timeline";

function stubStorage(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
    clear: () => void map.clear(),
  });
}

describe("Timeline Intrusion Progression & Playback", () => {
  beforeEach(() => {
    stubStorage();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("DEFAULT_TIMELINE_SCENARIO has 9 realistic intrusion events spanning delivery to containment", () => {
    expect(DEFAULT_TIMELINE_SCENARIO).toBeDefined();
    expect(DEFAULT_TIMELINE_SCENARIO.length).toBe(9);

    const sources = DEFAULT_TIMELINE_SCENARIO.map((e) => e.source);
    expect(sources).toContain("phishing");
    expect(sources).toContain("url");
    expect(sources).toContain("logs");
    expect(sources).toContain("file");
    expect(sources).toContain("siem");
    expect(sources).toContain("pcap");
    expect(sources).toContain("detection");
    expect(sources).toContain("case");
    expect(sources).toContain("analyst");
  });

  it("classifies timeline events into correct MITRE / Kill-Chain intrusion stages", () => {
    const phishingEvent = DEFAULT_TIMELINE_SCENARIO.find((e) => e.source === "phishing")!;
    expect(classifyEventIntrusionStage(phishingEvent)).toBe("initial_access");

    const execEvent = DEFAULT_TIMELINE_SCENARIO.find((e) => e.source === "logs")!;
    expect(classifyEventIntrusionStage(execEvent)).toBe("execution");

    const pcapEvent = DEFAULT_TIMELINE_SCENARIO.find((e) => e.source === "pcap")!;
    expect(classifyEventIntrusionStage(pcapEvent)).toBe("command_and_control");

    const containmentEvent = DEFAULT_TIMELINE_SCENARIO.find((e) => e.source === "analyst")!;
    expect(classifyEventIntrusionStage(containmentEvent)).toBe("containment");
  });

  it("computes intrusion progression metrics accurately", () => {
    const stages = computeIntrusionProgression(DEFAULT_TIMELINE_SCENARIO);

    expect(stages.length).toBe(9);

    // Initial Access should have the phishing event
    const initialAccess = stages.find((s) => s.stage === "initial_access");
    expect(initialAccess).toBeDefined();
    expect(initialAccess?.eventCount).toBeGreaterThan(0);
    expect(initialAccess?.label).toBe("Initial Access");

    // Command & Control should be present
    const c2 = stages.find((s) => s.stage === "command_and_control");
    expect(c2).toBeDefined();
    expect(c2?.eventCount).toBeGreaterThan(0);

    // Active stages should span multiple steps
    const activeStages = stages.filter((s) => s.eventCount > 0);
    expect(activeStages.length).toBeGreaterThanOrEqual(5);
  });

  it("computes attack velocity and dwell time", () => {
    const velocity = computeAttackVelocity(DEFAULT_TIMELINE_SCENARIO);

    expect(velocity.totalDwellTimeMinutes).toBeGreaterThan(0);
    expect(velocity.dwellTimeFormatted).toContain("m");
    expect(velocity.eventsPerMinute).toBeGreaterThan(0);
    expect(velocity.criticalMilestonesCount).toBeGreaterThan(0);
    expect(velocity.rootCause).toBeDefined();
    expect(velocity.activeStageLabel).toBeDefined();
  });

  it("handles empty or single-event scenarios gracefully in progression and velocity", () => {
    const emptyStages = computeIntrusionProgression([]);
    expect(emptyStages.length).toBe(9);
    expect(emptyStages.every((s) => s.eventCount === 0)).toBe(true);

    const emptyVelocity = computeAttackVelocity([]);
    expect(emptyVelocity.totalDwellTimeMinutes).toBe(0);
    expect(emptyVelocity.dwellTimeFormatted).toBe("0m");
    expect(emptyVelocity.eventsPerMinute).toBe(0);
    expect(emptyVelocity.criticalMilestonesCount).toBe(0);

    const singleEvent: TimelineEvent = {
      id: "ev-single",
      ts: "2026-09-13T10:00:00Z",
      source: "siem",
      verb: "Port Scan Detected",
      detail: "Test event detail",
      severity: "low",
      tags: [],
    };
    const singleVelocity = computeAttackVelocity([singleEvent]);
    expect(singleVelocity.totalDwellTimeMinutes).toBe(1);
    expect(singleVelocity.eventsPerMinute).toBeGreaterThan(0);
  });

  it("restores default timeline scenario and loads them via getTimelineEvents", () => {
    // Explicit restore returns newly seeded scenario
    const restored = restoreDefaultTimelineScenario();
    expect(restored.length).toBe(DEFAULT_TIMELINE_SCENARIO.length);
    expect(restored[0].verb).toBe(DEFAULT_TIMELINE_SCENARIO[0].verb);

    // After restore, getTimelineEvents retrieves them
    const events = getTimelineEvents();
    expect(events.length).toBe(DEFAULT_TIMELINE_SCENARIO.length);
  });
});
