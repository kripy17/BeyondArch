import { describe, it, expect } from "vitest";
import {
  filterTimelineEvents,
  sortTimelineEvents,
  groupTimelineByDay,
  dateKeyOf,
  dayKeyLabel,
} from "@/lib/timeline-view";
import type { CaseEvent, EventActor, EventImportance } from "@/data/case";

let seq = 0;
function mk(opts: Partial<CaseEvent> = {}): CaseEvent {
  seq += 1;
  return {
    id: opts.id ?? `evt-${String(seq).padStart(3, "0")}`,
    ts: opts.ts ?? "2026-08-25T10:00:00.000Z",
    kind: opts.kind ?? "analyst_action",
    category: opts.category ?? "analyst",
    importance: (opts.importance ?? "normal") as EventImportance,
    actor: (opts.actor ?? "analyst") as EventActor,
    origin: opts.origin ?? "/case",
    title: opts.title ?? `Event ${seq}`,
    detail: opts.detail ?? "",
    references: [],
  };
}

const FIXED_NOW = new Date(2026, 7, 25, 12, 0); // local 2026-08-25 noon

/** Build an ISO ts whose LOCAL calendar day is deterministic regardless of machine TZ. */
function localTs(y: number, m: number, d: number, h = 10, min = 0): string {
  return new Date(y, m - 1, d, h, min).toISOString();
}

describe("filterTimelineEvents", () => {
  const events = [
    mk({ title: "Cobalt Strike alert", detail: "beacon to C2", origin: "/alerts" }),
    mk({ title: "Analyst note", detail: "checked DNS records", origin: "/case" }),
    mk({ category: "ioc", title: "IOC created", actor: "automation" }),
    mk({ importance: "critical", title: "Critical escalation" }),
    mk({ importance: "high", title: "High severity finding" }),
  ];

  it("returns everything unchanged with no filters", () => {
    const { events: out, hidden } = filterTimelineEvents(events, {});
    expect(out).toHaveLength(5);
    expect(hidden).toBe(0);
  });

  it("matches query against title case-insensitively", () => {
    const { events: out } = filterTimelineEvents(events, { query: "COBALT" });
    expect(out.map(e => e.title)).toEqual(["Cobalt Strike alert"]);
  });

  it("matches query against detail and origin too", () => {
    expect(filterTimelineEvents(events, { query: "dns records" }).events).toHaveLength(1);
    expect(filterTimelineEvents(events, { query: "/alerts" }).events.map(e => e.title)).toEqual([
      "Cobalt Strike alert",
    ]);
  });

  it("reports hidden count honestly", () => {
    const { hidden } = filterTimelineEvents(events, { query: "nothing-matches-this" });
    expect(hidden).toBe(events.length);
  });

  it("filters by category and actor together", () => {
    const { events: out } = filterTimelineEvents(events, {
      categories: ["ioc"],
      actors: ["analyst"],
    });
    expect(out).toHaveLength(0);
    expect(filterTimelineEvents(events, { categories: ["ioc"], actors: ["automation"] }).events).toHaveLength(1);
  });

  it("applies importance thresholds high+ and critical", () => {
    expect(filterTimelineEvents(events, { importance: "high+" }).events).toHaveLength(2);
    expect(
      filterTimelineEvents(events, { importance: "critical" }).events.map(e => e.title),
    ).toEqual(["Critical escalation"]);
  });

  it("filters by exact origin", () => {
    const { events: out, hidden } = filterTimelineEvents(events, { origin: "/alerts" });
    expect(out.map(e => e.title)).toEqual(["Cobalt Strike alert"]);
    expect(hidden).toBe(4);
  });
});

describe("sortTimelineEvents", () => {
  const a = mk({ id: "evt-a", ts: localTs(2026, 8, 24, 9) });
  const b = mk({ id: "evt-b", ts: localTs(2026, 8, 25, 9) });
  const c = mk({ id: "evt-c", ts: localTs(2026, 8, 23, 9) });

  it("sorts newest first by default direction", () => {
    expect(sortTimelineEvents([a, b, c], "newest").map(e => e.id)).toEqual(["evt-b", "evt-a", "evt-c"]);
  });

  it("sorts oldest first for chronological reading order", () => {
    expect(sortTimelineEvents([b, a, c], "oldest").map(e => e.id)).toEqual(["evt-c", "evt-a", "evt-b"]);
  });

  it("breaks ties deterministically on id", () => {
    const x = mk({ id: "evt-x", ts: a.ts });
    expect(sortTimelineEvents([x, a], "newest").map(e => e.id)).toEqual(["evt-x", "evt-a"]);
    expect(sortTimelineEvents([x, a], "oldest").map(e => e.id)).toEqual(["evt-a", "evt-x"]);
  });
});

describe("groupTimelineByDay", () => {
  it("buckets into descending day groups with labels", () => {
    const events = [
      mk({ ts: localTs(2026, 8, 25, 10, 30) }),
      mk({ ts: localTs(2026, 8, 25, 8, 0) }),
      mk({ ts: localTs(2026, 8, 20, 22, 0) }),
    ];
    const groups = groupTimelineByDay(sortTimelineEvents(events, "newest"), FIXED_NOW);
    expect(groups.map(g => g.dateKey)).toEqual(["2026-08-25", "2026-08-20"]);
    expect(groups[0].label).toBe("Today");
    expect(groups[0].events).toHaveLength(2);
    expect(groups[1].label).toContain("Aug 20");
  });

  it("labels yesterday relatively", () => {
    const [group] = groupTimelineByDay([mk({ ts: localTs(2026, 8, 24, 10) })], FIXED_NOW);
    expect(group.label).toBe("Yesterday");
  });
});

describe("dateKeyOf / dayKeyLabel", () => {
  it("produces zero-padded local keys", () => {
    expect(dateKeyOf(localTs(2026, 3, 5, 0, 5))).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(dateKeyOf(localTs(2026, 3, 5, 12))).toBe("2026-03-05");
  });

  it("formats non-relative keys as readable dates", () => {
    const label = dayKeyLabel("2025-01-15", new Date("2026-08-25T00:00:00Z"));
    expect(label).toContain("Jan 15");
    expect(label).toContain("2025");
  });
});
