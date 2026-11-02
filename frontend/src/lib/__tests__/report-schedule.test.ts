import { describe, expect, it, beforeEach } from "vitest";
import {
  SCHED_KEY,
  CADENCES,
  nextRunAfter,
  isCadence,
  isSchedule,
  loadSchedules,
  saveSchedules,
  addSchedule,
  removeSchedule,
  schedulesForCase,
  dueSchedules,
  advanceAfterRun,
  fireDueSchedules,
  type Schedule,
} from "@/lib/report-schedule";

const store = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => { store.set(k, v); },
  removeItem: (k: string) => { store.delete(k); },
  clear: () => { store.clear(); },
  key: (i: number) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
};

const T0 = new Date("2026-08-13T12:00:00.000Z");

function schedule(over: Partial<Schedule> = {}): Schedule {
  return {
    id: "C-1:1",
    caseId: "C-1",
    cadence: "daily",
    reportType: "technical",
    createdAt: T0.toISOString(),
    nextRunAt: T0.toISOString(),
    missedRuns: 0,
    ...over,
  };
}

describe("report-schedule (scheduled report exports)", () => {
  beforeEach(() => {
    localStorage.clear();
    store.delete("ba.cases.v2");
    store.delete("ba.reports.v1");
  });

  it("exposes the documented cadences", () => {
    expect(CADENCES.map((c) => c.id)).toEqual(["daily", "weekly", "monthly"]);
  });

  it("advances next run by fixed periods per cadence", () => {
    expect(nextRunAfter(T0, "daily").toISOString()).toBe("2026-08-14T12:00:00.000Z");
    expect(nextRunAfter(T0, "weekly").toISOString()).toBe("2026-08-20T12:00:00.000Z");
    expect(nextRunAfter(T0, "monthly").toISOString()).toBe("2026-09-13T12:00:00.000Z");
  });

  it("clamps the monthly date to the target month length", () => {
    expect(nextRunAfter(new Date("2026-08-31T12:00:00.000Z"), "monthly").toISOString()).toBe("2026-09-30T12:00:00.000Z");
    expect(nextRunAfter(new Date("2026-12-31T12:00:00.000Z"), "monthly").toISOString()).toBe("2027-01-31T12:00:00.000Z");
  });

  it("validates cadence and schedule shapes", () => {
    expect(isCadence("daily")).toBe(true);
    expect(isCadence("hourly")).toBe(false);
    expect(isSchedule(schedule())).toBe(true);
    expect(isSchedule({ ...schedule(), cadence: "hourly" })).toBe(false);
    expect(isSchedule({ ...schedule(), nextRunAt: "not-a-date" })).toBe(false);
    expect(isSchedule(null)).toBe(false);
  });

  it("adds schedules with a storage key backing them", () => {
    const s = addSchedule({ caseId: "C-1", cadence: "weekly", reportType: "executive", now: T0 });
    expect(s.caseId).toBe("C-1");
    expect(s.reportType).toBe("executive");
    expect(s.nextRunAt).toBe("2026-08-20T12:00:00.000Z");
    expect(loadSchedules()).toEqual([s]);
    expect(localStorage.getItem(SCHED_KEY)).toContain("C-1");
  });

  it("scopes schedules per case and sorts by next run", () => {
    saveSchedules([
      schedule({ id: "C-1:1", nextRunAt: "2026-08-15T12:00:00.000Z" }),
      schedule({ id: "C-1:2", nextRunAt: "2026-08-14T12:00:00.000Z" }),
      schedule({ id: "C-2:1", caseId: "C-2", nextRunAt: "2026-08-14T12:00:00.000Z" }),
    ]);
    const scoped = schedulesForCase(loadSchedules(), "C-1");
    expect(scoped.map((s) => s.id)).toEqual(["C-1:2", "C-1:1"]);
  });

  it("detects due schedules at or before the reference time", () => {
    saveSchedules([
      schedule({ id: "s1", nextRunAt: "2026-08-13T12:00:00.000Z" }),
      schedule({ id: "s2", nextRunAt: "2026-08-13T12:01:00.000Z" }),
      schedule({ id: "s3", nextRunAt: "2026-08-13T11:59:00.000Z" }),
    ]);
    expect(dueSchedules(loadSchedules(), T0).map((s) => s.id).sort()).toEqual(["s1", "s3"]);
  });

  it("skips missed runs and counts them when advancing after a fire", () => {
    const advanced = advanceAfterRun(
      schedule({ nextRunAt: "2026-08-11T12:00:00.000Z" }),
      T0,
      "2026-08-13T12:00:00.000Z"
    );
    expect(advanced.nextRunAt).toBe("2026-08-14T12:00:00.000Z");
    expect(advanced.missedRuns).toBe(1);
    expect(advanced.generatedAt).toBe("2026-08-13T12:00:00.000Z");
    expect(advanced.lastRunAt).toBe("2026-08-13T12:00:00.000Z");
  });

  it("removes schedules by id", () => {
    saveSchedules([schedule({ id: "keep" }), schedule({ id: "drop" })]);
    const remaining = removeSchedule("drop");
    expect(remaining.map((s) => s.id)).toEqual(["keep"]);
    expect(loadSchedules().map((s) => s.id)).toEqual(["keep"]);
  });

  it("fires due schedules into the report history and advances them", () => {
    localStorage.setItem("ba.cases.v2", JSON.stringify([
      {
        id: "C-1",
        title: "Phishing wave",
        tags: [],
        createdAt: "2026-08-01T00:00:00.000Z",
        state: "active",
        events: [],
        entries: [],
      },
    ]));
    saveSchedules([schedule({ id: "s1", nextRunAt: "2026-08-10T12:00:00.000Z" })]);

    const fired = fireDueSchedules(new Date("2026-08-13T12:00:00.000Z"));
    expect(fired).toHaveLength(1);
    expect(fired[0].caseTitle).toBe("Phishing wave");
    expect(fired[0].reportType).toBe("technical");
    expect(fired[0].missedRuns).toBe(2);

    const history = JSON.parse(localStorage.getItem("ba.reports.v1") ?? "[]") as Record<string, unknown>;
    expect(history["C-1"]).toHaveLength(1);
    expect((history["C-1"] as Record<string, unknown>[])[0].source).toBe("scheduled");
    expect((history["C-1"] as Record<string, unknown>[])[0].scheduledFor).toBe("2026-08-10T12:00:00.000Z");
    expect((history["C-1"] as Record<string, unknown>[])[0].generatedAt).toBe("2026-08-13T12:00:00.000Z");
    expect((history["C-1"] as { summary: { events: number } }[])[0].summary.events).toBe(0);

    const remaining = loadSchedules();
    expect(remaining).toHaveLength(1);
    expect(remaining[0].nextRunAt).toBe("2026-08-14T12:00:00.000Z");
    expect(remaining[0].missedRuns).toBe(2);
  });

  it("keeps non-due schedules untouched while firing due ones", () => {
    localStorage.setItem("ba.cases.v2", JSON.stringify([
      {
        id: "C-1",
        title: "Phishing wave",
        tags: [],
        createdAt: "2026-08-01T00:00:00.000Z",
        state: "active",
        events: [],
        entries: [],
      },
    ]));
    saveSchedules([
      schedule({ id: "due", nextRunAt: "2026-08-12T12:00:00.000Z" }),
      schedule({ id: "future", nextRunAt: "2026-08-20T12:00:00.000Z" }),
    ]);

    const fired = fireDueSchedules(new Date("2026-08-13T12:00:00.000Z"));
    expect(fired.map((f) => f.missedRuns)).toEqual([0]);
    const remaining = Object.fromEntries(loadSchedules().map((s) => [s.id, s]));
    expect(remaining.due.nextRunAt).toBe("2026-08-14T12:00:00.000Z");
    expect(remaining.future.nextRunAt).toBe("2026-08-20T12:00:00.000Z");
    expect(remaining.future.missedRuns).toBe(0);
  });

  it("does nothing when no schedules exist", () => {
    expect(fireDueSchedules(T0)).toEqual([]);
  });

  it("tolerates a corrupted schedule store", () => {
    localStorage.setItem(SCHED_KEY, "{not json");
    expect(loadSchedules()).toEqual([]);
  });
});