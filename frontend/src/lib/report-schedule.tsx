import { useEffect } from "react";
import { notify } from "@/lib/notify";
import { loadCases } from "@/data/case";
import type { Case } from "@/data/case";
import { loadHypotheses } from "@/data/notebook";
import { mitreRows, hypothesisRows, REPORT_TYPES, type ReportType } from "@/lib/report";
import { getUnifiedFindings, getUnifiedIOCs } from "@/components/investigation";
import { snapshotFrom, saveReportVersion, type ReportVersion } from "@/lib/report-history";

export const SCHED_KEY = "ba.report-schedules.v1";
export const TICK_MS = 60_000;
export const MAX_SCHEDULES_PER_CASE = 5;

export type Cadence = "daily" | "weekly" | "monthly";

export const CADENCES: { id: Cadence; label: string }[] = [
  { id: "daily", label: "daily" },
  { id: "weekly", label: "weekly" },
  { id: "monthly", label: "monthly" },
];

export type Schedule = {
  id: string;
  caseId: string;
  cadence: Cadence;
  reportType: ReportType;
  createdAt: string;
  nextRunAt: string;
  lastRunAt?: string;
  generatedAt?: string;
  missedRuns: number;
};

const DAY_MS = 86_400_000;
const WEEK_MS = 7 * DAY_MS;

export function nextRunAfter(base: Date, cadence: Cadence): Date {
  const next = new Date(base);
  if (cadence === "daily") {
    next.setTime(next.getTime() + DAY_MS);
  } else if (cadence === "weekly") {
    next.setTime(next.getTime() + WEEK_MS);
  } else {
    const m = next.getMonth() + 1; // next month, 0-based index for the Date API
    const lastDayOfTarget = new Date(next.getFullYear(), m + 1, 0).getDate();
    next.setFullYear(m === 12 ? next.getFullYear() + 1 : next.getFullYear(), m === 12 ? 0 : m, Math.min(next.getDate(), lastDayOfTarget));
  }
  return next;
}

export function isCadence(v: unknown): v is Cadence {
  return v === "daily" || v === "weekly" || v === "monthly";
}

export function isSchedule(v: unknown): v is Schedule {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.id === "string" &&
    typeof o.caseId === "string" &&
    isCadence(o.cadence) &&
    REPORT_TYPES.some((t) => t.id === o.reportType) &&
    typeof o.nextRunAt === "string" && !Number.isNaN(Date.parse(o.nextRunAt)) &&
    typeof o.missedRuns === "number"
  );
}

export function loadSchedules(): Schedule[] {
  try {
    const raw = localStorage.getItem(SCHED_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown[];
    return Array.isArray(parsed) ? parsed.filter(isSchedule) : [];
  } catch {
    return [];
  }
}

export function saveSchedules(list: Schedule[]) {
  try {
    localStorage.setItem(SCHED_KEY, JSON.stringify(list));
  } catch {
    /* noop */
  }
}

export function addSchedule(input: {
  caseId: string;
  cadence: Cadence;
  reportType: ReportType;
  now?: Date;
}): Schedule {
  const now = input.now ?? new Date();
  const schedule: Schedule = {
    id: `${input.caseId}:${now.getTime()}`,
    caseId: input.caseId,
    cadence: input.cadence,
    reportType: input.reportType,
    createdAt: now.toISOString(),
    nextRunAt: nextRunAfter(now, input.cadence).toISOString(),
    missedRuns: 0,
  };
  saveSchedules([...loadSchedules(), schedule]);
  return schedule;
}

export function removeSchedule(id: string): Schedule[] {
  const next = loadSchedules().filter((s) => s.id !== id);
  saveSchedules(next);
  return next;
}

export function schedulesForCase(list: Schedule[], caseId: string): Schedule[] {
  return list.filter((s) => s.caseId === caseId).sort((a, b) => a.nextRunAt.localeCompare(b.nextRunAt));
}

export function dueSchedules(list: Schedule[], now: Date): Schedule[] {
  return list.filter((s) => new Date(s.nextRunAt).getTime() <= now.getTime());
}

export function advanceAfterRun(schedule: Schedule, now: Date, generatedAt: string): Schedule {
  const due = new Date(schedule.nextRunAt).getTime();
  let next = new Date(due);
  let steps = 0;
  while (next.getTime() < now.getTime()) {
    next = nextRunAfter(next, schedule.cadence);
    steps += 1;
  }
  if (next.getTime() <= now.getTime()) {
    next = nextRunAfter(next, schedule.cadence);
  }
  return {
    ...schedule,
    lastRunAt: now.toISOString(),
    generatedAt,
    nextRunAt: next.toISOString(),
    missedRuns: schedule.missedRuns + Math.max(0, steps - 1),
  };
}

export function generateScheduledSnapshot(c: Case, reportType: ReportType, scheduledFor: string, generatedAt?: string): ReportVersion {
  return snapshotFrom({
    caseId: c.id,
    reportType,
    findings: getUnifiedFindings(c),
    iocs: getUnifiedIOCs(c),
    hypotheses: hypothesisRows(loadHypotheses(), c.id),
    techniques: mitreRows(c).map((r) => r.technique),
    eventCount: c.events?.length ?? 0,
    generatedAt,
    source: "scheduled",
    scheduledFor,
  });
}

export type FireResult = { caseTitle: string; reportType: ReportType; scheduledFor: string; generatedAt: string; missedRuns: number }[];

export function fireDueSchedules(now: Date = new Date()): FireResult {
  const schedules = loadSchedules();
  const due = dueSchedules(schedules, now);
  if (due.length === 0) return [];
  const cases = loadCases();
  const fired: FireResult = [];
  const next = schedules.map((s) => {
    if (!due.some((d) => d.id === s.id)) return s;
    const c = cases.find((x) => x.id === s.caseId);
    if (!c) return s;
    const scheduledFor = s.nextRunAt;
    const version = generateScheduledSnapshot(c, s.reportType, scheduledFor, now.toISOString());
    saveReportVersion(version);
    const advanced = advanceAfterRun(s, now, version.generatedAt);
    fired.push({ caseTitle: c.title, reportType: s.reportType, scheduledFor, generatedAt: version.generatedAt, missedRuns: advanced.missedRuns });
    return advanced;
  });
  saveSchedules(next);
  return fired;
}

export function ReportSchedulerTicker() {
  useEffect(() => {
    const onTick = () => {
      const fired = fireDueSchedules();
      for (const f of fired) {
        const label = REPORT_TYPES.find((t) => t.id === f.reportType)?.label ?? f.reportType;
        notify.info(
          f.missedRuns > 0
            ? `Scheduled ${label} report generated for "${f.caseTitle}" — generated ${f.missedRuns > 1 ? `${f.missedRuns} runs` : "1 run"} late (app was closed at the scheduled time)`
            : `Scheduled ${label} report generated for "${f.caseTitle}"`
        );
      }
    };
    onTick();
    const id = window.setInterval(onTick, TICK_MS);
    return () => window.clearInterval(id);
  }, []);
  return null;
}