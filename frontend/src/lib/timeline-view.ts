import type { CaseEvent, EventCategory, EventActor } from "@/data/case";

export type TimelineSort = "newest" | "oldest";
export type TimelineImportanceFilter = "all" | "high+" | "critical";

const IMPORTANCE_RANK: Record<CaseEvent["importance"], number> = {
  low: 0,
  normal: 1,
  high: 2,
  critical: 3,
};

export type TimelineViewFilters = {
  query?: string;
  categories?: readonly EventCategory[];
  actors?: readonly EventActor[];
  importance?: TimelineImportanceFilter;
  origin?: string;
};

function matchesQuery(ev: CaseEvent, query: string): boolean {
  if (!query) return true;
  const q = query.toLowerCase();
  return (
    ev.title.toLowerCase().includes(q) ||
    ev.detail.toLowerCase().includes(q) ||
    ev.origin.toLowerCase().includes(q)
  );
}

function matchesImportance(ev: CaseEvent, filter: TimelineImportanceFilter): boolean {
  if (filter === "all") return true;
  if (filter === "critical") return ev.importance === "critical";
  return IMPORTANCE_RANK[ev.importance] >= IMPORTANCE_RANK.high;
}

export function filterTimelineEvents(
  events: readonly CaseEvent[],
  filters: TimelineViewFilters,
): { events: CaseEvent[]; hidden: number } {
  const query = (filters.query ?? "").trim();
  const categories = filters.categories;
  const actors = filters.actors;
  const importance = filters.importance ?? "all";
  const origin = filters.origin ?? "";

  const kept = events.filter(ev => {
    if (categories && categories.length > 0 && !categories.includes(ev.category)) return false;
    if (actors && actors.length > 0 && !actors.includes(ev.actor)) return false;
    if (!matchesImportance(ev, importance)) return false;
    if (origin && ev.origin !== origin) return false;
    return matchesQuery(ev, query);
  });
  return { events: kept, hidden: events.length - kept.length };
}

export function sortTimelineEvents(
  events: readonly CaseEvent[],
  sort: TimelineSort,
): CaseEvent[] {
  const dir = sort === "newest" ? -1 : 1;
  return [...events].sort((a, b) => {
    const ta = Date.parse(a.ts);
    const tb = Date.parse(b.ts);
    if (ta !== tb) return (ta - tb) * dir;
    return a.id.localeCompare(b.id) * dir;
  });
}

export function dateKeyOf(ts: string): string {
  const d = new Date(ts);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(
    d.getDate(),
  ).padStart(2, "0")}`;
}

export function dayKeyLabel(dateKey: string, now: Date = new Date()): string {
  const todayKey = dateKeyOf(now.toISOString());
  const yesterdayKey = dateKeyOf(new Date(now.getTime() - 864e5).toISOString());
  if (dateKey === todayKey) return "Today";
  if (dateKey === yesterdayKey) return "Yesterday";
  const [y, m, day] = dateKey.split("-").map(Number);
  return new Date(y, m - 1, day).toLocaleDateString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

export type TimelineDayGroup = {
  dateKey: string;
  label: string;
  events: CaseEvent[];
};

/** Group already-filtered, already-sorted events into descending day buckets. */
export function groupTimelineByDay(
  events: readonly CaseEvent[],
  now: Date = new Date(),
): TimelineDayGroup[] {
  const groups = new Map<string, CaseEvent[]>();
  for (const ev of events) {
    const key = dateKeyOf(ev.ts);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(ev);
  }
  return Array.from(groups.entries())
    .sort(([a], [b]) => b.localeCompare(a))
    .map(([dateKey, dayEvents]) => ({
      dateKey,
      label: dayKeyLabel(dateKey, now),
      events: dayEvents,
    }));
}
