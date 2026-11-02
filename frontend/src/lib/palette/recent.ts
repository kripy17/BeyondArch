/** Recent palette commands (Analyst experience v1): last N invoked results. */
export interface RecentCommand {
  id: string;
  title: string;
  ts: number;
}

const RECENT_KEY = "ba.palette.recent.v1";
const RECENT_LIMIT = 8;

export function loadRecentCommands(): RecentCommand[] {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : [];
    return Array.isArray(parsed)
      ? parsed.filter((x): x is RecentCommand => Boolean(x && typeof (x as RecentCommand).id === "string"))
      : [];
  } catch {
    return [];
  }
}

/** Record an invocation; identical ids move to the front. */
export function recordRecentCommand(id: string, title: string) {
  const next = [{ id, title, ts: Date.now() }, ...loadRecentCommands().filter((c) => c.id !== id)].slice(0, RECENT_LIMIT);
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(next));
  } catch {
    /* best-effort */
  }
}