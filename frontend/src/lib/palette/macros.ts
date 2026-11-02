/**
 * Palette macros (Analyst experience v1): named, replayable sequences of
 * recently invoked palette commands. Steps are stored as {id, title} pairs and
 * re-resolved against live providers at run time — closures are never stored,
 * so replays always execute the current behavior for a command id.
 */
import { objectId } from "@/lib/ids";
import { loadRecentCommands, type RecentCommand } from "./recent";

export const MACROS_KEY = "ba.palette.macros.v1";
export const MACRO_STEPS_LIMIT = 8;

export interface MacroStep {
  id: string;
  title: string;
}

export interface Macro {
  id: string;
  name: string;
  steps: MacroStep[];
  createdAt: number;
}

/** Deterministic id (constraint 5): same normalized name → same macro id, so
 * re-saving a name replaces the previous definition instead of duplicating. */
export function macroId(name: string): string {
  return `mac-${objectId("palette-macro", name.trim().toLowerCase())}`;
}

function isValidMacro(m: unknown): m is Macro {
  if (!m || typeof m !== "object") return false;
  const x = m as Macro;
  return (
    typeof x.id === "string" &&
    typeof x.name === "string" &&
    typeof x.createdAt === "number" &&
    Array.isArray(x.steps) &&
    x.steps.every((s) => s && typeof s.id === "string" && typeof s.title === "string")
  );
}

export function loadMacros(): Macro[] {
  try {
    const raw = localStorage.getItem(MACROS_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : [];
    const list = Array.isArray(parsed) ? parsed.filter(isValidMacro) : [];
    return list.sort((a, b) => b.createdAt - a.createdAt);
  } catch {
    return [];
  }
}

function persist(macros: Macro[]) {
  try {
    localStorage.setItem(MACROS_KEY, JSON.stringify(macros));
  } catch {
    /* best-effort */
  }
}

/**
 * Build a macro from the recent-command ledger. Duplicate step ids are deduped
 * keeping the most recent occurrence; capped at MACRO_STEPS_LIMIT.
 * Returns null when the name is empty or there is nothing to record — never
 * fabricates an empty macro.
 */
export function createMacroFromRecent(
  name: string,
  recents: RecentCommand[] = loadRecentCommands(),
  limit: number = MACRO_STEPS_LIMIT,
): Macro | null {
  const clean = name.trim();
  if (!clean) return null;
  const seen = new Set<string>();
  const steps: MacroStep[] = [];
  for (const r of recents) {
    if (!r.id || !r.title || seen.has(r.id)) continue;
    seen.add(r.id);
    steps.push({ id: r.id, title: r.title });
    if (steps.length >= limit) break;
  }
  if (steps.length === 0) return null;
  const id = macroId(clean);
  const macro: Macro = { id, name: clean, steps, createdAt: Date.now() };
  const rest = loadMacros().filter((m) => m.id !== id);
  persist([macro, ...rest]);
  return macro;
}

export function deleteMacro(id: string): void {
  persist(loadMacros().filter((m) => m.id !== id));
}
