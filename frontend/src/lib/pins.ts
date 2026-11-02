/**
 * Case pinning (Dashboard 2.0). Lightweight localStorage set of case ids —
 * pinned investigations surface on the dashboard and sort first in the case
 * sidebar. Mirrors the SIEM-hunt `pinned` precedent but stays keyed by id so
 * pins survive case renames.
 */
export const PINS_KEY = "ba.pins.v1";

export function loadPinnedCaseIds(): string[] {
  try {
    const raw = localStorage.getItem(PINS_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : [];
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

function savePinnedCaseIds(ids: string[]) {
  try {
    localStorage.setItem(PINS_KEY, JSON.stringify(ids));
  } catch {
    /* best-effort */
  }
}

export function isPinned(caseId: string): boolean {
  return loadPinnedCaseIds().includes(caseId);
}

/** Toggle pin state for a case id; returns the new pinned value. */
export function togglePin(caseId: string): boolean {
  const ids = loadPinnedCaseIds();
  const next = ids.includes(caseId) ? ids.filter((id) => id !== caseId) : [caseId, ...ids];
  savePinnedCaseIds(next);
  return next.includes(caseId);
}

/* ── Namespaced pins (personal workspace) ─────────────────
 * One storage key, one bucket per surface so detection rules,
 * intel entities, hunts and cases can each pin independently.
 * Ids only — titles resolve live at render time, so renames
 * never orphan a pin. */

export const PINS_V2_KEY = "ba.pins.v2";

export type PinNamespace = "detection" | "entity" | "hunt";

const NS_SET: Set<string> = new Set(["detection", "entity", "hunt"]);

function loadPinsV2(): Record<string, string[]> {
  try {
    const raw = localStorage.getItem(PINS_V2_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : {};
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const out: Record<string, string[]> = {};
    for (const [ns, ids] of Object.entries(parsed as Record<string, unknown>)) {
      if (!NS_SET.has(ns) || !Array.isArray(ids)) continue;
      out[ns] = ids.filter((x): x is string => typeof x === "string");
    }
    return out;
  } catch {
    return {};
  }
}

function savePinsV2(map: Record<string, string[]>) {
  try { localStorage.setItem(PINS_V2_KEY, JSON.stringify(map)); } catch { /* best-effort */ }
}

export function loadPins(ns: PinNamespace): string[] {
  return loadPinsV2()[ns] ?? [];
}

export function isPinnedIn(ns: PinNamespace, id: string): boolean {
  return loadPins(ns).includes(id);
}

/** Toggle pin for a namespaced id; returns the new pinned value. */
export function togglePinned(ns: PinNamespace, id: string): boolean {
  const map = loadPinsV2();
  const ids = map[ns] ?? [];
  map[ns] = ids.includes(id) ? ids.filter((x) => x !== id) : [id, ...ids];
  savePinsV2(map);
  return map[ns].includes(id);
}
