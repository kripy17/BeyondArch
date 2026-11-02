/**
 * Session-recovery depth (Analyst experience v1): per-view UI state (active
 * tab, filters, graph mode/hops) persisted under one namespaced store so a
 * reload resumes where the analyst left off. Pure storage — no behavior.
 */
import { storageGet, storageSet } from "@/lib/storage";

export const SESSION_VIEW_KEY = "ba.session.view.v1";
export const SESSION_VIEW_TTL_MS = 7 * 24 * 60 * 60 * 1000;

interface Entry {
  v: unknown;
  ts: number;
}

type Store = Record<string, Entry>;

function prune(store: Store, now = Date.now()): Store {
  const out: Store = {};
  for (const [k, e] of Object.entries(store)) {
    if (e && typeof e.ts === "number" && now - e.ts <= SESSION_VIEW_TTL_MS) out[k] = e;
  }
  return out;
}

export function loadViewState<T>(key: string): T | null {
  const all = prune(storageGet<Store>(SESSION_VIEW_KEY, {}));
  return (all[key]?.v as T | undefined) ?? null;
}

export function saveViewState<T>(key: string, value: T): void {
  const all = prune(storageGet<Store>(SESSION_VIEW_KEY, {}));
  all[key] = { v: value, ts: Date.now() };
  storageSet(SESSION_VIEW_KEY, all);
}

export function clearViewState(key: string): void {
  const all = storageGet<Store>(SESSION_VIEW_KEY, {});
  delete all[key];
  storageSet(SESSION_VIEW_KEY, all);
}

export function clearAllViewStates(): void {
  try { localStorage.removeItem(SESSION_VIEW_KEY); } catch { /* best-effort */ }
}
