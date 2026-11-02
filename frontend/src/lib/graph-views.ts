/**
 * Named, restorable graph views per case (ROADMAP-v4 V4.2): filters, focus
 * node, and viewport saved together under an analyst-chosen name. Pure
 * storage — validation happens on read so junk entries never surface.
 */
import { storageGet, storageSet } from "@/lib/storage";

export const GRAPH_VIEWS_KEY = "ba.graph.views.v1";
export const MAX_VIEWS_PER_CASE = 20;

export type NamedViewState = {
  mode?: unknown;
  hops?: unknown;
  source?: unknown;
  confidence?: unknown;
  kinds?: unknown;
  relations?: unknown;
};

export type NamedGraphView = {
  id: string;
  caseId: string;
  name: string;
  state: NamedViewState;
  focus: string | null;
  viewport: { x: number; y: number; zoom: number } | null;
  savedAt: number;
};

function validViewport(vp: unknown): NamedGraphView["viewport"] {
  if (!vp || typeof vp !== "object") return null;
  const { x, y, zoom } = vp as Record<string, unknown>;
  if (
    typeof x !== "number" || !Number.isFinite(x) ||
    typeof y !== "number" || !Number.isFinite(y) ||
    typeof zoom !== "number" || !Number.isFinite(zoom) ||
    zoom < 0.15 || zoom > 1.75
  ) return null;
  return { x, y, zoom };
}

function validView(raw: unknown): NamedGraphView | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.id !== "string" || !r.id) return null;
  if (typeof r.caseId !== "string" || !r.caseId) return null;
  if (typeof r.name !== "string" || !r.name.trim()) return null;
  if (typeof r.savedAt !== "number" || !Number.isFinite(r.savedAt)) return null;
  return {
    id: r.id,
    caseId: r.caseId,
    name: r.name.trim(),
    state: r.state && typeof r.state === "object" ? (r.state as NamedViewState) : {},
    focus: typeof r.focus === "string" && r.focus.includes(":") ? r.focus : null,
    viewport: validViewport(r.viewport),
    savedAt: r.savedAt,
  };
}

type Store = Record<string, NamedGraphView[]>;

function loadStore(): Store {
  return storageGet<Store>(GRAPH_VIEWS_KEY, {});
}

export function loadGraphViews(caseId: string): NamedGraphView[] {
  const store = loadStore();
  const list = Array.isArray(store[caseId]) ? store[caseId] : [];
  return list
    .map(validView)
    .filter((v): v is NamedGraphView => v !== null)
    .sort((a, b) => b.savedAt - a.savedAt);
}

export function saveNamedView(
  caseId: string,
  name: string,
  state: NamedViewState,
  focus: string | null,
  viewport: NamedGraphView["viewport"],
  now = Date.now(),
): NamedGraphView {
  const trimmed = name.trim();
  if (!trimmed) throw new Error("view name required");
  const store = loadStore();
  const list = Array.isArray(store[caseId]) ? store[caseId] : [];
  const existingIdx = list.findIndex((v) => validView(v)?.name === trimmed);
  const view: NamedGraphView = {
    id: existingIdx >= 0 ? (list[existingIdx] as NamedGraphView).id : `${now.toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
    caseId,
    name: trimmed,
    state,
    focus,
    viewport,
    savedAt: now,
  };
  const next = existingIdx >= 0
    ? list.map((v, i) => (i === existingIdx ? view : v))
    : [view, ...list].slice(0, MAX_VIEWS_PER_CASE);
  store[caseId] = next;
  storageSet(GRAPH_VIEWS_KEY, store);
  return view;
}

export function deleteNamedView(caseId: string, id: string): void {
  const store = loadStore();
  const list = Array.isArray(store[caseId]) ? store[caseId] : [];
  store[caseId] = list.filter((v) => (validView(v)?.id ?? v) !== id);
  storageSet(GRAPH_VIEWS_KEY, store);
}
