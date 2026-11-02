import { useMemo, useState, useEffect, useRef } from "react";
import Fuse from "fuse.js";
import { buildSearchIndex, type SearchItem } from "@/lib/search-index";
import { detectObservable } from "@/lib/palette/intent";
import { LS_ACTIVE } from "@/data/case";

let cache: { index: SearchItem[]; fuse: Fuse<SearchItem> } | null = null;

function ensureBuilt() {
  if (!cache) {
    const index = buildSearchIndex();
    const fuse = new Fuse(index, {
      keys: [
        { name: "label", weight: 10 },
        { name: "description", weight: 5 },
        { name: "tags", weight: 3 },
      ],
      threshold: 0.35,
      distance: 100,
    });
    cache = { index, fuse };
  }
  return cache;
}

export function invalidateSearchCache() {
  cache = null;
}

function activeCaseId(): string | null {
  try { return localStorage.getItem(LS_ACTIVE); } catch { return null; }
}

function rankScore(item: SearchItem, query: string, fuseScore: number): number {
  const q = query.trim().toLowerCase();
  const label = item.label.toLowerCase();
  let s = 0;
  if (label === q) s += 1000;
  const obsKind = detectObservable(q);
  if (obsKind && (item.type === "ioc" || item.type === "entity") && (label === q || item.objectId?.toLowerCase() === q)) s += 2000;
  if (item.caseId && item.caseId === activeCaseId()) s += 300;
  s += (item.scoreWeight ?? 0) * 10;
  s += (1 - fuseScore) * 100;
  return s;
}

export function searchIndex(query: string, opts?: { log?: boolean }): SearchItem[] {
  const { index, fuse } = ensureBuilt();
  const { qualifiers, text } = parseQualifiers(query ?? "");
  const cleaned = text.trim();
  if (!query.trim()) {
    return [...index].sort((a, b) => (b.scoreWeight ?? 0) - (a.scoreWeight ?? 0)).slice(0, 250);
  }
  if (opts?.log !== false && query.trim().length >= 2) logSearchQuery(query);
  const qualifies = (item: SearchItem) => qualifiers.every((q) => matchesQualifier(item, q));
  if (!cleaned) {
    return [...index]
      .filter(qualifies)
      .sort((a, b) => (b.scoreWeight ?? 0) - (a.scoreWeight ?? 0))
      .slice(0, 250);
  }
  const q = cleaned;
  return fuse
    .search(q)
    .map((r) => ({ item: r.item, score: rankScore(r.item, q, r.score ?? 1) }))
    .filter(({ item }) => qualifies(item))
    .sort((a, b) => b.score - a.score)
    .slice(0, 250)
    .map((r) => r.item);
}

const SEARCH_LOG_KEY = "ba.search.log";

/* ── GitHub-style qualifiers (Global Search 2.0) ────────── */

export type Qualifier = { key: string; value: string };

/** Whitelist of qualifier keys. Anything else keeps its colon as plain text
 *  (e.g. CVE-2024-1234, IPv6 addresses, URLs). */
const QUALIFIER_KEYS = new Set([
  "type", "severity", "tag", "state", "source", "technique", "format",
  "ioctype", "kind", "category", "importance", "tactic", "entity",
  "confidence", "status", "actor", "report",
]);

export function parseQualifiers(query: string): { qualifiers: Qualifier[]; text: string } {
  const qualifiers: Qualifier[] = [];
  const rest: string[] = [];
  for (const token of query.trim().split(/\s+/)) {
    const m = token.match(/^([a-zA-Z]+):(.+)$/);
    if (m && QUALIFIER_KEYS.has(m[1].toLowerCase())) {
      qualifiers.push({ key: m[1].toLowerCase(), value: m[2] });
    } else {
      rest.push(token);
    }
  }
  return { qualifiers, text: rest.join(" ") };
}

const normTechnique = (v: string) => v.replace(/[.\s]/g, "").toLowerCase();

export function matchesQualifier(item: SearchItem, q: Qualifier): boolean {
  const v = q.value.toLowerCase();
  const meta = item.metadata ?? {};
  const text = `${item.label} ${item.description} ${item.tags}`.toLowerCase();
  switch (q.key) {
    case "type": return item.type === q.value;
    case "severity": return meta.severity?.toLowerCase() === v;
    case "tag": {
      const field = (meta.tags ?? "").toLowerCase();
      return item.tags.toLowerCase().includes(v) || field.split(/[, ]+/).some((t) => t.includes(v));
    }
    case "state": return meta.state?.toLowerCase() === v;
    case "source": return meta.source?.toLowerCase() === v;
    case "technique": return normTechnique(meta.technique ?? "").includes(normTechnique(q.value));
    case "format": return meta.format?.toLowerCase() === v;
    case "ioctype": return meta.iocType?.toLowerCase() === v;
    case "kind": return meta.kind?.toLowerCase() === v;
    case "category": return meta.category?.toLowerCase() === v;
    case "importance": return meta.importance?.toLowerCase() === v;
    case "tactic": return meta.tactic?.toLowerCase() === v;
    case "entity": return meta.entityType?.toLowerCase() === v;
    case "confidence": return meta.confidence?.toLowerCase() === v;
    case "status": return meta.status?.toLowerCase() === v;
    case "actor": return item.type === "entity" && text.includes(v);
    case "report": return item.type === "report" && text.includes(v);
    default: return true;
  }
}

export function logSearchQuery(query: string) {
  try {
    const log = JSON.parse(localStorage.getItem(SEARCH_LOG_KEY) || "[]");
    log.push({ q: query.trim(), ts: Date.now() });
    if (log.length > 1000) log.splice(0, log.length - 1000);
    localStorage.setItem(SEARCH_LOG_KEY, JSON.stringify(log));
  } catch {}
}

export function getSearchLog(): { q: string; ts: number }[] {
  try { return JSON.parse(localStorage.getItem(SEARCH_LOG_KEY) || "[]"); } catch { return []; }
}

export function clearSearchLog() {
  try { localStorage.removeItem(SEARCH_LOG_KEY); } catch {}
}

declare global {
  interface Window {
    __searchLog?: typeof import("./search-engine");
  }
}
if (typeof window !== "undefined") {
  window.__searchLog = { searchIndex, invalidateSearchCache, getSearchLog, clearSearchLog, logSearchQuery, parseQualifiers, matchesQualifier } as any;
}

export function useSearch(query: string, opts?: { log?: boolean }): SearchItem[] {
  const [tick, setTick] = useState(0);

  const optsRef = useRef(opts);
  optsRef.current = opts;

  useEffect(() => {
    const fn = () => { invalidateSearchCache(); setTick((v) => v + 1); };
    window.addEventListener("search-index-invalidate", fn);
    return () => window.removeEventListener("search-index-invalidate", fn);
  }, []);

  return useMemo(() => { void tick; return searchIndex(query, optsRef.current); }, [query, tick]);
}
