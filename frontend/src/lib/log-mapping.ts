/* Log field mapping: detect columnar log formats, guess semantic fields
 * (src/dst/user/sig/sev), let analysts correct the guesses, persist
 * corrections per detected source format. All local storage; heuristics are
 * labeled as such in the UI. Architectural freeze: pure data + storage,
 * no new analysis engine — corrections only affect display/extraction here.
 */

import { storageGet, storageSet } from "@/lib/storage";

export const SEMANTIC_FIELDS = ["src", "dst", "user", "sig", "sev"] as const;
export type SemanticField = (typeof SEMANTIC_FIELDS)[number];

export type GuessConfidence = "high" | "medium" | "low";

export interface FieldGuess {
  source: string;
  columns: string[];
  guess: Partial<Record<SemanticField, string>>;
  confidence: Partial<Record<SemanticField, GuessConfidence>>;
}

export interface StoredMapping {
  fields: Partial<Record<SemanticField, string>>;
  updatedAt: number;
}

export const LOG_MAPPINGS_KEY = "ba.parser.mappings.v1";

type MappingStore = Record<string, StoredMapping>;

function readStore(): MappingStore {
  return storageGet<MappingStore>(LOG_MAPPINGS_KEY, {});
}

export function loadStoredMapping(source: string): StoredMapping | null {
  return readStore()[source] ?? null;
}

export function saveFieldMapping(source: string, field: SemanticField, key: string | null): void {
  const store = readStore();
  const cur = store[source] ?? { fields: {}, updatedAt: Date.now() };
  const fields = { ...cur.fields };
  if (key === null) delete fields[field];
  else fields[field] = key;
  store[source] = { fields, updatedAt: Date.now() };
  storageSet(LOG_MAPPINGS_KEY, store);
}

const CANONICAL: Record<SemanticField, RegExp[]> = {
  src: [/^src_ip$/i, /^src$/i, /^source\.ip$/i],
  dst: [/^dst_ip$/i, /^dest_ip$/i, /^dst$/i, /^dest$/i, /^destination\.ip$/i],
  user: [/^user_?name$/i, /^user(name)?$/i, /^suser$/i, /^duser$/i, /^account_name$/i, /^source\.user\.name$/i],
  sig: [/^signature$/i, /^(alert\.)?rule_name$/i, /^alert\.signature$/i, /^sig$/i],
  sev: [/^(alert\.)?severity$/i, /^sev$/i, /^level$/i, /^priority$/i],
};

const ALIASES: Record<SemanticField, RegExp[]> = {
  src: [/^id\.orig_h$/i, /^client(ip)?$/i, /^ip_?src/i, /^source(_addr|_address)?$/i, /^c-ip$/i],
  dst: [/^id\.resp_h$/i, /^server(ip)?$/i, /^ip_?dst/i, /^target(_addr|_address)?$/i, /^r-ip$/i],
  user: [/_user$/i, /^usr$/i, /^login$/i, /^principal$/i],
  sig: [/(alert|event)_?name$/i, /^msg$/i, /^name$/i, /^cs1$/i],
  sev: [/^(alert\.)?(risk|urgency)$/i, /^cs2$/i],
};

function bestMatch(columns: string[], field: SemanticField): { col: string; level: GuessConfidence } | null {
  for (const rx of CANONICAL[field]) {
    const hit = columns.find((c) => rx.test(c));
    if (hit) return { col: hit, level: "high" };
  }
  for (const rx of ALIASES[field]) {
    const hit = columns.find((c) => rx.test(c));
    if (hit) return { col: hit, level: "medium" };
  }
  return null;
}

function flattenKeys(obj: Record<string, unknown>, prefix = "", depth = 0): string[] {
  if (depth > 1) return [];
  const out: string[] = [];
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) out.push(...flattenKeys(v as Record<string, unknown>, key, depth + 1));
    else out.push(key);
  }
  return out;
}

function zeekColumns(text: string): string[] | null {
  const m = text.match(/^#fields\s+(.+)$/m);
  if (!m) return null;
  return m[1].trim().split(/\t+/);
}

function csvColumns(text: string): string[] | null {
  const first = text.split(/\r?\n/)[0] ?? "";
  if (!first.includes(",")) return null;
  const cols = first.split(",").map((c) => c.trim().replace(/^"|"$/g, ""));
  return cols.length >= 2 && cols.every((c) => /^[\w .-]+$/.test(c)) ? cols : null;
}

function jsonKeys(text: string): string[] | null {
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    try { return flattenKeys(JSON.parse(t) as Record<string, unknown>); } catch { return null; }
  }
  return null;
}

function cefExtension(text: string): { columns: string[]; headerSig: string; headerSev: string } | null {
  const line = text.split(/\r?\n/).find((l) => l.includes("CEF:"));
  if (!line) return null;
  const pipes = line.split("|");
  if (pipes.length < 7) return null;
  const ext = pipes.slice(7).join("|");
  const keys = Array.from(ext.matchAll(/(\w+)=/g)).map((m) => m[1]);
  return { columns: keys, headerSig: pipes[5]?.trim() ?? "", headerSev: pipes[6]?.trim() ?? "" };
}

/** Detect a columnar format and propose semantic-field guesses from headers/keys. */
export function detectLogFields(text: string): FieldGuess | null {
  const t = text.trim();
  if (!t) return null;

  const build = (source: string, columns: string[]): FieldGuess => {
    const guess: Partial<Record<SemanticField, string>> = {};
    const confidence: Partial<Record<SemanticField, GuessConfidence>> = {};
    for (const f of SEMANTIC_FIELDS) {
      const m = bestMatch(columns, f);
      if (m) { guess[f] = m.col; confidence[f] = m.level; }
    }
    return { source, columns, guess, confidence };
  };

  const zeek = zeekColumns(t);
  if (zeek) return build("zeek-tsv", zeek);

  const csv = csvColumns(t);
  if (csv) return build("csv", csv);

  const json = jsonKeys(t);
  if (json && json.length) return build("json", json);

  const cef = cefExtension(t);
  if (cef) {
    const g = build("cef", [...cef.columns]);
    if (cef.headerSig && !g.guess.sig) { g.guess.sig = "__cef_header_name"; g.confidence.sig = "medium"; }
    if (cef.headerSev && !g.guess.sev) { g.guess.sev = "__cef_header_severity"; g.confidence.sev = "medium"; }
    return g;
  }

  return null;
}

export function extractValue(rowText: string, source: string, key: string): string | null {
  if (key.startsWith("__cef_header")) {
    const pipes = rowText.split("|");
    return key === "__cef_header_name" ? pipes[5]?.trim() ?? null : pipes[6]?.trim() ?? null;
  }
  if (source === "json") {
    try {
      const obj = JSON.parse(rowText) as Record<string, unknown>;
      let cur: unknown = obj;
      for (const part of key.split(".")) {
        if (!cur || typeof cur !== "object") return null;
        cur = (cur as Record<string, unknown>)[part];
      }
      return cur === undefined || cur === null ? null : String(cur);
    } catch { return null; }
  }
  if (source === "zeek-tsv") {
    const fieldsLine = rowText.match(/^#fields\s+(.+)$/m);
    if (fieldsLine) {
      const cols = fieldsLine[1].trim().split(/\t+/);
      const dataLine = rowText.split(/\r?\n/).find((l) => l && !l.startsWith("#"));
      if (!dataLine) return null;
      const idx = cols.indexOf(key);
      return idx >= 0 ? (dataLine.split("\t")[idx] ?? null) : null;
    }
    return null;
  }
  const first = rowText.split(/\r?\n/)[0] ?? "";
  if (source === "csv") {
    const headerLine = first;
    const cols = headerLine.split(",").map((c) => c.trim().replace(/^"|"$/g, ""));
    const idx = cols.indexOf(key);
    const dataLine = rowText.split(/\r?\n/)[1];
    if (idx < 0 || !dataLine) return null;
    return (dataLine.split(",")[idx] ?? "").trim().replace(/^"|"$/g, "") || null;
  }
  const m = rowText.match(new RegExp(`${key}=([^\\s|]*)`));
  return m ? m[1] || null : null;
}

/** Effective mapping: analyst correction wins over auto-guess. Absent key = auto guess. */
export function effectiveMapping(guess: FieldGuess, stored: StoredMapping | null): Partial<Record<SemanticField, string>> {
  const merged: Partial<Record<SemanticField, string>> = { ...guess.guess };
  if (!stored) return merged;
  for (const f of SEMANTIC_FIELDS) {
    const v = stored.fields[f];
    if (typeof v === "string") merged[f] = v;
  }
  return merged;
}
