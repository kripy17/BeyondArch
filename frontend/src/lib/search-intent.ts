import type { SearchItemType } from "@/lib/search-index";

export type SearchIntent = {
  scope: SearchItemType[] | null;
  term: string;
  recentDays?: number;
  note?: string;
};

const TYPE_BY_WORD: Record<string, SearchItemType | undefined> = {
  case: "case", cases: "case", investigation: "case", investigations: "case",
  finding: "finding", findings: "finding",
  ioc: "ioc", iocs: "ioc", observable: "ioc", observables: "ioc", ip: "ioc", hash: "ioc",
  detection: "detection", detections: "detection", rule: "detection", rules: "detection", signature: "detection", signatures: "detection",
  report: "report", reports: "report",
  entity: "entity", entities: "entity", actor: "entity", group: "entity", malware: "entity",
  event: "event", events: "event", alert: "alert", alerts: "alert",
  note: "note", notes: "note", artifact: "artifact", artifacts: "artifact",
};

const NOISE = /^(?:show|me|find|list|any|all|the|a|an|of|my|recent)\s+/gi;

export function detectIntent(raw: string): SearchIntent {
  const q = raw.trim();
  if (!q) return { scope: null, term: "", note: undefined };

  const recent = q.match(/^recent\s+(.+)$/i);
  if (recent) {
    const tail = recent[1].trim();
    const words = tail.toLowerCase().split(/\s+/).filter(Boolean);
    const first = words[0];
    const scopeType = first ? TYPE_BY_WORD[first] : undefined;
    const scope = scopeType ? [scopeType] : null;
    const term = scopeType && words.length > 1 ? words.slice(1).join(" ") : scopeType ? "" : tail;
    return {
      scope,
      term: cleanTerm(term),
      recentDays: 7,
      note: scope ? `${TYPE_LABEL[scopeType!]} only · last 7 days` : "last 7 days",
    };
  }

  const typeWord = q.match(/(?:^|\s)([a-z]+s?)\s+(?:involving|with|about|for|on|related to)\s+(.+)$/i);
  if (typeWord) {
    const t = TYPE_BY_WORD[typeWord[1].toLowerCase()];
    if (t) {
      return { scope: [t], term: cleanTerm(typeWord[2]), note: `${TYPE_LABEL[t]} only` };
    }
  }

  const tailType = q.match(/^(.+?)\s+(detections?|rules?|signatures?|investigations?|cases?|iocs?|findings?)\s*$/i);
  if (tailType && tailType[1].trim().length > 0) {
    const t = TYPE_BY_WORD[tailType[2].toLowerCase().replace(/s$/, "") === "investigation" ? "case" : normalizePlural(tailType[2])];
    if (t) {
      return { scope: [t], term: cleanTerm(tailType[1]), note: `${TYPE_LABEL[t]} only` };
    }
  }

  return { scope: null, term: q, note: undefined };
}

function cleanTerm(raw: string): string {
  return raw.replace(NOISE, "").trim().replace(/\s+/g, " ");
}

function normalizePlural(word: string): string {
  const w = word.toLowerCase().replace(/s$/, "");
  if (w === "case" || w === "investigation" || w === "detection" || w === "ioc" || w === "finding" || w === "rule") return w;
  return word.toLowerCase();
}

const TYPE_LABEL: Record<string, string> = {
  case: "cases", finding: "findings", ioc: "iocs", detection: "detections", report: "reports",
  entity: "entities", event: "events", alert: "alerts", note: "notes", artifact: "artifacts",
};

export function applyIntent<T extends { type: SearchItemType; metadata?: Record<string, string> }>(items: T[], intent: SearchIntent): T[] {
  let out = items;
  if (intent.scope) out = out.filter((i) => intent.scope!.includes(i.type));
  if (intent.recentDays != null) {
    out = out.filter((i) => {
      const age = i.metadata?.age;
      return age != null && Number(age) <= intent.recentDays!;
    });
  }
  return out;
}