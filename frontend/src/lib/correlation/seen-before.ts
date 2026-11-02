import { loadCases, type Case } from "@/data/case";
import { caseValues } from "./history";

export interface SeenBeforeCaseRef {
  id: string;
  title: string;
  createdAt: string;
  state: "active" | "closed";
}

export interface SeenBeforeCard {
  value: string;
  kind: string;
  context: string;
  priorCases: SeenBeforeCaseRef[];
}

export interface SeenBeforeResult {
  cards: SeenBeforeCard[];
  priorCaseIds: string[];
}

/**
 * "Seen before" projection (ROADMAP-v4 V4.2): which of this case's
 * observables also appear in other cases. Derived at render time from the
 * cases store — review only, never feeds back into analysis. Normalization
 * matches buildLocalHistory so this surface and the correlation engine
 * agree on what "same value" means.
 */
export function seenBeforeForCase(active: Case): SeenBeforeResult {
  const self = new Set(caseValues(active));
  if (self.size === 0) return { cards: [], priorCaseIds: [] };

  const kindFor = new Map<string, { kind: string; context: string }>();
  for (const ioc of active.iocs ?? []) {
    const norm = ioc.value.trim().toLowerCase();
    if (!kindFor.has(norm)) kindFor.set(norm, { kind: ioc.type, context: ioc.context });
  }

  const byValue = new Map<string, SeenBeforeCaseRef[]>();

  for (const c of loadCases()) {
    if (c.id === active.id) continue;
    const shared = caseValues(c).filter((v) => self.has(v));
    for (const v of shared) {
      const refs = byValue.get(v) ?? [];
      refs.push({ id: c.id, title: c.title, createdAt: c.createdAt, state: c.state });
      byValue.set(v, refs);
    }
  }

  const cards: SeenBeforeCard[] = [...byValue.entries()]
    .map(([value, priorCases]) => {
      const meta = kindFor.get(value);
      return {
        value,
        kind: meta?.kind ?? "ioc",
        context: meta?.context ?? "",
        priorCases: priorCases.sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0)),
      };
    })
    .sort((a, b) =>
      b.priorCases.length !== a.priorCases.length
        ? b.priorCases.length - a.priorCases.length
        : a.value < b.value ? -1 : a.value > b.value ? 1 : 0,
    );

  const priorCaseIds = [...new Set(cards.flatMap((c) => c.priorCases.map((r) => r.id)))];

  return { cards, priorCaseIds };
}
