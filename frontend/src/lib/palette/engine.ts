import type { CommandResult, PaletteContext, PaletteProvider } from "./types";

export function rankResults(
  providers: PaletteProvider[],
  input: string,
  ctx: PaletteContext,
): { header: string; results: CommandResult[] }[] {
  const all: CommandResult[] = [];
  const seen = new Set<string>();

  for (const provider of providers) {
    try {
      const results = provider.getResults(input, ctx);
      for (const r of results) {
        if (!seen.has(r.id)) {
          seen.add(r.id);
          all.push(r);
        }
      }
    } catch {
      /* provider error, skip */
    }
  }

  const q = input.trim().toLowerCase();
  const scored = all.map((r) => {
    let score = r.score;

    if (q) {
      const haystack = [r.title, r.subtitle ?? "", ...r.keywords].join(" ").toLowerCase();
      const exactMatch = haystack.includes(q);

      if (r.title.toLowerCase().startsWith(q)) score += 15;
      else if (exactMatch) score += 8;
      else {
        const words = q.split(/\s+/);
        const matchCount = words.filter((w) => haystack.includes(w)).length;
        score += (matchCount / words.length) * 10;
      }
    }

    if (ctx.activeCase && r.category === "Investigation") score += 12;

    return { ...r, score };
  });

  scored.sort((a, b) => b.score - a.score);

  const groups: { header: string; results: CommandResult[] }[] = [];
  const catOrder = ["Investigation", "Search", "Navigate", "Intel", "Intake", "Detection", "Create", "Macros", "Recent", "Actions"];
  const catMap = new Map<string, CommandResult[]>();

  for (const r of scored) {
    const cat = r.category;
    if (!catMap.has(cat)) catMap.set(cat, []);
    catMap.get(cat)!.push(r);
  }

  for (const cat of catOrder) {
    const items = catMap.get(cat);
    if (items && items.length > 0) {
      groups.push({ header: cat, results: items });
    }
  }

  return groups;
}
