import type { SiemEvent } from "@/data/siem";

export type FacetCategory = "network" | "identity" | "endpoint" | "web" | "security";

export interface FacetValue {
  value: string;
  count: number;
  percent: number;
}

export interface FieldFacet {
  field: string;
  label: string;
  category: FacetCategory;
  coverage: number; // 0 to 100
  totalPopulated: number;
  uniqueCount: number;
  topValues: FacetValue[];
}

export const FACET_DEFINITIONS: { field: string; label: string; category: FacetCategory }[] = [
  { field: "src", label: "Source IP / Host", category: "network" },
  { field: "dst", label: "Destination IP / Host", category: "network" },
  { field: "user", label: "User Account", category: "identity" },
  { field: "sig", label: "Signature / Event Message", category: "security" },
  { field: "sev", label: "Severity Level", category: "security" },
];

/**
 * Computes field facet statistics across an array of SIEM events.
 */
export function computeFieldFacets(events: SiemEvent[]): FieldFacet[] {
  const total = events.length;
  if (total === 0) {
    return FACET_DEFINITIONS.map((def) => ({
      field: def.field,
      label: def.label,
      category: def.category,
      coverage: 0,
      totalPopulated: 0,
      uniqueCount: 0,
      topValues: [],
    }));
  }

  return FACET_DEFINITIONS.map((def) => {
    const counts = new Map<string, number>();
    let populatedCount = 0;

    for (const e of events) {
      const rawVal = e[def.field as keyof SiemEvent];
      const val = String(rawVal ?? "").trim();
      if (val && val !== "—" && val !== "-") {
        populatedCount++;
        counts.set(val, (counts.get(val) || 0) + 1);
      }
    }

    const coverage = Math.round((populatedCount / total) * 100);
    const sorted = Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    const topValues: FacetValue[] = sorted.map(([value, count]) => ({
      value,
      count,
      percent: Math.round((count / populatedCount) * 100),
    }));

    return {
      field: def.field,
      label: def.label,
      category: def.category,
      coverage,
      totalPopulated: populatedCount,
      uniqueCount: counts.size,
      topValues,
    };
  });
}
