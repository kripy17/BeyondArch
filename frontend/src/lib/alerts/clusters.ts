import { extractIocsFromText } from "@/lib/alerts/escalate";
import type { TriageItem } from "@/data/triage";

export type ClusterKind = "ioc" | "technique" | "unclustered";

export type AlertCluster = {
  key: string;
  kind: ClusterKind;
  label: string;
  iocType?: string;
  items: TriageItem[];
};

const TECHNIQUE_RE = /\bT\d{4}(?:\.\d{3})?\b/gi;

export function extractTechniques(...texts: (string | undefined)[]): string[] {
  const seen = new Set<string>();
  for (const text of texts) {
    if (!text) continue;
    for (const match of text.matchAll(TECHNIQUE_RE)) {
      seen.add(match[0].toUpperCase());
    }
  }
  return [...seen];
}

const CLUSTERABLE_STATUSES = new Set(["open", "in_review"]);

export function clusterItems(items: TriageItem[]): AlertCluster[] {
  const byKey = new Map<string, AlertCluster>();
  const unclustered: TriageItem[] = [];

  for (const item of items) {
    if (!CLUSTERABLE_STATUSES.has(item.status)) continue;
    const iocs = item.iocs?.length ? item.iocs : extractIocsFromText(item.title, item.description);
    const techniques = extractTechniques(item.title, item.description);

    let keyed = false;
    for (const ioc of iocs) {
      const key = `ioc:${ioc.type}:${ioc.value}`;
      let cluster = byKey.get(key);
      if (!cluster) {
        cluster = { key, kind: "ioc", label: ioc.value, iocType: ioc.type, items: [] };
        byKey.set(key, cluster);
      }
      if (!cluster.items.some((i) => i.id === item.id)) cluster.items.push(item);
      keyed = true;
    }
    for (const technique of techniques) {
      const key = `technique:${technique}`;
      let cluster = byKey.get(key);
      if (!cluster) {
        cluster = { key, kind: "technique", label: technique, items: [] };
        byKey.set(key, cluster);
      }
      if (!cluster.items.some((i) => i.id === item.id)) cluster.items.push(item);
      keyed = true;
    }
    if (!keyed) unclustered.push(item);
  }

  const clusters = [...byKey.values()];
  if (unclustered.length > 0) {
    clusters.push({ key: "unclustered", kind: "unclustered", label: "no shared entity or technique", items: unclustered });
  }
  return clusters.sort((a, b) => {
    if (a.kind === "unclustered") return 1;
    if (b.kind === "unclustered") return -1;
    return b.items.length - a.items.length || a.label.localeCompare(b.label);
  });
}
