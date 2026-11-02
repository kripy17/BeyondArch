import { loadCases, type Case } from "@/data/case";
import { loadRules } from "@/data/detection";
import { ALL_ENTITIES } from "@/data/intel";
import { refang } from "@/lib/ioc-patterns";
import { type CorrelationHistory, type HistoryCase, type HistoryDetection, type HistoryEntity } from "./engine";

/**
 * Local-history bridge (ANALYSIS_ENGINE §4e): builds the CorrelationHistory
 * injected into artifact analysis from the workspace's own stores — prior
 * cases (IOC values), saved detections (MITRE technique targets), and the
 * intel-corpus entities. Storage is read only here; the correlation engine
 * never touches it. Detections without a technique are omitted — the
 * existing-detection dimension is technique-keyed and cannot match honestly.
 */

export function caseValues(c: Case): string[] {
  const seen = new Set<string>();
  const add = (v: string) => {
    const norm = refang(v).trim().toLowerCase();
    if (norm && !seen.has(norm)) seen.add(norm);
  };
  if (c.iocs?.length) {
    for (const i of c.iocs) add(i.value);
  }
  for (const e of c.entries) {
    if (e.kind !== "ioc") continue;
    const body = e.body.trim();
    if (body) add(body);
  }
  return [...seen];
}

export function buildLocalHistory(): CorrelationHistory {
  const cases: HistoryCase[] = loadCases()
    .map((c) => ({ id: c.id, title: c.title, values: caseValues(c) }))
    .filter((c) => c.values.length > 0);

  const detections: HistoryDetection[] = loadRules()
    .filter((r) => Boolean(r.technique))
    .map((r) => ({ id: r.id, name: r.name, technique: r.technique }));

  const entities: HistoryEntity[] = ALL_ENTITIES
    .map((e) => ({
      id: e.id,
      name: e.title,
      observables: e.observables.map((o) => o.value),
    }))
    .filter((e) => e.observables.length > 0);

  return { cases, entities, detections };
}