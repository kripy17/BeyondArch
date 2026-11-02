import type { Case } from "@/data/case";
import type { Severity } from "@/lib/severity";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export type CaseLoadStats = {
  cases: number;
  active: number;
  closed: number;
  indicators: number;
  findings: number;
  evidenceItems: number;
  entries: number;
  bySeverity: Record<Severity, number>;
  recentCases: Case[];
};

export const EMPTY_CASE_LOAD: CaseLoadStats = {
  cases: 0, active: 0, closed: 0,
  indicators: 0, findings: 0, evidenceItems: 0, entries: 0,
  bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  recentCases: [],
};

/** Pure rollup over the stored case list — no wall clock, deterministic ordering. */
export function computeCaseLoad(cases: Case[]): CaseLoadStats {
  const stats: CaseLoadStats = {
    ...EMPTY_CASE_LOAD,
    bySeverity: { ...EMPTY_CASE_LOAD.bySeverity },
    recentCases: [],
  };
  for (const c of cases) {
    if (c.state === "active") stats.active++;
    stats.entries += c.entries?.length ?? 0;
    for (const ioc of c.iocs ?? []) {
      stats.indicators++;
      if (SEVERITIES.includes(ioc.severity)) stats.bySeverity[ioc.severity]++;
    }
    for (const f of c.findings ?? []) {
      stats.findings++;
      if (SEVERITIES.includes(f.severity)) stats.bySeverity[f.severity]++;
    }
    stats.evidenceItems += c.evidenceItems?.length ?? 0;
  }
  stats.closed = cases.length - stats.active;
  stats.cases = cases.length;
  stats.recentCases = [...cases]
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .slice(0, 5);
  return stats;
}

export function severityShare(count: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((count / total) * 100);
}
