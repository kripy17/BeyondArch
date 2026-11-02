import type { Case } from "@/data/case";

export type ChecklistItemId =
  | "intake"
  | "analysis"
  | "findings-reviewed"
  | "iocs-investigated"
  | "intel-enriched"
  | "notes-written"
  | "report-generated"
  | "ready-handoff";

export type ChecklistItem = {
  id: ChecklistItemId;
  label: string;
  done: boolean;
  detail?: string;
};

const META_PREFIX = "ba.case.meta.";

type CaseMeta = {
  findingsReviewed?: boolean;
  readyForHandoff?: boolean;
};

function getCaseMeta(caseId: string): CaseMeta {
  try {
    return JSON.parse(localStorage.getItem(META_PREFIX + caseId) || "{}");
  } catch {
    return {};
  }
}

function setCaseMeta(caseId: string, meta: CaseMeta) {
  try {
    const current = getCaseMeta(caseId);
    localStorage.setItem(META_PREFIX + caseId, JSON.stringify({ ...current, ...meta }));
    window.dispatchEvent(new Event("checklist-update"));
  } catch {
    /* noop */
  }
}



export function getChecklist(c: Case): ChecklistItem[] {
  const meta = getCaseMeta(c.id);

  const findingsCount = c.findings?.length ?? 0;
  const iocCount = c.iocs?.length ?? 0;
  const hasIntel = c.findings?.some((f) => f.source === "/intel") ?? false;
  const noteCount = c.entries.filter((e) => e.kind === "note").length;
  const hasReport = c.events?.some((e) => e.kind === "report_generated") ?? false;

  return [
    {
      id: "intake",
      label: "Intake Completed",
      done: (c.artifacts?.length ?? 0) > 0,
      detail: c.artifacts?.length ? `${c.artifacts.length} artifact${c.artifacts.length > 1 ? "s" : ""}` : undefined,
    },
    {
      id: "analysis",
      label: "Analysis Completed",
      done: c.analysisSummary !== null && c.analysisSummary !== undefined,
      detail: findingsCount > 0 ? `${findingsCount} findings` : undefined,
    },
    {
      id: "findings-reviewed",
      label: "Findings Reviewed",
      done: findingsCount === 0 || !!meta.findingsReviewed,
      detail: findingsCount > 0 && !meta.findingsReviewed ? `${findingsCount} pending` : undefined,
    },
    {
      id: "iocs-investigated",
      label: "IOCs Investigated",
      done: (c.iocs?.length ?? 0) === 0 && (c.findings?.some((f) => f.iocs?.length) ?? false),
      detail: iocCount > 0 ? `${iocCount} attached` : undefined,
    },
    {
      id: "intel-enriched",
      label: "Intel Enriched",
      done: hasIntel,
      detail: !hasIntel ? undefined : undefined,
    },
    {
      id: "notes-written",
      label: "Notes Written",
      done: noteCount > 0,
      detail: noteCount > 0 ? `${noteCount} note${noteCount > 1 ? "s" : ""}` : undefined,
    },
    {
      id: "report-generated",
      label: "Report Generated",
      done: hasReport,
    },
    {
      id: "ready-handoff",
      label: "Ready for Handoff",
      done: !!meta.readyForHandoff,
    },
  ];
}

export function getProgress(items: ChecklistItem[]): number {
  if (items.length === 0) return 0;
  const done = items.filter((i) => i.done).length;
  return Math.round((done / items.length) * 100);
}

export function markFindingsReviewed(caseId: string) {
  setCaseMeta(caseId, { findingsReviewed: true });
}

export function markHandoffReady(caseId: string, ready: boolean) {
  setCaseMeta(caseId, { readyForHandoff: ready });
}
