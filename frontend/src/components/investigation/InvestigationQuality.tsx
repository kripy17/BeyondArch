import { useMemo } from "react";
import { ShieldAlert, ArrowRight, Check } from "lucide-react";
import type { Case } from "@/data/case";
import { getUnifiedFindings, getUnifiedIOCs } from "@/components/investigation/legacy-adapter";
import { getChecklist } from "@/data/case-checklist";
import { cn } from "@/lib/utils";

type Nav = {
  goToTab?: (tab: string) => void;
  goToRoute?: (path: string) => void;
};

type Issue = {
  id: string;
  label: string;
  onClick?: () => void;
  fixType?: string;
};

export type QualityResult = { issues: Issue[]; score: number };

export function InvestigationQuality({ case: c, goToTab, goToRoute }: { case: Case } & Nav) {
  const nav = useMemo<Nav>(() => ({ goToTab, goToRoute }), [goToTab, goToRoute]);
  const { issues, score } = useMemo<QualityResult>(() => checkCaseQuality(c, nav), [c, nav]);

  if (issues.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-surface-1 p-3">
        <div className="flex items-center gap-1.5 text-mono ba-text-2xs text-success">
          <Check className="h-3 w-3" />
          Quality — no open issues
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-surface-1 p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="inline-flex items-center gap-1.5 text-mono ba-text-2xs text-muted-foreground">
          <ShieldAlert className="h-3 w-3 text-warning" />
          Investigation Quality
        </span>
        <span className={cn("text-mono ba-text-2xs font-bold", score < 60 ? "text-destructive" : score < 85 ? "text-warning" : "text-success")}>
          {score}/100
        </span>
      </div>
      <ul className="space-y-1">
        {issues.map((issue) => (
          <li key={issue.id} className="flex items-center gap-2 px-1 py-1">
            <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-warning" />
            <span className="min-w-0 flex-1 text-mono ba-text-2xs text-foreground">{issue.label}</span>
            {issue.onClick && (
              <button
                onClick={issue.onClick}
                className="inline-flex shrink-0 items-center gap-0.5 rounded border border-border bg-surface-2 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground transition-colors duration-150 hover:border-primary/40 hover:text-primary"
              >
                {issue.fixType ?? "fix"} <ArrowRight className="h-2.5 w-2.5" />
              </button>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
export function checkCaseQuality(c: Case, nav: Nav = {}): QualityResult {
  const issues: Issue[] = [];
  const findings = getUnifiedFindings(c);
  const iocs = getUnifiedIOCs(c);
  const checklist = getChecklist(c);

  const noteCount = c.entries.filter((e) => e.kind === "note").length;
  const evidenceCount = c.entries.filter((e) => e.kind === "evidence").length;
  const decisions = c.entries.filter((e) => e.kind === "decision");
  const events = (c.events ?? []).length;
  const artifacts = (c.artifacts?.length ?? 0);

  let score = 100;

  const addIssue = (id: string, label: string, penalty: number, onClick?: () => void) => {
    issues.push({ id, label, onClick });
    score -= penalty;
  };

  if (artifacts === 0) addIssue("no-artifact", "Missing evidence — no artifact attributed", 15);
  else if (evidenceCount === 0) addIssue("no-evidence", "Evidence collected but findings not attributed", 10, () => nav.goToTab?.("findings"));

  if (c.analysisSummary === null && findings.length === 0) addIssue("no-analysis", "No analysis recorded", 10, () => nav.goToRoute?.("/parser"));

  const pendingFindings = checklist.find((i) => i.id === "findings-reviewed");
  if (pendingFindings && !pendingFindings.done) addIssue("unreviewed", "Findings not reviewed", 5, () => nav.goToTab?.("findings"));

  if (iocs.length > 0 && !findings.some((f) => f.source === "/intel")) addIssue("no-intel", "IOCs not enriched", 10, () => nav.goToRoute?.("/intel"));

  if (findings.filter((f) => !f.technique).length > 0) addIssue("no-mitre", "Findings missing MITRE mapping", 10, () => nav.goToRoute?.("/detection"));

  const seen = new Set<string>();
  const dupeIocs = iocs.filter((i) => (seen.has(i.value) ? true : (seen.add(i.value), false))).length;
  if (dupeIocs > 0) addIssue("dupe-iocs", `Duplicate IOCs (${dupeIocs})`, 5);

  const seenF = new Set<string>();
  const dupeFindings = findings.filter((f) => (seenF.has(f.title) ? true : (seenF.add(f.title), false))).length;
  if (dupeFindings > 0) addIssue("dupe-findings", `Duplicate findings (${dupeFindings})`, 5);

  if (noteCount === 0) addIssue("no-notebook", "Analyst notebook not written", 10, () => nav.goToTab?.("notebook"));

  if (!c.events?.some((e) => e.kind === "report_generated") && checklist.find((i) => i.id === "report-generated") && !checklist.find((i) => i.id === "report-generated")?.done) {
    addIssue("no-report", "No report generated", 10, () => nav.goToTab?.("notebook"));
  }

  if (events === 0) addIssue("no-timeline", "No case timeline events", 5, () => nav.goToTab?.("timeline"));

  if (decisions.length > 0 && !c.entries.some((e) => e.kind === "action")) addIssue("unresolved", "Unresolved decisions (no follow-up actions)", 5, () => nav.goToTab?.("timeline"));

  score = Math.max(0, Math.min(100, Math.round(score)));

  return { issues, score };
}