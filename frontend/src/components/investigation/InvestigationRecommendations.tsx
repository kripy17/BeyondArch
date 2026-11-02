import { useEffect, useMemo, useState } from "react";
import { Lightbulb, ArrowRight } from "lucide-react";
import type { Case } from "@/data/case";
import { getUnifiedFindings, getUnifiedIOCs } from "@/components/investigation/legacy-adapter";
import { loadRules, ruleTechniques } from "@/data/detection";

type Nav = {
  goToTab?: (tab: string) => void;
  goToRoute?: (path: string) => void;
  closeCase?: () => void;
};

type Rec = {
  id: string;
  label: string;
  why: string;
  onClick: () => void;
};

/** Deterministic recommendation rules over local case data — no AI, always explainable. */
export function computeRecommendations(c: Case, nav: Nav): Rec[] {
  const findings = getUnifiedFindings(c);
  const iocs = getUnifiedIOCs(c);
  const recs: Rec[] = [];
  const dismissed = loadDismissed(c.id);

  const push = (id: string, label: string, why: string, onClick: () => void) => {
    if (dismissed.has(id)) return;
    recs.push({ id, label, why, onClick });
  };

  if (findings.length === 0) {
    push("no-findings", "Analyse an artifact", "No findings on record — upload and run an artifact through the parser.", () => nav.goToRoute?.("/parser"));
  }

  const unmapped = findings.filter((f) => !f.technique);
  if (unmapped.length > 0) {
    push("unmapped-technique", "Map techniques to MITRE", `${unmapped.length} finding${unmapped.length > 1 ? "s have" : " has"} no MITRE technique mapped.`, () => nav.goToRoute?.("/detection"));
  }

  const mapped = findings.filter((f) => f.technique).map((f) => f.technique!.toUpperCase());
  if (mapped.length > 0) {
    const ruleIds = new Set(loadRules().flatMap((r) => ruleTechniques(r).map((t) => t.toUpperCase())));
    const uncovered = mapped.filter((t) => !ruleIds.has(t));
    if (uncovered.length > 0) {
      push("create-rule", "Create a detection rule", `${uncovered.length} technique${uncovered.length > 1 ? "s" : ""} (${uncovered.join(", ")}) from findings has no rule in the library.`, () => nav.goToRoute?.("/detection"));
    }
  }

  const hasIntel = findings.some((f) => f.source === "/intel");
  if (iocs.length > 0 && !hasIntel) {
    push("no-enrichment", "Enrich IOCs in Intel Hub", `${iocs.length} IOC${iocs.length > 1 ? "s are" : " is"} still local-only — enrich to confirm.`, () => nav.goToRoute?.("/intel"));
  }

  const evidenceCount = c.entries.filter((e) => e.kind === "evidence").length;
  if ((c.artifacts?.length ?? 0) > 0 && evidenceCount === 0) {
    push("unattributed", "Attribute artifacts to evidence", "Artifacts not attributed to evidence items.", () => nav.goToTab?.("findings"));
  }

  const events = c.events ?? [];
  const hasReport = events.some((e) => e.kind === "report_generated");
  if (findings.length > 0 && !hasReport) {
    push("no-report", "Generate a case report", `${findings.length} finding${findings.length > 1 ? "s" : ""} on record but no report generated.`, () => nav.goToRoute?.(`/report/${c.id}`));
  }

  const hasDecision = events.some((e) => e.kind === "case_decision_made");
  if (c.state === "active" && findings.length > 0 && !hasDecision) {
    push("no-decision", "Record a case decision", "Case is active with findings — record a decision to close it out.", () => nav.goToTab?.("overview"));
  }

  if (c.state === "active" && hasReport && hasDecision) {
    push("close-investigation", "Close this investigation", "Report generated and decision recorded — ready to close out.", () => nav.closeCase?.());
  }

  return recs.slice(0, 4);
}

export function InvestigationRecommendations({ case: c, onDismiss, ...nav }: { case: Case; onDismiss?: (id: string) => void } & Nav) {
  const [version, setVersion] = useState(0);

  useEffect(() => {
    const reload = () => setVersion((v) => v + 1);
    window.addEventListener("recommendations-update", reload);
    return () => window.removeEventListener("recommendations-update", reload);
  }, []);

  const recommendations = useMemo<Rec[]>(() => {
    void version;
    return computeRecommendations(c, nav);
  }, [c, nav, version]);

  if (recommendations.length === 0) return null;

  return (
    <div className="rounded-lg border border-border bg-surface-1 p-3">
      <div className="mb-2 flex items-center gap-1.5 text-mono ba-text-2xs text-muted-foreground">
        <Lightbulb className="h-3 w-3 text-warning" />
        Recommendations
      </div>
      <ul className="space-y-1.5">
        {recommendations.map((r) => (
          <li key={r.id} className="rounded-md border border-border/70 bg-card/60 p-2">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="text-mono ba-text-2xs font-semibold text-foreground">{r.label}</div>
                <div className="mt-0.5 text-mono ba-text-3xs text-muted-foreground">{r.why}</div>
              </div>
              <button
                onClick={r.onClick}
                className="inline-flex shrink-0 items-center gap-1 rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-mono ba-text-3xs text-primary transition-colors duration-150 hover:bg-primary/20"
                title="Go to the required action"
              >
                open <ArrowRight className="h-2.5 w-2.5" />
              </button>
            </div>
            {onDismiss && (
              <button
                onClick={() => {
                  dismissRecommendation(c.id, r.id);
                  onDismiss(r.id);
                }}
                className="mt-1 text-mono ba-text-3xs text-muted-foreground/70 hover:text-muted-foreground"
              >
                dismiss
              </button>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

const DISMISSED_KEY = "ba.case.recs.dismissed";

function loadDismissed(caseId: string): Set<string> {
  try {
    const raw = localStorage.getItem(DISMISSED_KEY);
    if (!raw) return new Set();
    const map = JSON.parse(raw) as Record<string, string[]>;
    return new Set(map[caseId] ?? []);
  } catch {
    return new Set();
  }
}

export function dismissRecommendation(caseId: string, id: string) {
  try {
    const raw = localStorage.getItem(DISMISSED_KEY);
    const map = raw ? (JSON.parse(raw) as Record<string, string[]>) : {};
    const next = map[caseId] ?? [];
    if (!next.includes(id)) next.push(id);
    map[caseId] = next.slice(-10);
    localStorage.setItem(DISMISSED_KEY, JSON.stringify(map));
    window.dispatchEvent(new Event("recommendations-update"));
  } catch {
    /* noop */
  }
}