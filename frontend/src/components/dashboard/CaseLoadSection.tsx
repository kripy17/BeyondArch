import { useMemo, useState } from "react";
import { Link } from "@tanstack/react-router";
import { BarChart3, ArrowRight, ChevronDown } from "lucide-react";
import { EntitySection } from "@/components/entity";
import { Chip } from "@/components/soc";
import { loadCases } from "@/data/case";
import type { Severity } from "@/lib/severity";
import {
  SEVERITIES, computeCaseLoad, severityShare,
} from "@/lib/dashboard-metrics";

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "critical", high: "high", medium: "medium", low: "low", info: "info",
};

export function CaseLoadSection() {
  const cases = useMemo(() => loadCases(), []);
  const stats = useMemo(() => computeCaseLoad(cases), [cases]);
  const totalSev = SEVERITIES.reduce((n, s) => n + stats.bySeverity[s], 0);
  const [showDetails, setShowDetails] = useState(false);

  const activeCases = useMemo(() => cases.filter((c) => c.state === "active"), [cases]);
  const activeTechniques = useMemo(() => {
    const set = new Set<string>();
    for (const c of activeCases) {
      for (const f of c.findings ?? []) {
        if (f.technique) set.add(f.technique);
      }
    }
    return Array.from(set);
  }, [activeCases]);

  const activeTags = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const c of activeCases) {
      for (const t of c.tags ?? []) {
        counts[t] = (counts[t] || 0) + 1;
      }
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [activeCases]);

  const tiles = [
    { label: "cases", value: stats.cases },
    { label: "active", value: stats.active },
    { label: "closed", value: stats.closed },
    { label: "indicators", value: stats.indicators },
    { label: "findings", value: stats.findings },
    { label: "evidence", value: stats.evidenceItems },
  ];

  return (
    <EntitySection title="Case Load & Threat Posture" icon={BarChart3} headingLevel="h2">
      {stats.cases === 0 ? (
        <div className="py-3 text-center font-mono ba-text-2xs text-muted-foreground">
          No cases yet — escalate an alert or hand off a parser artifact to open one.
        </div>
      ) : (
        <>
          <div className="grid gap-1.5 grid-cols-3 sm:grid-cols-6">
            {tiles.map((t) => (
              <div key={t.label} className="rounded border border-subtle bg-surface-1 px-2 py-1.5">
                <div className="font-mono ba-text-sm text-foreground">{t.value}</div>
                <div className="font-mono ba-text-3xs text-fg-dim">{t.label}</div>
              </div>
            ))}
          </div>

          {(activeTechniques.length > 0 || activeTags.length > 0) && (
            <div className="mt-2.5 flex flex-wrap items-center gap-1.5 border-t border-subtle pt-2 font-mono ba-text-3xs">
              <span className="text-muted-foreground">Active Posture:</span>
              {activeTechniques.slice(0, 4).map((tech) => (
                <Link
                  key={tech}
                  to="/mitre"
                  search={{ technique: tech }}
                  className="rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-primary hover:bg-primary/20"
                >
                  {tech}
                </Link>
              ))}
              {activeTags.map(([tag, count]) => (
                <span key={tag} className="rounded border border-subtle bg-surface-0 px-1.5 py-0.5 text-fg-dim">
                  #{tag} ({count})
                </span>
              ))}
            </div>
          )}

          <button
            onClick={() => setShowDetails((v) => !v)}
            className="mt-2 inline-flex items-center gap-1.5 font-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:text-primary"
          >
            <ChevronDown className={"h-3 w-3 transition-transform duration-150" + (showDetails ? " rotate-180" : "")} />
            {showDetails ? "hide details" : "show details — severity + recent cases"}
          </button>

          {showDetails && (
          <>
          <div className="mt-3 space-y-1.5">
            <div className="font-mono ba-text-3xs text-muted-foreground">
              severity · indicators + findings ({totalSev} total)
            </div>
            {SEVERITIES.map((s) => {
              const n = stats.bySeverity[s];
              return (
                <div key={s} className="flex items-center gap-2" title={SEVERITY_LABEL[s]}>
                  <span className={`w-14 shrink-0 font-mono ba-text-3xs ${n === 0 ? "text-fg-dim/50" : "text-fg-dim"}`}>{s}</span>
                  <div className="h-2 min-w-0 flex-1 overflow-hidden rounded-full bg-surface-2">
                    <div
                      data-testid={`sev-bar-${s}`}
                      className={
                        s === "critical" ? "h-full rounded-full bg-destructive"
                        : s === "high" ? "h-full rounded-full bg-warning"
                        : s === "medium" ? "h-full rounded-full bg-warning/70"
                        : s === "low" ? "h-full rounded-full bg-success/70"
                        : "h-full rounded-full bg-info/70"
                      }
                      style={{ width: `${severityShare(n, totalSev)}%` }}
                    />
                  </div>
                  <span className={`w-8 shrink-0 text-right font-mono ba-text-3xs ${n === 0 ? "text-fg-dim/50" : "text-foreground"}`}>{n}</span>
                </div>
              );
            })}
          </div>

          {stats.recentCases.length > 0 && (
            <div className="mt-3 space-y-1.5 border-t border-subtle pt-3">
              <div className="font-mono ba-text-3xs text-muted-foreground">recent cases</div>
              {stats.recentCases.map((c) => (
                <Link
                  key={c.id}
                  to="/case"
                  className="flex items-center justify-between gap-2 rounded border border-border/60 bg-surface-0/60 px-2.5 py-1.5 transition-colors duration-150 hover:border-primary/40"
                >
                  <div className="min-w-0">
                    <div className="truncate font-mono ba-text-xs text-foreground">{c.title}</div>
                    <div className="text-mono ba-text-3xs text-muted-foreground">
                      {(c.events ?? []).length} events · opened {new Date(c.createdAt).toLocaleDateString()}
                    </div>
                  </div>
                  <Chip tone={c.state === "active" ? "warning" : "default"}>{c.state}</Chip>
                </Link>
              ))}
            </div>
          )}
          </>
          )}

          <div className="mt-3 border-t border-subtle pt-3">
            <Link to="/case" className="group inline-flex items-center gap-1.5 font-mono ba-text-2xs text-primary transition-colors duration-150">
              open case notebook <ArrowRight className="h-3 w-3 transition-transform group-hover:translate-x-0.5" />
            </Link>
          </div>
        </>
      )}
    </EntitySection>
  );
}
