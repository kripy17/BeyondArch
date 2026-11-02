import { useState, useMemo } from "react";
import { useNavigate } from "@tanstack/react-router";
import {
  Layers,
  Search,
  ExternalLink,
  Flame,
  CheckCircle2,
  Filter,
} from "lucide-react";
import { TACTICS, ALL_TECHNIQUES } from "@/data/mitre";
import { cn } from "@/lib/utils";

interface MitreNavigatorMatrixProps {
  actorTechniques: string[];
  actorTitle?: string;
  className?: string;
}

export function MitreNavigatorMatrix({
  actorTechniques,
  actorTitle,
  className,
}: MitreNavigatorMatrixProps) {
  const navigate = useNavigate();
  const [filterQuery, setFilterQuery] = useState("");
  const [highlightOnlyActive, setHighlightOnlyActive] = useState(false);

  const activeTechniqueSet = useMemo(() => {
    const set = new Set<string>();
    actorTechniques.forEach((t) => {
      set.add(t.toUpperCase());
      // Handle base techniques if sub-technique is given (e.g. T1059.001 -> T1059)
      if (t.includes(".")) {
        set.add(t.split(".")[0].toUpperCase());
      }
    });
    return set;
  }, [actorTechniques]);

  const filteredTactics = useMemo(() => {
    const q = filterQuery.trim().toLowerCase();
    return TACTICS.map((tactic) => {
      const techniques = tactic.techniques.filter((tech) => {
        const isActive = activeTechniqueSet.has(tech.id.toUpperCase());
        if (highlightOnlyActive && !isActive) return false;
        if (!q) return true;
        return (
          tech.id.toLowerCase().includes(q) ||
          tech.name.toLowerCase().includes(q) ||
          tactic.name.toLowerCase().includes(q)
        );
      });
      return { ...tactic, techniques };
    });
  }, [filterQuery, highlightOnlyActive, activeTechniqueSet]);

  const activeCountInMatrix = useMemo(() => {
    let count = 0;
    ALL_TECHNIQUES.forEach((t) => {
      if (activeTechniqueSet.has(t.id.toUpperCase())) count++;
    });
    return count;
  }, [activeTechniqueSet]);

  return (
    <div className={cn("rounded-lg border border-subtle bg-surface-1/60 p-4", className)}>
      {/* Header & Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-subtle pb-3">
        <div>
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-amber-400" />
            <h3 className="font-mono text-sm font-bold uppercase tracking-wider text-foreground">
              MITRE ATT&CK Enterprise Matrix Navigator
            </h3>
            <span className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 font-mono ba-text-3xs font-semibold text-amber-400">
              {activeCountInMatrix} Active TTPs
            </span>
          </div>
          <p className="mt-0.5 font-mono ba-text-2xs text-muted-foreground">
            Adversary technique coverage across Enterprise ATT&CK tactics · Click any cell to inspect detections
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Quick Search */}
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              placeholder="Filter technique ID or name…"
              className="rounded border border-subtle bg-surface-0 py-1 pl-8 pr-3 font-mono ba-text-2xs text-foreground placeholder:text-fg-dim outline-none focus:border-primary/50"
            />
          </div>

          {/* Toggle Active Only */}
          <button
            onClick={() => setHighlightOnlyActive(!highlightOnlyActive)}
            className={cn(
              "inline-flex items-center gap-1 rounded border px-2 py-1 font-mono ba-text-2xs transition-colors",
              highlightOnlyActive
                ? "border-amber-500/60 bg-amber-500/20 text-amber-300 font-semibold"
                : "border-subtle bg-surface-0 text-muted-foreground hover:text-foreground"
            )}
          >
            <Filter className="h-3 w-3" />
            {highlightOnlyActive ? "Show All Techniques" : "Active TTPs Only"}
          </button>

          <button
            onClick={() => navigate({ to: "/mitre", search: { q: actorTitle } })}
            className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-0 px-2.5 py-1 font-mono ba-text-2xs text-muted-foreground hover:border-primary/40 hover:text-foreground"
          >
            Open MITRE Workbench <ExternalLink className="h-3 w-3" />
          </button>
        </div>
      </div>

      {/* Matrix Horizontal Scroll Canvas */}
      <div className="mt-3 overflow-x-auto pb-2 scrollbar-thin">
        <div className="flex gap-2.5 min-w-[1300px]">
          {filteredTactics.map((tactic) => {
            const activeUnderThisTactic = tactic.techniques.filter((t) =>
              activeTechniqueSet.has(t.id.toUpperCase())
            ).length;

            return (
              <div
                key={tactic.id}
                className="flex flex-col flex-1 rounded border border-subtle bg-surface-0/60 min-w-[150px]"
              >
                {/* Tactic Column Header */}
                <div className="border-b border-subtle bg-surface-2/60 p-2 text-center">
                  <div className="font-mono ba-text-3xs font-bold uppercase tracking-wider text-muted-foreground">
                    {tactic.name}
                  </div>
                  <div className="mt-0.5 flex items-center justify-center gap-1 font-mono text-[10px] text-fg-dim">
                    <span>{tactic.id}</span>
                    {activeUnderThisTactic > 0 && (
                      <span className="rounded bg-amber-500/20 px-1 text-amber-300 font-bold">
                        {activeUnderThisTactic}
                      </span>
                    )}
                  </div>
                </div>

                {/* Technique Cell List */}
                <div className="space-y-1 p-1.5 flex-1">
                  {tactic.techniques.length === 0 ? (
                    <div className="py-4 text-center font-mono ba-text-3xs text-muted-foreground">
                      No matches
                    </div>
                  ) : (
                    tactic.techniques.map((tech) => {
                      const isActive = activeTechniqueSet.has(tech.id.toUpperCase());

                      return (
                        <div
                          key={tech.id}
                          onClick={() => navigate({ to: "/mitre", search: { q: tech.id } })}
                          className={cn(
                            "group cursor-pointer rounded border p-1.5 transition-all text-left",
                            isActive
                              ? "border-amber-500/60 bg-amber-500/15 hover:border-amber-400 hover:bg-amber-500/25 shadow-sm"
                              : "border-subtle/50 bg-surface-1/40 hover:border-subtle hover:bg-surface-2 opacity-60 hover:opacity-100"
                          )}
                          title={`${tech.id}: ${tech.name}`}
                        >
                          <div className="flex items-center justify-between gap-1">
                            <span
                              className={cn(
                                "font-mono ba-text-3xs font-bold",
                                isActive ? "text-amber-300" : "text-fg-dim"
                              )}
                            >
                              {tech.id}
                            </span>
                            {isActive && (
                              <Flame className="h-3 w-3 text-amber-400 shrink-0 animate-pulse" />
                            )}
                          </div>
                          <div className="mt-0.5 truncate font-mono text-[11px] font-medium text-foreground group-hover:text-primary">
                            {tech.name}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
