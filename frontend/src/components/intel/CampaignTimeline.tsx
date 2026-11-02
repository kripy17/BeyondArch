import { useNavigate } from "@tanstack/react-router";
import {
  Target,
  Clock,
  ExternalLink,
  ShieldAlert,
  Search,
  CheckCircle2,
} from "lucide-react";
import type { CampaignRecord } from "@/lib/intel/threat-intel-engine";
import { cn } from "@/lib/utils";

interface CampaignTimelineProps {
  campaigns: CampaignRecord[];
  actorTitle: string;
  className?: string;
}

export function CampaignTimeline({
  campaigns,
  actorTitle,
  className,
}: CampaignTimelineProps) {
  const navigate = useNavigate();

  return (
    <div className={cn("rounded-lg border border-subtle bg-surface-1/60 p-4", className)}>
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-subtle pb-3">
        <div className="flex items-center gap-2">
          <Target className="h-4 w-4 text-rose-400" />
          <h3 className="font-mono text-sm font-bold uppercase tracking-wider text-foreground">
            Adversary Campaign Timeline ({campaigns.length} Operations)
          </h3>
        </div>
        <span className="font-mono ba-text-3xs text-muted-foreground">
          Chronological attribution profile for {actorTitle}
        </span>
      </div>

      {/* Timeline List */}
      <div className="relative mt-4 pl-4 before:absolute before:left-1.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-subtle">
        <div className="space-y-4">
          {campaigns.map((camp) => (
            <div key={camp.id} className="relative group">
              {/* Timeline Node Icon */}
              <div
                className={cn(
                  "absolute -left-4 top-1.5 h-3 w-3 rounded-full border-2 bg-surface-0",
                  camp.active
                    ? "border-rose-400 ring-2 ring-rose-400/30"
                    : "border-muted-foreground"
                )}
              />

              <div className="rounded-lg border border-subtle bg-surface-0/80 p-3 transition-colors hover:border-primary/40 hover:bg-surface-0">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-bold text-foreground group-hover:text-primary">
                        {camp.name}
                      </span>
                      {camp.active && (
                        <span className="inline-flex items-center gap-1 rounded bg-rose-500/20 px-1.5 py-0.5 font-mono ba-text-3xs font-semibold text-rose-300 animate-pulse">
                          Active Monitoring
                        </span>
                      )}
                    </div>
                    <div className="mt-0.5 flex items-center gap-1.5 font-mono ba-text-2xs text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      <span>{camp.timeRange}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={() => navigate({ to: "/siem", search: { q: camp.name } })}
                      className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-0.5 font-mono ba-text-3xs text-muted-foreground hover:border-primary/40 hover:text-foreground"
                    >
                      <Search className="h-2.5 w-2.5" /> Hunt in SIEM
                    </button>
                    <button
                      onClick={() => navigate({ to: "/logs", search: { q: camp.name } })}
                      className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-0.5 font-mono ba-text-3xs text-muted-foreground hover:border-primary/40 hover:text-foreground"
                    >
                      Logs <ExternalLink className="h-2.5 w-2.5" />
                    </button>
                  </div>
                </div>

                <div className="mt-2.5 space-y-1.5 font-mono ba-text-xs">
                  <div className="flex flex-wrap items-center gap-1">
                    <span className="text-muted-foreground ba-text-2xs mr-1">Target Sectors:</span>
                    {camp.targets.map((t) => (
                      <span
                        key={t}
                        className="rounded border border-subtle bg-surface-2 px-1.5 py-0.5 ba-text-3xs text-fg-dim"
                      >
                        {t}
                      </span>
                    ))}
                  </div>

                  <div className="flex flex-wrap items-center gap-1">
                    <span className="text-muted-foreground ba-text-2xs mr-1">Deployed Arsenal:</span>
                    {camp.tools.map((tl) => (
                      <span
                        key={tl}
                        className="rounded border border-purple-500/30 bg-purple-500/10 px-1.5 py-0.5 ba-text-3xs font-medium text-purple-300"
                      >
                        {tl}
                      </span>
                    ))}
                  </div>

                  <div className="flex flex-wrap items-center gap-1">
                    <span className="text-muted-foreground ba-text-2xs mr-1">TTPs:</span>
                    {camp.techniques.map((tech) => (
                      <span
                        key={tech}
                        className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 ba-text-3xs font-semibold text-amber-300"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="mt-2 text-mono ba-text-2xs text-muted-foreground border-t border-subtle/50 pt-1.5">
                  <span className="text-fg-dim font-medium">Outcome:</span> {camp.outcome}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
