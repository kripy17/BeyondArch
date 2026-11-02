import { useMemo, useState } from "react";
import {
  ShieldAlert,
  Zap,
  Clock,
  ArrowRight,
  Copy,
  Check,
  FileText,
  Activity,
  Layers,
  CheckCircle2,
  Terminal,
} from "lucide-react";
import type { TimelineEvent } from "@/lib/timeline";
import {
  computeAttackVelocity,
  computeIntrusionProgression,
  type StageProgression,
} from "@/lib/timeline";
import { Chip } from "@/components/soc";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface AttackProgressionSynthesisProps {
  events: TimelineEvent[];
  className?: string;
}

export function AttackProgressionSynthesis({
  events,
  className = "",
}: AttackProgressionSynthesisProps) {
  const [copied, setCopied] = useState(false);

  const velocity = useMemo(() => computeAttackVelocity(events), [events]);
  const stages = useMemo(() => computeIntrusionProgression(events), [events]);
  const activeStages = stages.filter((s) => s.eventCount > 0);

  // Synthesize executive incident story
  const narrative = useMemo(() => {
    if (!events.length) {
      return "No incident telemetry available in timeline.";
    }

    const chronological = [...events].sort(
      (a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime()
    );

    const first = chronological[0];
    const last = chronological[chronological.length - 1];

    const hasPhishing = events.some((e) => e.source === "phishing");
    const hasMalware = events.some((e) => e.source === "file" || e.source === "attachment");
    const hasC2 = events.some((e) => e.source === "pcap" || e.detail.toLowerCase().includes("beacon"));
    const hasContained = events.some((e) => e.verb.toLowerCase().includes("contain") || e.detail.toLowerCase().includes("isolated"));

    const parts: string[] = [];
    if (hasPhishing) {
      parts.push(`Initial access gained via spear-phishing lure targeting corporate recipient at ${new Date(first.ts).toLocaleTimeString()}.`);
    } else {
      parts.push(`Initial compromise detected via ${first.verb} (${first.source.toUpperCase()}) at ${new Date(first.ts).toLocaleTimeString()}.`);
    }

    if (hasMalware) {
      parts.push("Host weaponization followed with encoded PowerShell and in-memory process injection capabilities identified.");
    }

    if (hasC2) {
      parts.push("Adversary established deterministic C2 communication cadence and executed internal subnet reconnaissance.");
    }

    if (hasContained) {
      parts.push(`Incident contained at ${new Date(last.ts).toLocaleTimeString()} through perimeter IP drop rules and host subnet isolation.`);
    } else {
      parts.push("Active threat containment currently in progress across operational endpoints.");
    }

    return parts.join(" ");
  }, [events]);

  const handleCopyStory = () => {
    const text = `=== BEYONDARCH INCIDENT ATTACK PROGRESSION DOSSIER ===\n` +
      `Incident Dwell Time: ${velocity.dwellTimeFormatted} (${velocity.totalDwellTimeMinutes} mins)\n` +
      `Root Entry Vector: ${velocity.rootCause}\n` +
      `Attack Velocity: ${velocity.eventsPerMinute} events/min | Critical Milestones: ${velocity.criticalMilestonesCount}\n` +
      `Current Posture: ${velocity.activeStageLabel}\n\n` +
      `Executive Summary:\n${narrative}\n\n` +
      `Kill-Chain Stages:\n` +
      activeStages.map((s) => `  - [${s.mitreTactic}] ${s.label}: ${s.eventCount} event(s)`).join("\n");

    copyText(text).then(() => {
      setCopied(true);
      toast.success("Incident progression dossier copied to clipboard");
      setTimeout(() => setCopied(false), 2000);
    });
  };

  if (!events.length) return null;

  return (
    <div
      id="attack-progression-synthesis"
      className={cn(
        "rounded-xl border border-border/80 bg-card p-3.5 shadow-sm space-y-3 font-mono min-w-0 max-w-full overflow-hidden",
        className
      )}
    >
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-2.5">
        <div className="flex items-center gap-2 min-w-0">
          <ShieldAlert className="h-4 w-4 text-warning shrink-0 animate-pulse" />
          <h3 className="ba-text-xs font-bold uppercase tracking-wider text-foreground truncate">
            Autonomous Multi-Stage Intrusion Synthesis
          </h3>
          <Chip tone={velocity.criticalMilestonesCount > 0 ? "destructive" : "warning"}>
            {velocity.activeStageLabel}
          </Chip>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <span className="text-[10px] text-muted-foreground">
            Dwell: <span className="font-bold text-foreground">{velocity.dwellTimeFormatted}</span>
          </span>
          <span>·</span>
          <span className="text-[10px] text-muted-foreground">
            Velocity: <span className="font-bold text-foreground">{velocity.eventsPerMinute} ev/m</span>
          </span>
          <button
            type="button"
            onClick={handleCopyStory}
            className="inline-flex items-center gap-1 rounded border border-border bg-surface-2 px-2 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-foreground transition"
            title="Copy full incident storyline"
          >
            {copied ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
            <span>Copy Dossier</span>
          </button>
        </div>
      </div>

      {/* Kill Chain Stage Flow Pills */}
      <div className="space-y-1">
        <div className="text-[10px] uppercase font-semibold text-muted-foreground">
          Kill-Chain Progression Sequence ({activeStages.length} Active Phases)
        </div>
        <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
          {activeStages.map((stg, idx) => (
            <div key={stg.stage} className="flex items-center gap-1.5">
              <div
                className={cn(
                  "flex items-center gap-1 rounded px-2 py-1 text-mono text-[10px] font-bold uppercase border transition",
                  stg.tone === "destructive"
                    ? "border-destructive/50 bg-destructive/15 text-destructive"
                    : stg.tone === "warning"
                    ? "border-warning/50 bg-warning/15 text-warning"
                    : stg.tone === "success"
                    ? "border-emerald-500/50 bg-emerald-500/15 text-emerald-400"
                    : "border-primary/50 bg-primary/15 text-primary"
                )}
              >
                <span>{stg.label}</span>
                <span className="rounded-full bg-background/50 px-1 py-0.1 text-[9px]">
                  {stg.eventCount}
                </span>
              </div>
              {idx < activeStages.length - 1 && (
                <ArrowRight className="h-3 w-3 text-muted-foreground/60 shrink-0" />
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Narrative Synthesis */}
      <div className="rounded-lg border border-border/70 bg-surface-0/80 p-2.5 space-y-1.5">
        <div className="flex items-center gap-1.5 text-muted-foreground ba-text-3xs uppercase font-semibold">
          <Activity className="h-3.5 w-3.5 text-primary shrink-0" />
          <span>Executive Intrusion Reconstruction</span>
        </div>
        <p className="ba-text-2xs text-fg-dim leading-relaxed">{narrative}</p>
      </div>

      {/* 3 Metric Summary Cards */}
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <div className="rounded-md border border-border bg-surface-1 p-2 space-y-0.5 min-w-0">
          <div className="text-[9px] uppercase font-semibold text-muted-foreground">Root Entry Point</div>
          <div className="ba-text-xs font-bold text-foreground truncate">{velocity.rootCause}</div>
          <div className="text-[10px] text-muted-foreground">First observed anomaly</div>
        </div>

        <div className="rounded-md border border-border bg-surface-1 p-2 space-y-0.5 min-w-0">
          <div className="text-[9px] uppercase font-semibold text-muted-foreground">Critical Milestones</div>
          <div className="ba-text-xs font-bold text-destructive truncate">
            {velocity.criticalMilestonesCount} Flagged TTPs
          </div>
          <div className="text-[10px] text-muted-foreground">High/Critical severity</div>
        </div>

        <div className="rounded-md border border-border bg-surface-1 p-2 space-y-0.5 min-w-0">
          <div className="text-[9px] uppercase font-semibold text-muted-foreground">Containment Velocity</div>
          <div className="ba-text-xs font-bold text-emerald-400 truncate">
            {velocity.dwellTimeFormatted} Total Dwell
          </div>
          <div className="text-[10px] text-muted-foreground">From initial contact</div>
        </div>
      </div>
    </div>
  );
}
