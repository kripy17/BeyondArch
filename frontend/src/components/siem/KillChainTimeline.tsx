import { useState } from "react";
import {
  ShieldAlert, AlertTriangle, ArrowRight, Activity, CheckCircle2,
  Lock, Terminal, RefreshCw, Radio,
} from "lucide-react";
import type {
  KillChainAnalysis,
  KillChainPhase,
  KillChainPhaseId,
} from "@/lib/siem/killchain-reconstruction";

interface KillChainTimelineProps {
  analysis: KillChainAnalysis;
  selectedPhase: KillChainPhaseId | null;
  onSelectPhase: (phaseId: KillChainPhaseId | null) => void;
}

const PHASE_ICONS: Record<KillChainPhaseId, typeof Radio> = {
  recon: Radio,
  initial_access: Lock,
  execution: Terminal,
  persistence_evasion: RefreshCw,
  c2_exfil: ShieldAlert,
};

export function KillChainTimeline({
  analysis,
  selectedPhase,
  onSelectPhase,
}: KillChainTimelineProps) {
  const { phases, activePhaseCount, progressionScore, threatNarrative, highestPhase } = analysis;

  const scoreTone =
    progressionScore >= 80
      ? "text-destructive border-destructive/40 bg-destructive/10"
      : progressionScore >= 60
      ? "text-warning border-warning/40 bg-warning/10"
      : progressionScore >= 40
      ? "text-primary border-primary/40 bg-primary/10"
      : "text-fg-dim border-subtle bg-surface-1";

  return (
    <div className="space-y-3 rounded-lg border border-subtle bg-surface-0 p-3.5 shadow-xs">
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-2.5">
        <div className="flex items-center gap-2">
          <Activity className="h-4 w-4 text-primary" />
          <h3 className="font-mono ba-text-xs font-semibold uppercase tracking-wider text-foreground">
            Cyber Kill-Chain Attack Reconstruction
          </h3>
          <span className="rounded bg-surface-2 px-1.5 py-0.5 text-mono ba-text-3xs text-fg-dim">
            {activePhaseCount} of 5 Phases Active
          </span>
        </div>

        {/* Progression Score Badge */}
        <div className="flex items-center gap-2">
          <span className="text-mono ba-text-2xs text-fg-dim">Progression Index:</span>
          <span
            className={
              "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono ba-text-2xs font-bold " +
              scoreTone
            }
          >
            {progressionScore}%
          </span>
        </div>
      </div>

      {/* Threat Narrative Banner */}
      {progressionScore > 0 && (
        <div
          className={
            "flex items-start gap-2.5 rounded-md border p-2.5 text-mono ba-text-2xs " +
            (progressionScore >= 80
              ? "border-destructive/40 bg-destructive/5 text-destructive"
              : progressionScore >= 60
              ? "border-warning/40 bg-warning/5 text-warning"
              : "border-primary/30 bg-primary/5 text-primary")
          }
        >
          {progressionScore >= 60 ? (
            <ShieldAlert className="h-4 w-4 shrink-0 mt-0.5" />
          ) : (
            <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
          )}
          <div className="min-w-0 flex-1 leading-relaxed">
            <span className="font-bold">Automated Threat Narrative: </span>
            {threatNarrative}
          </div>
        </div>
      )}

      {/* Attack Rail Stepper */}
      <div className="grid grid-cols-1 gap-2 md:grid-cols-5">
        {phases.map((phase, idx) => {
          const Icon = PHASE_ICONS[phase.id];
          const isSelected = selectedPhase === phase.id;

          const cardBorder = isSelected
            ? "border-primary ring-1 ring-primary/40 bg-primary/[0.07]"
            : phase.active
            ? phase.severity === "critical" || phase.severity === "high"
              ? "border-destructive/40 bg-destructive/[0.04] hover:border-destructive/60"
              : phase.severity === "medium"
              ? "border-warning/40 bg-warning/[0.04] hover:border-warning/60"
              : "border-primary/40 bg-primary/[0.03] hover:border-primary/60"
            : "border-subtle/70 bg-surface-1/50 opacity-60 hover:opacity-100";

          return (
            <button
              key={phase.id}
              onClick={() => onSelectPhase(isSelected ? null : phase.id)}
              className={
                "flex flex-col justify-between rounded-md border p-2.5 text-left transition-all duration-150 " +
                cardBorder
              }
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="flex h-5 w-5 items-center justify-center rounded-full bg-surface-2 text-mono ba-text-3xs font-bold text-fg-dim">
                    {phase.order}
                  </span>
                  {phase.active ? (
                    <span
                      className={
                        "rounded px-1.5 py-0.5 text-mono ba-text-3xs font-semibold " +
                        (phase.severity === "critical" || phase.severity === "high"
                          ? "bg-destructive/15 text-destructive"
                          : phase.severity === "medium"
                          ? "bg-warning/15 text-warning"
                          : "bg-primary/15 text-primary")
                      }
                    >
                      {phase.eventCount} evt{phase.eventCount === 1 ? "" : "s"}
                    </span>
                  ) : (
                    <span className="text-mono ba-text-3xs text-fg-dim/60">Idle</span>
                  )}
                </div>

                <div className="mt-2 flex items-center gap-1.5">
                  <Icon
                    className={
                      "h-3.5 w-3.5 shrink-0 " +
                      (phase.active
                        ? phase.severity === "critical" || phase.severity === "high"
                          ? "text-destructive"
                          : "text-primary"
                        : "text-fg-dim")
                    }
                  />
                  <div className="truncate font-mono ba-text-xs font-bold text-foreground">
                    {phase.name}
                  </div>
                </div>

                <p className="mt-1 line-clamp-2 text-mono ba-text-3xs text-fg-dim">
                  {phase.summary}
                </p>
              </div>

              <div className="mt-2.5 flex items-center justify-between border-t border-border/30 pt-1.5 text-mono ba-text-3xs text-fg-dim">
                <span className="truncate">{phase.mitreTactic.split(" ")[0]}</span>
                <span className="text-primary hover:underline">
                  {isSelected ? "clear" : "inspect"}
                </span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
