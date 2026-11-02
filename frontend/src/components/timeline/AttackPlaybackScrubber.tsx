import { useEffect, useRef, useState } from "react";
import { Play, Pause, SkipBack, SkipForward, RotateCcw, Clock, ShieldAlert, Zap, Radio } from "lucide-react";
import type { TimelineEvent } from "@/lib/timeline";
import { classifyEventIntrusionStage } from "@/lib/timeline";
import { Chip } from "@/components/soc";
import { cn } from "@/lib/utils";

interface AttackPlaybackScrubberProps {
  events: TimelineEvent[];
  activeEventIndex: number | null;
  onSelectEvent: (event: TimelineEvent | null, index: number) => void;
  className?: string;
}

export function AttackPlaybackScrubber({
  events,
  activeEventIndex,
  onSelectEvent,
  className = "",
}: AttackPlaybackScrubberProps) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [speed, setSpeed] = useState<1 | 2 | 5>(1);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Sort events chronologically for playback
  const chronological = [...events].sort(
    (a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime()
  );

  const total = chronological.length;
  const currentIndex = activeEventIndex !== null && activeEventIndex >= 0 ? activeEventIndex : 0;
  const currentEvent = total > 0 ? chronological[currentIndex] : null;

  // Calculate elapsed time from the first event to current event
  const firstTs = total > 0 ? new Date(chronological[0].ts).getTime() : 0;
  const currentTs = currentEvent ? new Date(currentEvent.ts).getTime() : firstTs;
  const elapsedSec = Math.max(0, Math.floor((currentTs - firstTs) / 1000));
  const elapsedMin = Math.floor(elapsedSec / 60);
  const elapsedRemainSec = elapsedSec % 60;
  const elapsedFormatted = `+${String(elapsedMin).padStart(2, "0")}:${String(elapsedRemainSec).padStart(2, "0")}`;

  // Current stage
  const currentStage = currentEvent ? classifyEventIntrusionStage(currentEvent) : null;

  // Playback timer
  useEffect(() => {
    if (!isPlaying) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    const intervalMs = Math.round(2000 / speed);
    timerRef.current = setInterval(() => {
      if (activeEventIndex === null || activeEventIndex >= total - 1) {
        // Loop back to start or pause
        onSelectEvent(chronological[0], 0);
      } else {
        const nextIndex = activeEventIndex + 1;
        onSelectEvent(chronological[nextIndex], nextIndex);
      }
    }, intervalMs);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, activeEventIndex, total, speed, chronological, onSelectEvent]);

  if (total === 0) return null;

  const handleTogglePlay = () => {
    setIsPlaying((prev) => !prev);
  };

  const handleStepBack = () => {
    setIsPlaying(false);
    const prev = Math.max(0, (activeEventIndex ?? 0) - 1);
    onSelectEvent(chronological[prev], prev);
  };

  const handleStepForward = () => {
    setIsPlaying(false);
    const next = Math.min(total - 1, (activeEventIndex ?? 0) + 1);
    onSelectEvent(chronological[next], next);
  };

  const handleReset = () => {
    setIsPlaying(false);
    onSelectEvent(chronological[0], 0);
  };

  const handleSliderChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setIsPlaying(false);
    const val = parseInt(e.target.value, 10);
    if (!Number.isNaN(val) && val >= 0 && val < total) {
      onSelectEvent(chronological[val], val);
    }
  };

  return (
    <div
      id="attack-playback-scrubber"
      className={cn(
        "rounded-lg border border-primary/30 bg-surface-1/90 p-3 shadow-md space-y-2.5 font-mono min-w-0 max-w-full overflow-hidden",
        className
      )}
    >
      {/* Top row: Title, Speed & Elapsed Dwell Time */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-2">
        <div className="flex items-center gap-1.5 min-w-0">
          <Radio className={cn("h-4 w-4 shrink-0 text-primary", isPlaying && "animate-pulse text-destructive")} />
          <span className="ba-text-xs font-bold uppercase text-foreground truncate">
            Incident Attack Progression Scrubber
          </span>
          <span className="text-[10px] text-muted-foreground bg-surface-2 px-1.5 py-0.5 rounded border border-border shrink-0">
            Step {currentIndex + 1} of {total}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {/* Speed Pills */}
          <div className="flex items-center rounded border border-border bg-surface-2 p-0.5 text-mono ba-text-3xs">
            <span className="px-1 text-muted-foreground">Speed:</span>
            {([1, 2, 5] as const).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setSpeed(s)}
                className={cn(
                  "rounded px-1.5 py-0.5 font-bold transition",
                  speed === s ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"
                )}
              >
                {s}x
              </button>
            ))}
          </div>

          {/* Dwell Clock */}
          <div className="flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-mono ba-text-3xs text-primary font-bold">
            <Clock className="h-3 w-3" />
            <span>{elapsedFormatted} Dwell</span>
          </div>
        </div>
      </div>

      {/* Scrubber slider track */}
      <div className="space-y-1">
        <input
          type="range"
          min={0}
          max={total - 1}
          value={currentIndex}
          onChange={handleSliderChange}
          aria-label="Attack timeline scrubber"
          className="w-full h-1.5 bg-surface-2 rounded-lg appearance-none cursor-pointer accent-primary"
        />
        <div className="flex items-center justify-between text-[10px] text-muted-foreground">
          <span className="truncate max-w-[140px]">{new Date(chronological[0].ts).toLocaleTimeString()}</span>
          <span className="font-semibold text-primary uppercase text-[9px] tracking-wider">
            {currentStage ? currentStage.replace("_", " ") : "Kill Chain"}
          </span>
          <span className="truncate max-w-[140px] text-right">
            {new Date(chronological[total - 1].ts).toLocaleTimeString()}
          </span>
        </div>
      </div>

      {/* Active Event Banner & Controls */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 pt-1">
        {/* Playback Button Group */}
        <div className="flex items-center gap-1.5 shrink-0">
          <button
            type="button"
            onClick={handleReset}
            title="Reset to initial access"
            className="rounded border border-border bg-surface-2 p-1.5 text-muted-foreground hover:text-foreground hover:bg-surface-3 transition"
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </button>

          <button
            type="button"
            onClick={handleStepBack}
            title="Previous step"
            className="rounded border border-border bg-surface-2 p-1.5 text-muted-foreground hover:text-foreground hover:bg-surface-3 transition"
          >
            <SkipBack className="h-3.5 w-3.5" />
          </button>

          <button
            type="button"
            onClick={handleTogglePlay}
            className={cn(
              "inline-flex items-center gap-1.5 rounded px-3 py-1 ba-text-xs font-bold transition shadow-sm",
              isPlaying
                ? "bg-amber-500/20 text-amber-400 border border-amber-500/40 hover:bg-amber-500/30"
                : "bg-primary text-primary-foreground hover:bg-primary/90"
            )}
          >
            {isPlaying ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
            <span>{isPlaying ? "Pause" : "Play Attack"}</span>
          </button>

          <button
            type="button"
            onClick={handleStepForward}
            title="Next step"
            className="rounded border border-border bg-surface-2 p-1.5 text-muted-foreground hover:text-foreground hover:bg-surface-3 transition"
          >
            <SkipForward className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* Current Event Telemetry Snippet */}
        {currentEvent && (
          <div className="flex-1 min-w-[220px] rounded border border-border/80 bg-surface-0 px-2.5 py-1 flex items-center justify-between gap-2">
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="text-primary font-bold ba-text-2xs truncate">{currentEvent.verb}</span>
                <span className="text-[9px] uppercase px-1 rounded bg-surface-2 text-muted-foreground border border-border shrink-0">
                  {currentEvent.source}
                </span>
              </div>
              <p className="text-[10px] text-fg-dim truncate max-w-[340px]">{currentEvent.detail}</p>
            </div>
            <Chip tone={currentEvent.severity === "critical" ? "destructive" : currentEvent.severity === "high" ? "warning" : "default"}>
              {currentEvent.severity || "info"}
            </Chip>
          </div>
        )}
      </div>
    </div>
  );
}
