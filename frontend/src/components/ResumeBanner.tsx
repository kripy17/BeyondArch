import { Clock, RotateCcw, Trash2 } from "lucide-react";

function timeAgo(ts: number): string {
  const s = Math.max(1, Math.floor((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} minute${m === 1 ? "" : "s"} ago`;
  const h = Math.floor(m / 60);
  return `${h} hour${h === 1 ? "" : "s"} ago`;
}

export function ResumeBanner({
  artifact,
  updatedAt,
  onResume,
  onStartFresh,
}: {
  artifact: string;
  updatedAt: number;
  onResume: () => void;
  onStartFresh: () => void;
}) {
  const preview = artifact.replace(/\s+/g, " ").trim().slice(0, 160);
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-md border border-primary/40 bg-primary/5 px-3 py-2">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5 text-mono ba-text-2xs text-primary">
          <RotateCcw className="h-3 w-3" />
          Previous analysis found
        </div>
        <div className="truncate text-mono ba-text-sm text-foreground" title={artifact}>
          {preview || "—"}
        </div>
        <div className="flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground">
          <Clock className="h-2.5 w-2.5" />
          {timeAgo(updatedAt)}
        </div>
      </div>
      <button
        type="button"
        onClick={onResume}
        className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"
      >
        <RotateCcw className="h-3 w-3" /> Resume
      </button>
      <button
        type="button"
        onClick={onStartFresh}
        className="inline-flex items-center gap-1.5 rounded border border-border px-2.5 py-1 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:border-destructive/50 hover:text-destructive"
      >
        <Trash2 className="h-3 w-3" /> Start Fresh
      </button>
    </div>
  );
}
