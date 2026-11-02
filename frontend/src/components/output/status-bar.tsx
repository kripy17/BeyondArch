import { type ReactNode } from "react";

export function StatusBar({
  stats,
}: {
  stats: { label: string; value: ReactNode; tone?: "default" | "primary" | "success" | "warning" | "destructive" | "muted" }[];
}) {
  return (
    <div className="relative flex flex-wrap items-center gap-x-5 gap-y-1.5 overflow-hidden rounded-md border border-border bg-surface-1 px-3 py-2.5 shadow-sm transition-shadow duration-200 hover:shadow-md">
      <span aria-hidden className="pointer-events-none absolute inset-y-0 left-0 w-[2px] bg-primary/50" />
      {stats.map((s, i) => {
        const dot =
          s.tone === "primary" ? "bg-primary" :
          s.tone === "success" ? "bg-success" :
          s.tone === "warning" ? "bg-warning animate-pulse" :
           s.tone === "destructive" ? "bg-destructive" :
           s.tone === "muted" ? "bg-muted-foreground/40" :
          "bg-foreground/40";
        return (
          <div key={i} className="flex items-center gap-1.5">
            <span className={"inline-block h-1.5 w-1.5 rounded-full " + dot} />
            <span className="text-mono ba-text-2xs text-muted-foreground">{s.label}</span>
            <span
              className={
                "text-mono ba-text-sm tabular-nums " +
                (s.tone === "primary" ? "text-primary" :
                 s.tone === "success" ? "text-success" :
                 s.tone === "warning" ? "text-warning" :
                  s.tone === "destructive" ? "text-destructive" :
                  s.tone === "muted" ? "text-muted-foreground" :
                 "text-foreground")
              }
            >
              {s.value}
            </span>
          </div>
        );
      })}
    </div>
  );
}
