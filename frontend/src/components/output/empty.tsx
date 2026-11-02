import { type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export function Empty({
  icon: Icon,
  title,
  hint,
  examples,
  onSample,
  shortcut,
  children,
  compact = false,
}: {
  icon?: LucideIcon;
  title: string;
  hint?: string;
  examples?: string[];
  onSample?: (example: string) => void;
  shortcut?: string;
  children?: ReactNode;
  compact?: boolean;
}) {
  return (
    <div className={"relative flex flex-col items-center justify-center overflow-hidden rounded-md border border-dashed border-border bg-background/30 text-center " + (compact ? "gap-2 py-6" : "gap-3 py-14")}>
      <div aria-hidden className="pointer-events-none absolute inset-0 bg-[linear-gradient(transparent_95%,hsl(var(--border)/0.4)_95%)] bg-[length:100%_8px] opacity-40" />
      {Icon && (
        <div className={"relative grid place-items-center rounded-lg border border-border bg-surface-2 shadow-sm transition-transform duration-200 " + (compact ? "h-9 w-9" : "h-12 w-12")}>
          <Icon className={compact ? "h-4 w-4 text-muted-foreground/70" : "h-5 w-5 text-muted-foreground/70"} />
        </div>
      )}
      <div className={"relative font-mono font-medium text-fg-dim " + (compact ? "text-mono ba-text-sm" : "text-mono ba-text-lg")}>{title}</div>
      {hint && <div className={"relative max-w-sm font-mono leading-relaxed text-muted-foreground " + (compact ? "text-mono ba-text-2xs" : "text-mono ba-text-sm")}>{hint}</div>}
      {examples && examples.length > 0 && (
        <div className="relative mt-2 flex flex-wrap justify-center gap-1.5">
          {examples.map((ex) =>
            onSample ? (
              <button
                key={ex}
                onClick={() => onSample(ex)}
                className="cursor-pointer rounded-full border border-divider-soft bg-surface-1 px-2.5 py-0.5 text-mono ba-text-3xs text-muted-foreground transition-colors duration-150 hover:border-primary/50 hover:text-foreground"
              >
                {ex}
              </button>
            ) : (
              <span key={ex} className="rounded-full border border-divider-soft bg-surface-1 px-2.5 py-0.5 text-mono ba-text-3xs text-muted-foreground">
                {ex}
              </span>
            ),
          )}
        </div>
      )}
      {children && <div className="relative mt-2">{children}</div>}
    </div>
  );
}
