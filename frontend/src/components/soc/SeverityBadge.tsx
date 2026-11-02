import { cn } from "@/lib/utils";
import { type Severity } from "@/lib/severity";

const styles: Record<Severity, string> = {
  critical: "border-destructive/40 bg-destructive/15 text-destructive",
  high:     "border-warning/40 bg-warning/15 text-warning",
  medium:   "border-warning/40 bg-warning/10 text-warning",
  low:      "border-success/40 bg-success/10 text-success",
  info:     "border-border bg-muted/40 text-muted-foreground",
};

export function SeverityBadge({ level, className }: { level: Severity; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-mono ba-text-2xs font-semibold",
        styles[level],
        className,
      )}
    >
      <span className="status-dot" /> {level}
    </span>
  );
}
