import { Panel, Chip } from "@/components/soc";

type TimelineEntry = { line?: number | string; severity: string; label: string };

export function TimelinePanel({
  events,
  title = "Event Timeline",
  onSelectLine,
}: {
  events: TimelineEntry[];
  title?: string;
  onSelectLine?: (line: number) => void;
}) {
  if (events.length === 0) return null;
  return (
    <Panel title={title}>
      <div className="space-y-1">
        {events.map((t, i) => (
          <div
            key={i}
            onClick={() => t.line != null && onSelectLine?.(Number(t.line))}
            className={`flex items-center gap-3 rounded border border-border/60 bg-surface-0 px-3 py-2 transition-colors ${
              onSelectLine && t.line != null ? "cursor-pointer hover:border-primary/50 hover:bg-surface-1" : ""
            }`}
          >
            {t.line != null && (
              <div className="flex-shrink-0 w-16 text-mono ba-text-2xs text-primary font-mono font-medium">
                L{t.line}
              </div>
            )}
            <Chip tone={t.severity === "critical" ? "destructive" : t.severity === "high" || t.severity === "medium" ? "warning" : t.severity === "low" ? "success" : "info"}>{t.severity}</Chip>
            <span className="text-mono ba-text-sm text-fg-dim">{t.label}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}
