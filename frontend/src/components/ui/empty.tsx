import { type LucideIcon, SearchX, Inbox } from "lucide-react";

export function Empty({
  icon: Icon = Inbox,
  title,
  hint,
  children,
}: {
  icon?: LucideIcon;
  title: string;
  hint?: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="relative flex flex-col items-center justify-center gap-2 overflow-hidden rounded-md border border-dashed border-border bg-background/30 py-10 text-center">
      <div aria-hidden className="pointer-events-none absolute inset-0 bg-[linear-gradient(transparent_95%,hsl(var(--border)/0.4)_95%)] bg-[length:100%_8px] opacity-40" />
      <div className="relative grid h-9 w-9 place-items-center rounded-md border border-border bg-surface-2">
        <Icon className="h-4 w-4 text-muted-foreground/80" />
      </div>
      <div className="relative text-mono ba-text-base text-fg-dim">{title}</div>
      {hint && <div className="relative max-w-xs ba-text-sm text-muted-foreground">{hint}</div>}
      {children && <div className="relative mt-2">{children}</div>}
    </div>
  );
}

export function SearchEmpty({
  query,
  onClear,
}: {
  query?: string;
  onClear?: () => void;
}) {
  return (
    <Empty icon={SearchX} title={query ? `No results for "${query}"` : "No results"} hint="Try a different search term">
      {onClear && (
        <button onClick={onClear} className="rounded border border-divider-soft bg-surface-1 px-2.5 py-0.5 text-mono ba-text-3xs text-muted-foreground transition-colors duration-150 hover:border-primary/50 hover:text-foreground">
          Clear filters
        </button>
      )}
    </Empty>
  );
}
