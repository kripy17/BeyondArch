import { useState, useCallback, type ReactNode } from "react";
import { ChevronDown, type LucideIcon } from "lucide-react";

export function Panel({
  title,
  icon: Icon,
  meta,
  actions,
  children,
  className = "",
  bodyClassName = "",
  collapsible,
  defaultCollapsed,
  storageKey,
  sticky,
}: {
  title?: string;
  icon?: LucideIcon;
  meta?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  collapsible?: boolean;
  defaultCollapsed?: boolean;
  storageKey?: string;
  sticky?: boolean;
  priority?: "primary" | "secondary" | "raw";
}) {
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    if (storageKey) {
      try { return JSON.parse(localStorage.getItem(storageKey) || "null") ?? !!defaultCollapsed; } catch {}
    }
    return !!defaultCollapsed;
  });

  const toggle = useCallback(() => {
    setCollapsed((c) => {
      const next = !c;
      if (storageKey) {
        try { localStorage.setItem(storageKey, JSON.stringify(next)); } catch {}
      }
      return next;
    });
  }, [storageKey]);

  const canCollapse = collapsible && !!title;

  return (
    <section className={"ba-fade-in relative overflow-hidden rounded-md border bg-surface-2 shadow-sm transition-all duration-200 hover:border-primary/20 hover:shadow-md " + (sticky ? "sticky top-0 z-10 elevation-flat" : "") + " " + className}>
      {title && (
        <header
          className={"flex items-center justify-between gap-2 border-b border-divider-strong px-4 py-2.5 " + (canCollapse ? "cursor-pointer select-none hover:bg-surface-1" : "")}
          onClick={canCollapse ? toggle : undefined}
        >
          <div className="flex items-center gap-2 min-w-0">
            {canCollapse && (
              <ChevronDown className={"h-3 w-3 shrink-0 text-muted-foreground transition-transform duration-150 " + (collapsed ? "-rotate-90" : "")} />
            )}
            {Icon && <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />}
            <h2 className="text-mono ba-text-sm text-foreground truncate">{title}</h2>
            {meta && <span className="text-mono ba-text-2xs text-muted-foreground shrink-0">· {meta}</span>}
          </div>
          {actions && <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>{actions}</div>}
        </header>
      )}
      {(!canCollapse || !collapsed) && (
        <div className={"p-4 " + bodyClassName}>{children}</div>
      )}
    </section>
  );
}
