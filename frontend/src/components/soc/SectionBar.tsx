import { type ReactNode } from "react";
import { ArrowDownToLine, ArrowUpFromLine, Clock, Filter, Settings2, ShieldCheck, type LucideIcon } from "lucide-react";

const SECTION_ICONS: Record<string, LucideIcon> = {
  IN: ArrowDownToLine,
  OT: ArrowUpFromLine,
  RC: Clock,
  FL: Filter,
  CF: Settings2,
  AI: ShieldCheck,
};

export function SectionBar({
  id,
  label,
  meta,
  action,
  icon,
  priority = "primary",
  children,
  headingLevel = "h3",
}: {
  id: string;
  label: string;
  meta?: string;
  action?: ReactNode;
  icon?: LucideIcon;
  priority?: "primary" | "secondary" | "raw";
  children?: ReactNode;
  headingLevel?: "h2" | "h3";
}) {
  const Icon = icon ?? SECTION_ICONS[id.toUpperCase()];
  const Tag = headingLevel as "h2" | "h3";
  if (priority === "raw") {
    return (
      <>
        <div className="mb-2 mt-0.5 flex items-center gap-2">
          {Icon && <Icon className="h-3 w-3 text-muted-foreground" strokeWidth={2} />}
          <span className="text-mono ba-text-sm text-muted-foreground">{label}</span>
          {meta && <span className="text-mono ba-text-3xs text-fg-dim">· {meta}</span>}
          <div className="h-px flex-1 bg-border/30" />
          {action}
        </div>
        {children}
      </>
    );
  }
  if (priority === "secondary") {
    return (
      <>
        <div className="group/sb mb-2 mt-0.5 flex items-center gap-2.5">
          <span className="relative grid h-5 w-5 place-items-center rounded-sm border border-divider-strong bg-surface-1 text-muted-foreground">
            {Icon ? <Icon className="h-3 w-3" strokeWidth={2} /> : <span className="text-mono ba-text-3xs font-bold">{id.slice(0, 2).toUpperCase()}</span>}
          </span>
          <Tag className="text-mono ba-text-sm text-fg-dim">{label}</Tag>
          <div className="h-px flex-1 bg-border/30" />
          {meta && <span className="rounded border border-divider-soft bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground">{meta}</span>}
          {action}
        </div>
        {children}
      </>
    );
  }
  return (
    <>
      <div className="group/sb mb-3 mt-1 flex flex-wrap items-center gap-2 sm:gap-3">
        <span className="relative grid h-6 w-6 place-items-center rounded-sm border border-primary/40 bg-primary/10 text-primary transition-colors duration-150 group-hover/sb:border-primary/60">
          {Icon ? (
            <Icon className="h-3.5 w-3.5" strokeWidth={2.25} />
          ) : (
            <span className="text-mono ba-text-3xs font-bold">{id.slice(0, 2).toUpperCase()}</span>
          )}
        </span>
        <h2 className="font-display text-mono ba-text-sm text-foreground">
          {label}
        </h2>
        <div className="h-px flex-1 min-w-[12px] bg-border/30" />
        {meta && <span className="rounded border border-divider-strong bg-surface-1 px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground">{meta}</span>}
        {action}
      </div>
      {children}
    </>
  );
}
