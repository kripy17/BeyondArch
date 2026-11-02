import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";

export function EntitySection({
  title,
  icon: Icon,
  meta,
  children,
  className = "",
  headingLevel = "h3",
}: {
  title?: string;
  icon?: LucideIcon;
  meta?: string;
  children: ReactNode;
  className?: string;
  headingLevel?: "h2" | "h3";
}) {
  const Title = headingLevel;
  return (
    <section className={"group/section rounded-md border border-subtle bg-surface-1 shadow-sm transition-all duration-200 hover:border-primary/20 hover:shadow-md " + className}>
      {title && (
        <header className="flex items-center gap-3 border-b border-subtle px-4 py-2.5">
          {Icon && <Icon className="h-3.5 w-3.5 shrink-0 text-primary/70" />}
          <Title className="font-mono ba-text-2xs text-fg-dim">{title}</Title>
          {meta && <span className="font-mono ba-text-3xs text-muted-foreground">· {meta}</span>}
        </header>
      )}
      <div className="px-4 py-3">{children}</div>
    </section>
  );
}

export function EntitySectionRow({ label, value, className = "" }: { label: string; value: string; className?: string }) {
  return (
    <div className={"flex items-baseline gap-3 " + className}>
      <span className="shrink-0 font-mono ba-text-3xs text-fg-dim">{label}</span>
      <span className="truncate font-mono ba-text-xs text-foreground">{value}</span>
    </div>
  );
}
