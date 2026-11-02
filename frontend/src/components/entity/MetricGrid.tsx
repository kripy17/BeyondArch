import type { ReactNode } from "react";

interface Metric {
  label: string;
  value: string | number;
  tone?: "default" | "primary" | "destructive" | "warning" | "info";
}

export function MetricGrid({ metrics, className = "" }: { metrics: Metric[]; className?: string }) {
  return (
    <div className={"grid grid-cols-2 gap-3 sm:grid-cols-4 " + className}>
      {metrics.map((m) => (
        <MetricCard key={m.label} label={m.label} value={m.value} tone={m.tone} />
      ))}
    </div>
  );
}

export function MetricCard({
  label,
  value,
  tone = "default",
  children,
  onClick,
}: {
  label: string;
  value?: string | number;
  tone?: Metric["tone"];
  children?: ReactNode;
  onClick?: () => void;
}) {
  const valueCls =
    tone === "primary" ? "text-primary" :
    tone === "destructive" ? "text-destructive" :
    tone === "warning" ? "text-warning" :
    tone === "info" ? "text-info" :
    "text-foreground";
  return (
    <button
      disabled={!onClick}
      onClick={onClick}
      className="group/metric relative overflow-hidden rounded-md border border-subtle bg-surface-1 p-3 text-left shadow-sm transition-all duration-200 hover:-translate-y-[1px] hover:border-primary/30 hover:bg-surface-2 hover:shadow-md disabled:cursor-default"
    >
      <span aria-hidden className="absolute inset-x-0 bottom-0 h-[2px] bg-primary/30 transition-all duration-200 group-hover/metric:bg-primary/60 group-hover/metric:h-[3px]" />
      <div className="font-mono ba-text-2xs text-fg-dim">{label}</div>
      {children ?? (
        <div className={"mt-0.5 font-mono text-lg font-bold tabular-nums " + valueCls}>{value ?? "—"}</div>
      )}
    </button>
  );
}
