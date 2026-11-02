import type { Finding } from "@/types/security";
import { Panel, Chip } from "@/components/soc";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "border-destructive/40",
  high: "border-warning/40",
  medium: "border-warning/30",
  low: "border-success/30",
  info: "border-info/20",
};

const SEVERITY_CHIP: Record<string, "destructive" | "warning" | "success" | "info"> = {
  critical: "destructive",
  high: "warning",
  medium: "warning",
  low: "success",
  info: "info",
};

export function FindingsPanel({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return null;
  return (
    <div>
      {findings.map((f, i) => (
        <div key={f.id ?? i} className="mb-2 last:mb-0">
          <Panel title="" bodyClassName="p-0">
            <div className={"border-l-2 px-4 py-3 " + (SEVERITY_STYLES[f.severity] ?? "border-info/20")}>
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Chip tone={SEVERITY_CHIP[f.severity] ?? "info"}>{f.severity}</Chip>
                  <span className="text-mono ba-text-sm font-medium text-foreground">{f.title}</span>
                </div>
              </div>
              <p className="mt-1.5 text-mono ba-text-sm text-fg-dim">{f.detail}</p>
            </div>
          </Panel>
        </div>
      ))}
    </div>
  );
}
