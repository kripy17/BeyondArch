export type Severity = "info" | "low" | "medium" | "high" | "critical";

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityTone(sev: Severity): "info" | "warning" | "success" | "destructive" {
  switch (sev) {
    case "critical": return "destructive";
    case "high": return "warning";
    case "medium": return "warning";
    case "low": return "success";
    case "info": return "info";
  }
}
