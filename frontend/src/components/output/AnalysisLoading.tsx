import { Activity } from "lucide-react";

export function AnalysisLoading({ label = "Analyzing..." }: { label?: string }) {
  return (
    <div className="flex items-center justify-center py-12">
      <div className="text-center">
        <Activity className="mx-auto h-8 w-8 animate-pulse text-fg-dim" />
        <p className="mt-3 text-mono ba-text-sm text-muted-foreground">{label}</p>
      </div>
    </div>
  );
}
