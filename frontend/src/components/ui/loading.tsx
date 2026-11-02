import { Loader2 } from "lucide-react";

export function Loading({
  label = "Loading...",
  className,
}: {
  label?: string;
  className?: string;
}) {
  return (
    <div className={"flex items-center justify-center py-12 " + (className ?? "")}>
      <div className="text-center">
        <Loader2 className="mx-auto h-6 w-6 animate-spin text-muted-foreground/50" />
        <p className="mt-3 text-mono ba-text-sm text-muted-foreground">{label}</p>
      </div>
    </div>
  );
}
