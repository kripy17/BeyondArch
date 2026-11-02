import { AlertTriangle } from "lucide-react";

export function ErrorState({
  title = "Something went wrong",
  message,
  onRetry,
  className,
}: {
  title?: string;
  message?: string;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div className={"flex items-center justify-center py-12 " + (className ?? "")}>
      <div className="max-w-sm text-center">
        <AlertTriangle className="mx-auto h-8 w-8 text-destructive/70" />
        <h3 className="mt-3 text-mono ba-text-base text-foreground">{title}</h3>
        {message && (
          <p className="mt-1 ba-text-sm text-muted-foreground">{message}</p>
        )}
        {onRetry && (
          <button
            onClick={onRetry}
            className="mt-4 inline-flex items-center gap-1.5 rounded-md border border-primary/40 bg-primary/10 px-3 py-1.5 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"
          >
            $ retry
          </button>
        )}
      </div>
    </div>
  );
}
