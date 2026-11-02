import { useNavigate } from "@tanstack/react-router";
import { FileText, Siren, Database, ExternalLink, FolderOpen, Check } from "lucide-react";


interface ActionDockProps {
  activeCase: { id: string; title: string } | null;
  findingCreated: boolean;
  iocsAttached: boolean;
  observableCount: number;
  onCreateFinding: () => void;
  onAttachIocs: () => void;
  onAddToLocker: () => void;
  onExport: () => void;
}

export function ActionDock({
  activeCase,
  findingCreated,
  iocsAttached,
  observableCount,
  onCreateFinding,
  onAttachIocs,
  onAddToLocker,
  onExport,
}: ActionDockProps) {
  const navigate = useNavigate();

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={onAddToLocker}
          className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 font-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"
        >
          <Database className="h-3.5 w-3.5" /> Add to Locker
        </button>
        <button
          onClick={onExport}
          className="inline-flex items-center gap-1 rounded border border-subtle px-2.5 py-1.5 font-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:text-foreground"
        >
          <ExternalLink className="h-3.5 w-3.5" /> Export MD
        </button>
      </div>

      <div className="rounded-md border border-subtle bg-surface-1 p-3">
        <h4 className="mb-2 font-mono ba-text-2xs text-fg-dim">Case Actions</h4>
        {activeCase ? (
          <div className="space-y-2">
            <div className="flex items-center gap-2 font-mono ba-text-2xs text-fg-dim">
              <FolderOpen className="h-3.5 w-3.5" />
              Case:{" "}
              <button
                onClick={() => navigate({ to: "/case" })}
                className="font-semibold text-foreground underline-offset-2 hover:underline"
              >
                {activeCase.title}
              </button>
            </div>
            {findingCreated && iocsAttached ? (
              <div className="flex items-center gap-2 rounded border border-success/40 bg-success/10 px-3 py-2 font-mono ba-text-2xs text-success">
                <Check className="h-3.5 w-3.5" />
                Entity added to case — finding created, IOCs attached.
                <button
                  onClick={() => navigate({ to: "/case" })}
                  className="ml-auto underline-offset-2 hover:underline"
                >
                  View in Case →
                </button>
              </div>
            ) : findingCreated ? (
              <div className="flex items-center gap-2 rounded border border-success/40 bg-success/10 px-3 py-2 font-mono ba-text-2xs">
                <Check className="h-3.5 w-3.5 text-success" />
                <span className="text-foreground">Finding created</span>
                <button
                  onClick={() => navigate({ to: "/case" })}
                  className="ml-auto text-primary underline-offset-2 hover:underline"
                >
                  View in Case →
                </button>
              </div>
            ) : null}
            <div className="flex flex-wrap gap-2">
              {!findingCreated && (
                <button
                  onClick={onCreateFinding}
                  className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 font-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"
                >
                  <FileText className="h-3.5 w-3.5" /> Create Finding
                </button>
              )}
              {observableCount > 0 && !iocsAttached && (
                <button
                  onClick={onAttachIocs}
                  className="inline-flex items-center gap-1 rounded border border-warning/40 bg-warning/10 px-2.5 py-1.5 font-mono ba-text-2xs text-warning transition-colors duration-150 hover:bg-warning/20"
                >
                  <Siren className="h-3.5 w-3.5" /> Attach IOCs ({observableCount})
                </button>
              )}
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-2 font-mono ba-text-2xs text-fg-dim">
            <FolderOpen className="h-3.5 w-3.5" />
            No active case — open a case from the Investigation workspace first.
          </div>
        )}
      </div>
    </div>
  );
}
