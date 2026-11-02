import { useState } from "react";
import { X, ShieldAlert, Terminal, Copy, Check, Database, ExternalLink, Bookmark, StickyNote, Info, Layers } from "lucide-react";
import { Chip } from "@/components/soc";
import { getTechniqueEnrichment, type CoverageLevel } from "@/lib/detection/navigator-layer-engine";
import { copyText } from "@/lib/copy";
import { notify } from "@/lib/notify";

interface TechniqueDetailDrawerProps {
  technique: {
    id: string;
    name: string;
    tactic: string;
    tacticId: string;
  } | null;
  coverage: CoverageLevel;
  onCoverageChange: (cov: CoverageLevel) => void;
  note: string;
  onSaveNote: (note: string) => void;
  onClose: () => void;
  onSendToDetection: (techId: string, techName: string) => void;
  onSendToCase?: (techId: string, techName: string) => void;
  localRulesCount?: number;
}

export function TechniqueDetailDrawer({
  technique,
  coverage,
  onCoverageChange,
  note,
  onSaveNote,
  onClose,
  onSendToDetection,
  onSendToCase,
  localRulesCount = 0,
}: TechniqueDetailDrawerProps) {
  if (!technique) return null;

  const enrichment = getTechniqueEnrichment(technique.id);
  const [cmdCopied, setCmdCopied] = useState(false);
  const [cleanupCopied, setCleanupCopied] = useState(false);
  const [noteEditing, setNoteEditing] = useState(false);
  const [noteDraft, setNoteDraft] = useState(note);

  const handleCopyCommand = (cmd: string, isCleanup = false) => {
    copyText(cmd);
    if (isCleanup) {
      setCleanupCopied(true);
      setTimeout(() => setCleanupCopied(false), 1200);
    } else {
      setCmdCopied(true);
      setTimeout(() => setCmdCopied(false), 1200);
    }
    notify.success("Copied to clipboard");
  };

  const handleSaveNote = () => {
    onSaveNote(noteDraft);
    setNoteEditing(false);
    notify.success("Note saved");
  };

  return (
    <div className="fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l border-border bg-surface-1 shadow-2xl backdrop-blur">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border p-3.5">
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-primary" />
          <span className="text-mono text-sm font-semibold text-foreground">{technique.id}</span>
          <span className="text-mono ba-text-xs text-muted-foreground">· {technique.tactic}</span>
        </div>
        <button
          onClick={onClose}
          className="rounded p-1 text-muted-foreground hover:bg-surface-2 hover:text-foreground"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 space-y-4 overflow-y-auto p-4 text-mono ba-text-2xs">
        {/* Title and Coverage */}
        <div className="rounded border border-subtle bg-surface-0 p-3">
          <div className="text-sm font-medium text-foreground">{technique.name}</div>
          <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 border-t border-border/50 pt-2">
            <span className="text-muted-foreground">Coverage Status:</span>
            <div className="flex items-center gap-1">
              {(["none", "partial", "full"] as CoverageLevel[]).map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => onCoverageChange(lvl)}
                  className={`rounded border px-2 py-0.5 capitalize transition-colors ${
                    coverage === lvl
                      ? lvl === "full"
                        ? "border-success bg-success/20 text-success font-semibold"
                        : lvl === "partial"
                          ? "border-warning bg-warning/20 text-warning font-semibold"
                          : "border-border bg-surface-2 text-foreground font-semibold"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Platforms and Data Sources */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">Platforms:</span>
            <div className="flex flex-wrap gap-1">
              {enrichment.platforms.map((p) => (
                <Chip key={p} tone="default">{p}</Chip>
              ))}
            </div>
          </div>
          <div>
            <span className="text-muted-foreground block mb-1">Required Data Sources:</span>
            <div className="flex flex-wrap gap-1">
              {enrichment.dataSources.map((ds) => (
                <span key={ds} className="rounded border border-border/60 bg-surface-0 px-2 py-0.5 text-mono ba-text-3xs text-fg-dim">
                  {ds}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Atomic Red Team Emulation */}
        <div className="rounded border border-border bg-surface-0 p-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 font-medium text-foreground">
              <Terminal className="h-3.5 w-3.5 text-warning" />
              <span>Atomic Red Team Emulation Test</span>
            </div>
            <Chip tone="warning">{enrichment.atomicTest.platform}</Chip>
          </div>
          <div className="mt-1 text-fg-dim">{enrichment.atomicTest.name}</div>
          <p className="mt-1 ba-text-3xs text-muted-foreground">{enrichment.atomicTest.description}</p>

          <div className="mt-2 relative rounded border border-border bg-background p-2">
            <pre className="overflow-x-auto text-mono ba-text-3xs text-amber-300 whitespace-pre-wrap select-all">
              {enrichment.atomicTest.command}
            </pre>
            <button
              onClick={() => handleCopyCommand(enrichment.atomicTest.command)}
              className="absolute top-1.5 right-1.5 inline-flex items-center gap-1 rounded border border-border bg-surface-1 px-1.5 py-0.5 ba-text-3xs text-muted-foreground hover:text-foreground hover:border-primary/40"
            >
              {cmdCopied ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
              {cmdCopied ? "Copied" : "Copy"}
            </button>
          </div>

          {enrichment.atomicTest.cleanup && (
            <div className="mt-2 text-muted-foreground">
              <div className="flex items-center justify-between mb-1">
                <span className="ba-text-3xs">Cleanup Command:</span>
                <button
                  onClick={() => handleCopyCommand(enrichment.atomicTest.cleanup!, true)}
                  className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground ba-text-3xs"
                >
                  {cleanupCopied ? <Check className="h-2.5 w-2.5 text-success" /> : <Copy className="h-2.5 w-2.5" />}
                  {cleanupCopied ? "Copied" : "Copy cleanup"}
                </button>
              </div>
              <pre className="overflow-x-auto rounded border border-border/60 bg-background/50 p-1.5 text-mono ba-text-3xs text-muted-foreground">
                {enrichment.atomicTest.cleanup}
              </pre>
            </div>
          )}
        </div>

        {/* Detection Guidance */}
        <div className="rounded border border-subtle bg-surface-0 p-3">
          <div className="flex items-center gap-1.5 text-foreground font-medium mb-1">
            <Info className="h-3.5 w-3.5 text-primary" />
            <span>Detection Guidance</span>
          </div>
          <p className="ba-text-3xs text-muted-foreground leading-relaxed">
            {enrichment.detectionGuidance}
          </p>
          <div className="mt-2 flex items-center justify-between border-t border-border/50 pt-2 text-muted-foreground">
            <span>Rules in BeyondLabs Library:</span>
            <Chip tone={localRulesCount > 0 ? "success" : "default"}>
              {localRulesCount} {localRulesCount === 1 ? "rule" : "rules"}
            </Chip>
          </div>
        </div>

        {/* Per-Technique Analyst Notes */}
        <div className="rounded border border-subtle bg-surface-0 p-3">
          <div className="flex items-center justify-between mb-1.5">
            <div className="flex items-center gap-1.5 text-foreground font-medium">
              <StickyNote className="h-3.5 w-3.5 text-amber-400" />
              <span>Analyst Observation Note</span>
            </div>
            {!noteEditing ? (
              <button
                onClick={() => {
                  setNoteDraft(note);
                  setNoteEditing(true);
                }}
                className="text-muted-foreground hover:text-foreground ba-text-3xs"
              >
                {note ? "Edit" : "+ Add note"}
              </button>
            ) : (
              <div className="flex items-center gap-1">
                <button
                  onClick={handleSaveNote}
                  className="text-success hover:underline ba-text-3xs"
                >
                  Save
                </button>
                <button
                  onClick={() => setNoteEditing(false)}
                  className="text-muted-foreground hover:underline ba-text-3xs"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>

          {noteEditing ? (
            <textarea
              rows={3}
              value={noteDraft}
              onChange={(e) => setNoteDraft(e.target.value)}
              placeholder="Record detection sprint status, gaps, or data source engineering notes..."
              className="w-full rounded border border-border bg-background p-2 text-mono ba-text-3xs text-foreground placeholder:text-muted-foreground outline-none focus:border-primary/50"
            />
          ) : note ? (
            <p className="ba-text-3xs text-foreground italic bg-surface-1 p-2 rounded border border-border/60">
              "{note}"
            </p>
          ) : (
            <p className="ba-text-3xs text-muted-foreground">No notes recorded yet.</p>
          )}
        </div>
      </div>

      {/* Footer Actions */}
      <div className="flex items-center justify-between gap-2 border-t border-border p-3 bg-surface-0">
        {onSendToCase && (
          <button
            onClick={() => onSendToCase(technique.id, technique.name)}
            className="inline-flex items-center gap-1.5 rounded border border-border px-2.5 py-1.5 text-mono ba-text-2xs text-muted-foreground hover:text-foreground"
          >
            <Database className="h-3.5 w-3.5" /> To Case
          </button>
        )}
        <button
          onClick={() => onSendToDetection(technique.id, technique.name)}
          className="ml-auto inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/20 px-3 py-1.5 text-mono ba-text-2xs text-primary hover:bg-primary/30"
        >
          <ShieldAlert className="h-3.5 w-3.5" /> Open in Detection Lab
        </button>
      </div>
    </div>
  );
}
