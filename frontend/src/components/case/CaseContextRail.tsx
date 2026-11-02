import { useState, useRef } from "react";
import { Link } from "@tanstack/react-router";
import {
  StickyNote, Search, GitBranch, Crosshair, Siren, Paperclip,
  Check, Copy, ExternalLink, ShieldAlert, Layers, ChevronRight,
  ChevronDown, Plus, Clock, X
} from "lucide-react";
import type { Case, EntryKind } from "@/data/case";
import type { EntryAttachment } from "@/lib/attachments";
import { getUnifiedIOCs } from "@/components/investigation/legacy-adapter";
import { defang } from "@/lib/ioc-patterns";
import { copyText } from "@/lib/copy";
import { mitreRows } from "@/lib/report";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface CaseContextRailProps {
  caseData: Case;
  onAddEntry: (body: string, kind: EntryKind, attachments?: EntryAttachment[]) => void;
  pendingAttachments: EntryAttachment[];
  onAddAttachmentFiles: (files: FileList) => void;
  onRemoveAttachment: (id: string) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  className?: string;
}

const KIND_META: { kind: EntryKind; label: string; icon: typeof StickyNote; tone: string }[] = [
  { kind: "note", label: "Note", icon: StickyNote, tone: "text-muted-foreground" },
  { kind: "evidence", label: "Evidence", icon: Search, tone: "text-primary" },
  { kind: "decision", label: "Decision", icon: GitBranch, tone: "text-warning" },
  { kind: "action", label: "Action", icon: Crosshair, tone: "text-success" },
  { kind: "ioc", label: "IOC", icon: Siren, tone: "text-destructive" },
];

export function CaseContextRail({
  caseData,
  onAddEntry,
  pendingAttachments,
  onAddAttachmentFiles,
  onRemoveAttachment,
  collapsed,
  onToggleCollapse,
  className,
}: CaseContextRailProps) {
  const [draft, setDraft] = useState("");
  const [selectedKind, setSelectedKind] = useState<EntryKind>("note");
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const iocs = getUnifiedIOCs(caseData);
  const mitre = mitreRows(caseData);

  const handleSubmit = () => {
    if (!draft.trim() && pendingAttachments.length === 0) return;
    onAddEntry(draft.trim(), selectedKind, pendingAttachments);
    setDraft("");
  };

  const handleCopyIoc = async (val: string, id: string) => {
    const safe = defang(val);
    const ok = await copyText(safe);
    if (ok) {
      setCopiedIoc(id);
      toast.success(`Copied safe observable: ${safe}`);
      setTimeout(() => setCopiedIoc(null), 1500);
    }
  };

  if (collapsed) {
    return (
      <div className={cn("flex flex-col items-center py-2 px-1 border border-border/70 rounded-xl bg-surface-0 shadow-xs", className)}>
        <button
          onClick={onToggleCollapse}
          className="rounded p-1 text-muted-foreground hover:text-foreground hover:bg-surface-2 transition-colors"
          title="Expand Incident Context Rail"
        >
          <ChevronRight className="h-4 w-4 rotate-180" />
        </button>
        <span className="mt-4 font-mono ba-text-3xs text-muted-foreground uppercase tracking-widest [writing-mode:vertical-lr] rotate-180">
          Context & Intake
        </span>
      </div>
    );
  }

  return (
    <aside className={cn("w-full lg:w-84 xl:w-92 shrink-0 rounded-xl border border-border/80 bg-surface-0 shadow-xs flex flex-col gap-3 p-3.5 overflow-y-auto", className)}>
      {/* Rail Header */}
      <div className="flex items-center justify-between pb-2 border-b border-subtle">
        <div className="flex items-center gap-1.5 font-mono ba-text-2xs font-bold text-foreground uppercase tracking-wider">
          <Layers className="h-3.5 w-3.5 text-primary" />
          <span>Incident Context & Intake</span>
        </div>
        <button
          onClick={onToggleCollapse}
          className="rounded p-1 text-muted-foreground hover:text-foreground hover:bg-surface-2 transition-colors"
          title="Collapse rail"
        >
          <ChevronRight className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Quick Intake Dock */}
      <div className="rounded-lg border border-subtle bg-surface-0/90 p-3 space-y-2.5 shadow-xs">
        <div className="flex items-center justify-between">
          <span className="font-mono ba-text-3xs text-muted-foreground uppercase font-semibold">
            Fast Intake Entry
          </span>
          <span className="font-mono ba-text-3xs text-muted-foreground">
            Active Case
          </span>
        </div>

        {/* Kind Picker */}
        <div className="grid grid-cols-5 gap-1">
          {KIND_META.map((k) => (
            <button
              key={k.kind}
              type="button"
              onClick={() => setSelectedKind(k.kind)}
              className={cn(
                "flex flex-col items-center justify-center py-1 rounded font-mono ba-text-3xs transition-all",
                selectedKind === k.kind
                  ? "bg-primary/20 text-primary font-bold border border-primary/40 shadow-2xs"
                  : "bg-surface-1 text-muted-foreground hover:text-foreground hover:bg-surface-2 border border-subtle"
              )}
            >
              <k.icon className={cn("h-3 w-3 mb-0.5", k.tone)} />
              <span>{k.label}</span>
            </button>
          ))}
        </div>

        {/* Text Input */}
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
              e.preventDefault();
              handleSubmit();
            }
          }}
          placeholder={`Append ${selectedKind} to case timeline...`}
          rows={3}
          className="w-full rounded border border-border bg-surface-1 p-2 font-mono ba-text-xs text-foreground placeholder:text-muted-foreground/60 focus:border-primary/50 focus:outline-none resize-none"
        />

        {/* Attachments & Submit */}
        <div className="flex items-center justify-between pt-1">
          <div className="flex items-center gap-1.5">
            <input
              ref={fileInputRef}
              type="file"
              multiple
              className="hidden"
              onChange={(e) => {
                if (e.target.files) onAddAttachmentFiles(e.target.files);
              }}
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-1 font-mono ba-text-3xs text-muted-foreground hover:text-foreground"
              title="Attach forensic evidence file"
            >
              <Paperclip className="h-3 w-3" />
              <span>Attach</span>
            </button>
            {pendingAttachments.length > 0 && (
              <span className="font-mono ba-text-3xs text-primary">
                {pendingAttachments.length} file(s)
              </span>
            )}
          </div>

          <button
            type="button"
            onClick={handleSubmit}
            disabled={!draft.trim() && pendingAttachments.length === 0}
            className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/15 px-3 py-1 font-mono ba-text-2xs font-semibold text-primary hover:bg-primary/25 disabled:opacity-40 disabled:pointer-events-none transition-colors"
          >
            <Plus className="h-3 w-3" />
            <span>Append</span>
          </button>
        </div>

        {/* Pending attachments preview */}
        {pendingAttachments.length > 0 && (
          <div className="space-y-1 pt-1 border-t border-subtle">
            {pendingAttachments.map((att) => (
              <div
                key={att.id}
                className="flex items-center justify-between rounded bg-surface-1 px-2 py-0.5 font-mono ba-text-3xs text-muted-foreground"
              >
                <span className="truncate max-w-[180px]">{att.name}</span>
                <button
                  onClick={() => onRemoveAttachment(att.id)}
                  className="text-muted-foreground hover:text-destructive"
                >
                  <X className="h-2.5 w-2.5" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Lead Observables Quick Vault */}
      <div className="rounded-lg border border-subtle bg-surface-0/70 p-3 space-y-2">
        <div className="flex items-center justify-between font-mono ba-text-3xs">
          <span className="font-semibold uppercase text-muted-foreground">
            Lead Observables ({iocs.length})
          </span>
          <Link to="/parser" className="text-primary hover:underline lowercase">
            + parser
          </Link>
        </div>

        {iocs.length > 0 ? (
          <div className="space-y-1 max-h-48 overflow-y-auto pr-1">
            {iocs.slice(0, 6).map((ioc) => {
              const defVal = defang(ioc.value);
              const isCrit = ioc.severity === "critical";
              const isHigh = ioc.severity === "high";

              return (
                <div
                  key={ioc.id || ioc.value}
                  className="flex items-center justify-between gap-1.5 rounded border border-subtle bg-surface-1 px-2 py-1"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1 font-mono ba-text-3xs">
                      <span
                        className={cn(
                          "rounded px-1 py-0.2 uppercase font-bold",
                          isCrit
                            ? "bg-destructive/15 text-destructive"
                            : isHigh
                            ? "bg-warning/15 text-warning"
                            : "bg-surface-2 text-muted-foreground"
                        )}
                      >
                        {ioc.severity}
                      </span>
                      <span className="text-muted-foreground">{ioc.type}</span>
                    </div>
                    <div className="mt-0.5 truncate font-mono ba-text-xs text-foreground" title={defVal}>
                      {defVal}
                    </div>
                  </div>

                  <div className="flex items-center gap-0.5 shrink-0">
                    <button
                      onClick={() => handleCopyIoc(ioc.value, ioc.id || ioc.value)}
                      className="p-1 rounded text-muted-foreground hover:bg-surface-2 hover:text-foreground"
                      title="Copy defanged value"
                    >
                      {copiedIoc === (ioc.id || ioc.value) ? (
                        <Check className="h-3 w-3 text-success" />
                      ) : (
                        <Copy className="h-3 w-3" />
                      )}
                    </button>
                    <Link
                      to="/intel"
                      search={{ q: ioc.value }}
                      className="p-1 rounded text-muted-foreground hover:bg-surface-2 hover:text-primary"
                      title="Intel Pivot"
                    >
                      <ExternalLink className="h-3 w-3" />
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-center py-2 font-mono ba-text-3xs text-muted-foreground">
            No indicators attached yet.
          </div>
        )}
      </div>

      {/* MITRE ATT&CK Technique Posture */}
      {mitre.length > 0 && (
        <div className="rounded-lg border border-subtle bg-surface-0/70 p-3 space-y-2">
          <div className="flex items-center justify-between font-mono ba-text-3xs">
            <span className="font-semibold uppercase text-muted-foreground">
              MITRE ATT&CK Posture
            </span>
            <Link to="/mitre" className="text-primary hover:underline">
              matrix
            </Link>
          </div>

          <div className="flex flex-wrap gap-1">
            {mitre.slice(0, 6).map((m) => (
              <Link
                key={m.technique}
                to="/mitre"
                search={{ technique: m.technique }}
                className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 font-mono ba-text-3xs text-primary hover:bg-primary/20"
                title={`${m.technique} — ${m.count} detection(s)`}
              >
                <span>{m.technique}</span>
                <span className="opacity-70 text-2xs font-bold">({m.count})</span>
              </Link>
            ))}
          </div>
        </div>
      )}
    </aside>
  );
}
