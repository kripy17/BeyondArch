import { useState } from "react";
import { X, Copy, Check, Download, FileText, Sparkles } from "lucide-react";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";

interface ShiftHandoverModalProps {
  open: boolean;
  onClose: () => void;
  reportMarkdown: string;
}

export function ShiftHandoverModal({ open, onClose, reportMarkdown }: ShiftHandoverModalProps) {
  const [copied, setCopied] = useState(false);

  if (!open) return null;

  const handleCopy = async () => {
    const ok = await copyText(reportMarkdown);
    if (ok) {
      setCopied(true);
      toast.success("Copied handover briefing to clipboard");
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = () => {
    try {
      const blob = new Blob([reportMarkdown], { type: "text/markdown;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      const dateStr = new Date().toISOString().slice(0, 10);
      link.href = url;
      link.download = `beyondlabs-shift-handover-${dateStr}.md`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      toast.success("Downloaded handover briefing report");
    } catch {
      toast.error("Failed to trigger file download");
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div
        className="relative w-full max-w-2xl max-h-[85vh] flex flex-col rounded-lg border border-primary/40 bg-surface-1 shadow-xl animate-in fade-in zoom-in-95 duration-150"
        role="dialog"
        aria-modal="true"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-subtle p-4">
          <div className="flex items-center gap-2.5">
            <div className="grid h-8 w-8 place-items-center rounded-lg border border-primary/40 bg-primary/10 text-primary">
              <FileText className="h-4 w-4" />
            </div>
            <div>
              <h2 className="font-mono ba-text-sm font-bold text-foreground flex items-center gap-2">
                <span>SOC Shift Handover Briefing</span>
                <span className="rounded border border-primary/40 bg-primary/10 px-1.5 py-0.2 font-mono ba-text-3xs text-primary font-normal">
                  markdown
                </span>
              </h2>
              <p className="font-mono ba-text-3xs text-muted-foreground">
                Automated summary of active cases, lead indicators, and security chronology.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="rounded p-1 text-muted-foreground hover:bg-surface-2 hover:text-foreground"
            aria-label="Close dialog"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Modal Content / Preview Area */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <div className="rounded border border-subtle bg-surface-0/80 p-3.5">
            <pre className="whitespace-pre-wrap break-words font-mono ba-text-xs text-foreground leading-relaxed selection:bg-primary/20">
              {reportMarkdown}
            </pre>
          </div>
        </div>

        {/* Modal Footer Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-subtle bg-surface-0/50 p-3">
          <span className="font-mono ba-text-3xs text-muted-foreground">
            Local-First & Confidential · Ready for Standups
          </span>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/15 px-3 py-1.5 font-mono ba-text-2xs font-semibold text-primary transition-colors hover:bg-primary/25"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copied ? "Copied" : "Copy Briefing"}</span>
            </button>

            <button
              onClick={handleDownload}
              className="inline-flex items-center gap-1.5 rounded border border-subtle bg-surface-1 px-3 py-1.5 font-mono ba-text-2xs text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
            >
              <Download className="h-3.5 w-3.5" />
              <span>Download .md</span>
            </button>

            <button
              onClick={onClose}
              className="rounded border border-subtle bg-surface-1 px-3 py-1.5 font-mono ba-text-2xs text-muted-foreground hover:bg-surface-2 hover:text-foreground"
            >
              Done
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
