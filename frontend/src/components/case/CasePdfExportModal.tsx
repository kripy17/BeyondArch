import { useState } from "react";
import { X, Printer, Download, Copy, Check, FileText, Code2, ShieldAlert } from "lucide-react";
import type { Case } from "@/data/case";
import { copyText } from "@/lib/copy";
import { downloadTextFile } from "@/lib/download";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface CasePdfExportModalProps {
  open: boolean;
  onClose: () => void;
  caseData: Case;
  markdown: string;
  printHtml: string;
}

export function CasePdfExportModal({
  open,
  onClose,
  caseData,
  markdown,
  printHtml,
}: CasePdfExportModalProps) {
  const [copied, setCopied] = useState(false);
  const [previewTab, setPreviewTab] = useState<"visual" | "markdown">("visual");

  if (!open) return null;

  const handlePrintPdf = () => {
    try {
      const printWindow = window.open("", "_blank");
      if (printWindow) {
        printWindow.document.write(printHtml);
        printWindow.document.close();
        printWindow.focus();
        setTimeout(() => {
          printWindow.print();
        }, 400);
        toast.success("Opened print dialog — select 'Save as PDF' to save");
      } else {
        toast.error("Pop-up blocked by browser. Please allow pop-ups to print PDF.");
      }
    } catch {
      toast.error("Failed to initiate PDF print dialog");
    }
  };

  const handleDownloadHtml = () => {
    try {
      downloadTextFile(`dfir-incident-report-${caseData.id}.html`, printHtml, "text/html");
      toast.success("Downloaded standalone publication HTML report");
    } catch {
      toast.error("Failed to download HTML report");
    }
  };

  const handleDownloadMd = () => {
    try {
      downloadTextFile(`dfir-incident-report-${caseData.id}.md`, markdown, "text/markdown");
      toast.success("Downloaded enterprise Markdown report");
    } catch {
      toast.error("Failed to download Markdown report");
    }
  };

  const handleCopyMd = async () => {
    const ok = await copyText(markdown);
    if (ok) {
      setCopied(true);
      toast.success("Copied full Markdown report with YAML frontmatter to clipboard");
      setTimeout(() => setCopied(false), 1600);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-xs p-3 sm:p-6 animate-in fade-in duration-150">
      <div
        className="relative w-full max-w-5xl max-h-[92vh] flex flex-col rounded-xl border border-primary/40 bg-surface-1 shadow-2xl overflow-hidden"
        role="dialog"
        aria-modal="true"
      >
        {/* Modal Top Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-subtle bg-surface-1/90 px-4 py-3.5">
          <div className="flex items-center gap-3">
            <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-primary/40 bg-primary/10 text-primary">
              <FileText className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="font-mono ba-text-sm font-bold text-foreground">
                  Enterprise DFIR Incident Report Suite
                </h2>
                <span className="rounded border border-amber-500/50 bg-amber-500/10 px-1.5 py-0.2 font-mono ba-text-3xs font-bold text-amber-400">
                  TLP:AMBER+STRICT
                </span>
              </div>
              <p className="font-mono ba-text-3xs text-muted-foreground">
                SANS IR / NIST SP 800-61r2 Post-Mortem Standards · Publication-grade PDF & Markdown
              </p>
            </div>
          </div>

          {/* Top Quick Actions */}
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              onClick={handlePrintPdf}
              className="inline-flex items-center gap-1.5 rounded-md border border-primary/60 bg-primary/20 px-3 py-1.5 font-mono ba-text-2xs font-bold text-primary transition-all hover:bg-primary/30 shadow-xs"
              title="Open browser print dialog formatted specifically for PDF saving"
            >
              <Printer className="h-3.5 w-3.5" />
              <span>Print / Save as PDF</span>
            </button>

            <button
              onClick={handleDownloadHtml}
              className="inline-flex items-center gap-1.5 rounded-md border border-subtle bg-surface-0 px-2.5 py-1.5 font-mono ba-text-2xs font-medium text-foreground transition-colors hover:border-primary/40"
              title="Download standalone HTML with embedded print styles"
            >
              <Download className="h-3.5 w-3.5" />
              <span>Standalone .html</span>
            </button>

            <button
              onClick={handleDownloadMd}
              className="inline-flex items-center gap-1.5 rounded-md border border-subtle bg-surface-0 px-2.5 py-1.5 font-mono ba-text-2xs font-medium text-foreground transition-colors hover:border-primary/40"
              title="Download Markdown report with YAML frontmatter"
            >
              <Download className="h-3.5 w-3.5" />
              <span>.md</span>
            </button>

            <button
              onClick={handleCopyMd}
              className="inline-flex items-center gap-1.5 rounded-md border border-subtle bg-surface-0 px-2.5 py-1.5 font-mono ba-text-2xs font-medium text-foreground transition-colors hover:border-primary/40"
              title="Copy Markdown with YAML frontmatter"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copied ? "Copied" : "Copy"}</span>
            </button>

            <button
              onClick={onClose}
              className="rounded p-1 text-muted-foreground hover:bg-surface-2 hover:text-foreground"
              aria-label="Close modal"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Preview Selector Toolbar */}
        <div className="flex items-center justify-between border-b border-subtle bg-surface-0/60 px-4 py-2 font-mono ba-text-3xs">
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setPreviewTab("visual")}
              className={cn(
                "rounded px-2.5 py-1 transition-colors",
                previewTab === "visual"
                  ? "bg-primary/20 text-primary font-semibold border border-primary/40"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              Visual Publication Preview
            </button>
            <button
              onClick={() => setPreviewTab("markdown")}
              className={cn(
                "rounded px-2.5 py-1 transition-colors",
                previewTab === "markdown"
                  ? "bg-primary/20 text-primary font-semibold border border-primary/40"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              Raw DFIR Markdown (with Frontmatter)
            </button>
          </div>

          <span className="hidden sm:inline text-muted-foreground">
            Case: <strong>{caseData.id}</strong> · {caseData.title}
          </span>
        </div>

        {/* Modal Main Stage Preview */}
        <div className="flex-1 overflow-y-auto p-4 bg-surface-0/90">
          {previewTab === "visual" ? (
            <div className="rounded-lg border border-subtle bg-white text-slate-900 shadow-inner overflow-hidden">
              <iframe
                title="DFIR Incident Report Preview"
                srcDoc={printHtml}
                className="w-full h-[65vh] border-0 bg-white"
                sandbox="allow-same-origin"
              />
            </div>
          ) : (
            <div className="rounded-lg border border-subtle bg-surface-1 p-4">
              <pre className="whitespace-pre-wrap break-words font-mono ba-text-xs text-foreground leading-relaxed selection:bg-primary/25">
                {markdown}
              </pre>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-subtle bg-surface-1 px-4 py-2.5">
          <div className="flex items-center gap-2 font-mono ba-text-3xs text-muted-foreground">
            <ShieldAlert className="h-3.5 w-3.5 text-warning" />
            <span>Ready for Executive Board Review, Legal Hold, and SANS Incident Closure</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrintPdf}
              className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-3 py-1 font-mono ba-text-2xs font-semibold text-primary hover:bg-primary/20"
            >
              <Printer className="h-3 w-3" />
              <span>Print to PDF</span>
            </button>
            <button
              onClick={onClose}
              className="rounded border border-subtle bg-surface-2 px-3 py-1 font-mono ba-text-2xs text-muted-foreground hover:text-foreground"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
