import { useState } from "react";
import { X, Copy, Download, Check, ShieldAlert } from "lucide-react";
import { toast } from "sonner";

interface SuricataRuleModalProps {
  isOpen: boolean;
  onClose: () => void;
  ruleset: string;
}

export function SuricataRuleModal({
  isOpen,
  onClose,
  ruleset,
}: SuricataRuleModalProps) {
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(ruleset);
    setCopied(true);
    toast.success("Suricata rules copied to clipboard");
    setTimeout(() => setCopied(false), 1500);
  };

  const handleDownload = () => {
    const blob = new Blob([ruleset], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `beyondlabs-pcap-detections-${Date.now()}.rules`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Downloaded Suricata rules file");
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="flex h-[75vh] w-full max-w-3xl flex-col rounded-xl border border-border bg-card shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border bg-surface-1 px-4 py-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-warning" />
            <span className="font-mono text-xs font-semibold text-foreground">
              Synthesized Suricata / Snort IDS Signatures
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopy}
              className="inline-flex items-center gap-1 rounded border border-border bg-surface-0 px-2.5 py-1 font-mono text-2xs text-muted-foreground hover:text-foreground"
            >
              {copied ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
              <span>Copy</span>
            </button>

            <button
              type="button"
              onClick={handleDownload}
              className="inline-flex items-center gap-1 rounded border border-border bg-surface-0 px-2.5 py-1 font-mono text-2xs text-muted-foreground hover:text-foreground"
            >
              <Download className="h-3 w-3" />
              <span>Download .rules</span>
            </button>

            <button
              type="button"
              onClick={onClose}
              className="rounded p-1 text-muted-foreground hover:bg-surface-2 hover:text-foreground transition"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Rules syntax view */}
        <div className="flex-1 overflow-auto bg-surface-0 p-4 font-mono text-xs text-foreground">
          <pre className="whitespace-pre-wrap leading-relaxed text-emerald-400/90 font-mono">
            {ruleset}
          </pre>
        </div>

        {/* Footer */}
        <div className="border-t border-border bg-surface-1 px-4 py-2 text-mono ba-text-2xs text-muted-foreground">
          Ready to drop into <code className="font-mono text-foreground">/etc/suricata/rules/</code> or import into pfSense / OPNsense / Security Onion.
        </div>
      </div>
    </div>
  );
}
