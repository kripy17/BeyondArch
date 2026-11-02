import { useState } from "react";
import { Terminal, Copy, Check, ExternalLink, ArrowRight, ShieldAlert, Sparkles, X } from "lucide-react";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import { sendToCase } from "@/lib/handoff";
import { detectAndDeobfuscate, type DeobfuscatedPayload } from "@/lib/siem/payload-deobfuscator";

interface DecodedPayloadPopoverProps {
  rawText: string;
  onPivotToDetection?: (decoded: string) => void;
}

export function DecodedPayloadPopover({ rawText, onPivotToDetection }: DecodedPayloadPopoverProps) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const payload: DeobfuscatedPayload | null = detectAndDeobfuscate(rawText);
  if (!payload) return null;

  const handleCopy = () => {
    copyText(payload.decodedText);
    setCopied(true);
    toast.success("Copied deobfuscated payload");
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSendToCase = () => {
    const lines = [
      `### Deobfuscated Payload (${payload.encoding.toUpperCase()})`,
      `\`\`\`powershell`,
      payload.decodedText,
      `\`\`\``,
      payload.extractedObservables.urls.length > 0 ? `- URLs: ${payload.extractedObservables.urls.join(", ")}` : "",
      payload.extractedObservables.ips.length > 0 ? `- IPs: ${payload.extractedObservables.ips.join(", ")}` : "",
    ].filter(Boolean);

    sendToCase({
      body: lines.join("\n"),
      source: "/siem",
      kind: "evidence",
    });
    toast.success("Attached deobfuscated payload to Case Notebook");
  };

  return (
    <div className="relative inline-block">
      <button
        onClick={() => setOpen(!open)}
        className="inline-flex items-center gap-1 rounded border border-warning/40 bg-warning/10 px-1.5 py-0.5 font-mono ba-text-3xs text-warning hover:bg-warning/20 transition-colors"
        title="Click to inspect deobfuscated payload"
      >
        <Terminal className="h-3 w-3 animate-pulse text-warning" />
        <span>Deobfuscated ({payload.encoding.toUpperCase()})</span>
      </button>

      {open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-xs"
          onClick={() => setOpen(false)}
        >
          <div
            className="flex max-h-[85vh] w-full max-w-xl flex-col rounded-lg border border-warning/40 bg-surface-0 p-4 shadow-2xl elevation-floating"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-center justify-between border-b border-border/60 pb-2.5">
              <div className="flex items-center gap-2">
                <div className="rounded-md bg-warning/10 p-1.5 text-warning">
                  <Terminal className="h-4 w-4" />
                </div>
                <div>
                  <h4 className="font-mono ba-text-sm font-bold text-foreground">
                    Inline Forensic Deobfuscator
                  </h4>
                  <span className="font-mono ba-text-3xs text-muted-foreground">
                    Decoded format: <strong className="text-warning uppercase">{payload.encoding}</strong>
                  </span>
                </div>
              </div>
              <button
                onClick={() => setOpen(false)}
                className="rounded p-1 text-muted-foreground hover:bg-surface-2 hover:text-foreground"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Extracted Observables Strip */}
            {(payload.extractedObservables.urls.length > 0 || payload.extractedObservables.ips.length > 0 || payload.extractedObservables.commands.length > 0) && (
              <div className="my-2.5 flex flex-wrap items-center gap-1 rounded border border-subtle bg-surface-1 p-2">
                <span className="text-mono ba-text-3xs text-fg-dim">Extracted:</span>
                {payload.extractedObservables.urls.map((u) => (
                  <span key={u} className="rounded bg-info/10 px-1.5 py-0.5 text-mono ba-text-3xs text-info font-mono truncate max-w-xs">
                    {u}
                  </span>
                ))}
                {payload.extractedObservables.ips.map((ip) => (
                  <span key={ip} className="rounded bg-destructive/10 px-1.5 py-0.5 text-mono ba-text-3xs text-destructive font-mono">
                    {ip}
                  </span>
                ))}
                {payload.extractedObservables.commands.map((cmd) => (
                  <span key={cmd} className="rounded bg-warning/10 px-1.5 py-0.5 text-mono ba-text-3xs text-warning font-mono">
                    {cmd}
                  </span>
                ))}
              </div>
            )}

            {/* Decoded Plaintext Content */}
            <div className="my-2 flex-1 overflow-y-auto">
              <label className="text-mono ba-text-3xs uppercase tracking-wider text-muted-foreground">
                Decoded Plaintext Command
              </label>
              <pre className="mt-1 max-h-60 overflow-x-auto whitespace-pre-wrap rounded border border-divider-strong bg-surface-1 p-3 font-mono ba-text-xs leading-relaxed text-foreground select-text">
                {payload.decodedText}
              </pre>
            </div>

            {/* Raw Obfuscated String */}
            <div className="mb-3">
              <label className="text-mono ba-text-3xs uppercase tracking-wider text-muted-foreground">
                Matched Raw Token
              </label>
              <div className="mt-1 truncate rounded border border-subtle bg-surface-2 px-2 py-1 font-mono ba-text-3xs text-fg-dim">
                {payload.rawMatch}
              </div>
            </div>

            {/* Action Bar */}
            <div className="flex items-center justify-between border-t border-border/60 pt-2.5">
              <div className="flex items-center gap-2">
                <button
                  onClick={handleSendToCase}
                  className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2.5 py-1 text-mono ba-text-2xs text-foreground hover:bg-surface-2 transition-colors"
                >
                  <ArrowRight className="h-3 w-3" />
                  <span>Attach to Case</span>
                </button>
                {onPivotToDetection && (
                  <button
                    onClick={() => {
                      onPivotToDetection(payload.decodedText);
                      setOpen(false);
                    }}
                    className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs text-primary hover:bg-primary/20 transition-colors"
                  >
                    <ShieldAlert className="h-3 w-3" />
                    <span>Send to Detection Lab</span>
                  </button>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopy}
                  className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-3 py-1 font-mono ba-text-2xs text-primary hover:bg-primary/20 transition-colors"
                >
                  {copied ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                  <span>{copied ? "Copied" : "Copy Plaintext"}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
