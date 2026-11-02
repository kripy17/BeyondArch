import { useState } from "react";
import { X, Copy, Download, Search, Check, FileCode, Binary } from "lucide-react";
import { toast } from "sonner";

export interface StreamDialogueItem {
  origin: "client" | "server";
  text: string;
  bytes?: Uint8Array | number[];
}

interface TcpStreamModalProps {
  isOpen: boolean;
  onClose: () => void;
  streamTitle: string;
  dialogue: StreamDialogueItem[];
}

function toHexDump(str: string): string {
  const lines: string[] = [];
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);

  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const offset = i.toString(16).padStart(8, "0");
    const hexParts: string[] = [];
    let asciiPart = "";

    for (let j = 0; j < 16; j++) {
      if (j < chunk.length) {
        hexParts.push(chunk[j].toString(16).padStart(2, "0"));
        asciiPart += chunk[j] >= 32 && chunk[j] <= 126 ? String.fromCharCode(chunk[j]) : ".";
      } else {
        hexParts.push("  ");
      }
    }

    const hexFormatted = `${hexParts.slice(0, 8).join(" ")}  ${hexParts.slice(8).join(" ")}`;
    lines.push(`${offset}  ${hexFormatted}  |${asciiPart}|`);
  }

  return lines.join("\n") || "00000000                     ||";
}

export function TcpStreamModal({
  isOpen,
  onClose,
  streamTitle,
  dialogue,
}: TcpStreamModalProps) {
  const [viewMode, setViewMode] = useState<"ascii" | "hex">("ascii");
  const [searchQuery, setSearchQuery] = useState("");
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const fullText = dialogue.map((d) => d.text).join("\n\n");

  const handleCopy = () => {
    navigator.clipboard.writeText(fullText);
    setCopied(true);
    toast.success("Stream contents copied to clipboard");
    setTimeout(() => setCopied(false), 1500);
  };

  const handleDownload = () => {
    const blob = new Blob([fullText], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `stream-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Stream downloaded");
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="flex h-[80vh] w-full max-w-4xl flex-col rounded-xl border border-border bg-card shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border bg-surface-1 px-4 py-3">
          <div className="flex items-center gap-2 min-w-0">
            <span className="flex h-2 w-2 rounded-full bg-primary animate-pulse" />
            <span className="font-mono text-xs font-semibold text-foreground truncate">
              Follow TCP Stream — {streamTitle}
            </span>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {/* View switcher */}
            <div className="flex rounded border border-border bg-surface-0 p-0.5">
              <button
                type="button"
                onClick={() => setViewMode("ascii")}
                className={`flex items-center gap-1 rounded px-2 py-0.5 font-mono text-2xs transition ${
                  viewMode === "ascii" ? "bg-primary/15 text-primary font-medium" : "text-muted-foreground hover:text-foreground"
                }`}
              >
                <FileCode className="h-3 w-3" />
                ASCII
              </button>
              <button
                type="button"
                onClick={() => setViewMode("hex")}
                className={`flex items-center gap-1 rounded px-2 py-0.5 font-mono text-2xs transition ${
                  viewMode === "hex" ? "bg-primary/15 text-primary font-medium" : "text-muted-foreground hover:text-foreground"
                }`}
              >
                <Binary className="h-3 w-3" />
                Hex Dump
              </button>
            </div>

            <button
              type="button"
              onClick={handleCopy}
              className="inline-flex items-center gap-1 rounded border border-border bg-surface-0 px-2 py-1 font-mono text-2xs text-muted-foreground hover:text-foreground"
              title="Copy stream"
            >
              {copied ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
              <span>Copy</span>
            </button>

            <button
              type="button"
              onClick={handleDownload}
              className="inline-flex items-center gap-1 rounded border border-border bg-surface-0 px-2 py-1 font-mono text-2xs text-muted-foreground hover:text-foreground"
              title="Download text payload"
            >
              <Download className="h-3 w-3" />
              <span>Download</span>
            </button>

            <button
              type="button"
              onClick={onClose}
              className="rounded p-1 text-muted-foreground hover:bg-surface-2 hover:text-foreground transition"
              title="Close modal"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Filter / search bar */}
        <div className="flex items-center gap-2 border-b border-border/60 bg-surface-0 px-4 py-2">
          <Search className="h-3.5 w-3.5 text-muted-foreground" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search payload content..."
            className="flex-1 bg-transparent font-mono text-xs text-foreground placeholder:text-muted-foreground outline-none"
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery("")}
              className="font-mono text-3xs text-muted-foreground hover:text-foreground"
            >
              clear
            </button>
          )}
        </div>

        {/* Payload content */}
        <div className="flex-1 overflow-auto p-4 font-mono text-xs leading-relaxed bg-surface-0">
          {dialogue.length === 0 ? (
            <div className="flex h-full items-center justify-center text-muted-foreground">
              No payload data captured in this stream.
            </div>
          ) : (
            <div className="space-y-4">
              {dialogue.map((item, idx) => {
                const isClient = item.origin === "client";
                const isMatch = !searchQuery || item.text.toLowerCase().includes(searchQuery.toLowerCase());
                if (!isMatch) return null;

                return (
                  <div
                    key={idx}
                    className={`rounded border p-3 ${
                      isClient
                        ? "border-sky-500/30 bg-sky-950/20 text-sky-200"
                        : "border-emerald-500/30 bg-emerald-950/20 text-emerald-200"
                    }`}
                  >
                    <div className="mb-1.5 flex items-center justify-between text-3xs font-semibold uppercase tracking-wider opacity-80">
                      <span>{isClient ? "Originator (Client → Server)" : "Responder (Server → Client)"}</span>
                      <span>{item.text.length} chars</span>
                    </div>

                    <pre className="whitespace-pre-wrap break-all font-mono">
                      {viewMode === "ascii" ? item.text : toHexDump(item.text)}
                    </pre>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer info */}
        <div className="flex items-center justify-between border-t border-border bg-surface-1 px-4 py-2 font-mono text-3xs text-muted-foreground">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-sky-400 inline-block" /> Client
            </span>
            <span className="flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-emerald-400 inline-block" /> Server
            </span>
          </div>
          <div>Press ESC to exit</div>
        </div>
      </div>
    </div>
  );
}
