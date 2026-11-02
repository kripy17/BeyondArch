import { useState } from "react";
import { Filter, Copy, Check, Terminal, ExternalLink } from "lucide-react";
import { WIRESHARK_PRESETS, buildTsharkCommand, type FilterPreset } from "@/lib/pcap/wireshark-filters";
import { toast } from "sonner";

interface WiresharkFilterBarProps {
  filter: string;
  onFilterChange: (newFilter: string) => void;
  onApplyPreset: (preset: FilterPreset) => void;
  pcapFilename?: string;
  matchedCount?: number;
  totalCount?: number;
}

export function WiresharkFilterBar({
  filter,
  onFilterChange,
  onApplyPreset,
  pcapFilename = "capture.pcap",
  matchedCount,
  totalCount,
}: WiresharkFilterBarProps) {
  const [copiedFilter, setCopiedFilter] = useState(false);
  const [copiedTshark, setCopiedTshark] = useState(false);

  const handleCopyFilter = () => {
    navigator.clipboard.writeText(filter || "frame");
    setCopiedFilter(true);
    toast.success("Wireshark display filter copied to clipboard");
    setTimeout(() => setCopiedFilter(false), 1500);
  };

  const handleCopyTshark = () => {
    const cmd = buildTsharkCommand(filter, pcapFilename);
    navigator.clipboard.writeText(cmd);
    setCopiedTshark(true);
    toast.success("TShark command copied to clipboard");
    setTimeout(() => setCopiedTshark(false), 1500);
  };

  return (
    <div className="space-y-2 rounded-lg border border-border/80 bg-card/60 p-3 shadow-sm backdrop-blur">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-primary" />
          <span className="font-mono text-xs font-semibold text-foreground uppercase tracking-wider">
            Wireshark Display Filter
          </span>
          {typeof matchedCount === "number" && typeof totalCount === "number" && (
            <span className="rounded bg-primary/10 px-2 py-0.5 font-mono text-2xs text-primary font-medium">
              {matchedCount} / {totalCount} flows
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={handleCopyFilter}
            className="inline-flex items-center gap-1 rounded border border-border bg-surface-1 px-2 py-1 font-mono text-2xs text-muted-foreground transition hover:border-primary/40 hover:text-foreground"
            title="Copy Wireshark display filter for use in Wireshark desktop GUI"
          >
            {copiedFilter ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
            <span>Copy Filter</span>
          </button>
          <button
            type="button"
            onClick={handleCopyTshark}
            className="inline-flex items-center gap-1 rounded border border-border bg-surface-1 px-2 py-1 font-mono text-2xs text-muted-foreground transition hover:border-primary/40 hover:text-foreground"
            title="Copy equivalent tshark terminal command line"
          >
            {copiedTshark ? <Check className="h-3 w-3 text-success" /> : <Terminal className="h-3 w-3" />}
            <span>Copy TShark</span>
          </button>
        </div>
      </div>

      <div className="relative">
        <input
          type="text"
          value={filter}
          onChange={(e) => onFilterChange(e.target.value)}
          placeholder='e.g. http.request.method == "POST" || dns.flags.response == 0 || tcp.port == 443'
          className="w-full rounded border border-border bg-surface-0 px-3 py-1.5 font-mono text-xs text-foreground placeholder:text-muted-foreground/60 outline-none transition focus:border-primary/60 focus:ring-1 focus:ring-primary/40"
        />
      </div>

      <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
        <span className="font-mono text-3xs text-muted-foreground uppercase tracking-wider mr-1">
          Presets:
        </span>
        {WIRESHARK_PRESETS.map((preset) => (
          <button
            key={preset.id}
            type="button"
            onClick={() => onApplyPreset(preset)}
            className="rounded border border-subtle bg-surface-1 px-2 py-0.5 font-mono text-3xs text-fg-dim transition hover:border-primary/50 hover:bg-primary/10 hover:text-primary"
            title={preset.description}
          >
            {preset.name}
          </button>
        ))}
      </div>
    </div>
  );
}
