import { useState, useRef, useEffect } from "react";
import {
  Search, X, Copy, Check, Terminal, Code2, Download,
  Layers, Clock, Filter, ChevronRight, HelpCircle, Shield,
} from "lucide-react";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import {
  type FilterChip,
  type Range,
  HUNT_PRESETS,
  type SavedHunt,
} from "@/data/siem";
import { translateAll, type TranslatedQueries } from "@/lib/siem/query-translator";

interface SplunkSearchBarProps {
  query: string;
  onQueryChange: (q: string) => void;
  chips: FilterChip[];
  onAddChip: (field: string, value: string) => void;
  onRemoveChip: (index: number) => void;
  onClearChips: () => void;
  range: Range;
  onRangeChange: (r: Range) => void;
  onApplyHuntPreset?: (hunt: SavedHunt) => void;
  mitreTechniques?: string[];
  totalMatches: number;
  totalEvents: number;
}

export function SplunkSearchBar({
  query,
  onQueryChange,
  chips,
  onAddChip,
  onRemoveChip,
  onClearChips,
  range,
  onRangeChange,
  onApplyHuntPreset,
  mitreTechniques = [],
  totalMatches,
  totalEvents,
}: SplunkSearchBarProps) {
  const [showTranslator, setShowTranslator] = useState(false);
  const [activeTab, setActiveTab] = useState<"splunk" | "elastic" | "sentinel" | "sigma" | "vql">("splunk");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const translated: TranslatedQueries = translateAll(query, chips, range, mitreTechniques);

  const handleCopy = (key: string, text: string) => {
    copyText(text);
    setCopiedKey(key);
    toast.success(`Copied ${key.toUpperCase()} to clipboard`);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleDownloadSigma = () => {
    const blob = new Blob([translated.sigmaYaml], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `hunt-rule-${Date.now()}.yml`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Downloaded Sigma rule YAML");
  };

  return (
    <div className="space-y-2 rounded-lg border border-subtle bg-surface-0 p-3 shadow-xs">
      {/* Search Input Bar */}
      <div className="relative flex flex-wrap sm:flex-nowrap items-center gap-2">
        <div className="relative w-full sm:flex-1 min-w-[200px] flex items-center">
          <Search className="absolute left-3 h-4 w-4 text-fg-dim" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => onQueryChange(e.target.value)}
            placeholder="Search events... e.g. user:admin | Failed password | mimikatz | stats count by src"
            className="h-9 w-full rounded-md border border-divider-strong bg-surface-1 pl-9 pr-10 font-mono ba-text-xs text-foreground outline-none transition-colors duration-150 placeholder:text-fg-dim/60 focus:border-primary/60 focus:ring-1 focus:ring-primary/40"
          />
          {query && (
            <button
              onClick={() => onQueryChange("")}
              className="absolute right-3 rounded p-1 text-fg-dim hover:text-foreground"
              title="Clear search"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        {/* Range Selector */}
        <div className="flex items-center gap-0.5 rounded-md border border-subtle bg-surface-1 p-0.5">
          <Clock className="ml-1.5 mr-0.5 h-3.5 w-3.5 text-fg-dim" />
          {(["15m", "1h", "24h", "all"] as Range[]).map((r) => (
            <button
              key={r}
              onClick={() => onRangeChange(r)}
              className={
                "rounded px-2 py-1 text-mono ba-text-2xs transition-colors duration-150 " +
                (range === r
                  ? "bg-primary text-primary-foreground font-semibold shadow-xs"
                  : "text-fg-dim hover:text-foreground hover:bg-surface-2")
              }
            >
              {r}
            </button>
          ))}
        </div>

        {/* Cross-SIEM Query Translator Modal Trigger */}
        <button
          onClick={() => setShowTranslator(!showTranslator)}
          className={
            "flex h-9 items-center gap-1.5 rounded-md border px-3 text-mono ba-text-2xs transition-colors duration-150 " +
            (showTranslator
              ? "border-primary bg-primary/15 text-primary font-semibold"
              : "border-primary/40 bg-primary/10 text-primary hover:bg-primary/20")
          }
          title="Translate query into Splunk SPL, Elastic KQL, Sigma, and Velociraptor VQL"
        >
          <Code2 className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">Cross-SIEM Translator</span>
        </button>
      </div>

      {/* Filter Chips Row */}
      {(chips.length > 0 || query) && (
        <div className="flex flex-wrap items-center gap-1.5 pt-1 text-mono ba-text-2xs">
          <span className="inline-flex items-center gap-1 text-fg-dim">
            <Filter className="h-3 w-3" /> Filters:
          </span>
          {chips.map((chip, idx) => (
            <span
              key={idx}
              className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-primary"
            >
              <span className="text-primary/70">{chip.field}:</span>
              <span className="font-semibold">{chip.value}</span>
              <button
                onClick={() => onRemoveChip(idx)}
                className="ml-0.5 text-primary/70 hover:text-primary"
                title="Remove filter"
              >
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
          {chips.length > 1 && (
            <button
              onClick={onClearChips}
              className="rounded px-1.5 py-0.5 text-fg-dim hover:text-destructive transition-colors duration-150"
            >
              Clear all
            </button>
          )}

          <span className="ml-auto text-fg-dim">
            Showing <strong className="text-foreground">{totalMatches}</strong> of{" "}
            {totalEvents} events
          </span>
        </div>
      )}

      {/* Quick Hunt Presets Bar */}
      <div className="flex flex-wrap items-center gap-1.5 pt-1">
        <span className="text-mono ba-text-3xs uppercase tracking-wider text-fg-dim/80">
          Hunt Presets:
        </span>
        {HUNT_PRESETS.map((p) => (
          <button
            key={p.id}
            onClick={() => onApplyHuntPreset?.(p)}
            className="inline-flex items-center gap-1 rounded-md border border-subtle bg-surface-1 px-2 py-1 text-mono ba-text-3xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-primary"
          >
            <Layers className="h-3 w-3 text-primary/70" />
            <span>{p.name}</span>
          </button>
        ))}
      </div>

      {/* Cross-SIEM Query Translator Card */}
      {showTranslator && (
        <div className="mt-3 rounded-lg border border-primary/30 bg-surface-1 p-4 shadow-sm animate-in fade-in slide-in-from-top-2 duration-150">
          <div className="flex items-center justify-between border-b border-border/70 pb-2.5">
            <div className="flex items-center gap-2">
              <Code2 className="h-4 w-4 text-primary" />
              <h4 className="font-mono ba-text-sm font-semibold text-foreground">
                Cross-SIEM Query Translator
              </h4>
              <span className="rounded bg-primary/10 px-1.5 py-0.5 text-mono ba-text-3xs text-primary">
                Multi-Engine
              </span>
            </div>
            <button
              onClick={() => setShowTranslator(false)}
              className="rounded p-1 text-fg-dim hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <p className="mt-2 text-mono ba-text-2xs text-fg-dim">
            Formulate your search once in BeyondLabs, deploy directly to enterprise SIEM and EDR
            platforms without writing separate syntax from scratch.
          </p>

          {/* Engine Tabs */}
          <div className="mt-3 flex flex-wrap gap-1 border-b border-border/60 pb-1">
            {[
              { id: "splunk" as const, label: "Splunk (SPL)", icon: Terminal },
              { id: "elastic" as const, label: "Elastic (KQL)", icon: Code2 },
              { id: "sentinel" as const, label: "Sentinel (KQL)", icon: Shield },
              { id: "sigma" as const, label: "Sigma HQ (YAML)", icon: Layers },
              { id: "vql" as const, label: "Velociraptor (VQL)", icon: Terminal },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={
                  "inline-flex items-center gap-1.5 rounded-t px-3 py-1.5 text-mono ba-text-2xs transition-colors duration-150 " +
                  (activeTab === tab.id
                    ? "border-b-2 border-primary bg-surface-2 text-primary font-semibold"
                    : "text-fg-dim hover:text-foreground")
                }
              >
                <tab.icon className="h-3.5 w-3.5" />
                {tab.label}
              </button>
            ))}
          </div>

          {/* Code Viewer Container */}
          <div className="relative mt-2 rounded border border-divider bg-surface-0 p-3 font-mono ba-text-2xs">
            {activeTab === "splunk" && (
              <pre className="overflow-x-auto whitespace-pre-wrap leading-relaxed text-foreground">
                {translated.splunkSpl}
              </pre>
            )}
            {activeTab === "elastic" && (
              <pre className="overflow-x-auto whitespace-pre-wrap leading-relaxed text-foreground">
                {translated.elasticKql}
              </pre>
            )}
            {activeTab === "sentinel" && (
              <pre className="overflow-x-auto whitespace-pre-wrap leading-relaxed text-foreground">
                {translated.sentinelKql}
              </pre>
            )}
            {activeTab === "sigma" && (
              <pre className="max-h-60 overflow-y-auto whitespace-pre-wrap leading-relaxed text-foreground">
                {translated.sigmaYaml}
              </pre>
            )}
            {activeTab === "vql" && (
              <pre className="max-h-60 overflow-y-auto whitespace-pre-wrap leading-relaxed text-foreground">
                {translated.velociraptorVql}
              </pre>
            )}

            {/* Action Buttons */}
            <div className="mt-3 flex items-center justify-end gap-2 border-t border-border/40 pt-2">
              {activeTab === "sigma" && (
                <button
                  onClick={handleDownloadSigma}
                  className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2.5 py-1 text-mono ba-text-2xs text-fg-dim hover:text-foreground transition-colors duration-150"
                >
                  <Download className="h-3 w-3" />
                  Download .yml
                </button>
              )}
              <button
                onClick={() => {
                  const textMap = {
                    splunk: translated.splunkSpl,
                    elastic: translated.elasticKql,
                    sentinel: translated.sentinelKql,
                    sigma: translated.sigmaYaml,
                    vql: translated.velociraptorVql,
                  };
                  handleCopy(activeTab, textMap[activeTab]);
                }}
                className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-3 py-1 text-mono ba-text-2xs text-primary hover:bg-primary/20 transition-colors duration-150"
              >
                {copiedKey === activeTab ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-success" />
                    Copied!
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" />
                    Copy to Clipboard
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
