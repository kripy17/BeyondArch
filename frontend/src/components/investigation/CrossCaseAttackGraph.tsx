import { useMemo, useState } from "react";
import {
  Network,
  ShieldAlert,
  FolderOpen,
  ArrowRight,
  Search,
  Layers,
  Copy,
  Check,
  ExternalLink,
  Target,
  Server,
  User,
  Globe,
  Hash,
  AlertTriangle,
  Zap,
} from "lucide-react";
import type { Case } from "@/data/case";
import { getUnifiedIOCs } from "@/components/investigation/legacy-adapter";
import { Chip } from "@/components/soc";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface CrossCaseAttackGraphProps {
  cases: Case[];
  activeCaseId: string | null;
  onSelectCase: (caseId: string) => void;
  className?: string;
}

interface SharedIndicator {
  type: "ip" | "domain" | "hash" | "email" | "user" | "other";
  value: string;
  caseIds: string[];
  cases: Case[];
}

export function CrossCaseAttackGraph({
  cases,
  activeCaseId,
  onSelectCase,
  className = "",
}: CrossCaseAttackGraphProps) {
  const [selectedIndicator, setSelectedIndicator] = useState<SharedIndicator | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Extract and cross-correlate observables across all cases
  const { sharedIndicators, allIndicators, blastRadius } = useMemo(() => {
    const iocToCases = new Map<string, { type: SharedIndicator["type"]; value: string; cases: Set<Case> }>();
    const allHosts = new Set<string>();
    const allUsers = new Set<string>();

    for (const c of cases) {
      const iocs = getUnifiedIOCs(c);
      for (const ioc of iocs) {
        const val = ioc.value.trim().toLowerCase();
        if (!val) continue;

        let type: SharedIndicator["type"] = "other";
        const t = (ioc.type || "").toLowerCase();
        if (t.includes("ip")) type = "ip";
        else if (t.includes("domain") || t.includes("url")) type = "domain";
        else if (t.includes("hash") || t.includes("md5") || t.includes("sha")) type = "hash";
        else if (t.includes("email") || t.includes("user")) type = "user";

        if (!iocToCases.has(val)) {
          iocToCases.set(val, { type, value: ioc.value.trim(), cases: new Set() });
        }
        iocToCases.get(val)!.cases.add(c);

        if (type === "ip" || val.includes("ws-") || val.includes("srv-")) {
          allHosts.add(val);
        }
        if (type === "user" || val.includes("@")) {
          allUsers.add(val);
        }
      }
    }

    const allList: SharedIndicator[] = Array.from(iocToCases.values()).map((item) => ({
      type: item.type,
      value: item.value,
      caseIds: Array.from(item.cases).map((c) => c.id),
      cases: Array.from(item.cases),
    }));

    // Shared across 2 or more cases
    const sharedList = allList.filter((item) => item.cases.length > 1);

    return {
      sharedIndicators: sharedList.sort((a, b) => b.cases.length - a.cases.length),
      allIndicators: allList,
      blastRadius: {
        totalCases: cases.length,
        sharedIocCount: sharedList.length,
        uniqueHosts: allHosts.size,
        uniqueUsers: allUsers.size,
      },
    };
  }, [cases]);

  // Filter indicators by search
  const filteredShared = useMemo(() => {
    if (!searchQuery.trim()) return sharedIndicators;
    const q = searchQuery.toLowerCase();
    return sharedIndicators.filter(
      (ind) => ind.value.toLowerCase().includes(q) || ind.cases.some((c) => c.title.toLowerCase().includes(q))
    );
  }, [sharedIndicators, searchQuery]);

  const handleCopy = (text: string) => {
    copyText(text).then(() => {
      setCopiedText(text);
      toast.success(`Copied: ${text}`);
      setTimeout(() => setCopiedText(null), 2000);
    });
  };

  return (
    <div
      id="cross-case-attack-graph"
      className={cn(
        "rounded-xl border border-border/80 bg-card p-4 shadow-sm space-y-4 font-mono min-w-0 max-w-full overflow-hidden",
        className
      )}
    >
      {/* Header & Blast Radius Telemetry */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/60 pb-3">
        <div className="flex items-center gap-2 min-w-0">
          <Network className="h-5 w-5 text-primary shrink-0 animate-pulse" />
          <div>
            <h3 className="ba-text-sm font-bold uppercase tracking-wider text-foreground">
              Cross-Case Intrusion Correlation Matrix
            </h3>
            <p className="ba-text-3xs text-muted-foreground">
              Multi-case attack topology & shared hostile infrastructure intelligence
            </p>
          </div>
        </div>

        {/* Blast Radius Metrics */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <div className="flex items-center gap-1.5 rounded-lg border border-border bg-surface-1 px-2.5 py-1 text-mono ba-text-2xs">
            <span className="text-muted-foreground">Cases:</span>
            <span className="font-bold text-foreground">{blastRadius.totalCases}</span>
          </div>

          <div className="flex items-center gap-1.5 rounded-lg border border-destructive/40 bg-destructive/10 px-2.5 py-1 text-mono ba-text-2xs text-destructive">
            <ShieldAlert className="h-3.5 w-3.5" />
            <span className="font-bold">{blastRadius.sharedIocCount} Shared IOCs</span>
          </div>

          <div className="flex items-center gap-1.5 rounded-lg border border-primary/40 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs text-primary">
            <Target className="h-3.5 w-3.5" />
            <span className="font-bold">{blastRadius.uniqueHosts} Assets Mapped</span>
          </div>
        </div>
      </div>

      {/* Campaign Convergence Banner if shared IOCs exist */}
      {sharedIndicators.length > 0 && (
        <div className="rounded-lg border border-warning/40 bg-warning/10 p-3 flex flex-wrap items-start justify-between gap-2.5">
          <div className="flex items-start gap-2.5 min-w-0">
            <Zap className="h-4 w-4 text-warning shrink-0 mt-0.5" />
            <div>
              <div className="text-xs font-bold text-warning uppercase">
                Coordinated Adversary Campaign Detected
              </div>
              <p className="text-[11px] text-fg-dim mt-0.5 leading-relaxed">
                {sharedIndicators.length} indicator(s) converge across multiple active incident dossiers. Evidence indicates shared command-and-control infrastructure or identical weaponization payloads.
              </p>
            </div>
          </div>
          <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-warning/20 text-warning border border-warning/30 shrink-0">
            Campaign Convergence
          </span>
        </div>
      )}

      {/* Search & Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search shared IOC, IP, domain, or case title…"
            aria-label="Filter shared indicators"
            className="w-full rounded-md border border-border bg-surface-0 pl-8 pr-3 py-1.5 text-mono ba-text-2xs text-foreground placeholder:text-muted-foreground/60 outline-none focus:border-primary/50"
          />
        </div>

        <div className="text-[11px] text-muted-foreground">
          Showing {filteredShared.length} shared indicators linking {cases.length} incident cases
        </div>
      </div>

      {/* Main Multi-Case Correlation Layout */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-12 min-w-0 max-w-full">
        {/* Left Column: Shared Infrastructure Hub (7 cols) */}
        <div className="lg:col-span-7 space-y-2.5 min-w-0">
          <div className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center justify-between">
            <span>Shared Hostile Infrastructure & Attack Indicators</span>
            <span className="text-primary font-bold">{filteredShared.length} Hub Nodes</span>
          </div>

          {filteredShared.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border bg-surface-0/50 py-12 text-center text-muted-foreground space-y-2">
              <Layers className="h-8 w-8 mx-auto text-muted-foreground/40" />
              <div className="text-xs font-semibold text-foreground">No shared observables found</div>
              <p className="text-[11px] max-w-xs mx-auto text-muted-foreground">
                Active incident cases currently operate on disjoint observable sets or no multiple cases exist yet.
              </p>
            </div>
          ) : (
            <div className="space-y-2 max-h-[460px] overflow-y-auto pr-1">
              {filteredShared.map((ind) => {
                const isSelected = selectedIndicator?.value === ind.value;
                return (
                  <div
                    key={ind.value}
                    onClick={() => setSelectedIndicator(ind)}
                    className={cn(
                      "group rounded-lg border p-2.5 transition-all cursor-pointer space-y-1.5",
                      isSelected
                        ? "border-primary bg-primary/[0.08] shadow-sm ring-1 ring-primary/50"
                        : "border-border/70 bg-surface-0 hover:border-primary/40 hover:bg-surface-1"
                    )}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-1.5">
                      <div className="flex items-center gap-2 min-w-0">
                        {ind.type === "ip" ? (
                          <Globe className="h-3.5 w-3.5 text-destructive shrink-0" />
                        ) : ind.type === "domain" ? (
                          <Globe className="h-3.5 w-3.5 text-warning shrink-0" />
                        ) : ind.type === "hash" ? (
                          <Hash className="h-3.5 w-3.5 text-purple-400 shrink-0" />
                        ) : (
                          <User className="h-3.5 w-3.5 text-primary shrink-0" />
                        )}
                        <span className="font-bold text-foreground text-xs truncate max-w-[240px] select-all">
                          {ind.value}
                        </span>
                        <span className="text-[9px] uppercase px-1 rounded bg-surface-2 text-muted-foreground border border-border shrink-0">
                          {ind.type}
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-[10px] text-destructive font-bold bg-destructive/15 px-1.5 py-0.5 rounded border border-destructive/30">
                          Links {ind.cases.length} Cases
                        </span>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleCopy(ind.value);
                          }}
                          className="rounded p-1 text-muted-foreground hover:text-foreground transition"
                          title="Copy indicator"
                        >
                          {copiedText === ind.value ? (
                            <Check className="h-3 w-3 text-success" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                        </button>
                      </div>
                    </div>

                    {/* Linked Cases Chips */}
                    <div className="flex flex-wrap gap-1 pt-0.5">
                      {ind.cases.map((c) => (
                        <button
                          key={c.id}
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectCase(c.id);
                          }}
                          className={cn(
                            "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] border transition",
                            activeCaseId === c.id
                              ? "border-primary bg-primary/20 text-primary font-bold"
                              : "border-border bg-surface-2 text-muted-foreground hover:text-foreground hover:border-primary/40"
                          )}
                        >
                          <FolderOpen className="h-2.5 w-2.5 text-primary" />
                          <span className="truncate max-w-[150px]">{c.title}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Indicator Deep Correlation Inspector (5 cols) */}
        <div className="lg:col-span-5 space-y-3 min-w-0">
          <div className="text-[10px] uppercase font-semibold text-muted-foreground">
            Correlation Inspector & Incident Convergence
          </div>

          {selectedIndicator ? (
            <div className="rounded-lg border border-primary/30 bg-surface-1 p-3.5 space-y-3 shadow-sm">
              <div className="space-y-1">
                <div className="text-[9px] uppercase text-muted-foreground font-semibold">Selected Observable</div>
                <div className="flex items-center justify-between gap-1">
                  <div className="font-bold text-foreground text-sm truncate select-all">{selectedIndicator.value}</div>
                  <Chip tone="destructive">Linked to {selectedIndicator.cases.length} Dossiers</Chip>
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="text-[10px] uppercase font-semibold text-muted-foreground">Converging Cases</div>
                <div className="space-y-1.5 max-h-52 overflow-y-auto pr-1">
                  {selectedIndicator.cases.map((c) => (
                    <div
                      key={c.id}
                      className="rounded border border-border bg-surface-0 p-2 space-y-1 hover:border-primary/40 transition"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-foreground text-xs truncate max-w-[180px]">{c.title}</span>
                        <span className="text-[9px] font-mono text-muted-foreground uppercase">{c.state}</span>
                      </div>
                      <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                        <span>ID: {c.id}</span>
                        <button
                          type="button"
                          onClick={() => onSelectCase(c.id)}
                          className="inline-flex items-center gap-1 text-primary hover:underline text-[10px] font-semibold"
                        >
                          <span>Open Case</span>
                          <ArrowRight className="h-2.5 w-2.5" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="pt-1 flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => handleCopy(selectedIndicator.value)}
                  className="inline-flex items-center gap-1 rounded border border-border bg-surface-2 px-2 py-1 text-mono ba-text-3xs text-muted-foreground hover:text-foreground transition"
                >
                  <Copy className="h-3 w-3" />
                  <span>Copy Indicator</span>
                </button>

                <button
                  type="button"
                  onClick={() => {
                    toast.info(`Pivot into Intel Hub for ${selectedIndicator.value}`);
                  }}
                  className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-1 text-mono ba-text-3xs text-primary hover:bg-primary/20 transition"
                >
                  <ExternalLink className="h-3 w-3" />
                  <span>Query Intel Hub</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="rounded-lg border border-border/80 bg-surface-0/60 p-6 text-center text-muted-foreground space-y-2">
              <Network className="h-8 w-8 mx-auto text-muted-foreground/40" />
              <div className="text-xs font-semibold text-foreground">Select an observable</div>
              <p className="text-[11px] max-w-xs mx-auto">
                Click any shared indicator on the left to inspect which incident cases converge on it and execute cross-case pivots.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
