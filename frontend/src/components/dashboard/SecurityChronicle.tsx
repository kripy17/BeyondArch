import { useState, useMemo } from "react";
import { Link } from "@tanstack/react-router";
import {
  Activity, Bell, Target, Folder, Terminal, Search, ArrowUpRight,
  Filter, Layers, ShieldAlert, Sparkles
} from "lucide-react";
import type { TimelineEvent } from "@/lib/timeline";
import type { AlertLedgerEntry } from "@/lib/alerts/ingest";
import type { Case } from "@/data/case";
import { aggregateChronicle, type ChronicleCategory, type ChronicleItem } from "@/lib/command-deck";
import { cn } from "@/lib/utils";

interface SecurityChronicleProps {
  timelineEvents: TimelineEvent[];
  alerts: AlertLedgerEntry[];
  cases: Case[];
}

export function SecurityChronicle({ timelineEvents, alerts, cases }: SecurityChronicleProps) {
  const [activeCategory, setActiveCategory] = useState<ChronicleCategory>("all");
  const [searchQuery, setSearchQuery] = useState("");

  const items = useMemo(() => {
    return aggregateChronicle(timelineEvents, alerts, cases, activeCategory, searchQuery);
  }, [timelineEvents, alerts, cases, activeCategory, searchQuery]);

  const categories: { id: ChronicleCategory; label: string; count?: number }[] = [
    { id: "all", label: "All Telemetry" },
    { id: "alert", label: "Alerts", count: alerts.length },
    { id: "detection", label: "Detections" },
    { id: "case", label: "Cases" },
    { id: "workspace", label: "Workspaces" },
  ];

  const getCategoryIcon = (cat: ChronicleItem["category"]) => {
    switch (cat) {
      case "alert":
        return <Bell className="h-3.5 w-3.5 text-warning" />;
      case "detection":
        return <Target className="h-3.5 w-3.5 text-purple-400" />;
      case "case":
        return <Folder className="h-3.5 w-3.5 text-primary" />;
      case "workspace":
      default:
        return <Terminal className="h-3.5 w-3.5 text-emerald-400" />;
    }
  };

  const getSeverityBadge = (sev: ChronicleItem["severity"]) => {
    switch (sev) {
      case "critical":
        return "border-destructive/60 bg-destructive/15 text-destructive";
      case "high":
        return "border-warning/60 bg-warning/15 text-warning";
      case "medium":
        return "border-yellow-500/40 bg-yellow-500/10 text-yellow-400";
      case "low":
        return "border-success/40 bg-success/10 text-success";
      case "info":
      default:
        return "border-subtle bg-surface-2 text-muted-foreground";
    }
  };

  return (
    <div className="rounded-lg border border-subtle bg-surface-1/80 p-4 shadow-sm">
      {/* Top Header & Search */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-subtle">
        <div className="flex items-center gap-2">
          <div className="grid h-7 w-7 place-items-center rounded bg-surface-0 border border-subtle">
            <Activity className="h-3.5 w-3.5 text-primary" />
          </div>
          <div>
            <h3 className="font-mono ba-text-sm font-semibold text-foreground flex items-center gap-2">
              <span>Security Chronicle</span>
              <span className="rounded-full bg-primary/20 text-primary px-2 py-0.2 font-mono ba-text-3xs font-normal">
                {items.length} events
              </span>
            </h3>
          </div>
        </div>

        {/* Quick Search */}
        <div className="relative min-w-[200px] sm:w-64">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter chronicle events..."
            className="w-full rounded border border-subtle bg-surface-0 py-1 pl-8 pr-3 font-mono ba-text-2xs text-foreground placeholder:text-muted-foreground focus:border-primary/50 focus:outline-none"
          />
        </div>
      </div>

      {/* Category Tabs */}
      <div className="flex flex-wrap items-center gap-1.5 py-2.5 border-b border-subtle font-mono ba-text-3xs">
        {categories.map((c) => (
          <button
            key={c.id}
            onClick={() => setActiveCategory(c.id)}
            className={cn(
              "rounded px-2.5 py-1 transition-colors",
              activeCategory === c.id
                ? "bg-primary/20 text-primary border border-primary/40 font-semibold"
                : "bg-surface-0 text-muted-foreground border border-subtle hover:text-foreground hover:border-primary/30"
            )}
          >
            <span>{c.label}</span>
            {typeof c.count === "number" && c.count > 0 && (
              <span className="ml-1 text-xs opacity-75">({c.count})</span>
            )}
          </button>
        ))}
      </div>

      {/* Events List */}
      <div className="mt-3 divide-y divide-subtle/60 max-h-96 overflow-y-auto pr-1">
        {items.length > 0 ? (
          items.map((it) => {
            const timeStr = new Date(it.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
            return (
              <Link
                key={it.id}
                to={it.pivotTo}
                search={it.pivotSearch}
                className="group flex items-start justify-between gap-3 py-2 px-1.5 transition-colors hover:bg-surface-0/60 rounded"
              >
                <div className="flex items-start gap-2.5 min-w-0 flex-1">
                  <div className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded border border-subtle bg-surface-0">
                    {getCategoryIcon(it.category)}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5 font-mono ba-text-3xs">
                      <span className="font-semibold text-foreground truncate group-hover:text-primary transition-colors">
                        {it.title}
                      </span>
                      <span className={cn("rounded border px-1.5 py-0.2 uppercase font-medium", getSeverityBadge(it.severity))}>
                        {it.severity}
                      </span>
                      <span className="text-muted-foreground ml-auto">
                        {timeStr}
                      </span>
                    </div>
                    <p className="mt-0.5 truncate font-mono ba-text-2xs text-muted-foreground" title={it.detail}>
                      {it.detail}
                    </p>
                  </div>
                </div>

                <ArrowUpRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity mt-1" />
              </Link>
            );
          })
        ) : (
          <div className="py-6 text-center font-mono ba-text-2xs text-muted-foreground">
            No chronicle events matching active filter.
          </div>
        )}
      </div>

      <div className="mt-3 pt-2 border-t border-subtle flex items-center justify-between font-mono ba-text-3xs text-muted-foreground">
        <span>Continuous Session Telemetry Stream</span>
        <Link to="/timeline" className="text-primary hover:underline flex items-center gap-1">
          <span>Open Full Timeline Station</span>
          <ArrowUpRight className="h-3 w-3" />
        </Link>
      </div>
    </div>
  );
}
