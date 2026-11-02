import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Chip, MetricTile, Panel } from "@/components/soc";
import { Empty } from "@/components/output";
import {
  getTimelineEvents,
  clearTimeline,
  exportTimelineCsv,
  exportTimelineJsonl,
  exportTimelineMarkdown,
  TIMELINE_UPDATED_EVENT,
  type TimelineEvent,
  type TimelineSeverity,
} from "@/lib/timeline";
import { toast } from "sonner";
import {
  Activity,
  Search,
  Trash2,
  RefreshCw,
  Download,
  ShieldAlert,
  Bot,
  User,
  Server,
  ArrowRight,
  FileSpreadsheet,
  FileText,
  Clock,
  Layers,
  CheckCircle2,
  Radio,
} from "lucide-react";
import { ErrorBoundary } from "@/components/ErrorBoundary";

export const Route = createFileRoute("/activity")({ component: ActivityPage });

type ActivityCategory = "all" | "analyst" | "detection" | "automation" | "high_severity";

const CATEGORY_TABS: { id: ActivityCategory; label: string; icon: typeof Activity }[] = [
  { id: "all", label: "All Activity", icon: Activity },
  { id: "analyst", label: "Analyst Actions", icon: User },
  { id: "detection", label: "Detections & Alerts", icon: ShieldAlert },
  { id: "automation", label: "Automated Telemetry", icon: Bot },
  { id: "high_severity", label: "High Severity", icon: Radio },
];

const SOURCE_COLORS: Record<string, "primary" | "warning" | "success" | "destructive" | "info" | "default"> = {
  parser: "warning",
  url: "primary",
  phishing: "warning",
  detection: "destructive",
  case: "info",
  mitre: "primary",
  attachment: "warning",
  logs: "info",
  siem: "info",
  analyst: "success",
  chef: "primary",
  recon: "info",
  pcap: "primary",
};

const SOURCE_ROUTES: Record<string, string> = {
  parser: "/parser",
  url: "/url",
  phishing: "/phishing",
  detection: "/detection",
  case: "/case",
  mitre: "/mitre",
  attachment: "/attachment",
  logs: "/logs",
  siem: "/siem",
  chef: "/chef",
  pcap: "/pcap",
};

function formatRelativeTime(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 60_000) return "just now";
  const mins = Math.floor(diff / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function groupEvents(events: TimelineEvent[]): { label: string; events: TimelineEvent[] }[] {
  const now = new Date();
  const today = now.toDateString();
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  const yStr = yesterday.toDateString();
  const groups = new Map<string, TimelineEvent[]>();
  for (const ev of events) {
    const d = new Date(ev.ts);
    const key =
      d.toDateString() === today
        ? "Today"
        : d.toDateString() === yStr
        ? "Yesterday"
        : d.toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric" });
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(ev);
  }
  return Array.from(groups.entries()).map(([label, evts]) => ({ label, events: evts }));
}

function ActivityPage() {
  const navigate = useNavigate();
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [filterSource, setFilterSource] = useState<string>("all");
  const [activeCategory, setActiveCategory] = useState<ActivityCategory>("all");
  const [searchText, setSearchText] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape" && searchText) {
        setSearchText("");
      }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [searchText]);

  const refresh = useCallback(() => {
    setIsRefreshing(true);
    const all = getTimelineEvents();
    all.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());
    setEvents(all);
    setTimeout(() => setIsRefreshing(false), 200);
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Real-time listener for timeline updates
  useEffect(() => {
    const handleUpdated = () => refresh();
    window.addEventListener(TIMELINE_UPDATED_EVENT, handleUpdated);
    window.addEventListener("storage", handleUpdated);
    const onFocus = () => refresh();
    const onVisibility = () => {
      if (!document.hidden) refresh();
    };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisibility);

    let intervalId: number | undefined;
    if (autoRefresh) {
      intervalId = window.setInterval(() => {
        refresh();
      }, 5000);
    }

    return () => {
      window.removeEventListener(TIMELINE_UPDATED_EVENT, handleUpdated);
      window.removeEventListener("storage", handleUpdated);
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVisibility);
      if (intervalId) clearInterval(intervalId);
    };
  }, [refresh, autoRefresh]);

  const sources = useMemo(() => Array.from(new Set(events.map((e) => e.source))).sort(), [events]);

  // Category counts
  const categoryCounts = useMemo(() => {
    let analystCount = 0;
    let detectionCount = 0;
    let automationCount = 0;
    let highSevCount = 0;

    for (const e of events) {
      if (e.actor === "analyst") analystCount++;
      if (
        e.source === "detection" ||
        e.source === "sigma" ||
        e.severity === "critical" ||
        e.severity === "high"
      ) {
        detectionCount++;
      }
      if (e.actor === "automation") automationCount++;
      if (e.severity === "critical" || e.severity === "high") highSevCount++;
    }

    return {
      all: events.length,
      analyst: analystCount,
      detection: detectionCount,
      automation: automationCount,
      high_severity: highSevCount,
    };
  }, [events]);

  // Filtered by category, source, and search
  const filtered = useMemo(() => {
    let e = events;

    // Category filter
    if (activeCategory === "analyst") {
      e = e.filter((ev) => ev.actor === "analyst");
    } else if (activeCategory === "detection") {
      e = e.filter(
        (ev) =>
          ev.source === "detection" ||
          ev.source === "sigma" ||
          ev.severity === "critical" ||
          ev.severity === "high",
      );
    } else if (activeCategory === "automation") {
      e = e.filter((ev) => ev.actor === "automation");
    } else if (activeCategory === "high_severity") {
      e = e.filter((ev) => ev.severity === "critical" || ev.severity === "high");
    }

    // Source filter
    if (filterSource !== "all") {
      e = e.filter((ev) => ev.source === filterSource);
    }

    // Search query
    if (searchText.trim()) {
      const q = searchText.toLowerCase();
      e = e.filter(
        (ev) =>
          ev.detail.toLowerCase().includes(q) ||
          ev.source.toLowerCase().includes(q) ||
          ev.verb.toLowerCase().includes(q) ||
          (ev.target && ev.target.toLowerCase().includes(q)) ||
          (ev.result && ev.result.toLowerCase().includes(q)),
      );
    }

    return e;
  }, [events, activeCategory, filterSource, searchText]);

  const stats = useMemo(() => {
    const total = events.length;
    const analystActions = categoryCounts.analyst;
    const detections = categoryCounts.detection;
    const range =
      events.length > 1
        ? `${new Date(events[events.length - 1].ts).toLocaleDateString("en-US", { month: "short", day: "numeric" })} — ${new Date(events[0].ts).toLocaleDateString("en-US", { month: "short", day: "numeric" })}`
        : events.length === 1
        ? new Date(events[0].ts).toLocaleDateString("en-US", { month: "short", day: "numeric" })
        : "—";

    return { total, analystActions, detections, range };
  }, [events, categoryCounts]);

  const grouped = useMemo(() => groupEvents(filtered), [filtered]);

  function handleExport(format: "md" | "csv" | "jsonl") {
    let content = "";
    let mime = "";
    let filename = "";

    if (format === "csv") {
      content = exportTimelineCsv(filtered);
      mime = "text/csv;charset=utf-8;";
      filename = `soc-activity-${Date.now()}.csv`;
    } else if (format === "jsonl") {
      content = exportTimelineJsonl(filtered);
      mime = "application/x-ndjson;charset=utf-8;";
      filename = `soc-activity-${Date.now()}.jsonl`;
    } else {
      content = exportTimelineMarkdown(filtered, "SOC Operational Activity Feed");
      mime = "text/markdown;charset=utf-8;";
      filename = `soc-activity-${Date.now()}.md`;
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Exported Activity Feed (${format.toUpperCase()})`);
  }

  function handleClearWithUndo() {
    const snapshot = getTimelineEvents();
    clearTimeline();
    refresh();
    toast("Activity log cleared", {
      action: {
        label: "Undo",
        onClick: () => {
          try {
            localStorage.setItem("ba.timeline.v1", JSON.stringify(snapshot));
            refresh();
          } catch {}
        },
      },
    });
  }

  return (
    <ErrorBoundary name="ActivityPage">
      <PageShell
        eyebrow="ops / activity"
        title="Live SOC Activity Chronicle"
        description="Real-time operational stream distinguishing analyst triage, automated detections, and forensic tool telemetry."
        crumbs={[{ label: "Ops" }, { label: "Activity" }]}
        meta={[
          { label: "Events", value: String(stats.total), tone: "primary" },
          { label: "Analyst Actions", value: String(stats.analystActions), tone: "success" },
          {
            label: "Detections",
            value: String(stats.detections),
            tone: stats.detections > 0 ? "destructive" : "muted",
          },
        ]}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-mono ba-text-2xs font-medium transition-colors ${
                autoRefresh
                  ? "border-success/40 bg-success/10 text-success"
                  : "border-subtle bg-surface-1 text-fg-dim"
              }`}
            >
              <Radio className={`h-3 w-3 ${autoRefresh ? "animate-pulse" : ""}`} />
              <span>{autoRefresh ? "Live 5s" : "Live Paused"}</span>
            </button>

            <button
              onClick={refresh}
              aria-label="Refresh Activity Stream"
              title="Refresh Activity Stream"
              className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-subtle bg-surface-1 text-fg-dim hover:text-foreground transition-colors"
            >
              <RefreshCw className={`h-3 w-3 ${isRefreshing ? "animate-spin" : ""}`} />
            </button>

            {events.length > 0 && (
              <>
                <div className="flex items-center rounded-md border border-subtle bg-surface-1 p-0.5">
                  <button
                    onClick={() => handleExport("csv")}
                    title="Export CSV"
                    className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-mono ba-text-2xs text-fg-dim hover:text-foreground hover:bg-surface-2 transition-colors"
                  >
                    <FileSpreadsheet className="h-3 w-3 text-success" /> csv
                  </button>
                  <button
                    onClick={() => handleExport("md")}
                    title="Export Markdown"
                    className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-mono ba-text-2xs text-fg-dim hover:text-foreground hover:bg-surface-2 transition-colors"
                  >
                    <Download className="h-3 w-3 text-warning" /> md
                  </button>
                </div>

                <button
                  onClick={handleClearWithUndo}
                  className="inline-flex items-center gap-1 rounded-md border border-destructive/40 bg-destructive/10 px-2 py-1 text-mono ba-text-2xs text-destructive hover:bg-destructive/20 transition-colors"
                >
                  <Trash2 className="h-3 w-3" /> clear
                </button>
              </>
            )}
          </div>
        }
      >
        {/* Metric Ribbon */}
        <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <MetricTile
            label="Total Activity Events"
            value={String(stats.total)}
            hint="All telemetry sources"
            icon={Activity}
            tone="primary"
          />
          <MetricTile
            label="Analyst Interventions"
            value={String(stats.analystActions)}
            hint="Manual investigations & milestones"
            icon={User}
            tone="success"
          />
          <MetricTile
            label="Security Detections"
            value={String(stats.detections)}
            hint="Sigma rules & alert matches"
            icon={ShieldAlert}
            tone={stats.detections > 0 ? "destructive" : "info"}
          />
          <MetricTile
            label="Active Telemetry Tools"
            value={String(sources.length)}
            hint={stats.range}
            icon={Layers}
            tone="accent"
          />
        </div>

        {/* Operational Category Filter Tabs */}
        <div className="mb-4 flex flex-wrap items-center gap-1.5 border-b border-subtle pb-3">
          {CATEGORY_TABS.map((tab) => {
            const Icon = tab.icon;
            const count = categoryCounts[tab.id];
            const active = activeCategory === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveCategory(tab.id)}
                className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-mono ba-text-xs transition-colors ${
                  active
                    ? "border border-primary/40 bg-primary/15 text-primary font-semibold shadow-xs"
                    : "border border-transparent text-fg-dim hover:bg-surface-1 hover:text-foreground"
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                <span>{tab.label}</span>
                <span className={`rounded-full px-1.5 py-0.2 text-[10px] ${active ? "bg-primary/20" : "bg-surface-2"}`}>
                  {count}
                </span>
              </button>
            );
          })}

          <button
            onClick={() => navigate({ to: "/timeline" })}
            className="ml-auto inline-flex items-center gap-1 rounded-md border border-subtle bg-surface-1 px-2.5 py-1 text-mono ba-text-2xs text-fg-dim hover:text-foreground hover:border-primary/40 transition-colors"
          >
            <span>Open Deep-Dive Timeline</span>
            <ArrowRight className="h-3 w-3" />
          </button>
        </div>

        {/* Search & Source Filter Bar */}
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-fg-dim" />
            <input
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              aria-label="Search events"
              placeholder="Filter live activity by detail, verb, observable, target…"
              className="h-8 w-full rounded border border-subtle bg-surface-0 pl-8 pr-2 text-mono ba-text-xs text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/50 transition-colors"
            />
          </div>

          <select
            value={filterSource}
            onChange={(e) => setFilterSource(e.target.value)}
            aria-label="Filter by source"
            className="h-8 rounded border border-subtle bg-surface-0 px-2 text-mono ba-text-xs text-foreground outline-none focus:border-primary/50"
          >
            <option value="all">All sources ({events.length})</option>
            {sources.map((s) => (
              <option key={s} value={s}>
                {s} ({events.filter((ev) => ev.source === s).length})
              </option>
            ))}
          </select>
        </div>

        {/* Chronological Activity Feed */}
        {grouped.length === 0 ? (
          <Empty
            icon={Activity}
            title={events.length === 0 ? "No SOC activity recorded yet" : "No matching activity events"}
            hint={
              events.length === 0
                ? "Activity is automatically captured as you extract IOCs, analyze PCAPs, inspect URLs, and investigate cases."
                : "Try selecting 'All Activity' or clearing your search filter."
            }
          />
        ) : (
          <div className="space-y-6">
            {grouped.map((group) => (
              <div key={group.label}>
                <SectionBar
                  id={`DAY-${group.label}`}
                  label={group.label}
                  meta={`${group.events.length} event${group.events.length === 1 ? "" : "s"}`}
                />
                <div className="relative space-y-0">
                  {group.events.map((ev, i) => {
                    const ts = new Date(ev.ts);
                    const timeStr = ts.toLocaleTimeString("en-US", {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                    });
                    const sev = ev.severity || "info";
                    const actor = ev.actor || "automation";

                    // Color border and dot according to severity
                    const dotClass =
                      sev === "critical"
                        ? "bg-destructive ring-destructive/30"
                        : sev === "high"
                        ? "bg-warning ring-warning/30"
                        : sev === "medium"
                        ? "bg-amber-400 ring-amber-400/30"
                        : sev === "low"
                        ? "bg-primary ring-primary/30"
                        : "bg-primary/50 ring-background";

                    return (
                      <div
                        key={ev.id}
                        className="group relative flex gap-3 py-2 pl-8 hover:bg-surface-1 rounded-md transition-colors"
                      >
                        {/* Vertical timeline node */}
                        <div className="absolute left-2.5 top-3 flex flex-col items-center">
                          <div className={`z-10 h-2 w-2 rounded-full ring-2 ${dotClass}`} />
                          {i < group.events.length - 1 && <div className="mt-1 h-full w-px bg-border/40" />}
                        </div>

                        {/* Content */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            {/* Source Workstation */}
                            {SOURCE_ROUTES[ev.source] ? (
                              <button
                                onClick={() => navigate({ to: SOURCE_ROUTES[ev.source] })}
                                title={`Open ${ev.source} workspace`}
                                className="cursor-pointer"
                              >
                                <Chip tone={SOURCE_COLORS[ev.source] ?? "default"}>{ev.source}</Chip>
                              </button>
                            ) : (
                              <Chip tone={SOURCE_COLORS[ev.source] ?? "default"}>{ev.source}</Chip>
                            )}

                            {/* Verb */}
                            <span className="text-mono ba-text-xs font-semibold text-foreground">{ev.verb}</span>

                            {/* Actor Badge */}
                            {actor === "analyst" && (
                              <span className="inline-flex items-center gap-1 text-[10px] text-success font-medium">
                                <User className="h-2.5 w-2.5" /> analyst
                              </span>
                            )}
                            {actor === "system" && (
                              <span className="inline-flex items-center gap-1 text-[10px] text-fg-dim">
                                <Server className="h-2.5 w-2.5" /> system
                              </span>
                            )}

                            {/* Relative & Clock Time */}
                            <span className="ml-auto text-mono ba-text-2xs text-muted-foreground group-hover:text-foreground transition-colors">
                              {formatRelativeTime(ev.ts)} · {timeStr}
                            </span>
                          </div>

                          {/* Detail */}
                          <p className="mt-1 text-mono ba-text-xs text-muted-foreground leading-snug break-words">
                            {ev.detail}
                          </p>

                          {/* Target / Result */}
                          {(ev.target || ev.result) && (
                            <div className="mt-1 flex flex-wrap items-center gap-2 text-mono ba-text-2xs">
                              {ev.target && (
                                <code className="truncate max-w-[280px] rounded border border-subtle bg-surface-0 px-1.5 py-0.5 text-foreground font-mono">
                                  {ev.target}
                                </code>
                              )}
                              {ev.result && <span className="text-fg-dim">→ {ev.result}</span>}
                            </div>
                          )}
                        </div>

                        {/* Quick Action: Pivot to Timeline */}
                        <div className="shrink-0 flex items-center pr-2 opacity-80 md:opacity-0 group-hover:opacity-100 transition-opacity">
                          <button
                            onClick={() =>
                              navigate({
                                to: "/timeline",
                                search: () => ({ search: ev.target || ev.verb }),
                              })
                            }
                            title="Investigate in deep-dive Timeline"
                            className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-2xs text-fg-dim hover:text-foreground hover:border-primary/40 transition-colors"
                          >
                            <span>Investigate</span>
                            <ArrowRight className="h-2.5 w-2.5" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </PageShell>
    </ErrorBoundary>
  );
}

