import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useState, useCallback, useRef } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, SectionBar, Chip, MetricTile } from "@/components/soc";
import { Empty } from "@/components/output";
import {
  getTimelineEvents,
  restoreDefaultTimelineScenario,
  clearTimeline,
  deleteTimelineEvent,
  addAnalystMilestone,
  bucketEventsByTime,
  filterTimelineEvents,
  exportTimelineCsv,
  exportTimelineJsonl,
  exportTimelineMarkdown,
  promoteEventToCase,
  TIMELINE_UPDATED_EVENT,
  type TimelineEvent,
  type TimelineSeverity,
  type TimelineActor,
  type TimelineBucket,
} from "@/lib/timeline";
import { useCaseList, useActiveCase } from "@/data/case";
import { toast } from "sonner";
import {
  Trash2,
  Clock,
  Filter,
  Search,
  X,
  Download,
  PlusCircle,
  Flag,
  FileSpreadsheet,
  FileText,
  Copy,
  Check,
  ExternalLink,
  ShieldAlert,
  FolderPlus,
  User,
  Bot,
  Server,
  BarChart2,
  Calendar,
  Layers,
  AlertTriangle,
  RotateCcw,
  Briefcase,
} from "lucide-react";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { AttackPlaybackScrubber } from "@/components/timeline/AttackPlaybackScrubber";
import { AttackProgressionSynthesis } from "@/components/timeline/AttackProgressionSynthesis";
import { ShiftHandoverBriefingModal } from "@/components/case/ShiftHandoverBriefingModal";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/timeline")({ component: TimelinePage });

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

const SEVERITY_CONFIG: Record<
  TimelineSeverity,
  { label: string; tone: "destructive" | "warning" | "primary" | "info" | "default"; badgeClass: string; barFill: string }
> = {
  critical: {
    label: "Critical",
    tone: "destructive",
    badgeClass: "border-destructive/50 bg-destructive/15 text-destructive font-semibold",
    barFill: "fill-destructive",
  },
  high: {
    label: "High",
    tone: "warning",
    badgeClass: "border-warning/50 bg-warning/15 text-warning font-semibold",
    barFill: "fill-warning",
  },
  medium: {
    label: "Medium",
    tone: "warning",
    badgeClass: "border-amber-400/40 bg-amber-400/10 text-amber-300",
    barFill: "fill-amber-400",
  },
  low: {
    label: "Low",
    tone: "primary",
    badgeClass: "border-primary/40 bg-primary/10 text-primary",
    barFill: "fill-primary",
  },
  info: {
    label: "Info",
    tone: "default",
    badgeClass: "border-subtle bg-surface-1 text-fg-dim",
    barFill: "fill-muted-foreground/40",
  },
};

const TIME_PRESETS = [
  { id: "all", label: "All Time" },
  { id: "15m", label: "Last 15m" },
  { id: "1h", label: "Last 1h" },
  { id: "6h", label: "Last 6h" },
  { id: "24h", label: "Last 24h" },
  { id: "7d", label: "Last 7d" },
] as const;

function dateGroup(ts: string): string {
  const d = new Date(ts);
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yesterday = new Date(today.getTime() - 86400000);
  const eventDate = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  if (eventDate.getTime() === today.getTime()) return "Today";
  if (eventDate.getTime() === yesterday.getTime()) return "Yesterday";
  return d.toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" });
}

function formatTime(ts: string): string {
  const d = new Date(ts);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}

function formatRelativeTime(ts: string): string {
  const now = Date.now();
  const diff = now - new Date(ts).getTime();
  if (diff < 60_000) return "just now";
  const mins = Math.floor(diff / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function TimelinePage() {
  const navigate = useNavigate();
  const cases = useCaseList();
  const { activeCase } = useActiveCase();

  // State
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [filterSource, setFilterSource] = useState<string | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<TimelineSeverity | null>(null);
  const [filterActor, setFilterActor] = useState<TimelineActor | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [timePreset, setTimePreset] = useState<string>("all");
  const [timeSlice, setTimeSlice] = useState<{ start: string; end: string } | null>(null);
  const [hoveredBucket, setHoveredBucket] = useState<TimelineBucket | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activeEventIndex, setActiveEventIndex] = useState<number | null>(null);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  // Milestone modal state
  const [isMilestoneOpen, setIsMilestoneOpen] = useState(false);
  const [milestoneTitle, setMilestoneTitle] = useState("");
  const [milestoneDetail, setMilestoneDetail] = useState("");
  const [milestoneSeverity, setMilestoneSeverity] = useState<TimelineSeverity>("high");
  const [milestoneTarget, setMilestoneTarget] = useState("");
  const [milestoneResult, setMilestoneResult] = useState("");
  const [milestonePromoteCase, setMilestonePromoteCase] = useState(true);
  const [isShiftHandoverOpen, setIsShiftHandoverOpen] = useState(false);

  // Target case selector for "Add to Case"
  const [targetCaseId, setTargetCaseId] = useState<string>("");

  const searchInputRef = useRef<HTMLInputElement>(null);

  // Load events
  const loadEvents = useCallback(() => {
    let list = getTimelineEvents();
    if (list.length === 0 && localStorage.getItem("ba.timeline.cleared") !== "true") {
      list = restoreDefaultTimelineScenario();
    }
    setEvents(list);
  }, []);

  useEffect(() => {
    loadEvents();
    const handleUpdated = () => loadEvents();
    window.addEventListener(TIMELINE_UPDATED_EVENT, handleUpdated);
    window.addEventListener("storage", handleUpdated);
    return () => {
      window.removeEventListener(TIMELINE_UPDATED_EVENT, handleUpdated);
      window.removeEventListener("storage", handleUpdated);
    };
  }, [loadEvents]);

  // Set default case
  useEffect(() => {
    if (activeCase?.id) {
      setTargetCaseId(activeCase.id);
    } else if (cases.length > 0 && !targetCaseId) {
      setTargetCaseId(cases[0].id);
    }
  }, [activeCase, cases, targetCaseId]);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setSearchQuery("");
        setFilterSource(null);
        setFilterSeverity(null);
        setFilterActor(null);
        setTimeSlice(null);
        setConfirmClear(false);
        setIsMilestoneOpen(false);
      }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  // Events filtered WITHOUT time-slice (used for the histogram so it always shows the broader trend)
  const eventsForHistogram = useMemo(() => {
    return filterTimelineEvents(events, {
      searchQuery,
      sources: filterSource ? [filterSource] : undefined,
      severities: filterSeverity ? [filterSeverity] : undefined,
      actors: filterActor ? [filterActor] : undefined,
      timeRange: timePreset as any,
    });
  }, [events, searchQuery, filterSource, filterSeverity, filterActor, timePreset]);

  // Buckets for histogram
  const buckets = useMemo(() => {
    return bucketEventsByTime(eventsForHistogram, { bucketCount: 28 });
  }, [eventsForHistogram]);

  // Final filtered events (including timeSlice if clicked)
  const filteredEvents = useMemo(() => {
    if (!timeSlice) return eventsForHistogram;
    return filterTimelineEvents(eventsForHistogram, { timeRange: timeSlice });
  }, [eventsForHistogram, timeSlice]);

  // Distinct sources and counts
  const sourceFacets = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const e of events) {
      counts[e.source] = (counts[e.source] || 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [events]);

  // Distinct severities and counts
  const severityFacets = useMemo(() => {
    const counts: Record<TimelineSeverity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const e of events) {
      const s = e.severity || "info";
      counts[s] = (counts[s] || 0) + 1;
    }
    return counts;
  }, [events]);

  // Grouped by date
  const grouped = useMemo(() => {
    const map = new Map<string, TimelineEvent[]>();
    for (const e of filteredEvents) {
      const g = dateGroup(e.ts);
      if (!map.has(g)) map.set(g, []);
      map.get(g)!.push(e);
    }
    return Array.from(map.entries());
  }, [filteredEvents]);

  // Investigation stats
  const stats = useMemo(() => {
    const total = events.length;
    const criticalOrHigh = severityFacets.critical + severityFacets.high;
    const sourcesCount = sourceFacets.length;
    let spanStr = "—";
    if (events.length > 1) {
      const first = new Date(events[events.length - 1].ts);
      const last = new Date(events[0].ts);
      spanStr = `${first.toLocaleDateString("en-US", { month: "short", day: "numeric" })} — ${last.toLocaleDateString("en-US", { month: "short", day: "numeric" })}`;
    } else if (events.length === 1) {
      spanStr = new Date(events[0].ts).toLocaleDateString("en-US", { month: "short", day: "numeric" });
    }
    return { total, criticalOrHigh, sourcesCount, spanStr };
  }, [events, severityFacets, sourceFacets]);

  // Actions
  function handleClear() {
    const snapshot = getTimelineEvents();
    clearTimeline();
    loadEvents();
    toast.success("Timeline cleared", {
      action: {
        label: "Undo",
        onClick: () => {
          try {
            localStorage.setItem("ba.timeline.v1", JSON.stringify(snapshot));
            loadEvents();
          } catch {}
        },
      },
    });
  }

  function handleDeleteEvent(id: string) {
    deleteTimelineEvent(id);
    loadEvents();
    toast.info("Event removed from timeline");
  }

  function handlePromoteEvent(event: TimelineEvent) {
    const target = targetCaseId || activeCase?.id || cases[0]?.id;
    if (!target) {
      toast.error("No case available. Create a case first in /case.");
      return;
    }
    const targetCaseObj = cases.find((c) => c.id === target);
    const ok = promoteEventToCase(event, target);
    if (ok) {
      toast.success(`Event promoted to case "${targetCaseObj?.title || target}"`);
    } else {
      toast.error("Failed to promote event to case");
    }
  }

  function handleAddMilestoneSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!milestoneTitle.trim() || !milestoneDetail.trim()) {
      toast.error("Milestone title and detail are required");
      return;
    }

    const created = addAnalystMilestone({
      title: milestoneTitle,
      detail: milestoneDetail,
      severity: milestoneSeverity,
      target: milestoneTarget || undefined,
      result: milestoneResult || undefined,
      caseId: milestonePromoteCase && targetCaseId ? targetCaseId : undefined,
    });

    if (milestonePromoteCase && targetCaseId) {
      promoteEventToCase(created, targetCaseId);
    }

    loadEvents();
    setIsMilestoneOpen(false);
    setMilestoneTitle("");
    setMilestoneDetail("");
    setMilestoneTarget("");
    setMilestoneResult("");
    toast.success("Forensic milestone injected into timeline");
  }

  function copyText(text: string, id: string) {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
    toast.success("Copied to clipboard");
  }

  function handleExportCsv() {
    const csv = exportTimelineCsv(filteredEvents);
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `timesketch-timeline-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Exported Timesketch CSV");
  }

  function handleExportJsonl() {
    const jsonl = exportTimelineJsonl(filteredEvents);
    const blob = new Blob([jsonl], { type: "application/x-ndjson;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `timeline-${Date.now()}.jsonl`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Exported JSONL Stream");
  }

  function handleExportMd() {
    const md = exportTimelineMarkdown(filteredEvents, "Incident Chronological Timeline");
    const blob = new Blob([md], { type: "text/markdown;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `forensic-timeline-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Exported Publication DFIR Markdown");
  }

  return (
    <ErrorBoundary name="TimelinePage">
      <PageShell
        eyebrow="ops / timeline"
        title="Forensic Timeline Analysis"
        description="Timesketch-grade chronological reconstruction and event frequency telemetry across all investigation workspaces."
        crumbs={[{ label: "Ops" }, { label: "Timeline" }]}
        meta={[
          { label: "events", value: String(stats.total), tone: "primary" },
          ...(stats.criticalOrHigh > 0
            ? [{ label: "alerts", value: String(stats.criticalOrHigh), tone: "destructive" as const }]
            : []),
          { label: "filtered", value: String(filteredEvents.length), tone: "info" },
        ]}
        actions={
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              onClick={() => setIsMilestoneOpen(true)}
              className="inline-flex items-center gap-1.5 rounded-md border border-primary/40 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs font-medium text-primary hover:bg-primary/20 transition-colors"
            >
              <PlusCircle className="h-3 w-3" />
              <span>Log Milestone</span>
            </button>

            <button
              onClick={() => setIsShiftHandoverOpen(true)}
              className="inline-flex items-center gap-1.5 rounded-md border border-amber-500/50 bg-amber-500/15 px-2.5 py-1 text-mono ba-text-2xs font-bold text-amber-400 hover:bg-amber-500/25 transition-colors"
              title="Generate SOC Shift Handover & Incident Briefing"
              id="btn-timeline-shift-handover"
            >
              <Briefcase className="h-3 w-3" />
              <span>Shift Handover</span>
            </button>

            {events.length > 0 && (
              <>
                <div className="flex items-center rounded-md border border-subtle bg-surface-1 p-0.5">
                  <button
                    onClick={handleExportCsv}
                    title="Export Timesketch CSV"
                    className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-mono ba-text-2xs text-fg-dim hover:text-foreground hover:bg-surface-2 transition-colors"
                  >
                    <FileSpreadsheet className="h-3 w-3 text-success" /> csv
                  </button>
                  <button
                    onClick={handleExportJsonl}
                    title="Export Machine JSONL"
                    className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-mono ba-text-2xs text-fg-dim hover:text-foreground hover:bg-surface-2 transition-colors"
                  >
                    <FileText className="h-3 w-3 text-info" /> jsonl
                  </button>
                  <button
                    onClick={handleExportMd}
                    title="Export DFIR Markdown"
                    className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-mono ba-text-2xs text-fg-dim hover:text-foreground hover:bg-surface-2 transition-colors"
                  >
                    <Download className="h-3 w-3 text-warning" /> md
                  </button>
                </div>

                <button
                  onClick={() => {
                    if (confirmClear) {
                      handleClear();
                      setConfirmClear(false);
                    } else {
                      setConfirmClear(true);
                    }
                  }}
                  onBlur={() => setConfirmClear(false)}
                  onMouseLeave={() => setConfirmClear(false)}
                  className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-mono ba-text-2xs transition-colors border ${
                    confirmClear
                      ? "border-destructive bg-destructive/20 text-destructive font-semibold"
                      : "border-destructive/40 bg-destructive/10 text-destructive hover:bg-destructive/20"
                  }`}
                >
                  <Trash2 className="h-3 w-3" /> {confirmClear ? "Confirm Clear?" : "Clear"}
                </button>
              </>
            )}
          </div>
        }
      >
        {/* KPI Metrics Ribbon */}
        <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <MetricTile
            label="Total Telemetry Events"
            value={String(stats.total)}
            hint="Aggregated across 18 workspaces"
            icon={Clock}
            tone="primary"
          />
          <MetricTile
            label="Critical & High Alerts"
            value={String(stats.criticalOrHigh)}
            hint="Requiring triage or containment"
            icon={ShieldAlert}
            tone={stats.criticalOrHigh > 0 ? "destructive" : "success"}
          />
          <MetricTile
            label="Active Telemetry Tools"
            value={String(stats.sourcesCount)}
            hint="Workstations generating events"
            icon={Layers}
            tone="info"
          />
          <MetricTile
            label="Chronicle Timespan"
            value={stats.spanStr}
            hint="Earliest to latest recorded"
            icon={Calendar}
            tone="accent"
          />
        </div>

        {/* Autonomous Multi-Stage Intrusion Synthesis */}
        {events.length > 0 && (
          <AttackProgressionSynthesis events={events} className="mb-4" />
        )}

        {/* Incident Attack Progression Scrubber */}
        {events.length > 0 && (
          <AttackPlaybackScrubber
            events={filteredEvents}
            activeEventIndex={activeEventIndex}
            onSelectEvent={(evt, idx) => {
              setActiveEventIndex(idx);
              if (evt) setSelectedEventId(evt.id);
            }}
            className="mb-4"
          />
        )}

        {/* Interactive Event Frequency Histogram */}
        {events.length > 0 && (
          <Panel className="mb-6 overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-subtle pb-3">
              <div className="flex items-center gap-2">
                <BarChart2 className="h-4 w-4 text-primary" />
                <span className="text-mono ba-text-xs font-semibold text-foreground uppercase tracking-wider">
                  Event Frequency Distribution
                </span>
                <span className="text-mono ba-text-2xs text-muted-foreground">
                  ({eventsForHistogram.length} events across {buckets.length} time buckets)
                </span>
              </div>

              {/* Time window presets */}
              <div className="flex flex-wrap items-center gap-1">
                {TIME_PRESETS.map((preset) => (
                  <button
                    key={preset.id}
                    onClick={() => {
                      setTimePreset(preset.id);
                      setTimeSlice(null);
                    }}
                    className={`rounded px-2 py-0.5 text-mono ba-text-2xs transition-colors ${
                      timePreset === preset.id && !timeSlice
                        ? "border border-primary/50 bg-primary/20 text-primary font-medium"
                        : "border border-subtle bg-surface-1 text-fg-dim hover:text-foreground"
                    }`}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>

            {/* SVG Histogram Chart */}
            <div className="relative pt-4 pb-1">
              <div className="h-28 w-full">
                <svg
                  viewBox={`0 0 ${Math.max(buckets.length * 28, 560)} 100`}
                  preserveAspectRatio="none"
                  className="h-full w-full overflow-visible"
                >
                  <defs>
                    <linearGradient id="histGradPrimary" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity="0.8" />
                      <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity="0.2" />
                    </linearGradient>
                    <linearGradient id="histGradDestructive" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="hsl(var(--destructive))" stopOpacity="0.9" />
                      <stop offset="100%" stopColor="hsl(var(--destructive))" stopOpacity="0.3" />
                    </linearGradient>
                    <linearGradient id="histGradWarning" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="hsl(var(--warning))" stopOpacity="0.85" />
                      <stop offset="100%" stopColor="hsl(var(--warning))" stopOpacity="0.25" />
                    </linearGradient>
                  </defs>

                  {/* Horizontal guideline */}
                  <line x1="0" y1="95" x2="10000" y2="95" stroke="currentColor" strokeOpacity="0.1" strokeWidth="1" />

                  {/* Buckets */}
                  {buckets.map((bucket, i) => {
                    const totalBuckets = buckets.length;
                    const svgWidth = Math.max(buckets.length * 28, 560);
                    const barWidth = Math.max(svgWidth / totalBuckets - 4, 6);
                    const x = i * (svgWidth / totalBuckets) + 2;
                    const barHeight = Math.max((bucket.heightPercent / 100) * 80, bucket.count > 0 ? 4 : 0);
                    const y = 95 - barHeight;

                    const fillGrad =
                      bucket.peakSeverity === "critical"
                        ? "url(#histGradDestructive)"
                        : bucket.peakSeverity === "high" || bucket.peakSeverity === "medium"
                        ? "url(#histGradWarning)"
                        : "url(#histGradPrimary)";

                    const isSelected =
                      timeSlice &&
                      new Date(bucket.start).getTime() >= new Date(timeSlice.start).getTime() &&
                      new Date(bucket.end).getTime() <= new Date(timeSlice.end).getTime();

                    return (
                      <g key={bucket.start} className="cursor-pointer">
                        <rect
                          x={x}
                          y={y}
                          width={barWidth}
                          height={barHeight}
                          rx="2"
                          fill={fillGrad}
                          className={`transition-all duration-150 ${
                            isSelected
                              ? "stroke-primary stroke-2 filter drop-shadow-[0_0_8px_rgba(59,130,246,0.5)]"
                              : "hover:opacity-80"
                          }`}
                          onMouseEnter={() => setHoveredBucket(bucket)}
                          onMouseLeave={() => setHoveredBucket(null)}
                          onClick={() => {
                            if (isSelected) {
                              setTimeSlice(null);
                            } else {
                              setTimeSlice({ start: bucket.start, end: bucket.end });
                            }
                          }}
                        />
                      </g>
                    );
                  })}
                </svg>
              </div>

              {/* Bucket Hover Tooltip */}
              {hoveredBucket && (
                <div className="absolute top-0 right-3 pointer-events-none rounded-md border border-subtle bg-surface-0/95 p-2 shadow-lg backdrop-blur-sm z-20 text-mono ba-text-2xs">
                  <div className="font-semibold text-foreground">
                    {hoveredBucket.label} UTC · {hoveredBucket.count} event{hoveredBucket.count === 1 ? "" : "s"}
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    <span className="text-muted-foreground">Peak:</span>
                    <span className={`font-semibold ${SEVERITY_CONFIG[hoveredBucket.peakSeverity].badgeClass} px-1 rounded`}>
                      {hoveredBucket.peakSeverity.toUpperCase()}
                    </span>
                  </div>
                  {Object.keys(hoveredBucket.sourceCounts).length > 0 && (
                    <div className="mt-1 text-fg-dim">
                      {Object.entries(hoveredBucket.sourceCounts)
                        .map(([src, count]) => `${src} (${count})`)
                        .join(" · ")}
                    </div>
                  )}
                  <div className="mt-1 text-primary/80 italic text-[10px]">Click bar to filter time slice</div>
                </div>
              )}

              {/* Active Time Slice Banner */}
              {timeSlice && (
                <div className="mt-3 flex items-center justify-between rounded-md border border-primary/40 bg-primary/10 px-3 py-1.5 text-mono ba-text-2xs">
                  <div className="flex items-center gap-2 text-primary">
                    <Clock className="h-3.5 w-3.5" />
                    <span>
                      Active Time Slice:{" "}
                      <strong>
                        {new Date(timeSlice.start).toLocaleTimeString()} — {new Date(timeSlice.end).toLocaleTimeString()}
                      </strong>{" "}
                      ({filteredEvents.length} events match)
                    </span>
                  </div>
                  <button
                    onClick={() => setTimeSlice(null)}
                    className="inline-flex items-center gap-1 rounded border border-primary/40 bg-surface-0 px-2 py-0.5 text-primary hover:bg-primary/20"
                  >
                    <RotateCcw className="h-2.5 w-2.5" /> Reset Slice
                  </button>
                </div>
              )}
            </div>
          </Panel>
        )}

        {/* Multi-Facet Filter Bar */}
        <div className="mb-6 space-y-3">
          <div className="flex flex-wrap items-center gap-3">
            {/* Search query with keyboard prompt */}
            <div className="relative flex-1 min-w-[240px] max-w-md">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <input
                ref={searchInputRef}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                aria-label="Search timeline events"
                placeholder="Search events, observables, targets, results… (Press /)"
                className="w-full rounded-md border border-subtle bg-surface-0 py-1.5 pl-8 pr-8 text-mono ba-text-sm text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50 transition-colors"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-fg-dim hover:text-foreground"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>

            {/* Target Case Selector for 1-click promotion */}
            {cases.length > 0 && (
              <div className="flex items-center gap-1.5 text-mono ba-text-2xs">
                <span className="text-muted-foreground hidden sm:inline">Active Case:</span>
                <select
                  value={targetCaseId}
                  onChange={(e) => setTargetCaseId(e.target.value)}
                  className="rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-2xs text-foreground outline-none focus:border-primary/50"
                >
                  {cases.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.title.length > 28 ? c.title.slice(0, 28) + "…" : c.title}
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          {/* Facet Filters: Severities & Sources */}
          <div className="flex flex-wrap items-center gap-2 pt-1">
            <span className="text-mono ba-text-2xs text-muted-foreground flex items-center gap-1">
              <Filter className="h-3 w-3" /> Severity:
            </span>
            <button
              onClick={() => setFilterSeverity(null)}
              className={`rounded border px-2 py-0.5 text-mono ba-text-2xs transition-colors ${
                !filterSeverity
                  ? "border-primary bg-primary/15 text-primary font-semibold"
                  : "border-divider-strong bg-surface-1 text-muted-foreground hover:text-foreground"
              }`}
            >
              All ({events.length})
            </button>
            {(["critical", "high", "medium", "low", "info"] as TimelineSeverity[]).map((sev) => {
              const count = severityFacets[sev] || 0;
              if (count === 0 && sev !== "critical" && sev !== "high") return null;
              const active = filterSeverity === sev;
              return (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(active ? null : sev)}
                  className={`rounded border px-2 py-0.5 text-mono ba-text-2xs transition-colors flex items-center gap-1 ${
                    active
                      ? `${SEVERITY_CONFIG[sev].badgeClass} font-semibold ring-1 ring-primary/40`
                      : "border-divider-strong bg-surface-1 text-fg-dim hover:text-foreground"
                  }`}
                >
                  <span
                    className={`inline-block h-1.5 w-1.5 rounded-full ${
                      sev === "critical"
                        ? "bg-destructive"
                        : sev === "high"
                        ? "bg-warning"
                        : "bg-muted-foreground"
                    }`}
                  />
                  <span>{sev}</span>
                  <span className="opacity-70">({count})</span>
                </button>
              );
            })}

            {/* Actor Toggle */}
            <div className="ml-auto flex items-center gap-1 border-l border-subtle pl-2">
              <span className="text-mono ba-text-2xs text-muted-foreground">Actor:</span>
              <button
                onClick={() => setFilterActor(null)}
                className={`rounded border px-1.5 py-0.5 text-mono ba-text-2xs ${
                  !filterActor ? "border-primary bg-primary/15 text-primary" : "border-subtle text-fg-dim"
                }`}
              >
                All
              </button>
              <button
                onClick={() => setFilterActor(filterActor === "analyst" ? null : "analyst")}
                className={`rounded border px-1.5 py-0.5 text-mono ba-text-2xs flex items-center gap-1 ${
                  filterActor === "analyst"
                    ? "border-success bg-success/15 text-success font-medium"
                    : "border-subtle text-fg-dim hover:text-foreground"
                }`}
              >
                <User className="h-2.5 w-2.5" /> Analyst
              </button>
              <button
                onClick={() => setFilterActor(filterActor === "system" ? null : "system")}
                className={`rounded border px-1.5 py-0.5 text-mono ba-text-2xs flex items-center gap-1 ${
                  filterActor === "system"
                    ? "border-destructive bg-destructive/15 text-destructive font-medium"
                    : "border-subtle text-fg-dim hover:text-foreground"
                }`}
              >
                <Server className="h-2.5 w-2.5" /> System
              </button>
            </div>
          </div>

          {/* Workstations / Sources chips */}
          {sourceFacets.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 pt-1">
              <span className="text-mono ba-text-2xs text-muted-foreground">Workstations:</span>
              <button
                onClick={() => setFilterSource(null)}
                className={`rounded border px-2 py-0.5 text-mono ba-text-2xs ${
                  !filterSource
                    ? "border-primary bg-primary/15 text-primary font-medium"
                    : "border-subtle bg-surface-1 text-fg-dim hover:text-foreground"
                }`}
              >
                all
              </button>
              {sourceFacets.map(([src, count]) => {
                const active = filterSource === src;
                return (
                  <button
                    key={src}
                    onClick={() => setFilterSource(active ? null : src)}
                    className={`rounded border px-2 py-0.5 text-mono ba-text-2xs transition-colors flex items-center gap-1 ${
                      active
                        ? "border-primary bg-primary/15 text-primary font-semibold"
                        : "border-divider-strong bg-surface-1 text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    <span>{src}</span>
                    <span className="opacity-70">({count})</span>
                    {active && <X className="h-2.5 w-2.5" />}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Milestone Injector Modal */}
        {isMilestoneOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-xs animate-in fade-in duration-150">
            <div className="relative w-full max-w-lg rounded-lg border border-border bg-card p-6 shadow-2xl">
              <div className="flex items-center justify-between border-b border-subtle pb-3">
                <div className="flex items-center gap-2">
                  <Flag className="h-4 w-4 text-primary" />
                  <h3 className="text-mono ba-text-base font-semibold text-foreground">Log Forensic Milestone</h3>
                </div>
                <button
                  onClick={() => setIsMilestoneOpen(false)}
                  className="rounded p-1 text-fg-dim hover:bg-surface-2 hover:text-foreground"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <form onSubmit={handleAddMilestoneSubmit} className="mt-4 space-y-4">
                <div>
                  <label className="block text-mono ba-text-2xs font-semibold text-muted-foreground mb-1">
                    Milestone Title / Action <span className="text-destructive">*</span>
                  </label>
                  <input
                    required
                    value={milestoneTitle}
                    onChange={(e) => setMilestoneTitle(e.target.value)}
                    placeholder="e.g. Lateral Movement Isolated, C2 Beacon Confirmed"
                    className="w-full rounded-md border border-subtle bg-surface-0 px-3 py-1.5 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-mono ba-text-2xs font-semibold text-muted-foreground mb-1">
                      Severity Level
                    </label>
                    <select
                      value={milestoneSeverity}
                      onChange={(e) => setMilestoneSeverity(e.target.value as TimelineSeverity)}
                      className="w-full rounded-md border border-subtle bg-surface-0 px-2.5 py-1.5 text-mono ba-text-xs text-foreground outline-none focus:border-primary/50"
                    >
                      <option value="critical">Critical (Breach / Containment)</option>
                      <option value="high">High (Malicious Finding)</option>
                      <option value="medium">Medium (Suspicious Anomaly)</option>
                      <option value="low">Low (Benign Observation)</option>
                      <option value="info">Info (Investigative Action)</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-mono ba-text-2xs font-semibold text-muted-foreground mb-1">
                      Observable / Target (Optional)
                    </label>
                    <input
                      value={milestoneTarget}
                      onChange={(e) => setMilestoneTarget(e.target.value)}
                      placeholder="e.g. 198.51.100.4 or WS-FIN-01"
                      className="w-full rounded-md border border-subtle bg-surface-0 px-3 py-1.5 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-mono ba-text-2xs font-semibold text-muted-foreground mb-1">
                    Observation Notes & Forensic Detail <span className="text-destructive">*</span>
                  </label>
                  <textarea
                    required
                    rows={3}
                    value={milestoneDetail}
                    onChange={(e) => setMilestoneDetail(e.target.value)}
                    placeholder="Detailed analyst findings, indicators, or root-cause notes..."
                    className="w-full rounded-md border border-subtle bg-surface-0 p-2 text-mono ba-text-xs text-foreground outline-none focus:border-primary/50 resize-y"
                  />
                </div>

                <div>
                  <label className="block text-mono ba-text-2xs font-semibold text-muted-foreground mb-1">
                    Outcome / Result (Optional)
                  </label>
                  <input
                    value={milestoneResult}
                    onChange={(e) => setMilestoneResult(e.target.value)}
                    placeholder="e.g. Workstation isolated from VLAN 4"
                    className="w-full rounded-md border border-subtle bg-surface-0 px-3 py-1.5 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50"
                  />
                </div>

                {cases.length > 0 && (
                  <label className="flex items-center gap-2 text-mono ba-text-2xs text-muted-foreground cursor-pointer pt-1">
                    <input
                      type="checkbox"
                      checked={milestonePromoteCase}
                      onChange={(e) => setMilestonePromoteCase(e.target.checked)}
                      className="rounded border-subtle text-primary focus:ring-0"
                    />
                    <span>
                      Directly append as defensible event to active case (
                      <span className="text-foreground font-semibold">
                        {cases.find((c) => c.id === targetCaseId)?.title || "Active Case"}
                      </span>
                      )
                    </span>
                  </label>
                )}

                <div className="flex items-center justify-end gap-2 border-t border-subtle pt-3">
                  <button
                    type="button"
                    onClick={() => setIsMilestoneOpen(false)}
                    className="rounded-md border border-subtle px-3 py-1.5 text-mono ba-text-xs text-fg-dim hover:bg-surface-2 hover:text-foreground"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="rounded-md bg-primary px-4 py-1.5 text-mono ba-text-xs font-semibold text-primary-foreground hover:bg-primary/90 transition-colors"
                  >
                    Record Milestone
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Chronological Event Stream */}
        {filteredEvents.length === 0 ? (
          <Empty
            icon={Clock}
            title={events.length === 0 ? "No timeline events captured yet" : "No matching timeline events"}
            hint={
              events.length === 0
                ? "Run tools across workspaces (Parser, URL Analyzer, Phishing, Detection Lab, Nmap) or click 'Log Milestone' to inject human findings."
                : "Try broadening your search query or clearing active severity and workstation filters."
            }
          />
        ) : (
          <div className="space-y-6">
            {grouped.map(([group, items]) => (
              <div key={group}>
                <SectionBar
                  id={`DT-${group}`}
                  label={group}
                  meta={`${items.length} event${items.length === 1 ? "" : "s"}`}
                  priority="secondary"
                  headingLevel="h2"
                />
                <Panel bodyClassName="p-0">
                  <ul className="divide-y divide-border/50">
                    {items.map((e) => {
                      const sev = e.severity || "info";
                      const sevConfig = SEVERITY_CONFIG[sev];
                      const actor = e.actor || "automation";

                      return (
                        <li
                          key={e.id}
                          id={`timeline-event-${e.id}`}
                          onClick={() => {
                            setSelectedEventId(e.id);
                            const idx = filteredEvents.findIndex((ev) => ev.id === e.id);
                            if (idx >= 0) setActiveEventIndex(idx);
                          }}
                          className={cn(
                            "group relative flex flex-col md:flex-row md:items-start gap-3 px-4 py-3 hover:bg-surface-2/60 transition-all cursor-pointer",
                            selectedEventId === e.id && "bg-primary/[0.08] ring-1 ring-inset ring-primary/60 shadow-sm"
                          )}
                        >
                          {/* Time & Relative column */}
                          <div className="shrink-0 w-28 text-mono ba-text-2xs">
                            <div className="text-foreground font-medium tabular-nums">{formatTime(e.ts)}</div>
                            <div className="text-fg-dim text-[10px] tabular-nums">{formatRelativeTime(e.ts)}</div>
                          </div>

                          {/* Workstation, Severity & Actor badges */}
                          <div className="shrink-0 flex items-center gap-1.5 flex-wrap">
                            {/* Source Workstation */}
                            {SOURCE_ROUTES[e.source] ? (
                              <button
                                onClick={() => navigate({ to: SOURCE_ROUTES[e.source] })}
                                title={`Open ${e.source} workspace`}
                                className="cursor-pointer inline-flex items-center gap-1"
                              >
                                <Chip tone={SOURCE_COLORS[e.source] ?? "default"}>{e.source}</Chip>
                              </button>
                            ) : (
                              <Chip tone={SOURCE_COLORS[e.source] ?? "default"}>{e.source}</Chip>
                            )}

                            {/* Severity Pill */}
                            <span
                              className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-mono text-[10px] uppercase tracking-wider ${sevConfig.badgeClass}`}
                            >
                              <span
                                className={`h-1.5 w-1.5 rounded-full ${
                                  sev === "critical"
                                    ? "bg-destructive"
                                    : sev === "high"
                                    ? "bg-warning"
                                    : "bg-current opacity-70"
                                }`}
                              />
                              {sev}
                            </span>

                            {/* Actor Badge */}
                            {actor === "analyst" && (
                              <span
                                title="Analyst Action"
                                className="inline-flex items-center gap-1 rounded border border-success/40 bg-success/10 px-1 py-0.5 text-mono text-[10px] text-success font-medium"
                              >
                                <User className="h-2.5 w-2.5" /> analyst
                              </span>
                            )}
                            {actor === "system" && (
                              <span
                                title="Detection System"
                                className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-1 py-0.5 text-mono text-[10px] text-fg-dim"
                              >
                                <Server className="h-2.5 w-2.5" /> system
                              </span>
                            )}
                          </div>

                          {/* Main narrative content */}
                          <div className="min-w-0 flex-1">
                            <div className="flex items-baseline gap-2 flex-wrap">
                              <span className="text-mono ba-text-xs font-semibold text-foreground">{e.verb}</span>
                              <span className="text-mono ba-text-xs text-muted-foreground break-words">{e.detail}</span>
                            </div>

                            {/* Target & Result tags */}
                            {(e.target || e.result) && (
                              <div className="mt-1.5 flex flex-wrap items-center gap-2 text-mono ba-text-2xs">
                                {e.target && (
                                  <div className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-0 px-1.5 py-0.5 max-w-full">
                                    <span className="text-fg-dim text-[10px]">target:</span>
                                    <code className="truncate max-w-[280px] text-foreground font-mono">{e.target}</code>
                                    <button
                                      onClick={() => copyText(e.target!, `t-${e.id}`)}
                                      title="Copy target"
                                      className="text-fg-dim hover:text-foreground"
                                    >
                                      {copiedId === `t-${e.id}` ? (
                                        <Check className="h-2.5 w-2.5 text-success" />
                                      ) : (
                                        <Copy className="h-2.5 w-2.5" />
                                      )}
                                    </button>
                                  </div>
                                )}
                                {e.result && (
                                  <div className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-0 px-1.5 py-0.5 max-w-full">
                                    <span className="text-fg-dim text-[10px]">result:</span>
                                    <span className="truncate max-w-[320px] text-fg-dim">{e.result}</span>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>

                          {/* Action Toolbar on Hover */}
                          <div className="shrink-0 flex flex-wrap items-center gap-1 opacity-90 md:opacity-0 group-hover:opacity-100 transition-opacity">
                            {SOURCE_ROUTES[e.source] && (
                              <button
                                type="button"
                                onClick={(ev) => {
                                  ev.stopPropagation();
                                  navigate({ to: SOURCE_ROUTES[e.source] });
                                }}
                                title={`Pivot to ${e.source} workspace`}
                                className="inline-flex items-center gap-1 rounded border border-border bg-surface-2 px-1.5 py-0.5 text-mono text-[10px] text-muted-foreground hover:text-foreground hover:bg-surface-3 transition-colors"
                              >
                                <ExternalLink className="h-2.5 w-2.5" />
                                <span>Pivot</span>
                              </button>
                            )}

                            {cases.length > 0 && (
                              <button
                                onClick={(ev) => {
                                  ev.stopPropagation();
                                  handlePromoteEvent(e);
                                }}
                                title={`Add to case: ${cases.find((c) => c.id === targetCaseId)?.title || "Active Case"}`}
                                className="inline-flex items-center gap-1 rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-mono ba-text-2xs text-primary hover:bg-primary/20 transition-colors"
                              >
                                <FolderPlus className="h-3 w-3" />
                                <span className="hidden lg:inline">Add to Case</span>
                              </button>
                            )}

                            <button
                              onClick={(ev) => {
                                ev.stopPropagation();
                                handleDeleteEvent(e.id);
                              }}
                              title="Delete event from history"
                              className="rounded p-1 text-fg-dim hover:bg-destructive/15 hover:text-destructive transition-colors"
                            >
                              <Trash2 className="h-3 w-3" />
                            </button>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                </Panel>
              </div>
            ))}
          </div>
        )}

        {/* SOC Shift Handover Briefing Modal */}
        <ShiftHandoverBriefingModal
          open={isShiftHandoverOpen}
          onClose={() => setIsShiftHandoverOpen(false)}
          cases={cases}
          timelineEvents={events}
        />
      </PageShell>
    </ErrorBoundary>
  );
}

