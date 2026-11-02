import { useState, useMemo } from "react";
import { Upload, Brain, ShieldAlert, Siren, CaseUpper, UserRoundSearch, ScrollText, MessageSquare, Activity, type LucideIcon,
  ChevronDown, ExternalLink, Trash2, Search, ArrowDownWideNarrow, ArrowUpNarrowWide } from "lucide-react";
import type { CaseEvent, EventCategory, EventActor, EventImportance } from "@/data/case";
import type { NodeRef, ProjectedEvent } from "@/lib/provenance";
import {
  filterTimelineEvents,
  sortTimelineEvents,
  groupTimelineByDay,
  type TimelineSort,
  type TimelineImportanceFilter,
} from "@/lib/timeline-view";
import { Panel, Chip } from "@/components/soc";
import { Empty } from "@/components/output";

export type ActivityFeedFilters = {
  category?: EventCategory[];
  actor?: EventActor[];
  origin?: string[];
  importance?: EventImportance[];
};

const CATEGORY_ICON: Record<EventCategory, LucideIcon> = {
  artifact: Upload,
  analysis: Brain,
  finding: ShieldAlert,
  ioc: Siren,
  case: CaseUpper,
  detection: UserRoundSearch,
  report: ScrollText,
  analyst: MessageSquare,
};

const CATEGORY_LABEL: Record<EventCategory, string> = {
  artifact: "Artifact", analysis: "Analysis", finding: "Finding",
  ioc: "IOC", case: "Case", detection: "Detection",
  report: "Report", analyst: "Analyst",
};

const IMPORTANCE_COLOR: Record<EventImportance, string> = {
  critical: "text-destructive",
  high: "text-warning",
  normal: "text-info",
  low: "text-fg-dim",
};

const IMPORTANCE_DOT: Record<EventImportance, string> = {
  critical: "bg-destructive",
  high: "bg-warning",
  normal: "bg-info",
  low: "bg-muted-foreground/40",
};

const ACTOR_LABEL: Record<EventActor, string> = {
  system: "System", analyst: "Analyst", automation: "Auto", integration: "Integration",
};

const CATEGORY_FILTER_ORDER: EventCategory[] = [
  "case", "analysis", "artifact", "finding", "ioc", "detection", "report", "analyst",
];

const ACTOR_FILTER_ORDER: EventActor[] = ["analyst", "automation", "integration", "system"];

const IMPORTANCE_FILTERS: { id: TimelineImportanceFilter; label: string }[] = [
  { id: "all", label: "all" },
  { id: "high+", label: "high+" },
  { id: "critical", label: "critical" },
];

type FeedProps = {
  events: CaseEvent[];
  onReferenceClick?: (ref: { kind: string; id: string }) => void;
  onOriginFilter?: (origin: string) => void;
  originFilter?: string;
  emptyTitle?: string;
  emptyHint?: string;
  loading?: boolean;
  /** Causal projection of events onto the provenance graph (§9.5). */
  provenance?: Map<string, ProjectedEvent>;
  resolveNodeLabel?: (ref: NodeRef) => string;
  /** When provided, matching events render a delete affordance. */
  deletableEvent?: (ev: CaseEvent) => boolean;
  onDeleteEvent?: (id: string) => void;
};

function EventIcon({ category }: { category: EventCategory }) {
  const Icon = CATEGORY_ICON[category];
  return (
    <span className="grid h-7 w-7 shrink-0 place-items-center rounded-md border border-border bg-surface-2">
      <Icon className="h-3.5 w-3.5 text-muted-foreground/80" />
    </span>
  );
}

function ReferenceChip({ ref, onClick }: { ref: { kind: string; id: string }; onClick?: (ref: { kind: string; id: string }) => void }) {
  const kindLabel = ref.kind.charAt(0).toUpperCase() + ref.kind.slice(1);
  const shortId = ref.id.length > 12 ? ref.id.slice(0, 12) + "…" : ref.id;
  return (
    <button
      onClick={() => onClick?.(ref)}
      className="inline-flex items-center gap-1 rounded border border-border/60 bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:border-primary/40 hover:text-primary transition-colors duration-150"
    >
      <ExternalLink className="h-2.5 w-2.5" />
      {kindLabel}:{shortId}
    </button>
  );
}

export function InvestigationActivityFeed({
  events,
  onReferenceClick,
  onOriginFilter,
  originFilter,
  emptyTitle = "No events",
  emptyHint = "Events appear here as the investigation progresses—analysis runs, analyst notes, decisions, and IOCs.",
  loading = false,
  provenance,
  resolveNodeLabel,
  deletableEvent,
  onDeleteEvent,
}: FeedProps) {
  const [activeFilters, setActiveFilters] = useState<Set<EventCategory>>(new Set());
  const [activeActors, setActiveActors] = useState<Set<EventActor>>(new Set());
  const [importance, setImportance] = useState<TimelineImportanceFilter>("all");
  const [sort, setSort] = useState<TimelineSort>("newest");
  const [queryText, setQueryText] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [showFilters, setShowFilters] = useState(false);

  const toggleFilter = (cat: EventCategory) => {
    setActiveFilters(prev => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };

  const toggleActorFilter = (actor: EventActor) => {
    setActiveActors(prev => {
      const next = new Set(prev);
      if (next.has(actor)) next.delete(actor);
      else next.add(actor);
      return next;
    });
  };

  const hasFacets =
    activeFilters.size > 0 || activeActors.size > 0 || importance !== "all" || queryText.trim().length > 0;

  const clearAllFacets = () => {
    setActiveFilters(new Set());
    setActiveActors(new Set());
    setImportance("all");
    setQueryText("");
  };

  const { events: filtered, hidden } = useMemo(
    () =>
      filterTimelineEvents(events, {
        query: queryText,
        categories: Array.from(activeFilters),
        actors: Array.from(activeActors),
        importance,
        origin: originFilter,
      }),
    [events, activeFilters, activeActors, importance, queryText, originFilter],
  );

  const sorted = useMemo(() => sortTimelineEvents(filtered, sort), [filtered, sort]);

  const dayGroups = useMemo(() => groupTimelineByDay(sorted), [sorted]);

  if (loading) {
    return (
      <Panel title="Investigation Activity" icon={Activity}>
        <div className="space-y-3">
          {[1, 2, 3, 4].map(i => (
            <div key={i} className="flex animate-pulse items-start gap-3 rounded-md border border-subtle bg-surface-1 p-3">
              <div className="h-7 w-7 rounded-md bg-muted-foreground/10" />
              <div className="flex-1 space-y-2">
                <div className="h-3 w-3/4 rounded bg-muted-foreground/10" />
                <div className="h-2 w-1/2 rounded bg-muted-foreground/8" />
              </div>
            </div>
          ))}
        </div>
      </Panel>
    );
  }

  if (events.length === 0) {
    return (
      <Panel title="Investigation Activity" icon={Activity}>
        <Empty icon={Activity} title={emptyTitle} hint={emptyHint} />
      </Panel>
    );
  }

  return (
    <Panel
      title="Investigation Activity"
      icon={Activity}
      meta={`${filtered.length} / ${events.length} event${events.length !== 1 ? "s" : ""}${hidden > 0 ? ` · ${hidden} hidden` : ""}`}
      actions={
        <button
          onClick={() => setShowFilters(v => !v)}
          className="rounded px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-foreground transition-colors duration-150"
        >
          {showFilters ? "hide filters" : `filter${activeFilters.size + activeActors.size > 0 ? ` (${activeFilters.size + activeActors.size})` : ""}`}
        </button>
      }
      bodyClassName="p-0"
    >
      <div className="flex items-center gap-2 border-b border-subtle px-4 py-2">
        <div className="relative min-w-0 flex-1">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground/60" />
          <input
            value={queryText}
            onChange={e => setQueryText(e.target.value)}
            placeholder="search title · detail · origin"
            aria-label="Search timeline events"
            className={
              "w-full rounded border border-border/70 bg-surface-1 py-1 pl-7 pr-2 text-mono ba-text-sm text-foreground placeholder:text-fg-dim focus:border-primary/40 focus:outline-none transition-colors duration-150"
            }
          />
        </div>
        <div className="flex shrink-0 overflow-hidden rounded border border-border/70" role="group" aria-label="Importance filter">
          {IMPORTANCE_FILTERS.map(f => (
            <button
              key={f.id}
              onClick={() => setImportance(f.id)}
              className={
                "px-2 py-1 text-mono ba-text-3xs transition-colors duration-150 " +
                (importance === f.id
                  ? "bg-primary/15 text-primary"
                  : "text-muted-foreground hover:text-foreground")
              }
            >
              {f.label}
            </button>
          ))}
        </div>
        <button
          onClick={() => setSort(s => (s === "newest" ? "oldest" : "newest"))}
          aria-label={`Sort ${sort === "newest" ? "oldest first" : "newest first"}`}
          title={sort === "newest" ? "newest first — click for chronological" : "chronological — click for newest first"}
          className="inline-flex shrink-0 items-center gap-1 rounded border border-border/70 px-2 py-1 text-mono ba-text-3xs text-muted-foreground hover:border-border hover:text-foreground transition-colors duration-150"
        >
          {sort === "newest" ? <ArrowDownWideNarrow className="h-3 w-3" /> : <ArrowUpNarrowWide className="h-3 w-3" />}
          {sort === "newest" ? "newest" : "oldest"}
        </button>
      </div>
      {showFilters && (
        <div className="flex flex-wrap gap-1.5 border-b border-subtle px-4 py-2.5">
          {CATEGORY_FILTER_ORDER.map(cat => {
            const count = events.filter(ev => ev.category === cat).length;
            const active = activeFilters.has(cat);
            return (
              <button
                key={cat}
                onClick={() => toggleFilter(cat)}
                className={
                  "inline-flex items-center gap-1.5 rounded px-2 py-1 text-mono ba-text-2xs transition-colors duration-150" +
                  (active
                    ? "border border-primary/40 bg-primary/15 text-primary"
                    : "border border-transparent text-muted-foreground hover:border-border hover:text-foreground")
                }
              >
                {count}
                <span>{CATEGORY_LABEL[cat]}</span>
              </button>
            );
          })}
          <span className="mx-1 w-px self-stretch bg-border" aria-hidden />
          {ACTOR_FILTER_ORDER.map(actor => {
            const count = events.filter(ev => ev.actor === actor).length;
            const active = activeActors.has(actor);
            if (count === 0 && !active) return null;
            return (
              <button
                key={actor}
                onClick={() => toggleActorFilter(actor)}
                className={
                  "inline-flex items-center gap-1.5 rounded px-2 py-1 text-mono ba-text-2xs transition-colors duration-150" +
                  (active
                    ? "border border-accent/40 bg-accent/15 text-accent"
                    : "border border-transparent text-muted-foreground hover:border-border hover:text-foreground")
                }
              >
                {count}
                <span>{ACTOR_LABEL[actor]}</span>
              </button>
            );
          })}
          {hasFacets && (
            <button
              onClick={clearAllFacets}
              className="rounded px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-destructive transition-colors duration-150"
            >
              clear all
            </button>
          )}
        </div>
      )}
      <div className="divide-y divide-border/50">
        {filtered.length === 0 ? (
          <p className="px-4 py-6 text-center text-mono ba-text-sm text-fg-dim">
            No events match the current filter{hasFacets ? " — clear all to reset" : ""}
          </p>
        ) : (
          dayGroups.flatMap(({ dateKey, label, events: dayEvents }) => {
              return [
                <div key={`hdr-${dateKey}`} className="sticky top-[var(--ba-topbar-h)] z-10 border-b border-subtle bg-card/90 px-4 py-1.5 text-mono ba-text-3xs text-fg-dim backdrop-blur-sm">
                  {label} · {dayEvents.length} event{dayEvents.length !== 1 ? "s" : ""}
                </div>,
                ...dayEvents.map(ev => {
                  const d = new Date(ev.ts);
                  const time = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
                  const expanded = expandedId === ev.id;
                  const hasDetail = ev.detail.length > 0;
                  const hasReferences = ev.references.length > 0;
                  return (
                    <div key={ev.id} className="group px-4 py-2.5 transition-colors duration-150 hover:bg-surface-1">
                      <div className="flex items-start gap-3">
                        <EventIcon category={ev.category} />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-start gap-2">
                            <span className={`inline-block h-1.5 w-1.5 shrink-0 translate-y-[7px] rounded-full ${IMPORTANCE_DOT[ev.importance]}`} />
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2">
                                <span className={"text-mono ba-text-sm truncate " + IMPORTANCE_COLOR[ev.importance]}>
                                  {ev.title}
                                </span>
                                {deletableEvent?.(ev) && onDeleteEvent && (
                                  <button
                                    onClick={() => {
                                      if (window.confirm(`Delete event "${ev.title}"? This cannot be undone.`)) onDeleteEvent(ev.id);
                                    }}
                                    aria-label={`Delete event: ${ev.title}`}
                                    title="delete this event"
                                    className="ml-auto shrink-0 rounded p-0.5 text-fg-dim opacity-0 transition-opacity duration-150 hover:text-destructive focus-visible:opacity-100 group-hover:opacity-100"
                                  >
                                    <Trash2 className="h-3 w-3" />
                                  </button>
                                )}
                              </div>
                              <div className="mt-0.5 flex items-center gap-2 text-mono ba-text-2xs text-fg-dim">
                                <span>{time}</span>
                                <Chip tone={
                                  ev.actor === "analyst" ? "primary" :
                                  ev.actor === "automation" ? "accent" :
                                  ev.actor === "integration" ? "info" : "default"
                                }>{ACTOR_LABEL[ev.actor]}</Chip>
                                {onOriginFilter ? (
                                  <button
                                    onClick={() => onOriginFilter(ev.origin)}
                                    className="rounded border border-transparent px-1 py-0.5 text-mono ba-text-3xs text-fg-dim hover:border-border hover:text-foreground transition-colors duration-150"
                                  >
                                    {ev.origin}
                                  </button>
                                ) : (
                                  <span className="rounded bg-surface-1 px-1 py-0.5">{ev.origin}</span>
                                )}
                              </div>
                            </div>
                          </div>
                          {(hasDetail || hasReferences) && (
                            <>
                              {hasDetail && (
                                <div className="ml-[22px] mt-1">
                                  <p className={"text-mono ba-text-sm text-muted-foreground/80 " + (expanded ? "" : "line-clamp-2")}>
                                    {ev.detail}
                                  </p>
                                  {ev.detail.length > 120 && (
                                    <button
                                      onClick={() => setExpandedId(expanded ? null : ev.id)}
                                      className="mt-0.5 inline-flex items-center gap-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-foreground transition-colors duration-150"
                                    >
                                      <ChevronDown className={"h-2.5 w-2.5 transition-transform " + (expanded ? "rotate-180" : "")} />
                                      {expanded ? "collapse" : "expand"}
                                    </button>
                                  )}
                                </div>
                              )}
                              {hasReferences && (
                                <div className="ml-[22px] mt-1.5 flex flex-wrap gap-1">
                                  {ev.references.map((ref, i) => (
                                    <ReferenceChip key={i} ref={ref} onClick={onReferenceClick} />
                                  ))}
                                </div>
                              )}
                              {provenance && (() => {
                                const proj = provenance.get(ev.id);
                                if (!proj) return null;
                                if (proj.edges.length > 0) {
                                  return (
                                    <div className="ml-[22px] mt-1.5 flex flex-col gap-0.5">
                                      {proj.edges.map(e => (
                                        <div key={e.id} className="flex items-baseline gap-2 font-mono ba-text-3xs text-muted-foreground">
                                          <span className="shrink-0 text-fg-dim">{e.relation}</span>
                                          <span className="shrink-0 text-fg-dim">→</span>
                                          <span className="truncate">[{e.to.kind}] {resolveNodeLabel ? resolveNodeLabel(e.to) : e.to.id}</span>
                                        </div>
                                      ))}
                                    </div>
                                  );
                                }
                                return (
                                  <div className="ml-[22px] mt-1.5 font-mono ba-text-3xs text-fg-dim">
                                    no provenance link
                                  </div>
                                );
                              })()}
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })
              ];
            })
        )}
      </div>
    </Panel>
  );
}
