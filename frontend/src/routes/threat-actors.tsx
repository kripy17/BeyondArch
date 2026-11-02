import { createFileRoute, useSearch, useNavigate } from "@tanstack/react-router";
import { useState, useMemo, useEffect } from "react";
import { PageShell } from "@/components/PageShell";
import { SectionBar } from "@/components/soc";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import {
  Users, Search, ShieldAlert, Crosshair, Target, ExternalLink,
  ChevronRight, ArrowUpDown, Filter, BookmarkPlus, Zap
} from "lucide-react";
import { getThreatActors, type ThreatActorEntity } from "@/data/intel";
import { ThreatActorDossier } from "@/components/intel/ThreatActorDossier";
import { useActiveCase } from "@/data/case";
import { addIntelFindingToCase } from "@/data/intel-handoff";
import { notify } from "@/lib/notify";
import { cn } from "@/lib/utils";

type ThreatActorsSearch = {
  actor?: string;
  origin?: string;
  motivation?: string;
  q?: string;
};

export const Route = createFileRoute("/threat-actors")({
  component: ThreatActorsPage,
  validateSearch: (s: Record<string, unknown>): ThreatActorsSearch => ({
    actor: typeof s.actor === "string" ? s.actor : undefined,
    origin: typeof s.origin === "string" ? s.origin : undefined,
    motivation: typeof s.motivation === "string" ? s.motivation : undefined,
    q: typeof s.q === "string" ? s.q : undefined,
  }),
});

const ORIGINS = ["All", "Russia", "China", "North Korea", "Iran", "Western", "Eastern Europe"];
const MOTIVATIONS = ["All", "Espionage", "Financial", "Sabotage", "Destruction"];

const ORIGIN_FLAGS: Record<string, string> = {
  Russia: "🇷🇺",
  China: "🇨🇳",
  "North Korea": "🇰🇵",
  Iran: "🇮🇷",
  Western: "🌐",
  "Eastern Europe": "🇪🇺",
};

function ThreatActorsPage() {
  const navigate = useNavigate();
  useEffect(() => {
    navigate({ to: "/mitre", replace: true });
  }, [navigate]);
  const searchParams = useSearch({ from: Route.id });
  const { activeCase } = useActiveCase();

  const allActors = useMemo(() => getThreatActors(), []);

  const [searchQuery, setSearchQuery] = useState(() => searchParams.q || "");
  const [selectedOrigin, setSelectedOrigin] = useState<string>(() => searchParams.origin || "All");
  const [selectedMotivation, setSelectedMotivation] = useState<string>(() => searchParams.motivation || "All");
  const [sortBy, setSortBy] = useState<"score" | "name" | "recent">("score");

  // Determine currently active actor if passed via URL or selected
  const activeActor = useMemo(() => {
    if (!searchParams.actor) return null;
    const q = searchParams.actor.trim().toLowerCase();
    return (
      allActors.find(
        (a) =>
          a.id.toLowerCase() === q ||
          a.title.toLowerCase() === q ||
          a.aliases.some((al) => al.toLowerCase() === q)
      ) || null
    );
  }, [searchParams.actor, allActors]);

  // Sync state if search query parameter changes
  useEffect(() => {
    if (searchParams.q !== undefined && searchParams.q !== searchQuery) {
      setSearchQuery(searchParams.q);
    }
  }, [searchParams.q]);

  // Filtered & sorted actors
  const filteredActors = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return allActors
      .filter((a) => {
        if (selectedOrigin !== "All" && a.origin !== selectedOrigin) return false;
        if (selectedMotivation !== "All" && !a.motivation.includes(selectedMotivation)) return false;
        if (!q) return true;
        return (
          a.title.toLowerCase().includes(q) ||
          a.aliases.some((al) => al.toLowerCase().includes(q)) ||
          a.summary.toLowerCase().includes(q) ||
          a.tools.some((t) => t.toLowerCase().includes(q)) ||
          a.campaigns.some((c) => c.toLowerCase().includes(q)) ||
          a.targets.some((tg) => tg.toLowerCase().includes(q)) ||
          a.origin.toLowerCase().includes(q) ||
          (a.targetedCves && a.targetedCves.some((cve) => cve.toLowerCase().includes(q))) ||
          a.observables.some((obs) => obs.value.toLowerCase().includes(q))
        );
      })
      .sort((a, b) => {
        if (sortBy === "score") return b.score - a.score;
        if (sortBy === "name") return a.title.localeCompare(b.title);
        if (sortBy === "recent") return (b.lastSeen || "").localeCompare(a.lastSeen || "");
        return 0;
      });
  }, [allActors, searchQuery, selectedOrigin, selectedMotivation, sortBy]);

  // Global telemetry calculations
  const stats = useMemo(() => {
    const totalActors = allActors.length;
    const campaignsCount = new Set(allActors.flatMap((a) => a.campaigns)).size;
    const criticalRatingCount = allActors.filter((a) => a.score >= 90).length;
    const totalTechniquesTracked = new Set(allActors.flatMap((a) => a.techniques)).size;
    return { totalActors, campaignsCount, criticalRatingCount, totalTechniquesTracked };
  }, [allActors]);

  function selectActor(actor: ThreatActorEntity | null) {
    navigate({
      to: "/threat-actors",
      search: {
        ...searchParams,
        actor: actor ? actor.title : undefined,
      },
    });
  }

  function handleQuickAttach(actor: ThreatActorEntity, e: React.MouseEvent) {
    e.stopPropagation();
    if (!activeCase) {
      notify.error("No active case to attach to");
      return;
    }
    const note = `Threat Actor: ${actor.title} (${actor.aliases.join(", ")}). Origin: ${actor.origin}. Motivation: ${actor.motivation}.`;
    if (addIntelFindingToCase(activeCase.id, actor, note)) {
      notify.success(`Added ${actor.title} to case ${activeCase.id}`);
    }
  }

  return (
    <ErrorBoundary name="ThreatActors">
      <PageShell
        eyebrow="intelligence / adversaries"
        title="Threat Actors & Intrusion Sets"
        description="Comprehensive CTI dossiers, active campaign tracking, adversary toolkits, and MITRE ATT&CK mappings."
        crumbs={[{ label: "Intelligence" }, { label: "Threat Actors" }]}
      >
        <SectionBar id="TA" label="Adversary Telemetry · Threat Landscape" />

        {/* Global Landscape Metrics Bar */}
        <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="rounded-lg border border-subtle bg-surface-1/60 p-3">
            <div className="flex items-center gap-1.5 font-mono ba-text-3xs font-semibold uppercase text-muted-foreground">
              <Users className="h-3.5 w-3.5 text-primary" /> Tracked Adversaries
            </div>
            <div className="mt-1 font-mono text-xl font-bold text-foreground">
              {stats.totalActors} <span className="ba-text-2xs font-normal text-muted-foreground">threat groups</span>
            </div>
          </div>

          <div className="rounded-lg border border-subtle bg-surface-1/60 p-3">
            <div className="flex items-center gap-1.5 font-mono ba-text-3xs font-semibold uppercase text-muted-foreground">
              <Target className="h-3.5 w-3.5 text-rose-400" /> Active Campaigns
            </div>
            <div className="mt-1 font-mono text-xl font-bold text-foreground">
              {stats.campaignsCount} <span className="ba-text-2xs font-normal text-muted-foreground">operations</span>
            </div>
          </div>

          <div className="rounded-lg border border-subtle bg-surface-1/60 p-3">
            <div className="flex items-center gap-1.5 font-mono ba-text-3xs font-semibold uppercase text-muted-foreground">
              <ShieldAlert className="h-3.5 w-3.5 text-amber-400" /> Critical Severity (90+)
            </div>
            <div className="mt-1 font-mono text-xl font-bold text-foreground">
              {stats.criticalRatingCount} <span className="ba-text-2xs font-normal text-muted-foreground">tier-1 actors</span>
            </div>
          </div>

          <div className="rounded-lg border border-subtle bg-surface-1/60 p-3">
            <div className="flex items-center gap-1.5 font-mono ba-text-3xs font-semibold uppercase text-muted-foreground">
              <Zap className="h-3.5 w-3.5 text-purple-400" /> MITRE Techniques
            </div>
            <div className="mt-1 font-mono text-xl font-bold text-foreground">
              {stats.totalTechniquesTracked} <span className="ba-text-2xs font-normal text-muted-foreground">mapped TTPs</span>
            </div>
          </div>
        </div>

        {/* Selected Dossier View OR Catalog Grid */}
        {activeActor ? (
          <ThreatActorDossier actor={activeActor} onBack={() => selectActor(null)} />
        ) : (
          <div className="space-y-4">
            {/* Search & Filter Strip */}
            <div className="space-y-3 rounded-lg border border-subtle bg-surface-1/40 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative min-w-[260px] flex-1">
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <input
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search by actor name, alias (e.g. Fancy Bear), tool, campaign, CVE, IOC…"
                    className="w-full rounded-md border border-subtle bg-surface-0 py-2 pl-9 pr-4 font-mono text-sm text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50"
                  />
                  {searchQuery && (
                    <button
                      onClick={() => setSearchQuery("")}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 font-mono ba-text-3xs text-muted-foreground hover:text-foreground"
                    >
                      clear
                    </button>
                  )}
                </div>

                <div className="flex items-center gap-1.5">
                  <ArrowUpDown className="h-3.5 w-3.5 text-muted-foreground" />
                  <select
                    value={sortBy}
                    onChange={(e) => setSortBy(e.target.value as any)}
                    className="rounded border border-subtle bg-surface-0 px-2 py-1.5 font-mono ba-text-xs text-foreground outline-none"
                  >
                    <option value="score">Sort by: Threat Score</option>
                    <option value="name">Sort by: Name (A-Z)</option>
                    <option value="recent">Sort by: Last Active</option>
                  </select>
                </div>
              </div>

              {/* Origin Filter Chips */}
              <div className="flex flex-wrap items-center gap-1.5 border-t border-subtle/60 pt-2">
                <span className="font-mono ba-text-3xs text-muted-foreground mr-1 flex items-center gap-1">
                  <Filter className="h-3 w-3" /> Origin:
                </span>
                {ORIGINS.map((orig) => (
                  <button
                    key={orig}
                    onClick={() => setSelectedOrigin(orig)}
                    className={cn(
                      "rounded border px-2 py-0.5 font-mono ba-text-2xs transition-colors",
                      selectedOrigin === orig
                        ? "border-primary/60 bg-primary/20 text-primary font-semibold"
                        : "border-subtle bg-surface-0 text-muted-foreground hover:text-foreground"
                    )}
                  >
                    {ORIGIN_FLAGS[orig] ? `${ORIGIN_FLAGS[orig]} ` : ""}{orig}
                  </button>
                ))}

                <span className="font-mono ba-text-3xs text-muted-foreground ml-3 mr-1">
                  Motivation:
                </span>
                {MOTIVATIONS.map((mot) => (
                  <button
                    key={mot}
                    onClick={() => setSelectedMotivation(mot)}
                    className={cn(
                      "rounded border px-2 py-0.5 font-mono ba-text-2xs transition-colors",
                      selectedMotivation === mot
                        ? "border-primary/60 bg-primary/20 text-primary font-semibold"
                        : "border-subtle bg-surface-0 text-muted-foreground hover:text-foreground"
                    )}
                  >
                    {mot}
                  </button>
                ))}
              </div>
            </div>

            {/* Results Counter */}
            <div className="flex items-center justify-between px-1 text-mono ba-text-2xs text-muted-foreground">
              <span>Showing {filteredActors.length} of {allActors.length} threat actors</span>
              {activeCase && (
                <span className="text-primary font-medium">
                  Active Case: {activeCase.title}
                </span>
              )}
            </div>

            {/* Actor Catalog Grid */}
            <div className="grid grid-cols-1 gap-3.5 md:grid-cols-2 lg:grid-cols-3">
              {filteredActors.map((actor) => (
                <div
                  key={actor.id}
                  onClick={() => selectActor(actor)}
                  className="group flex flex-col justify-between rounded-lg border border-subtle bg-surface-1/70 p-4 transition-all duration-150 hover:border-primary/50 hover:bg-surface-2 cursor-pointer shadow-sm"
                >
                  <div>
                    {/* Top Row: Title, Flag, Score */}
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5">
                          <span className="text-base" title={actor.origin}>
                            {ORIGIN_FLAGS[actor.origin] || "🏴"}
                          </span>
                          <h3 className="truncate font-mono text-base font-bold text-foreground group-hover:text-primary">
                            {actor.title}
                          </h3>
                        </div>
                        {actor.aliases.length > 0 && (
                          <div className="mt-1 truncate font-mono text-xs text-muted-foreground">
                            aka {actor.aliases.join(", ")}
                          </div>
                        )}
                      </div>

                      <div className="shrink-0 text-right">
                        <span
                          className={cn(
                            "rounded border px-1.5 py-0.5 font-mono text-xs font-bold",
                            actor.score >= 90
                              ? "border-rose-500/40 bg-rose-500/10 text-rose-400"
                              : actor.score >= 80
                              ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
                              : "border-primary/40 bg-primary/10 text-primary"
                          )}
                        >
                          {actor.score}
                        </span>
                      </div>
                    </div>

                    {/* Meta badges: Origin & Motivation */}
                    <div className="mt-2.5 flex flex-wrap items-center gap-1">
                      <span className="rounded border border-subtle bg-surface-0 px-1.5 py-0.5 font-mono ba-text-3xs text-fg-dim">
                        {actor.origin}
                      </span>
                      <span className="rounded border border-subtle bg-surface-0 px-1.5 py-0.5 font-mono ba-text-3xs text-fg-dim">
                        {actor.motivation}
                      </span>
                      <span className="rounded border border-subtle bg-surface-0 px-1.5 py-0.5 font-mono ba-text-3xs text-muted-foreground">
                        Seen: {actor.firstSeen}—{actor.lastSeen || "Now"}
                      </span>
                    </div>

                    {/* Summary */}
                    <p className="mt-2.5 line-clamp-2 font-mono text-xs leading-relaxed text-muted-foreground">
                      {actor.summary}
                    </p>

                    {/* Campaigns */}
                    {actor.campaigns.length > 0 && (
                      <div className="mt-3 flex flex-wrap gap-1">
                        {actor.campaigns.slice(0, 3).map((camp) => (
                          <span
                            key={camp}
                            className="rounded border border-subtle/80 bg-surface-0 px-1.5 py-0.5 font-mono text-[10px] text-foreground"
                          >
                            {camp}
                          </span>
                        ))}
                        {actor.campaigns.length > 3 && (
                          <span className="font-mono text-[10px] text-muted-foreground self-center">
                            +{actor.campaigns.length - 3} more
                          </span>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Bottom Action Footer */}
                  <div className="mt-4 flex items-center justify-between border-t border-subtle/70 pt-2.5">
                    <div className="flex items-center gap-2 text-mono ba-text-3xs text-muted-foreground">
                      <span>{actor.techniques.length} TTPs</span>
                      <span>·</span>
                      <span>{actor.tools.length} Tools</span>
                      {actor.observables.length > 0 && (
                        <>
                          <span>·</span>
                          <span className="text-primary">{actor.observables.length} IOCs</span>
                        </>
                      )}
                    </div>

                    <div className="flex items-center gap-1">
                      {activeCase && (
                        <button
                          onClick={(e) => handleQuickAttach(actor, e)}
                          className="rounded p-1 text-muted-foreground hover:bg-surface-3 hover:text-primary"
                          title="Quick add to active case"
                        >
                          <BookmarkPlus className="h-3.5 w-3.5" />
                        </button>
                      )}
                      <span className="inline-flex items-center gap-0.5 font-mono ba-text-xs font-medium text-primary">
                        Dossier <ChevronRight className="h-3.5 w-3.5" />
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {filteredActors.length === 0 && (
              <div className="rounded-lg border border-dashed border-subtle p-8 text-center">
                <Users className="mx-auto h-8 w-8 text-muted-foreground opacity-50" />
                <div className="mt-2 font-mono text-sm font-semibold text-foreground">
                  No threat actors found matching filters
                </div>
                <div className="mt-1 font-mono ba-text-xs text-muted-foreground">
                  Try adjusting your search query, origin, or motivation filters.
                </div>
              </div>
            )}
          </div>
        )}
      </PageShell>
    </ErrorBoundary>
  );
}
