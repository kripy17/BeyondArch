import { createFileRoute, useSearch, useNavigate } from "@tanstack/react-router";
import { useState, useMemo, useEffect, useRef } from "react";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Chip, SendToRow } from "@/components/soc";
import { Empty } from "@/components/output";
import { EntityHeader, KnowledgeBar, EntitySection, EntityMetadata,
  ObservableList, RelationshipList, ActionDock, HeaderAction } from "@/components/entity";
import { useLocker } from "@/lib/locker";
import { useActiveCase, loadCases } from "@/data/case";
import { addEdge } from "@/lib/provenance";
import { isPinnedIn, togglePinned } from "@/lib/pins";


import { notify } from "@/lib/notify";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { StartWorking, RecentEntities, RecentSearches, KbdHints } from "@/components/WorkspaceHome";
import { pushTimelineEvent } from "@/lib/timeline";
import { Search, Bug, Users, Hash, Fingerprint, ShieldAlert,
  Database, ExternalLink, Pin, Target, ArrowRight, Download } from "lucide-react";
import { searchIntel, getEntityById, detectObservableType, discoverRelationships, buildGraphElements, ALL_ENTITIES } from "@/data/intel";
import { addIntelFindingToCase, addIntelObservablesToCase } from "@/data/intel-handoff";
import { logSearchQuery } from "@/lib/search-engine";
import { EnrichmentPanel } from "@/components/intel/EnrichmentPanel";
import { RelationshipGraph } from "@/components/intel/RelationshipGraph";
import { PassiveInfraTable } from "@/components/intel/PassiveInfraTable";
import {
  generatePassiveDnsRecords,
  generateWhoisData,
  generateSslCertData,
  buildStix21Bundle,
  exportStix21Json,
} from "@/lib/intel/threat-intel-engine";
import type { IntelEntity, IntelEntityGroup, Relationship, IntelEntityType } from "@/data/intel";
import { cn } from "@/lib/utils";

type IntelSearch = { q?: string };
export const Route = createFileRoute("/intel")({
  component: IntelHub,
  validateSearch: (s: Record<string, unknown>): IntelSearch => ({
    q: typeof s.q === "string" ? s.q : undefined,
  }),
});

const TYPE_META: Record<IntelEntityType, { label: string; icon: typeof Bug }> = {
  vulnerability: { label: "Vulnerabilities", icon: ShieldAlert },
  "threat-actor": { label: "Threat Actors", icon: Users },
  malware: { label: "Malware", icon: Bug },
  "file-hash": { label: "File Hashes", icon: Hash },
  "tls-fingerprint": { label: "TLS Fingerprints", icon: Fingerprint },
};

const OBSERVABLE_STYLES: Record<string, string> = {
  cve: "border-destructive/40 bg-destructive/10 text-destructive",
  ja3: "border-warning/40 bg-warning/10 text-warning",
  ja4: "border-warning/40 bg-warning/10 text-warning",
  ipv4: "border-info/40 bg-info/10 text-info",
  domain: "border-info/40 bg-info/10 text-info",
  email: "border-info/40 bg-info/10 text-info",
};

function IntelHub() {
  const navigate = useNavigate();
  useEffect(() => {
    navigate({ to: "/parser", replace: true });
  }, [navigate]);
  const { q: initialQ } = useSearch({ from: Route.id });
  const [query, setQuery] = useState(() => initialQ ?? "");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const { activeCase } = useActiveCase();

  const detectedType = useMemo(() => query ? detectObservableType(query) : undefined, [query]);
  const searchResult = useMemo(() => query ? searchIntel(query) : null, [query]);
  const selected = useMemo(() => selectedId ? getEntityById(selectedId) ?? null : null, [selectedId]);
  const relationships = useMemo(() => selected ? discoverRelationships(selected) : [], [selected]);

  const lastLogged = useRef<string | null>(null);
  useEffect(() => {
    if (initialQ?.trim()) { logSearchQuery(initialQ); lastLogged.current = initialQ; }
  }, [initialQ]);

  useEffect(() => {
    if (!query.trim() || query === lastLogged.current) return;
    const t = setTimeout(() => {
      if (searchIntel(query).totalHits > 0) { logSearchQuery(query); lastLogged.current = query; }
    }, 1200);
    return () => clearTimeout(t);
  }, [query]);

  useEffect(() => {
    if (query && searchResult && searchResult.totalHits > 0) {
      pushTimelineEvent({ source: "intel", verb: "searched", detail: query, result: `${searchResult.totalHits} results` });
    }
  }, [query, searchResult]);

  const enrichedRef = useRef<string | null>(null);
  useEffect(() => {
    const q = query.trim();
    if (!q || q === enrichedRef.current || !searchResult || searchResult.totalHits === 0) return;
    const top = searchResult.entityGroups?.[0]?.entities?.[0];
    if (!top) return;
    const iocMatch = loadCases()
      .flatMap((c) => c.iocs ?? [])
      .find((i) => i.value.toLowerCase() === q.toLowerCase());
    if (!iocMatch) return;
    enrichedRef.current = q;
    addEdge({
      relation: "enriched-by",
      from: { kind: "ioc", id: iocMatch.id! },
      to: { kind: "entity", id: top.id },
      source: "/intel",
      confidence: top.score / 100,
      reason: "IOC pivoted to intel lookup",
    });
  }, [query, searchResult]);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        if (selectedId) setSelectedId(null);
        else setQuery("");
      }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [selectedId]);

  return (
    <ErrorBoundary name="Intel">
    <PageShell
      eyebrow="intelligence / hub"
      title="Intel Hub"
      description="Search CVEs, threat actors, malware, file hashes, and TLS fingerprints — unified."
      crumbs={[{ label: "Intelligence" }, { label: "Intel Hub" }]}
    >
      <SectionBar id="IN" label="Intelligence · unified lookup" />
      <div className="mb-2 text-mono ba-text-2xs text-muted-foreground">esc clear/close</div>

      <div className="relative mb-4">
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input
            id="intel-query"
            aria-label="Search intelligence"
            value={query}
            onChange={(e) => { setQuery(e.target.value); setSelectedId(null); }}
            placeholder="Search CVEs, threat actors, malware, hashes, JA3, IPs, domains…"
            className="w-full rounded-lg border border-subtle bg-surface-0 py-2.5 pl-10 pr-14 font-mono text-sm text-foreground outline-none placeholder:text-fg-dim focus:border-primary/50"
          />
          {detectedType && (
            <span className={cn(
              "absolute right-3 top-1/2 -translate-y-1/2 rounded border px-2 py-0.5 text-mono ba-text-3xs",
              OBSERVABLE_STYLES[detectedType] ?? "border-border text-muted-foreground",
            )}>
              {detectedType.toUpperCase()}
            </span>
          )}
        </div>
        {query && searchResult && (
          <div className="mt-1 px-1 text-mono ba-text-2xs text-muted-foreground">
            {searchResult.totalHits > 0
              ? `${searchResult.totalHits} hit${searchResult.totalHits > 1 ? "s" : ""}  · ${searchResult.entityGroups.length} categor${searchResult.entityGroups.length > 1 ? "ies" : "y"}`
              : "No matches — try a different search term"}
          </div>
        )}
      </div>

      <EnrichmentPanel query={query} />

      {selected ? (
        <IntelEntityDetail entity={selected} relationships={relationships} activeCase={activeCase} onBack={() => setSelectedId(null)} />
      ) : searchResult && searchResult.totalHits > 0 ? (
        <IntelResults groups={searchResult.entityGroups} onSelect={setSelectedId} />
      ) : query ? (
        <Empty icon={Search} title="No results" hint="Try a different search term — CVE IDs, actor names, hash values, JA3 fingerprints, IPs, and domains all work." />
      ) : (
        <div className="space-y-6">
          <StartWorking
            icon={Search}
            label="Search an observable"
            desc="IP, domain, hash, CVE, malware, or JA3 — paste it here or press Ctrl+K."
            hint="/intel"
            onClick={() => document.getElementById("intel-query")?.focus()}
          />
          <EntitySection title="Suggested lookups" icon={Search}>
            <div className="flex flex-wrap gap-1.5">
              {["CVE-2024-3400", "APT28", "185.220.101.4", "avsvmcloud.com", "Lazarus Group", "teardrop-stage.net", "lumma stealer"].map((q) => (
                <button
                  key={q}
                  onClick={() => navigate({ to: "/intel", search: { q } })}
                  className="rounded border border-subtle bg-surface-1 px-2 py-1 font-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-primary"
                >
                  {q}
                </button>
              ))}
            </div>
          </EntitySection>
          <RecentEntities label="Recent Entities" limit={4} onPick={(q) => navigate({ to: "/intel", search: { q } })} />
          <RecentSearches label="Recent Searches" limit={5} onPick={(q) => navigate({ to: "/intel", search: { q } })} />
        </div>
      )}
    </PageShell>
    </ErrorBoundary>
  );
}

function IntelResults({ groups, onSelect }: { groups: IntelEntityGroup[]; onSelect: (id: string) => void }) {
  return (
    <div className="space-y-4">
      {groups.map((group) => {
        const Icon = TYPE_META[group.entityType]?.icon ?? Bug;
        return (
          <div key={group.entityType}>
            <div className="mb-2 flex items-center gap-2 px-1">
              <Icon className="h-3.5 w-3.5 text-primary" />
              <span className="text-mono ba-text-2xs font-semibold text-fg-dim">{group.label}</span>
              <span className="rounded border border-subtle bg-surface-1 px-1.5 py-px text-mono ba-text-3xs text-fg-dim">{group.count}</span>
            </div>
            <div className="space-y-1.5">
              {group.entities.map((e) => (
                <button
                  key={e.id}
                  onClick={() => onSelect(e.id)}
                  className="w-full rounded-md border border-subtle bg-surface-1 p-3 text-left transition-colors duration-150 hover:border-primary/30 hover:bg-surface-2"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="text-mono text-sm font-bold text-foreground">{e.title}</div>
                      <div className="mt-0.5 line-clamp-2 text-mono ba-text-2xs text-muted-foreground">{e.summary}</div>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <Chip tone={e.confidence === "high" ? "success" : e.confidence === "medium" ? "warning" : "default"}>{e.confidence}</Chip>
                      <span className="rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-mono ba-text-2xs font-bold text-primary">{e.score}</span>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function IntelEntityDetail({ entity, relationships, activeCase, onBack }: { entity: IntelEntity; relationships: Relationship[]; activeCase: { id: string; title: string } | null; onBack: () => void }) {
  const navigate = useNavigate();
  const locker = useLocker();
  const [findingCreated, setFindingCreated] = useState(false);
  const [iocsAttached, setIocsAttached] = useState(false);
  const [entityPinned, setEntityPinned] = useState(() => isPinnedIn("entity", entity.id));
  const overview = useMemo(() => buildOverview(entity), [entity]);

  const primaryObs = entity.observables[0]?.value || (entity.type === "vulnerability" ? entity.title : undefined);
  const passiveDns = useMemo(() => primaryObs ? generatePassiveDnsRecords(primaryObs) : [], [primaryObs]);
  const whoisData = useMemo(() => primaryObs && primaryObs.includes(".") && !primaryObs.replace(/\./g, "").match(/^\d+$/) ? generateWhoisData(primaryObs) : null, [primaryObs]);
  const sslCertData = useMemo(() => primaryObs && (primaryObs.includes(".") || primaryObs.startsWith("http")) ? generateSslCertData(primaryObs) : null, [primaryObs]);
  const stixBundle = useMemo(() => buildStix21Bundle(entity), [entity]);

  function handleExportStix() {
    const filename = `stix-${entity.title.toLowerCase().replace(/[^a-z0-9]/g, "-")}.json`;
    exportStix21Json(stixBundle, filename);
    notify.success("STIX 2.1 bundle downloaded");
  }

  function toggleEntityPin() {
    setEntityPinned(togglePinned("entity", entity.id));
  }

  useEffect(() => {
    pushTimelineEvent({ source: "intel", verb: "viewed", detail: `Viewed entity: ${entity.title}`, target: entity.id });
  }, [entity.id, entity.title]);

  function handleExport() {
    const lines = [
      `# ${entity.title}`,
      `**Type:** ${entity.type}  **Score:** ${entity.score}/100  **Confidence:** ${entity.confidence}`,
      "",
      entity.summary,
      "",
      "## Overview",
      ...overview.map((o) => `- **${o.label}:** ${o.value}`),
      "",
      entity.tags.length > 0 ? "## Tags\n" + entity.tags.map((t) => `- ${t}`).join("\n") : "",
      entity.observables.length > 0 ? "\n## Observables\n" + entity.observables.map((o) => `- \`${o.value}\` (${o.type})`).join("\n") : "",
      relationships.length > 0 ? "\n## Relationships\n" + relationships.map((r) => `- ${r.relationshipType}: ${r.reason} [${r.confidence}]`).join("\n") : "",
    ].filter(Boolean).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([lines], { type: "text/markdown" }));
    a.download = `intel-${entity.id}.md`;
    a.click();
  }

  /** Relationship explorer: 2-hop chains from this entity (entity → relation → target → ioc). */
  const chains = useMemo(() => {
    const direct = discoverRelationships(entity);
    const out: { entity: string; rel: string; target: string; targetType: IntelEntityType; ioc: string }[] = [];
    for (const r of direct) {
      const target = ALL_ENTITIES.find((e) => e.id === r.targetId);
      if (!target) continue;
      const ioc = target.observables[0]?.value ?? "";
      out.push({ entity: entity.title, rel: r.relationshipType.replace(/-/g, " "), target: target.title, targetType: target.type, ioc });
      const hop2 = discoverRelationships(target).slice(0, 2);
      for (const r2 of hop2) {
        const t2 = ALL_ENTITIES.find((e) => e.id === r2.targetId);
        if (!t2) continue;
        out.push({ entity: target.title, rel: r2.relationshipType.replace(/-/g, " "), target: t2.title, targetType: t2.type, ioc: t2.observables[0]?.value ?? "" });
      }
    }
    return out;
  }, [entity]);

  const mitreCount = (entity as any).techniques?.length ?? 0;

  /** IOC pages: seen-in counts per observable across local cases. */
  const seenIn = useMemo(() => {
    const cases = loadCases();
    const map = new Map<string, { count: number; cases: string[] }>();
    for (const o of entity.observables) {
      const value = o.value.toLowerCase();
      const hits: string[] = [];
      for (const c of cases) {
        const match = (c.iocs ?? []).some((i) => String(i.value ?? "").toLowerCase() === value);
        if (match) hits.push(c.title);
      }
      map.set(o.value, { count: hits.length, cases: hits });
    }
    return map;
  }, [entity.observables]);

  const graphElements = useMemo(() => buildGraphElements(entity, relationships), [entity, relationships]);

  return (
    <div className="space-y-4">
      <EntityHeader
        variant="intel"
        entity={entity}
        onBack={onBack}
        backLabel="back to results"
        onExport={handleExport}
        onAddToLocker={() => locker.add({ value: entity.title, type: "text", source: "/intel" })}
        actions={
          <div className="flex items-center gap-1.5">
            <HeaderAction
              tone="default"
              icon={<Download className="h-3 w-3" />}
              onClick={handleExportStix}
            >
              STIX 2.1
            </HeaderAction>
            <HeaderAction
              tone={entityPinned ? "primary" : "default"}
              icon={<Pin className={"h-3 w-3" + (entityPinned ? " fill-current" : "")} />}
              onClick={toggleEntityPin}
            >
              {entityPinned ? "pinned" : "pin"}
            </HeaderAction>
          </div>
        }
      />

      {entity.type === "threat-actor" && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3">
          <div className="flex items-center gap-2.5">
            <Target className="h-5 w-5 text-amber-400 shrink-0" />
            <div>
              <div className="font-mono text-xs font-bold text-amber-300">
                Adversary Dossier & MITRE Heatmap Available
              </div>
              <div className="font-mono text-[11px] text-muted-foreground">
                Track full intelligence profile, active campaigns, and tactic coverage for {entity.title} in the Threat Actors workspace.
              </div>
            </div>
          </div>
          <button
            onClick={() => navigate({ to: "/threat-actors", search: { actor: entity.title } })}
            className="inline-flex items-center gap-1 rounded border border-amber-500/50 bg-amber-500/20 px-3 py-1 font-mono text-xs font-semibold text-amber-300 transition-colors hover:bg-amber-500/30"
          >
            Open Full Dossier <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      <KnowledgeBar
        entity={entity}
        relationshipCount={relationships.length}
        activeCase={activeCase}
        mitre={mitreCount}
      />

      <EntitySection title="Overview" icon={TYPE_META[entity.type]?.icon as any} meta={`${overview.length} fields`}>
        <EntityMetadata fields={overview} entityType={entity.type} />
      </EntitySection>

      {entity.observables.length > 0 && (
        <EntitySection title="Observables" icon={Database} meta={`${entity.observables.length} entries`}>
          <ObservableList observables={entity.observables} />
        </EntitySection>
      )}

      {entity.observables.length > 0 && (
        <EntitySection title="IOC detail · seen in" icon={Database} meta="case coverage">
          <div className="space-y-1.5">
            {entity.observables.map((o) => {
              const hit = seenIn.get(o.value);
              return (
                <div key={o.id} className="flex items-center justify-between gap-2 rounded border border-subtle bg-surface-1 px-3 py-1.5">
                  <div className="min-w-0">
                    <div className="truncate font-mono ba-text-xs text-foreground">{o.value}</div>
                    <div className="text-mono ba-text-2xs text-muted-foreground">
                      {o.type} · source {o.source || "internal"}{o.timestamp ? ` · ${new Date(o.timestamp).toLocaleDateString()}` : ""} · confidence {entity.confidence}
                    </div>
                  </div>
                  <div title={hit?.cases.join(", ") || "not seen in any local case"}>
                    <Chip tone={hit && hit.count > 0 ? "success" : "default"}>
                      {hit && hit.count > 0 ? `${hit.count} case${hit.count === 1 ? "" : "s"}` : "unseen"}
                    </Chip>
                  </div>
                </div>
              );
            })}
          </div>
        </EntitySection>
      )}

      {primaryObs && (
        <PassiveInfraTable
          indicator={primaryObs}
          indicatorType={entity.observables[0]?.type || "domain"}
          passiveDns={passiveDns}
          whois={whoisData}
          sslCert={sslCertData}
        />
      )}

      {relationships.length > 0 && (
        <EntitySection title="Relationships & Knowledge Graph" icon={ExternalLink} meta={`${relationships.length} connections`}>
          <RelationshipGraph
            nodes={graphElements.nodes}
            links={graphElements.links}
            onSelectNode={(id) => {
              const target = ALL_ENTITIES.find((e) => e.id === id);
              if (target) {
                if (target.type === "threat-actor") {
                  navigate({ to: "/threat-actors", search: { actor: target.title } });
                } else {
                  navigate({ to: "/intel", search: { q: target.title } });
                }
              }
            }}
            className="mb-3"
          />
          <RelationshipList relationships={relationships} />
        </EntitySection>
      )}

      {chains.length > 0 && (
        <EntitySection title="Relationship explorer" icon={ExternalLink} meta={`${chains.length} chain step(s)`}>
          <div className="space-y-1.5">
            {chains.slice(0, 12).map((c, i) => (
              <div key={i} className="flex flex-wrap items-center gap-1.5 rounded border border-subtle bg-surface-1 px-3 py-1.5 font-mono ba-text-xs">
                <span className="text-foreground">{c.entity}</span>
                <span className="text-primary/70">—{c.rel}→</span>
                <span className="text-foreground">{c.target}</span>
                {c.ioc && (
                  <>
                    <span className="text-primary/70">{">"} ioc</span>
                    <span className="truncate text-fg-dim max-w-[200px]" title={c.ioc}>{c.ioc}</span>
                  </>
                )}
              </div>
            ))}
          </div>
        </EntitySection>
      )}

      <ActionDock
        activeCase={activeCase}
        findingCreated={findingCreated}
        iocsAttached={iocsAttached}
        observableCount={entity.observables.length}
        onCreateFinding={() => {
          if (activeCase && addIntelFindingToCase(activeCase.id, entity)) {
            setFindingCreated(true);
            pushTimelineEvent({ source: "intel", verb: "created", detail: `Created finding from ${entity.title} in ${activeCase.title}`, target: activeCase.id });
          } else {
            notify.error("Failed to add finding");
          }
        }}
        onAttachIocs={() => {
          if (activeCase && addIntelObservablesToCase(activeCase.id, entity)) {
            setIocsAttached(true);
            pushTimelineEvent({ source: "intel", verb: "created", detail: `Attached ${entity.observables.length} IOC(s) from ${entity.title} to ${activeCase.title}`, target: activeCase.id });
          } else {
            notify.error("Failed to attach IOCs");
          }
        }}
        onAddToLocker={() => locker.add({ value: entity.title, type: "text", source: "/intel" })}
        onExport={handleExport}
      />

      <SendToRow targets={[
        { label: "Detection", to: "/detection", icon: ShieldAlert },
      ]} />
    </div>
  );
}

function buildOverview(entity: IntelEntity): { label: string; value: string }[] {
  const f: { label: string; value: string }[] = [];
  f.push({ label: "Type", value: entity.type.replace("-", " ") });
  f.push({ label: "Score", value: `${entity.score}/100` });
  f.push({ label: "Confidence", value: entity.confidence });
  f.push({ label: "Tags", value: entity.tags.join(", ") });
  if (entity.lastSeen) f.push({ label: "Last Seen", value: entity.lastSeen });

  switch (entity.type) {
    case "vulnerability": {
      const v = entity as any;
      f.push({ label: "CVSS", value: v.cvss.toFixed(1) });
      f.push({ label: "EPSS", value: `${(v.epss * 100).toFixed(0)}%` });
      f.push({ label: "KEV", value: v.kev ? "Yes" : "No" });
      f.push({ label: "Published", value: v.published });
      f.push({ label: "Vendor", value: v.vendor });
      f.push({ label: "Affected", value: v.affected });
      f.push({ label: "Exploits", value: [v.exploits.metasploit && "MSF", v.exploits.nuclei && "Nuclei", v.exploits.exploitDb && "EDB"].filter(Boolean).join(", ") || "None" });
      break;
    }
    case "threat-actor": {
      const a = entity as any;
      f.push({ label: "Origin", value: a.origin });
      f.push({ label: "Motivation", value: a.motivation });
      f.push({ label: "First Seen", value: a.firstSeen });
      f.push({ label: "Aliases", value: a.aliases.join(", ") });
      f.push({ label: "Campaigns", value: (a.campaigns ?? []).join(", ") });
      f.push({ label: "Tools", value: a.tools.join(", ") });
      f.push({ label: "Targets", value: a.targets.join(", ") });
      f.push({ label: "Techniques", value: a.techniques.join(", ") });
      break;
    }
    case "malware": {
      const m = entity as any;
      f.push({ label: "Category", value: m.category });
      f.push({ label: "Platforms", value: m.platforms.join(", ") });
      f.push({ label: "First Seen", value: m.firstSeen });
      if (m.aliases?.length) f.push({ label: "Aliases", value: m.aliases.join(", ") });
      if (m.capabilities?.length) f.push({ label: "Capabilities", value: m.capabilities.join(", ") });
      break;
    }
    case "file-hash": {
      const h = entity as any;
      f.push({ label: "Hash Type", value: h.hashType });
      f.push({ label: "Hash", value: h.hash.length > 32 ? h.hash.slice(0, 32) + "…" : h.hash });
      f.push({ label: "Verdict", value: h.verdict });
      f.push({ label: "AV Detection", value: `${h.avDetections}/${h.avTotal}` });
      f.push({ label: "Malware", value: h.malware });
      f.push({ label: "First Seen", value: h.firstSeen });
      break;
    }
    case "tls-fingerprint": {
      const t = entity as any;
      f.push({ label: "Hash Type", value: t.hashType });
      f.push({ label: "Hash", value: t.hash.length > 32 ? t.hash.slice(0, 32) + "…" : t.hash });
      f.push({ label: "Malware", value: t.malware });
      f.push({ label: "First Seen", value: t.firstSeen });
      if (t.lastSeen) f.push({ label: "Last Seen", value: t.lastSeen });
      break;
    }
  }
  return f;
}
