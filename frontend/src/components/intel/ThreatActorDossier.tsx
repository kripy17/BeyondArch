import { useState, useMemo } from "react";
import { useNavigate } from "@tanstack/react-router";
import {
  Users, ShieldAlert, Globe, Crosshair, Target, Copy, Check,
  ExternalLink, Briefcase, Terminal, FileText, ArrowLeft, Download, BookmarkPlus, Layers
} from "lucide-react";
import type { ThreatActorEntity } from "@/data/intel";
import { ALL_TECHNIQUES } from "@/data/mitre";
import { useActiveCase } from "@/data/case";
import { addIntelFindingToCase, addIntelObservablesToCase } from "@/data/intel-handoff";
import { useLocker } from "@/lib/locker";
import { notify } from "@/lib/notify";
import { defang } from "@/lib/ioc-patterns";
import { cn } from "@/lib/utils";
import { DiamondModelCard } from "./DiamondModelCard";
import { MitreNavigatorMatrix } from "./MitreNavigatorMatrix";
import { CampaignTimeline } from "./CampaignTimeline";
import { PassiveInfraTable } from "./PassiveInfraTable";
import {
  generateDiamondModelForActor,
  generateActorCampaigns,
  buildStix21Bundle,
  exportStix21Json,
  generatePassiveDnsRecords,
  generateWhoisData,
  generateSslCertData,
} from "@/lib/intel/threat-intel-engine";

interface ThreatActorDossierProps {
  actor: ThreatActorEntity;
  onBack?: () => void;
  className?: string;
}

const ORIGIN_FLAGS: Record<string, string> = {
  Russia: "🇷🇺",
  China: "🇨🇳",
  "North Korea": "🇰🇵",
  Iran: "🇮🇷",
  Western: "🌐",
  "Eastern Europe": "🇪🇺",
  Unknown: "🏴",
};

export function ThreatActorDossier({ actor, onBack, className }: ThreatActorDossierProps) {
  const navigate = useNavigate();
  const { activeCase } = useActiveCase();
  const locker = useLocker();

  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);
  const [defangAll, setDefangAll] = useState(false);
  const [findingAdded, setFindingAdded] = useState(false);
  const [iocsAttached, setIocsAttached] = useState(false);

  const diamondModel = useMemo(() => generateDiamondModelForActor(actor), [actor]);
  const campaigns = useMemo(() => generateActorCampaigns(actor), [actor]);
  const stixBundle = useMemo(() => buildStix21Bundle(actor), [actor]);
  const primaryObs = actor.observables[0]?.value;
  const passiveDns = useMemo(() => primaryObs ? generatePassiveDnsRecords(primaryObs) : [], [primaryObs]);
  const whoisData = useMemo(() => primaryObs && primaryObs.includes(".") && !primaryObs.replace(/\./g, "").match(/^\d+$/) ? generateWhoisData(primaryObs) : null, [primaryObs]);
  const sslCertData = useMemo(() => primaryObs ? generateSslCertData(primaryObs) : null, [primaryObs]);

  function handleExportStix() {
    const filename = `stix-${actor.title.toLowerCase().replace(/[^a-z0-9]/g, "-")}.json`;
    exportStix21Json(stixBundle, filename);
    notify.success("STIX 2.1 bundle downloaded");
  }

  // Map actor techniques (e.g. T1566, T1059) to rich names and tactics from ALL_TECHNIQUES
  const mappedTechniques = useMemo(() => {
    return actor.techniques.map((techId) => {
      const match = ALL_TECHNIQUES.find((t) => t.id === techId);
      return {
        id: techId,
        name: match?.name || "Technique " + techId,
        tactic: match?.tactic || "Adversary TTP",
        tacticId: match?.tacticId || "TA0000",
      };
    });
  }, [actor.techniques]);

  // Group techniques by tactic
  const techniquesByTactic = useMemo(() => {
    const map = new Map<string, { id: string; name: string }[]>();
    for (const tech of mappedTechniques) {
      if (!map.has(tech.tactic)) map.set(tech.tactic, []);
      map.get(tech.tactic)!.push({ id: tech.id, name: tech.name });
    }
    return map;
  }, [mappedTechniques]);

  function copyToClipboard(text: string, id: string) {
    navigator.clipboard.writeText(text);
    setCopiedIoc(id);
    setTimeout(() => setCopiedIoc(null), 1500);
    notify.success("Copied to clipboard");
  }

  function handleAddFinding() {
    if (!activeCase) {
      notify.error("No active case selected");
      return;
    }
    const note = `Threat Actor Dossier: ${actor.title} (${actor.aliases.join(", ")}). Origin: ${actor.origin}. Motivation: ${actor.motivation}. Targeted sectors: ${actor.targets.join(", ")}.`;
    if (addIntelFindingToCase(activeCase.id, actor, note)) {
      setFindingAdded(true);
      notify.success(`Added ${actor.title} dossier to Case ${activeCase.id}`);
    }
  }

  function handleAttachIocs() {
    if (!activeCase) {
      notify.error("No active case selected");
      return;
    }
    if (addIntelObservablesToCase(activeCase.id, actor)) {
      setIocsAttached(true);
      notify.success(`Attached ${actor.observables.length} observable(s) to Case ${activeCase.id}`);
    }
  }

  function handleStashToLocker() {
    let count = 0;
    locker.add({ value: `${actor.title} (${actor.aliases.join(", ")})`, type: "text", source: "/threat-actors" });
    count++;
    for (const obs of actor.observables) {
      const type = (["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email", "file", "cve", "ja3", "ua", "text"].includes(obs.type) ? obs.type : "unknown") as any;
      locker.add({ value: obs.value, type, source: `/threat-actors (${actor.title})` });
      count++;
    }
    notify.success(`Stashed ${count} item(s) to Locker`);
  }

  function handleExportDossier() {
    const markdown = [
      `# Threat Actor Dossier: ${actor.title}`,
      `**Aliases:** ${actor.aliases.join(", ")}`,
      `**Origin:** ${actor.origin}  |  **Motivation:** ${actor.motivation}  |  **Threat Score:** ${actor.score}/100`,
      `**First Seen:** ${actor.firstSeen}  |  **Last Seen:** ${actor.lastSeen}`,
      "",
      `## Executive Summary`,
      actor.summary,
      "",
      `## Targeted Industries & Sectors`,
      actor.targets.map((t) => `- ${t}`).join("\n"),
      "",
      `## Active Campaigns & Operations`,
      actor.campaigns.map((c) => `- ${c}`).join("\n"),
      "",
      `## Tooling & Malware Arsenal`,
      actor.tools.map((t) => `- ${t}`).join("\n"),
      "",
      actor.targetedCves?.length
        ? `## Targeted Vulnerabilities (CVEs)\n${actor.targetedCves.map((c) => `- ${c}`).join("\n")}\n`
        : "",
      `## MITRE ATT&CK Techniques`,
      mappedTechniques.map((t) => `- **${t.id}:** ${t.name} (${t.tactic})`).join("\n"),
      "",
      actor.observables.length
        ? `## Observed Infrastructure & IOCs\n${actor.observables.map((o) => `- \`${o.value}\` (${o.type}) - ${o.context || "infrastructure"}`).join("\n")}`
        : "",
    ].filter(Boolean).join("\n");

    const blob = new Blob([markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `dossier-${actor.title.toLowerCase().replace(/\s+/g, "-")}.md`;
    a.click();
    URL.revokeObjectURL(url);
    notify.success("Dossier exported to Markdown");
  }

  return (
    <div className={cn("space-y-4 rounded-lg border border-subtle bg-surface-0/60 p-4", className)}>
      {/* Top Breadcrumb & Navigation */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-subtle pb-3">
        {onBack && (
          <button
            onClick={onBack}
            className="inline-flex items-center gap-1.5 rounded border border-subtle bg-surface-1 px-2.5 py-1 font-mono ba-text-xs text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Back to Adversary Catalog
          </button>
        )}

        <div className="ml-auto flex flex-wrap items-center gap-1.5">
          <button
            onClick={handleExportStix}
            className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1 font-mono ba-text-xs font-semibold text-primary hover:bg-primary/20"
          >
            <Download className="h-3.5 w-3.5" /> Export STIX 2.1
          </button>
          <button
            onClick={handleExportDossier}
            className="inline-flex items-center gap-1.5 rounded border border-subtle bg-surface-1 px-2.5 py-1 font-mono ba-text-xs text-muted-foreground hover:border-primary/40 hover:text-foreground"
          >
            <Download className="h-3.5 w-3.5" /> Export Dossier (MD)
          </button>
          <button
            onClick={handleStashToLocker}
            className="inline-flex items-center gap-1.5 rounded border border-subtle bg-surface-1 px-2.5 py-1 font-mono ba-text-xs text-muted-foreground hover:border-primary/40 hover:text-foreground"
          >
            <BookmarkPlus className="h-3.5 w-3.5" /> Stash to Locker
          </button>
        </div>
      </div>

      {/* Hero Dossier Card */}
      <div className="rounded-lg border border-subtle bg-surface-1/80 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-2xl" title={actor.origin}>
                {ORIGIN_FLAGS[actor.origin] || "🏴"}
              </span>
              <h1 className="font-mono text-xl font-bold tracking-tight text-foreground">
                {actor.title}
              </h1>
              <span className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 font-mono ba-text-2xs font-semibold text-amber-400">
                Threat Score: {actor.score}/100
              </span>
            </div>
            {actor.aliases.length > 0 && (
              <div className="mt-1.5 flex flex-wrap items-center gap-1">
                <span className="font-mono ba-text-3xs text-muted-foreground">Known Aliases:</span>
                {actor.aliases.map((alias) => (
                  <span
                    key={alias}
                    className="rounded border border-subtle bg-surface-2 px-1.5 py-0.5 font-mono ba-text-3xs text-fg-dim"
                  >
                    {alias}
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="rounded border border-subtle bg-surface-0 px-2.5 py-1 text-right font-mono">
              <div className="ba-text-3xs text-muted-foreground uppercase">Origin & Motivation</div>
              <div className="ba-text-xs font-semibold text-foreground">
                {actor.origin} · {actor.motivation}
              </div>
            </div>
            <div className="rounded border border-subtle bg-surface-0 px-2.5 py-1 text-right font-mono">
              <div className="ba-text-3xs text-muted-foreground uppercase">Activity Window</div>
              <div className="ba-text-xs font-semibold text-foreground">
                {actor.firstSeen} — {actor.lastSeen || "Active"}
              </div>
            </div>
          </div>
        </div>

        <p className="mt-3 font-mono text-sm leading-relaxed text-muted-foreground">
          {actor.summary}
        </p>

        {/* Case Action Dock */}
        {activeCase && (
          <div className="mt-4 flex flex-wrap items-center gap-2 rounded border border-primary/30 bg-primary/5 p-2.5">
            <Briefcase className="h-4 w-4 text-primary shrink-0" />
            <span className="font-mono ba-text-xs text-foreground font-medium">
              Active Case: <span className="text-primary">{activeCase.title}</span>
            </span>
            <div className="ml-auto flex items-center gap-2">
              <button
                onClick={handleAddFinding}
                disabled={findingAdded}
                className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/20 px-2 py-1 font-mono ba-text-2xs font-semibold text-primary hover:bg-primary/30 disabled:opacity-50"
              >
                {findingAdded ? <Check className="h-3 w-3" /> : <BookmarkPlus className="h-3 w-3" />}
                {findingAdded ? "Finding Added" : "Add Actor Finding"}
              </button>
              {actor.observables.length > 0 && (
                <button
                  onClick={handleAttachIocs}
                  disabled={iocsAttached}
                  className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-1 font-mono ba-text-2xs text-muted-foreground hover:text-foreground disabled:opacity-50"
                >
                  {iocsAttached ? <Check className="h-3 w-3" /> : <Crosshair className="h-3 w-3" />}
                  {iocsAttached ? "IOCs Attached" : `Attach ${actor.observables.length} IOC(s)`}
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* The Diamond Model of Intrusion Analysis */}
      <DiamondModelCard diamond={diamondModel} stixBundle={stixBundle} />

      {/* Middle Grid: Campaigns, Targets, Arsenal */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {/* Active Campaigns */}
        <div className="rounded-lg border border-subtle bg-surface-1/40 p-3">
          <div className="flex items-center gap-1.5 border-b border-subtle pb-2 text-mono ba-text-xs font-semibold uppercase text-foreground">
            <Target className="h-3.5 w-3.5 text-primary" /> Known Campaigns ({actor.campaigns.length})
          </div>
          <ul className="mt-2 space-y-1.5">
            {actor.campaigns.map((camp) => (
              <li
                key={camp}
                className="rounded border border-subtle/80 bg-surface-1 px-2.5 py-1.5 font-mono ba-text-xs text-foreground"
              >
                {camp}
              </li>
            ))}
          </ul>
        </div>

        {/* Target Sectors & Verticals */}
        <div className="rounded-lg border border-subtle bg-surface-1/40 p-3">
          <div className="flex items-center gap-1.5 border-b border-subtle pb-2 text-mono ba-text-xs font-semibold uppercase text-foreground">
            <Crosshair className="h-3.5 w-3.5 text-rose-400" /> Target Sectors ({actor.targets.length})
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {actor.targets.map((target) => (
              <span
                key={target}
                className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 font-mono ba-text-2xs font-medium text-rose-300"
              >
                {target}
              </span>
            ))}
          </div>
        </div>

        {/* Tools & Malware Arsenal */}
        <div className="rounded-lg border border-subtle bg-surface-1/40 p-3">
          <div className="flex items-center gap-1.5 border-b border-subtle pb-2 text-mono ba-text-xs font-semibold uppercase text-foreground">
            <Terminal className="h-3.5 w-3.5 text-purple-400" /> Malware & Tools ({actor.tools.length})
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {actor.tools.map((tool) => (
              <button
                key={tool}
                onClick={() => navigate({ to: "/intel", search: { q: tool } })}
                className="group inline-flex items-center gap-1 rounded border border-purple-500/30 bg-purple-500/10 px-2 py-1 font-mono ba-text-2xs font-medium text-purple-300 transition-colors hover:border-purple-400 hover:bg-purple-500/20"
                title={`Pivot to ${tool} in Intel Hub`}
              >
                {tool}
                <ExternalLink className="h-2.5 w-2.5 opacity-60 group-hover:opacity-100" />
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Adversary Campaign Timeline */}
      {campaigns.length > 0 && (
        <CampaignTimeline campaigns={campaigns} actorTitle={actor.title} />
      )}

      {/* Targeted CVEs Section */}
      {actor.targetedCves && actor.targetedCves.length > 0 && (
        <div className="rounded-lg border border-subtle bg-surface-1/40 p-3">
          <div className="flex items-center justify-between border-b border-subtle pb-2">
            <div className="flex items-center gap-1.5 text-mono ba-text-xs font-semibold uppercase text-foreground">
              <ShieldAlert className="h-3.5 w-3.5 text-rose-400" /> Targeted Vulnerabilities ({actor.targetedCves.length})
            </div>
            <span className="text-mono ba-text-3xs text-muted-foreground">Click to pivot to CVE details</span>
          </div>
          <div className="mt-2.5 flex flex-wrap gap-2">
            {actor.targetedCves.map((cve) => (
              <button
                key={cve}
                onClick={() => navigate({ to: "/intel", search: { q: cve } })}
                className="group flex items-center gap-2 rounded border border-rose-500/40 bg-surface-0 px-3 py-1.5 font-mono text-xs transition-colors hover:border-rose-400 hover:bg-rose-950/20"
              >
                <span className="font-bold text-rose-400">{cve}</span>
                <span className="text-fg-dim text-[10px]">KEV / Weaponized</span>
                <ExternalLink className="h-3 w-3 text-muted-foreground group-hover:text-foreground" />
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Observed Infrastructure & Indicators of Compromise */}
      {actor.observables.length > 0 && (
        <div className="rounded-lg border border-subtle bg-surface-1/40 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-subtle pb-2">
            <div className="flex items-center gap-1.5 text-mono ba-text-xs font-semibold uppercase text-foreground">
              <Globe className="h-3.5 w-3.5 text-primary" /> Observed Infrastructure & IOCs ({actor.observables.length})
            </div>
            <div className="flex items-center gap-3">
              <label className="flex cursor-pointer items-center gap-1.5 font-mono ba-text-3xs text-muted-foreground">
                <input
                  type="checkbox"
                  checked={defangAll}
                  onChange={(e) => setDefangAll(e.target.checked)}
                  className="accent-[var(--primary)]"
                />
                Defang observables
              </label>
              <button
                onClick={() => {
                  const allValues = actor.observables
                    .map((o) => (defangAll ? defang(o.value) : o.value))
                    .join("\n");
                  copyToClipboard(allValues, "all-iocs");
                }}
                className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-1 px-2 py-0.5 font-mono ba-text-3xs text-muted-foreground hover:text-foreground"
              >
                {copiedIoc === "all-iocs" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                Copy All IOCs
              </button>
            </div>
          </div>

          <div className="mt-2 space-y-1.5">
            {actor.observables.map((obs) => {
              const displayVal = defangAll ? defang(obs.value) : obs.value;
              return (
                <div
                  key={obs.id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded border border-subtle bg-surface-0 px-3 py-2 font-mono text-xs"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="rounded border border-subtle bg-surface-2 px-1.5 py-px text-[10px] uppercase font-bold text-fg-dim">
                        {obs.type}
                      </span>
                      <span className="truncate font-mono font-medium text-foreground select-all">
                        {displayVal}
                      </span>
                    </div>
                    {obs.context && (
                      <div className="mt-0.5 text-mono text-[11px] text-muted-foreground">
                        {obs.context}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    <button
                      onClick={() => copyToClipboard(displayVal, obs.id)}
                      className="rounded p-1 text-muted-foreground hover:bg-surface-2 hover:text-foreground"
                      title="Copy indicator"
                    >
                      {copiedIoc === obs.id ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                    <button
                      onClick={() => navigate({ to: "/intel", search: { q: obs.value } })}
                      className="rounded p-1 text-muted-foreground hover:bg-surface-2 hover:text-foreground"
                      title="Pivot to Intel lookup"
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Passive Infrastructure & Attribution Footprint */}
      {primaryObs && (
        <PassiveInfraTable
          indicator={primaryObs}
          indicatorType={actor.observables[0]?.type || "domain"}
          passiveDns={passiveDns}
          whois={whoisData}
          sslCert={sslCertData}
        />
      )}

      {/* MITRE ATT&CK Matrix Navigator */}
      <MitreNavigatorMatrix
        actorTechniques={actor.techniques}
        actorTitle={actor.title}
      />
    </div>
  );
}
