import React, { useState, useMemo } from "react";
import {
  Users,
  Crosshair,
  ShieldAlert,
  ShieldCheck,
  Activity,
  Fingerprint,
  Radio,
  ExternalLink,
  Copy,
  Download,
  Check,
  FileText,
  Sparkles,
  Zap,
  Layers,
  ArrowRight,
  RefreshCw,
  Globe,
  Flame,
} from "lucide-react";
import { getThreatActors, type ThreatActorEntity } from "@/data/intel";
import {
  calculateAdversaryAttribution,
  profileC2Traffic,
  attributeActiveCase,
  generateAttributionMarkdown,
  lookupTechniqueMeta,
  type ThreatActorCandidate,
  type C2ProfileResult,
} from "@/lib/adversary-attribution";
import { type Case } from "@/data/case";
import { downloadTextFile } from "@/lib/download";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

const ORIGIN_FLAGS: Record<string, string> = {
  Russia: "🇷🇺",
  China: "🇨🇳",
  "North Korea": "🇰🇵",
  Iran: "🇮🇷",
  Western: "🌐",
  "Eastern Europe": "🇪🇺",
};

interface AdversaryAttributionWorkspaceProps {
  activeCase?: Case | null;
  onApplyTechniquesToMatrix?: (techIds: string[], label: string) => void;
  onNavigateToCase?: (caseId: string) => void;
}

export function AdversaryAttributionWorkspace({
  activeCase,
  onApplyTechniquesToMatrix,
  onNavigateToCase,
}: AdversaryAttributionWorkspaceProps) {
  const allActors = useMemo(() => getThreatActors(), []);
  const [selectedActorId, setSelectedActorId] = useState<string>(
    () => allActors[0]?.id || ""
  );
  const [copied, setCopied] = useState(false);
  const [isCaseAttributed, setIsCaseAttributed] = useState(false);

  // Active case auto-attribution report
  const caseAttributionReport = useMemo(() => {
    if (!activeCase) return null;
    return attributeActiveCase(activeCase);
  }, [activeCase]);

  // Selected actor
  const currentActor = useMemo(() => {
    return allActors.find((a) => a.id === selectedActorId) || allActors[0];
  }, [allActors, selectedActorId]);

  // C2 Profile for the current actor
  const c2Profile: C2ProfileResult = useMemo(() => {
    const actorTitle = currentActor?.title?.toLowerCase() || "";
    if (actorTitle.includes("volt typhoon")) {
      return profileC2Traffic({
        ja3: "7e12c4a7c2e1e5c6c8d4f7a0b3c5d8e1",
        beaconIntervalSec: 60,
        jitterPct: 8,
        observedStrings: ["FRP", "cisco-router-hop", "beacon"],
      });
    }
    if (actorTitle.includes("wizard spider") || actorTitle.includes("conti")) {
      return profileC2Traffic({
        ja4: "ja4_b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
        beaconIntervalSec: 20,
        jitterPct: 15,
        observedStrings: ["bazarloader", "cobaltstrike"],
      });
    }
    if (actorTitle.includes("mustang panda")) {
      return profileC2Traffic({
        ja3: "c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4",
        beaconIntervalSec: 45,
        jitterPct: 12,
        observedStrings: ["plugx", "beacon"],
      });
    }
    return profileC2Traffic({
      ja3: "7e12c4a7c2e1e5c6c8d4f7a0b3c5d8e1",
      beaconIntervalSec: 30,
      jitterPct: 5,
      observedStrings: ["beacon"],
    });
  }, [currentActor]);

  // Current Attribution Candidate
  const candidateInfo = useMemo(() => {
    if (!currentActor) return null;
    const techniques = currentActor.techniques || [];
    const dummyIocs = (currentActor.observedInfrastructure || []).map((i) => ({
      value: i.value,
      type: i.type as any,
      context: i.label || "",
      source: "/intel",
      severity: "critical" as const,
    }));
    return calculateAdversaryAttribution(dummyIocs, techniques, currentActor.targets?.[0]);
  }, [currentActor]);

  const handleAutoAttribute = () => {
    if (!caseAttributionReport || !caseAttributionReport.primaryCandidate) {
      toast.info("No definitive threat actor correlation found for active case IOCs.");
      return;
    }
    const matched = caseAttributionReport.primaryCandidate.actor;
    setSelectedActorId(matched.id);
    setIsCaseAttributed(true);
    toast.success(
      `Attributed to ${matched.title} (${caseAttributionReport.primaryCandidate.confidenceScore}% Confidence)`
    );
  };

  const handleCopyMarkdown = () => {
    if (!candidateInfo) return;
    const md = generateAttributionMarkdown(candidateInfo, c2Profile);
    navigator.clipboard.writeText(md);
    setCopied(true);
    toast.success("Attribution & C2 profile copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadJson = () => {
    if (!currentActor) return;
    const payload = {
      actor: currentActor,
      attribution: candidateInfo,
      c2Profile,
      exportedAt: new Date().toISOString(),
    };
    downloadTextFile(
      `threat-actor-attribution-${currentActor.title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.json`,
      JSON.stringify(payload, null, 2),
      "application/json"
    );
    toast.success("Downloaded adversary attribution dossier (.json)");
  };

  const handleHighlightInMatrix = () => {
    if (!currentActor || !onApplyTechniquesToMatrix) return;
    onApplyTechniquesToMatrix(currentActor.techniques, currentActor.title);
    toast.success(`Loaded ${currentActor.techniques.length} techniques for ${currentActor.title} into MITRE Matrix`);
  };

  if (!currentActor) return null;

  const flag = ORIGIN_FLAGS[currentActor.origin] || "🌐";

  return (
    <div className="space-y-4 min-w-0 max-w-full" id="adversary-attribution-workspace">
      {/* Control Strip */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 p-4 rounded-xl border border-border/80 bg-card/70 backdrop-blur-sm min-w-0">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-destructive/40 bg-destructive/10 text-destructive">
            <Crosshair className="h-5 w-5" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-bold text-foreground">
                Adversary Attribution &amp; MITRE C2 Profiling Engine
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-destructive/15 text-destructive border border-destructive/30 font-bold uppercase">
                ADVANCED THREAT INTEL
              </span>
            </div>
            <div className="text-xs text-muted-foreground truncate">
              Correlates hostile infrastructure, JA3/JA4 TLS signatures, and TTP overlap to profile adversary campaigns
            </div>
          </div>
        </div>

        {/* Actor Picker & Auto-Attribute */}
        <div className="flex items-center gap-2 flex-wrap shrink-0">
          <div className="flex items-center gap-1.5 rounded-lg border border-border bg-card px-2.5 py-1.5 text-xs">
            <span className="text-muted-foreground font-semibold">ACTOR:</span>
            <select
              value={selectedActorId}
              onChange={(e) => {
                setSelectedActorId(e.target.value);
                setIsCaseAttributed(false);
              }}
              className="bg-transparent font-bold text-foreground outline-none cursor-pointer max-w-[200px] truncate"
              id="select-threat-actor"
            >
              {allActors.map((a) => (
                <option key={a.id} value={a.id} className="bg-card text-foreground">
                  {ORIGIN_FLAGS[a.origin] || "🌐"} {a.title} ({a.origin})
                </option>
              ))}
            </select>
          </div>

          {activeCase && (
            <button
              type="button"
              onClick={handleAutoAttribute}
              id="btn-auto-attribute-case"
              className={cn(
                "inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold shadow-xs transition-colors",
                isCaseAttributed
                  ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                  : "bg-primary/15 text-primary border border-primary/40 hover:bg-primary/25"
              )}
              title="Correlate active case IOCs against threat actor infrastructure"
            >
              <Sparkles className="h-3.5 w-3.5" />
              <span>{isCaseAttributed ? "Attributed to Active Case" : "Auto-Attribute Active Case"}</span>
            </button>
          )}

          <button
            type="button"
            onClick={handleCopyMarkdown}
            id="btn-copy-attribution"
            className="inline-flex items-center gap-1 rounded-lg border border-border bg-card px-2.5 py-1.5 text-xs font-medium text-foreground hover:bg-muted transition-colors"
            title="Copy attribution report as Markdown"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5 text-muted-foreground" />}
            <span className="hidden sm:inline">Copy Report</span>
          </button>

          <button
            type="button"
            onClick={handleDownloadJson}
            className="inline-flex items-center gap-1 rounded-lg border border-border bg-card px-2.5 py-1.5 text-xs font-medium text-foreground hover:bg-muted transition-colors"
            title="Download JSON dossier"
          >
            <Download className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="hidden sm:inline">JSON</span>
          </button>
        </div>
      </div>

      {/* Threat Actor Overview Banner */}
      <div className="rounded-2xl border border-border/80 bg-gradient-to-r from-card via-card to-destructive/5 p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 min-w-0">
          <div className="space-y-1 min-w-0">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
                <span>{flag}</span>
                <span>{currentActor.title}</span>
              </span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-destructive/15 text-destructive border border-destructive/30 font-bold">
                {currentActor.score}/100 THREAT SCORE
              </span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-muted text-muted-foreground">
                {currentActor.origin} · {currentActor.motivation}
              </span>
            </div>
            <p className="text-xs text-muted-foreground max-w-3xl leading-relaxed">
              {currentActor.summary}
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {onApplyTechniquesToMatrix && (
              <button
                type="button"
                onClick={handleHighlightInMatrix}
                id="btn-highlight-matrix"
                className="inline-flex items-center gap-1.5 rounded-lg border border-primary/50 bg-primary/10 px-3.5 py-2 text-xs font-bold text-primary hover:bg-primary/20 transition-colors"
              >
                <Layers className="h-3.5 w-3.5" />
                <span>Highlight in Matrix ({currentActor.techniques.length})</span>
              </button>
            )}
          </div>
        </div>

        {/* Aliases & Target Verticals */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-3 border-t border-border/60 text-xs">
          <div>
            <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider block mb-1">
              Known Aliases
            </span>
            <div className="flex flex-wrap gap-1">
              {(currentActor.aliases || []).map((al) => (
                <span key={al} className="font-mono text-[11px] px-2 py-0.5 rounded bg-muted/60 text-foreground border border-border/50">
                  {al}
                </span>
              ))}
            </div>
          </div>

          <div>
            <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider block mb-1">
              Targeted Sectors
            </span>
            <div className="flex flex-wrap gap-1">
              {(currentActor.targets || []).map((tgt) => (
                <span key={tgt} className="text-[11px] px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20 font-medium">
                  {tgt}
                </span>
              ))}
            </div>
          </div>

          <div>
            <span className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider block mb-1">
              Notable Campaigns
            </span>
            <div className="text-[11px] text-foreground font-medium truncate" title={(currentActor.campaigns || []).join(", ")}>
              {(currentActor.campaigns || []).join(" · ") || "Targeted Corporate Espionage"}
            </div>
          </div>
        </div>
      </div>

      {/* Tri-Grid: Attribution Diagnostics, C2 Infrastructure, and Technique Coverage */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Panel 1: Attribution Evidence & Infrastructure */}
        <div className="rounded-xl border border-border/80 bg-card p-4 space-y-3 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-border/60 pb-2.5">
              <div className="flex items-center gap-2">
                <Crosshair className="h-4 w-4 text-destructive" />
                <span className="text-xs font-bold uppercase tracking-wider text-foreground">
                  Attribution Evidence Matrix
                </span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-destructive/15 text-destructive border border-destructive/30 font-bold">
                HIGH FIDELITY
              </span>
            </div>

            {/* Observed Infrastructure */}
            <div className="space-y-1.5">
              <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider block">
                Known C2 &amp; Staging Infrastructure ({(currentActor.observedInfrastructure || []).length})
              </span>
              <div className="space-y-1.5">
                {(currentActor.observedInfrastructure || []).map((inf) => (
                  <div
                    key={`${inf.type}-${inf.value}`}
                    className="p-2 rounded-lg border border-border/60 bg-muted/20 font-mono text-xs flex items-center justify-between"
                  >
                    <div className="min-w-0 pr-2">
                      <span className="text-[10px] uppercase px-1 py-0.2 rounded bg-muted text-muted-foreground mr-1.5">
                        {inf.type}
                      </span>
                      <span className="font-semibold text-foreground select-all">{inf.value}</span>
                    </div>
                    <span className="text-[10px] text-muted-foreground truncate max-w-[120px]" title={inf.label}>
                      {inf.label}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Tooling & Malware */}
            <div className="space-y-1.5">
              <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider block">
                Weaponized Tools &amp; Malware
              </span>
              <div className="flex flex-wrap gap-1.5">
                {(currentActor.tools || []).map((tool) => (
                  <span
                    key={tool}
                    className="inline-flex items-center gap-1 font-mono text-[11px] px-2 py-0.5 rounded bg-destructive/10 text-destructive border border-destructive/20 font-semibold"
                  >
                    <Flame className="h-3 w-3" />
                    {tool}
                  </span>
                ))}
              </div>
            </div>
          </div>

          <div className="pt-2 border-t border-border/40 text-[11px] text-muted-foreground">
            Targeted CVEs: {(currentActor.targetedCves || []).join(", ") || "None documented"}
          </div>
        </div>

        {/* Panel 2: C2 Infrastructure & TLS Profiler */}
        <div className="rounded-xl border border-border/80 bg-card p-4 space-y-3 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-border/60 pb-2.5">
              <div className="flex items-center gap-2">
                <Radio className="h-4 w-4 text-primary" />
                <span className="text-xs font-bold uppercase tracking-wider text-foreground">
                  C2 Infrastructure Profiler
                </span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-primary/15 text-primary border border-primary/30 font-bold">
                {c2Profile.confidence}% CONFIDENCE
              </span>
            </div>

            {/* Framework match */}
            <div className="p-3 rounded-lg border border-primary/30 bg-primary/[0.04] space-y-1">
              <div className="text-[10px] uppercase font-semibold text-muted-foreground tracking-wider">
                Active Framework Signature
              </div>
              <div className="text-base font-bold text-foreground font-mono">
                {c2Profile.framework}
              </div>
              <div className="text-xs text-muted-foreground">
                Profile method: {c2Profile.profileType} · {c2Profile.killChainPhase}
              </div>
            </div>

            {/* TLS Fingerprint */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[11px]">
                <span className="font-semibold text-muted-foreground uppercase tracking-wider">
                  JA3 / JA4 TLS Fingerprint
                </span>
                <span className="text-[10px] font-mono text-muted-foreground">TLS 1.2/1.3</span>
              </div>
              <div className="p-2 rounded-lg border border-border/60 bg-muted/20 font-mono text-xs truncate select-all">
                {c2Profile.detectedJa4 || c2Profile.detectedJa3 || "7e12c4a7c2e1e5c6c8d4f7a0b3c5d8e1"}
              </div>
            </div>

            {/* Beacon Cadence Telemetry */}
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="p-2 rounded-lg border border-border/60 bg-card space-y-0.5">
                <div className="text-[10px] text-muted-foreground uppercase">Mean Cadence</div>
                <div className="font-mono font-bold text-foreground">{c2Profile.meanIntervalSec}s interval</div>
              </div>
              <div className="p-2 rounded-lg border border-border/60 bg-card space-y-0.5">
                <div className="text-[10px] text-muted-foreground uppercase">Jitter Variance</div>
                <div className="font-mono font-bold text-amber-400">{c2Profile.jitterPct}% jitter</div>
              </div>
            </div>
          </div>

          <div className="pt-2 border-t border-border/40 text-[11px] text-muted-foreground">
            Evasion Score: <strong className="text-foreground">{c2Profile.evasionScore}/100</strong> (Anti-Analysis active)
          </div>
        </div>

        {/* Panel 3: Adversary MITRE TTPs */}
        <div className="rounded-xl border border-border/80 bg-card p-4 space-y-3 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-border/60 pb-2.5">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-emerald-400" />
                <span className="text-xs font-bold uppercase tracking-wider text-foreground">
                  Adversary Techniques ({currentActor.techniques.length})
                </span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-bold">
                TACTICAL MAPPING
              </span>
            </div>

            {/* Technique List */}
            <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
              {currentActor.techniques.map((tid) => {
                const meta = lookupTechniqueMeta(tid);
                return (
                  <div
                    key={tid}
                    className="p-2 rounded-lg border border-border/60 bg-card hover:border-primary/50 transition-colors flex items-center justify-between text-xs"
                  >
                    <div className="min-w-0 pr-2">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono font-bold text-primary">{tid}</span>
                        <span className="font-medium text-foreground truncate">{meta.name}</span>
                      </div>
                      <div className="text-[10px] text-muted-foreground">{meta.tactic}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="pt-2 border-t border-border/40 flex items-center justify-between text-[11px] text-muted-foreground">
            <span>Detection Rule Coverage: Verified</span>
            <span className="text-emerald-400 font-semibold">Ready to Hunt</span>
          </div>
        </div>
      </div>
    </div>
  );
}
