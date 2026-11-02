import { useState } from "react";
import {
  ShieldAlert,
  Terminal,
  Globe,
  Crosshair,
  Download,
  Copy,
  Check,
  ExternalLink,
  Layers,
  Sparkles,
} from "lucide-react";
import type { DiamondModel } from "@/lib/intel/threat-intel-engine";
import { exportStix21Json } from "@/lib/intel/threat-intel-engine";
import { notify } from "@/lib/notify";
import { cn } from "@/lib/utils";

interface DiamondModelCardProps {
  diamond: DiamondModel;
  stixBundle?: any;
  className?: string;
}

type VertexKey = "adversary" | "capability" | "infrastructure" | "victim" | "all";

export function DiamondModelCard({ diamond, stixBundle, className }: DiamondModelCardProps) {
  const [selectedVertex, setSelectedVertex] = useState<VertexKey>("all");
  const [copied, setCopied] = useState(false);

  function handleCopyJson() {
    navigator.clipboard.writeText(JSON.stringify(diamond, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
    notify.success("Diamond Model copied to clipboard");
  }

  function handleExportStix() {
    if (stixBundle) {
      const filename = `stix-${diamond.adversary.actor.toLowerCase().replace(/[^a-z0-9]/g, "-")}.json`;
      exportStix21Json(stixBundle, filename);
      notify.success("STIX 2.1 bundle downloaded");
    } else {
      notify.info("STIX bundle not available for this view");
    }
  }

  return (
    <div className={cn("rounded-lg border border-subtle bg-surface-1/60 p-4", className)}>
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-subtle pb-3">
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-primary" />
          <h3 className="font-mono text-sm font-bold uppercase tracking-wider text-foreground">
            The Diamond Model of Intrusion Analysis
          </h3>
          <span className="rounded border border-primary/40 bg-primary/10 px-2 py-0.5 font-mono ba-text-3xs font-semibold text-primary">
            Sergio et al. Standard
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <button
            onClick={handleCopyJson}
            className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-0 px-2 py-1 font-mono ba-text-2xs text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
          >
            {copied ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
            Copy Model JSON
          </button>
          {stixBundle && (
            <button
              onClick={handleExportStix}
              className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2.5 py-1 font-mono ba-text-2xs font-semibold text-primary transition-colors hover:bg-primary/20"
            >
              <Download className="h-3 w-3" />
              Export STIX 2.1
            </button>
          )}
        </div>
      </div>

      {/* Interactive Vertex Filter Strip */}
      <div className="mt-3 flex flex-wrap items-center gap-1 text-mono ba-text-2xs">
        <span className="text-muted-foreground mr-1.5 flex items-center gap-1">
          <Sparkles className="h-3 w-3 text-amber-400" /> Focus Vertex:
        </span>
        {(
          [
            { key: "all", label: "All 4 Vertices" },
            { key: "adversary", label: "Adversary (Who/Why)" },
            { key: "capability", label: "Capability (How)" },
            { key: "infrastructure", label: "Infrastructure (Where)" },
            { key: "victim", label: "Victim (Whom)" },
          ] as const
        ).map((v) => (
          <button
            key={v.key}
            onClick={() => setSelectedVertex(v.key)}
            className={cn(
              "rounded border px-2 py-0.5 font-mono ba-text-3xs transition-colors",
              selectedVertex === v.key
                ? "border-primary/60 bg-primary/20 text-primary font-semibold"
                : "border-subtle bg-surface-0 text-muted-foreground hover:text-foreground",
            )}
          >
            {v.label}
          </button>
        ))}
      </div>

      {/* Visual Diamond Canvas & Grid */}
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* SVG Diagram Representation */}
        <div className="relative flex flex-col items-center justify-center rounded-lg border border-subtle bg-surface-0/80 p-4">
          <svg viewBox="0 0 340 300" className="h-64 w-full max-w-sm drop-shadow-sm select-none">
            {/* Diamond Rhombus connecting paths */}
            <polygon
              points="170,30 310,150 170,270 30,150"
              fill="rgba(var(--surface-2-rgb, 20, 25, 35), 0.5)"
              stroke="currentColor"
              className="text-subtle/80"
              strokeWidth="2"
              strokeDasharray="4 4"
            />
            {/* Diagonal cross axis */}
            <line x1="170" y1="30" x2="170" y2="270" stroke="currentColor" className="text-subtle/40" strokeWidth="1" />
            <line x1="30" y1="150" x2="310" y2="150" stroke="currentColor" className="text-subtle/40" strokeWidth="1" />

            {/* Central Core Meta-Feature Badge */}
            <circle cx="170" cy="150" r="28" fill="#0f172a" stroke="#3b82f6" strokeWidth="2" />
            <text x="170" y="146" textAnchor="middle" fill="#93c5fd" fontSize="9" fontWeight="bold" fontFamily="monospace">
              CONFIDENCE
            </text>
            <text x="170" y="159" textAnchor="middle" fill="#ffffff" fontSize="10" fontWeight="bold" fontFamily="monospace">
              {diamond.confidence.toUpperCase()}
            </text>

            {/* TOP VERTEX: Adversary */}
            <g
              className="cursor-pointer transition-transform hover:scale-105"
              onClick={() => setSelectedVertex("adversary")}
            >
              <circle
                cx="170"
                cy="30"
                r="22"
                fill={selectedVertex === "adversary" || selectedVertex === "all" ? "#f59e0b" : "#1e293b"}
                stroke="#d97706"
                strokeWidth="2"
              />
              <text x="170" y="34" textAnchor="middle" fill="#ffffff" fontSize="11" fontWeight="bold" fontFamily="monospace">
                ADV
              </text>
              <text x="170" y="62" textAnchor="middle" fill="#f59e0b" fontSize="10" fontWeight="bold" fontFamily="monospace">
                Adversary
              </text>
            </g>

            {/* LEFT VERTEX: Capability */}
            <g
              className="cursor-pointer transition-transform hover:scale-105"
              onClick={() => setSelectedVertex("capability")}
            >
              <circle
                cx="30"
                cy="150"
                r="22"
                fill={selectedVertex === "capability" || selectedVertex === "all" ? "#a855f7" : "#1e293b"}
                stroke="#9333ea"
                strokeWidth="2"
              />
              <text x="30" y="154" textAnchor="middle" fill="#ffffff" fontSize="11" fontWeight="bold" fontFamily="monospace">
                CAP
              </text>
              <text x="30" y="184" textAnchor="middle" fill="#c084fc" fontSize="10" fontWeight="bold" fontFamily="monospace">
                Capability
              </text>
            </g>

            {/* RIGHT VERTEX: Infrastructure */}
            <g
              className="cursor-pointer transition-transform hover:scale-105"
              onClick={() => setSelectedVertex("infrastructure")}
            >
              <circle
                cx="310"
                cy="150"
                r="22"
                fill={selectedVertex === "infrastructure" || selectedVertex === "all" ? "#0ea5e9" : "#1e293b"}
                stroke="#0284c7"
                strokeWidth="2"
              />
              <text x="310" y="154" textAnchor="middle" fill="#ffffff" fontSize="11" fontWeight="bold" fontFamily="monospace">
                INF
              </text>
              <text x="310" y="184" textAnchor="middle" fill="#38bdf8" fontSize="10" fontWeight="bold" fontFamily="monospace">
                Infrastructure
              </text>
            </g>

            {/* BOTTOM VERTEX: Victim */}
            <g
              className="cursor-pointer transition-transform hover:scale-105"
              onClick={() => setSelectedVertex("victim")}
            >
              <circle
                cx="170"
                cy="270"
                r="22"
                fill={selectedVertex === "victim" || selectedVertex === "all" ? "#f43f5e" : "#1e293b"}
                stroke="#e11d48"
                strokeWidth="2"
              />
              <text x="170" y="274" textAnchor="middle" fill="#ffffff" fontSize="11" fontWeight="bold" fontFamily="monospace">
                VIC
              </text>
              <text x="170" y="242" textAnchor="middle" fill="#fb7185" fontSize="10" fontWeight="bold" fontFamily="monospace">
                Victim
              </text>
            </g>
          </svg>
          <div className="mt-1 text-center font-mono ba-text-3xs text-muted-foreground">
            Click any vertex to isolate attributes & pivots
          </div>
        </div>

        {/* Vertex Attribute Cards */}
        <div className="space-y-2.5">
          {/* Adversary Card */}
          {(selectedVertex === "all" || selectedVertex === "adversary") && (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
              <div className="flex items-center justify-between border-b border-amber-500/20 pb-1.5">
                <div className="flex items-center gap-1.5 font-mono text-xs font-bold text-amber-400">
                  <ShieldAlert className="h-3.5 w-3.5" /> Adversary Vertex
                </div>
                <span className="font-mono ba-text-3xs text-amber-300">
                  {diamond.adversary.countryFlag} {diamond.adversary.origin}
                </span>
              </div>
              <div className="mt-2 space-y-1 font-mono ba-text-xs">
                <div>
                  <span className="text-muted-foreground">Threat Actor: </span>
                  <span className="font-bold text-foreground">{diamond.adversary.actor}</span>
                </div>
                {diamond.adversary.sponsoringAgency && (
                  <div className="ba-text-2xs text-amber-300/90">
                    <span className="text-muted-foreground">Apparatus: </span>
                    {diamond.adversary.sponsoringAgency}
                  </div>
                )}
                <div>
                  <span className="text-muted-foreground">Motivation: </span>
                  <span className="text-foreground">{diamond.adversary.motivation}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Threat Score: </span>
                  <span className="font-bold text-amber-400">{diamond.adversary.threatScore}/100</span>
                </div>
              </div>
            </div>
          )}

          {/* Capability Card */}
          {(selectedVertex === "all" || selectedVertex === "capability") && (
            <div className="rounded-lg border border-purple-500/30 bg-purple-500/5 p-3">
              <div className="flex items-center justify-between border-b border-purple-500/20 pb-1.5">
                <div className="flex items-center gap-1.5 font-mono text-xs font-bold text-purple-400">
                  <Terminal className="h-3.5 w-3.5" /> Capability Vertex
                </div>
                <span className="font-mono ba-text-3xs text-purple-300">
                  {diamond.capability.arsenal.length} Tools · {diamond.capability.exploits.length} Exploits
                </span>
              </div>
              <div className="mt-2 space-y-1.5 font-mono ba-text-xs">
                <div>
                  <span className="text-muted-foreground ba-text-2xs block mb-1">Malware & Tooling:</span>
                  <div className="flex flex-wrap gap-1">
                    {diamond.capability.arsenal.map((tool) => (
                      <span
                        key={tool}
                        className="rounded border border-purple-500/30 bg-purple-500/10 px-1.5 py-0.5 ba-text-3xs font-medium text-purple-300"
                      >
                        {tool}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <span className="text-muted-foreground ba-text-2xs block mb-1">Targeted / Exploited CVEs:</span>
                  <div className="flex flex-wrap gap-1">
                    {diamond.capability.exploits.map((cve) => (
                      <span
                        key={cve}
                        className="rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 ba-text-3xs font-bold text-rose-300"
                      >
                        {cve}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Infrastructure Card */}
          {(selectedVertex === "all" || selectedVertex === "infrastructure") && (
            <div className="rounded-lg border border-sky-500/30 bg-sky-500/5 p-3">
              <div className="flex items-center justify-between border-b border-sky-500/20 pb-1.5">
                <div className="flex items-center gap-1.5 font-mono text-xs font-bold text-sky-400">
                  <Globe className="h-3.5 w-3.5" /> Infrastructure Vertex
                </div>
                <span className="font-mono ba-text-3xs text-sky-300">
                  {diamond.infrastructure.hostingProvider}
                </span>
              </div>
              <div className="mt-2 space-y-1 font-mono ba-text-xs">
                <div>
                  <span className="text-muted-foreground">Primary Observable: </span>
                  <span className="font-bold text-foreground">{diamond.infrastructure.indicator}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Observed Nodes: </span>
                  <span className="text-foreground">{diamond.infrastructure.coHostedCount} co-hosted items</span>
                </div>
                {diamond.infrastructure.tlsProfile && (
                  <div>
                    <span className="text-muted-foreground">TLS Profile: </span>
                    <span className="text-sky-300">{diamond.infrastructure.tlsProfile}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Victim Card */}
          {(selectedVertex === "all" || selectedVertex === "victim") && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/5 p-3">
              <div className="flex items-center justify-between border-b border-rose-500/20 pb-1.5">
                <div className="flex items-center gap-1.5 font-mono text-xs font-bold text-rose-400">
                  <Crosshair className="h-3.5 w-3.5" /> Victim Vertex
                </div>
                <span className="font-mono ba-text-3xs font-semibold text-rose-300">
                  Impact: {diamond.victim.impactPotential}
                </span>
              </div>
              <div className="mt-2 space-y-1.5 font-mono ba-text-xs">
                <div>
                  <span className="text-muted-foreground ba-text-2xs block mb-1">Targeted Sectors:</span>
                  <div className="flex flex-wrap gap-1">
                    {diamond.victim.targetedSectors.map((sec) => (
                      <span
                        key={sec}
                        className="rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 ba-text-3xs font-medium text-rose-300"
                      >
                        {sec}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <span className="text-muted-foreground ba-text-2xs block mb-1">Geographies:</span>
                  <div className="flex flex-wrap gap-1">
                    {diamond.victim.geographies.map((geo) => (
                      <span
                        key={geo}
                        className="rounded border border-subtle bg-surface-1 px-1.5 py-0.5 ba-text-3xs text-foreground"
                      >
                        {geo}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
