import { useState, useMemo } from "react";
import { Network, Layers, ShieldAlert, Users, Bug, Hash, Fingerprint, Eye, ArrowUpRight } from "lucide-react";
import type { GraphNode, GraphLink } from "@/data/intel";
import { cn } from "@/lib/utils";

interface RelationshipGraphProps {
  nodes: GraphNode[];
  links: GraphLink[];
  onSelectNode?: (id: string, type: string) => void;
  className?: string;
}

const TYPE_CONFIG: Record<string, { label: string; icon: typeof Bug; color: string; fill: string; stroke: string }> = {
  "threat-actor": {
    label: "Threat Actor",
    icon: Users,
    color: "text-amber-400 border-amber-500/50 bg-amber-950/40",
    fill: "#f59e0b",
    stroke: "#d97706",
  },
  vulnerability: {
    label: "Vulnerability",
    icon: ShieldAlert,
    color: "text-rose-400 border-rose-500/50 bg-rose-950/40",
    fill: "#f43f5e",
    stroke: "#e11d48",
  },
  malware: {
    label: "Malware",
    icon: Bug,
    color: "text-purple-400 border-purple-500/50 bg-purple-950/40",
    fill: "#a855f7",
    stroke: "#9333ea",
  },
  "file-hash": {
    label: "File Hash",
    icon: Hash,
    color: "text-sky-400 border-sky-500/50 bg-sky-950/40",
    fill: "#0ea5e9",
    stroke: "#0284c7",
  },
  "tls-fingerprint": {
    label: "TLS Fingerprint",
    icon: Fingerprint,
    color: "text-emerald-400 border-emerald-500/50 bg-emerald-950/40",
    fill: "#10b981",
    stroke: "#059669",
  },
  observable: {
    label: "Observable",
    icon: Eye,
    color: "text-teal-400 border-teal-500/50 bg-teal-950/40",
    fill: "#14b8a6",
    stroke: "#0d9488",
  },
};

export function RelationshipGraph({ nodes, links, onSelectNode, className }: RelationshipGraphProps) {
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<string>("all");

  const centerNode = useMemo(() => nodes.find((n) => n.isCenter) || nodes[0], [nodes]);

  const peripheralNodes = useMemo(() => {
    return nodes
      .filter((n) => n.id !== centerNode?.id)
      .filter((n) => (typeFilter === "all" ? true : n.type === typeFilter));
  }, [nodes, centerNode, typeFilter]);

  // Compute radial layout coordinates inside SVG (viewBox: 0 0 600 380, center: 300, 190)
  const layout = useMemo(() => {
    const cx = 300;
    const cy = 190;
    const radius = 140;
    const count = peripheralNodes.length;

    const nodeCoords = new Map<string, { x: number; y: number }>();
    if (centerNode) {
      nodeCoords.set(centerNode.id, { x: cx, y: cy });
    }

    peripheralNodes.forEach((node, i) => {
      const angle = (i / Math.max(count, 1)) * 2 * Math.PI - Math.PI / 2;
      const x = cx + radius * Math.cos(angle);
      const y = cy + radius * Math.sin(angle);
      nodeCoords.set(node.id, { x, y });
    });

    return { cx, cy, nodeCoords };
  }, [centerNode, peripheralNodes]);

  const availableTypes = useMemo(() => {
    const types = new Set<string>();
    nodes.forEach((n) => {
      if (!n.isCenter) types.add(n.type);
    });
    return Array.from(types);
  }, [nodes]);

  if (!nodes.length) return null;

  return (
    <div className={cn("rounded-lg border border-subtle bg-surface-1/40 p-3", className)}>
      {/* Graph Toolbar */}
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2 border-b border-subtle pb-2">
        <div className="flex items-center gap-2">
          <Network className="h-4 w-4 text-primary" />
          <span className="text-mono ba-text-xs font-semibold uppercase tracking-wider text-foreground">
            STIX 2.1 Relationship Graph
          </span>
          <span className="rounded border border-subtle bg-surface-2 px-1.5 py-px text-mono ba-text-3xs text-fg-dim">
            {nodes.length} entities · {links.length} relationships
          </span>
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-mono ba-text-3xs text-muted-foreground mr-1 flex items-center gap-1">
            <Layers className="h-3 w-3" /> Filter:
          </span>
          <button
            onClick={() => setTypeFilter("all")}
            className={cn(
              "rounded border px-1.5 py-0.5 text-mono ba-text-3xs transition-colors",
              typeFilter === "all"
                ? "border-primary/60 bg-primary/20 text-primary font-medium"
                : "border-subtle bg-surface-0 text-muted-foreground hover:text-foreground"
            )}
          >
            All ({nodes.length - (centerNode ? 1 : 0)})
          </button>
          {availableTypes.map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={cn(
                "rounded border px-1.5 py-0.5 text-mono ba-text-3xs transition-colors",
                typeFilter === t
                  ? "border-primary/60 bg-primary/20 text-primary font-medium"
                  : "border-subtle bg-surface-0 text-muted-foreground hover:text-foreground"
              )}
            >
              {TYPE_CONFIG[t]?.label || t}
            </button>
          ))}
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="relative w-full overflow-hidden rounded border border-subtle/60 bg-surface-0/90 shadow-inner">
        <svg
          viewBox="0 0 600 380"
          className="h-[340px] w-full select-none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Subtle grid pattern */}
          <defs>
            <pattern id="graph-grid" width="20" height="20" patternUnits="userSpaceOnUse">
              <path d="M 20 0 L 0 0 0 20" fill="none" stroke="currentColor" strokeWidth="0.5" className="text-border/20" />
            </pattern>
            <marker
              id="arrowhead"
              markerWidth="8"
              markerHeight="6"
              refX="18"
              refY="3"
              orient="auto"
            >
              <polygon points="0 0, 8 3, 0 6" fill="currentColor" className="text-primary/50" />
            </marker>
          </defs>
          <rect width="100%" height="100%" fill="url(#graph-grid)" />

          {/* Concentric helper circle */}
          <circle
            cx={layout.cx}
            cy={layout.cy}
            r="140"
            fill="none"
            stroke="currentColor"
            strokeDasharray="4 4"
            className="text-border/30"
          />

          {/* Links / Edges */}
          {links.map((link, idx) => {
            const sourceCoord = layout.nodeCoords.get(link.source);
            const targetCoord = layout.nodeCoords.get(link.target);
            if (!sourceCoord || !targetCoord) return null;

            const isHighlighted =
              hoveredNodeId === link.source || hoveredNodeId === link.target;

            // Compute midpoint for edge label
            const mx = (sourceCoord.x + targetCoord.x) / 2;
            const my = (sourceCoord.y + targetCoord.y) / 2;

            return (
              <g key={`link-${idx}`} className="transition-opacity duration-200">
                <line
                  x1={sourceCoord.x}
                  y1={sourceCoord.y}
                  x2={targetCoord.x}
                  y2={targetCoord.y}
                  stroke={isHighlighted ? "var(--primary)" : "currentColor"}
                  strokeWidth={isHighlighted ? 2 : 1.2}
                  strokeDasharray={link.label === "observable" ? "3 3" : undefined}
                  className={cn(
                    isHighlighted ? "text-primary opacity-100" : "text-border/60 opacity-60",
                    "transition-all"
                  )}
                  markerEnd="url(#arrowhead)"
                />
                {/* Edge badge */}
                <rect
                  x={mx - 34}
                  y={my - 7}
                  width="68"
                  height="14"
                  rx="3"
                  className={cn(
                    isHighlighted ? "fill-surface-3 stroke-primary" : "fill-surface-1 stroke-subtle",
                    "stroke-[0.5]"
                  )}
                />
                <text
                  x={mx}
                  y={my + 3}
                  textAnchor="middle"
                  className="font-mono text-[8px] fill-muted-foreground select-none pointer-events-none"
                >
                  {link.label.length > 14 ? link.label.slice(0, 13) + "…" : link.label}
                </text>
              </g>
            );
          })}

          {/* Peripheral Nodes */}
          {peripheralNodes.map((node) => {
            const coord = layout.nodeCoords.get(node.id);
            if (!coord) return null;

            const conf = TYPE_CONFIG[node.type] || TYPE_CONFIG.observable;
            const isHovered = hoveredNodeId === node.id;
            const isConnected =
              hoveredNodeId &&
              links.some(
                (l) =>
                  (l.source === hoveredNodeId && l.target === node.id) ||
                  (l.target === hoveredNodeId && l.source === node.id)
              );

            return (
              <g
                key={node.id}
                transform={`translate(${coord.x}, ${coord.y})`}
                className="cursor-pointer"
                onMouseEnter={() => setHoveredNodeId(node.id)}
                onMouseLeave={() => setHoveredNodeId(null)}
                onClick={() => onSelectNode?.(node.id, node.type)}
              >
                {/* Node circle */}
                <circle
                  r={isHovered ? 22 : 18}
                  fill={conf.fill}
                  fillOpacity={isHovered ? 0.25 : 0.15}
                  stroke={conf.stroke}
                  strokeWidth={isHovered ? 2.5 : 1.5}
                  className={cn("transition-all duration-150", isHovered && "filter drop-shadow(0 0 6px rgba(255,255,255,0.2))")}
                />

                {/* Score badge if available */}
                {node.score !== undefined && (
                  <circle
                    cx="14"
                    cy="-14"
                    r="8"
                    className="fill-surface-0 stroke-border stroke-[1]"
                  />
                )}
                {node.score !== undefined && (
                  <text
                    x="14"
                    y="-11"
                    textAnchor="middle"
                    className="font-mono text-[7px] font-bold fill-foreground"
                  >
                    {node.score}
                  </text>
                )}

                {/* Label text */}
                <text
                  y="30"
                  textAnchor="middle"
                  className={cn(
                    "font-mono text-[9px] font-medium transition-colors",
                    isHovered || isConnected ? "fill-foreground font-bold" : "fill-muted-foreground"
                  )}
                >
                  {node.label.length > 20 ? node.label.slice(0, 18) + "…" : node.label}
                </text>
                <text
                  y="40"
                  textAnchor="middle"
                  className="font-mono text-[7px] fill-fg-dim"
                >
                  {node.sublabel}
                </text>
              </g>
            );
          })}

          {/* Center Focal Node */}
          {centerNode && (
            <g
              transform={`translate(${layout.cx}, ${layout.cy})`}
              className="cursor-default"
              onMouseEnter={() => setHoveredNodeId(centerNode.id)}
              onMouseLeave={() => setHoveredNodeId(null)}
            >
              {/* Outer pulse circle */}
              <circle
                r="38"
                fill="currentColor"
                className="text-primary/10 animate-pulse"
              />
              <circle
                r="30"
                fill="var(--surface-0)"
                stroke="var(--primary)"
                strokeWidth="2.5"
                className="filter drop-shadow(0 0 8px rgba(var(--primary-rgb, 59, 130, 246), 0.3))"
              />
              <text
                y="-4"
                textAnchor="middle"
                className="font-mono text-[10px] font-bold fill-foreground"
              >
                {centerNode.label.length > 18 ? centerNode.label.slice(0, 16) + "…" : centerNode.label}
              </text>
              <text
                y="10"
                textAnchor="middle"
                className="font-mono text-[8px] font-medium fill-primary uppercase tracking-wider"
              >
                {centerNode.sublabel}
              </text>
              {centerNode.score !== undefined && (
                <text
                  y="22"
                  textAnchor="middle"
                  className="font-mono text-[7px] fill-muted-foreground"
                >
                  Score: {centerNode.score}/100
                </text>
              )}
            </g>
          )}
        </svg>

        {/* Legend strip */}
        <div className="flex flex-wrap items-center justify-center gap-3 border-t border-subtle/50 bg-surface-1/50 px-3 py-1.5 text-mono ba-text-3xs text-muted-foreground">
          {Object.entries(TYPE_CONFIG).map(([key, config]) => (
            <div key={key} className="flex items-center gap-1.5">
              <span
                className="h-2 w-2 rounded-full border"
                style={{ backgroundColor: config.fill, borderColor: config.stroke }}
              />
              <span>{config.label}</span>
            </div>
          ))}
          <div className="ml-auto flex items-center gap-1 text-fg-dim">
            <span>Click any node to pivot</span>
            <ArrowUpRight className="h-3 w-3" />
          </div>
        </div>
      </div>
    </div>
  );
}
