import { useState } from "react";
import {
  ChevronDown, ChevronRight, Plus, Copy, Check, Search,
  Network, Shield, User, Globe, Activity, Layers, BarChart3,
} from "lucide-react";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import type { FieldFacet, FacetCategory } from "@/lib/siem/field-facets";
import type { FilterChip } from "@/data/siem";

interface FieldFacetSidebarProps {
  facets: FieldFacet[];
  onAddChip: (field: string, value: string) => void;
  activeChips: FilterChip[];
  onViewStats?: (field: string) => void;
}

const CATEGORY_ICONS: Record<FacetCategory, typeof Network> = {
  network: Network,
  identity: User,
  endpoint: Activity,
  web: Globe,
  security: Shield,
};

export function FieldFacetSidebar({
  facets,
  onAddChip,
  activeChips,
  onViewStats,
}: FieldFacetSidebarProps) {
  const [search, setSearch] = useState("");
  const [expandedFields, setExpandedFields] = useState<Record<string, boolean>>({
    src: true,
    user: true,
    sig: true,
  });
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  const toggleExpand = (field: string) => {
    setExpandedFields((prev) => ({ ...prev, [field]: !prev[field] }));
  };

  const handleCopy = (val: string) => {
    copyText(val);
    setCopiedValue(val);
    toast.success("Copied to clipboard");
    setTimeout(() => setCopiedValue(null), 1500);
  };

  const filteredFacets = facets.filter(
    (f) =>
      f.field.toLowerCase().includes(search.toLowerCase()) ||
      f.label.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="flex h-full flex-col rounded-lg border border-subtle bg-surface-0 p-3 shadow-xs">
      <div className="mb-2.5 flex items-center justify-between border-b border-border/60 pb-2">
        <div className="flex items-center gap-1.5">
          <Layers className="h-4 w-4 text-primary" />
          <h3 className="font-mono ba-text-xs font-semibold uppercase tracking-wider text-foreground">
            Fields & Facets
          </h3>
        </div>
        <span className="text-mono ba-text-3xs text-fg-dim">Splunk CIM</span>
      </div>

      {/* Field Filter Input */}
      <div className="relative mb-3">
        <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-fg-dim" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter fields..."
          className="h-7 w-full rounded border border-divider-strong bg-surface-1 pl-8 pr-2 font-mono ba-text-3xs text-foreground outline-none placeholder:text-fg-dim/60 focus:border-primary/50"
        />
      </div>

      {/* Facet List */}
      <div className="flex-1 space-y-2 overflow-y-auto pr-1">
        {filteredFacets.map((facet) => {
          const Icon = CATEGORY_ICONS[facet.category] || Shield;
          const isExpanded = expandedFields[facet.field] ?? false;

          return (
            <div
              key={facet.field}
              className="rounded-md border border-subtle bg-surface-1 transition-colors duration-150"
            >
              {/* Facet Header */}
              <button
                onClick={() => toggleExpand(facet.field)}
                className="flex w-full items-center justify-between px-2.5 py-2 text-left hover:bg-surface-2 rounded-t-md"
              >
                <div className="flex items-center gap-1.5 min-w-0">
                  {isExpanded ? (
                    <ChevronDown className="h-3 w-3 shrink-0 text-fg-dim" />
                  ) : (
                    <ChevronRight className="h-3 w-3 shrink-0 text-fg-dim" />
                  )}
                  <Icon className="h-3.5 w-3.5 shrink-0 text-primary/70" />
                  <span className="truncate font-mono ba-text-xs font-medium text-foreground">
                    {facet.label}
                  </span>
                </div>
                <div className="flex items-center gap-1 shrink-0 text-mono ba-text-3xs text-fg-dim">
                  <span
                    className="rounded bg-surface-2 px-1 py-0.5"
                    title={`${facet.coverage}% of events contain this field`}
                  >
                    {facet.coverage}% cov
                  </span>
                  <span>·</span>
                  <span>{facet.uniqueCount} uniq</span>
                  {onViewStats && (
                    <span
                      onClick={(e) => {
                        e.stopPropagation();
                        onViewStats(facet.field);
                      }}
                      className="ml-0.5 rounded p-0.5 hover:bg-primary/20 hover:text-primary transition-colors"
                      title={`Inspect full field statistics for ${facet.label}`}
                    >
                      <BarChart3 className="h-3 w-3" />
                    </span>
                  )}
                </div>
              </button>


              {/* Facet Values Drawer */}
              {isExpanded && (
                <div className="border-t border-border/40 px-2.5 py-2 space-y-1.5">
                  {facet.topValues.length === 0 ? (
                    <div className="text-mono ba-text-3xs text-fg-dim italic py-1">
                      No values present in current view
                    </div>
                  ) : (
                    facet.topValues.map((item) => {
                      const isFiltered = activeChips.some(
                        (c) => c.field === facet.field && c.value === item.value
                      );

                      return (
                        <div
                          key={item.value}
                          className="group relative flex items-center justify-between text-mono ba-text-2xs"
                        >
                          {/* Background Frequency Bar */}
                          <div
                            className="absolute inset-0 -z-0 rounded bg-primary/10 transition-all duration-300"
                            style={{ width: `${item.percent}%` }}
                          />

                          {/* Value Name & Count */}
                          <div className="relative z-10 flex min-w-0 flex-1 items-center gap-1.5 pl-1.5 pr-2 py-0.5">
                            <span
                              className={
                                "truncate " +
                                (isFiltered
                                  ? "text-primary font-bold"
                                  : "text-foreground group-hover:text-primary")
                              }
                              title={item.value}
                            >
                              {item.value}
                            </span>
                            <span className="ml-auto shrink-0 text-fg-dim tabular-nums ba-text-3xs">
                              {item.count} ({item.percent}%)
                            </span>
                          </div>

                          {/* Quick Actions */}
                          <div className="relative z-10 flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity duration-150">
                            <button
                              onClick={() => onAddChip(facet.field, item.value)}
                              className="rounded p-0.5 text-fg-dim hover:text-primary hover:bg-surface-2"
                              title={`Filter ${facet.field} = "${item.value}"`}
                            >
                              <Plus className="h-3 w-3" />
                            </button>
                            <button
                              onClick={() => handleCopy(item.value)}
                              className="rounded p-0.5 text-fg-dim hover:text-foreground hover:bg-surface-2"
                              title="Copy value"
                            >
                              {copiedValue === item.value ? (
                                <Check className="h-3 w-3 text-success" />
                              ) : (
                                <Copy className="h-3 w-3" />
                              )}
                            </button>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
