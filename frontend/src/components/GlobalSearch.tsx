import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Chip } from "@/components/soc";
import { setActiveCaseId } from "@/data/case";
import { useSearch, parseQualifiers, type Qualifier } from "@/lib/search-engine";
import { applyIntent, detectIntent } from "@/lib/search-intent";
import type { SearchItem } from "@/lib/search-index";
import { Search, FileText, ShieldAlert, Database, Activity, MessageSquare, FolderOpen, LayoutDashboard, FileBarChart, ShieldCheck, Target, Bug, Bell, X } from "lucide-react";

const ITEM_ICON: Record<string, typeof Search> = {
  case: FolderOpen,
  finding: ShieldAlert,
  ioc: Database,
  event: Activity,
  note: FileText,
  artifact: MessageSquare,
  page: LayoutDashboard,
  report: FileBarChart,
  detection: ShieldCheck,
  mitre: Target,
  entity: Bug,
  alert: Bell,
};

const TYPE_ORDER: Record<string, number> = {
  case: 0, finding: 1, ioc: 2, event: 3, note: 4, artifact: 5, page: 6,
  report: 7, detection: 8, mitre: 9, entity: 10, alert: 11,
};

const TYPE_LABEL: Record<string, string> = {
  case: "Cases", finding: "Findings", ioc: "IOCs", event: "Events", note: "Notes", artifact: "Artifacts", page: "Pages",
  report: "Reports", detection: "Detections", mitre: "MITRE", entity: "Entities", alert: "Alerts",
};

const TYPE_META: Record<string, { label: string; tone: "default" | "primary" | "accent" | "success" | "warning" | "destructive" | "info" }> = {
  case: { label: "Investigation", tone: "primary" },
  finding: { label: "Finding", tone: "destructive" },
  ioc: { label: "Observable", tone: "warning" },
  event: { label: "Event", tone: "info" },
  note: { label: "Note", tone: "default" },
  artifact: { label: "Artifact", tone: "default" },
  page: { label: "Navigation", tone: "default" },
  report: { label: "Report", tone: "accent" },
  detection: { label: "Detection Rule", tone: "success" },
  mitre: { label: "MITRE Technique", tone: "info" },
  entity: { label: "Intel Entity", tone: "accent" },
  alert: { label: "Alert", tone: "destructive" },
};

const ENTITY_TYPE_LABEL: Record<string, string> = {
  vulnerability: "CVE", "threat-actor": "Threat Group", malware: "Malware",
  "file-hash": "File Hash", "tls-fingerprint": "TLS Fingerprint",
};

function severityTone(sev: string | undefined): "default" | "success" | "warning" | "destructive" | "info" | "primary" | "accent" {
  if (sev === "critical" || sev === "high") return "destructive";
  if (sev === "medium") return "warning";
  if (sev === "low") return "info";
  return "default";
}

function confidenceTone(c: string | undefined): "default" | "success" | "warning" | "destructive" | "info" | "primary" | "accent" {
  if (c === "high") return "success";
  if (c === "medium") return "warning";
  if (c === "low") return "default";
  return "default";
}

const QUALIFIER_VALUES: Record<string, string[]> = {
  type: ["case", "finding", "ioc", "event", "note", "artifact", "report", "detection", "mitre", "entity", "alert", "page"],
  severity: ["critical", "high", "medium", "low", "info"],
  state: ["active", "closed"],
  format: ["sigma", "splunk", "qradar", "suricata", "yara"],
  ioctype: ["ipv4", "ipv6", "domain", "url", "hash", "email"],
  kind: ["file", "process", "network", "registry", "dns", "scheduled-task"],
  technique: ["T1059", "T1566", "T1071", "T1190", "T1485"],
  confidence: ["high", "medium", "low"],
  status: ["new", "acknowledged", "resolved"],
};

function MetaChips({ item }: { item: SearchItem }) {
  const meta = item.metadata ?? {};
  switch (item.type) {
    case "case":
      return <Chip tone="default">{meta.state}</Chip>;
    case "finding":
      return <Chip tone={severityTone(meta.severity)}>{meta.severity}</Chip>;
    case "ioc":
      return <><Chip tone={severityTone(meta.severity)}>{meta.iocType}</Chip><Chip tone="default">{meta.severity}</Chip></>;
    case "event":
      return <Chip tone="default">{meta.kind}</Chip>;
    case "report":
      return <Chip tone="default">{meta.state}</Chip>;
    case "detection":
      return <Chip tone="default">{meta.format}</Chip>;
    case "mitre":
      return <Chip tone="info">{meta.tactic}</Chip>;
    case "entity":
      return <><Chip tone="accent">{ENTITY_TYPE_LABEL[meta.entityType ?? ""] ?? meta.entityType}</Chip><Chip tone={confidenceTone(meta.confidence)}>{meta.confidence}</Chip></>;
    case "alert":
      return <><Chip tone={severityTone(meta.severity)}>{meta.severity}</Chip><Chip tone="default">{meta.status}</Chip></>;
    default:
      return null;
  }
}

export function GlobalSearch({ open, onOpenChange, initialQuery }: { open: boolean; onOpenChange: (o: boolean) => void; initialQuery?: string }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const { qualifiers, text } = parseQualifiers(query);
  const intent = detectIntent(text);
  const results = applyIntent(useSearch(intent.scope ? intent.term : text), intent);

  const lastToken = query.trim().split(/\s+/).at(-1) ?? "";
  const suggestionMatch = lastToken.match(/^([a-zA-Z]+):$/);
  const suggestions = suggestionMatch ? QUALIFIER_VALUES[suggestionMatch[1].toLowerCase()] : undefined;

  useEffect(() => {
    if (open) setQuery(initialQuery ?? "");
    else setQuery("");
  }, [open, initialQuery]);

  const removeQualifier = (target: Qualifier) => {
    setQuery(query.trim().split(/\s+/).filter((t) => t !== `${target.key}:${target.value}`).join(" "));
  };

  const grouped = useMemo(() => {
    const map = new Map<string, SearchItem[]>();
    for (const r of results) {
      const key = r.type;
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(r);
    }
    return Array.from(map.entries()).sort((a, b) => (TYPE_ORDER[a[0]] ?? 99) - (TYPE_ORDER[b[0]] ?? 99));
  }, [results]);

  const go = (item: SearchItem) => {
    onOpenChange(false);
    if (item.url) { navigate({ to: item.url }); return; }
    if (item.caseId) setActiveCaseId(item.caseId);
    const search: Record<string, string> = {};
    if (item.tab) search.tab = item.tab;
    if (item.refIdx !== undefined) search.highlight = String(item.refIdx);
    navigate({ to: "/case", search } as any);
  };

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange} label="Search investigations" shouldFilter={false}>
      <CommandInput
        aria-label="Search investigations"
        placeholder="Search investigations… (try severity:high, type:ioc, technique:T1059)"
        onValueChange={v => setQuery(v)}
        value={query}
      />
      {qualifiers.length > 0 && (
        <div className="flex flex-wrap items-center gap-1 border-b border-divider-soft px-3 py-1.5">
          {qualifiers.map((q) => (
            <Chip key={`${q.key}:${q.value}`} tone="primary"
              actions={<button aria-label={`Remove ${q.key}:${q.value}`} onClick={() => removeQualifier(q)} className="text-primary/70 hover:text-primary"><X className="h-3 w-3" /></button>}>
              {q.key}:{q.value}
            </Chip>
          ))}
        </div>
      )}
      {suggestions && (
        <div className="flex flex-wrap items-center gap-1 border-b border-divider-soft px-3 py-1.5">
          <span className="text-mono ba-text-2xs text-muted-foreground">{suggestionMatch![1].toLowerCase()}:</span>
          {suggestions.map((v) => (
            <button key={v} onClick={() => setQuery(query + v)} className="rounded border border-subtle bg-surface-1 px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:text-primary">
              {v}
            </button>
          ))}
        </div>
      )}
      <CommandList className="max-h-[70vh]">
        <CommandEmpty>No results.</CommandEmpty>
        {intent.note && (
          <div className="flex items-center gap-2 border-b border-divider-soft px-3 py-1 text-mono ba-text-2xs text-primary">
            <Chip tone="primary">intent</Chip>
            {intent.note}
          </div>
        )}
        {grouped.map(([type, items]) => {
          const Icon = ITEM_ICON[type] ?? Search;
          return (
            <CommandGroup key={type} heading={`${TYPE_LABEL[type] ?? type} (${items.length})`}>
              {items.map((item) => (
                <CommandItem key={item.id} onSelect={() => go(item)} value={`${item.label} ${item.description} ${item.tags}`}>
                  <Icon className="h-4 w-4 shrink-0" />
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <span className="truncate text-mono text-[12.5px]">{item.label}</span>
                    <span className="flex flex-wrap items-center gap-1">
                      <Chip tone={TYPE_META[type]?.tone ?? "default"}>{TYPE_META[type]?.label ?? type}</Chip>
                      <MetaChips item={item} />
                    </span>
                    <span className="truncate ba-text-2xs text-muted-foreground">{item.description}</span>
                  </div>
                  {item.caseTitle && (
                    <span className="ml-auto shrink-0 truncate ba-text-2xs text-muted-foreground">{item.caseTitle}</span>
                  )}
                </CommandItem>
              ))}
            </CommandGroup>
          );
        })}
      </CommandList>
      <div className="flex items-center gap-3 border-t border-divider-soft bg-surface-0 px-3 py-1 text-mono ba-text-2xs text-muted-foreground">
        <span className="flex items-center gap-1"><kbd className="rounded border border-subtle bg-surface-1 px-1">↑↓</kbd> navigate</span>
        <span className="flex items-center gap-1"><kbd className="rounded border border-subtle bg-surface-1 px-1">↵</kbd> open case</span>
        <span className="flex items-center gap-1"><kbd className="rounded border border-subtle bg-surface-1 px-1">Esc</kbd> close</span>
        <span className="ml-auto hidden sm:inline">qualifiers: type: severity: tag: state: source: technique: format: ioctype:</span>
      </div>
    </CommandDialog>
  );
}
