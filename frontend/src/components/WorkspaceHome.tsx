import { useEffect, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { ArrowRight, CornerDownLeft, History } from "lucide-react";
import { cn } from "@/lib/utils";
import { findItem } from "@/lib/workspaces";
import { readRecents } from "@/lib/recents";
import { getSearchLog } from "@/lib/search-engine";
import { useCaseList } from "@/data/case";
import { searchIntel } from "@/data/intel";
import { Empty } from "@/components/output/empty";

const TYPE_LABEL: Record<string, string> = {
  vulnerability: "Vulnerabilities",
  "threat-actor": "Threat Actors",
  malware: "Malware",
  "file-hash": "File Hashes",
  "tls-fingerprint": "TLS Fingerprints",
};

/* ── Shared entry-point blocks for workspace homes ──────── */

export function StartWorking({
  to,
  label,
  desc,
  icon: Icon,
  hint,
  onClick,
}: {
  to?: string;
  label: string;
  desc?: string;
  icon: import("lucide-react").LucideIcon;
  hint?: string;
  onClick?: () => void;
}) {
  const navigate = useNavigate();
  return (
    <button
      onClick={() => { if (onClick) onClick(); else if (to) navigate({ to }); }}
      className="group flex w-full items-center justify-between gap-4 rounded-lg border border-primary/40 bg-primary/10 px-5 py-4 text-left shadow-sm transition-all duration-150 hover:bg-primary/15 hover:shadow-md active:scale-[0.99]"
    >
      <div className="flex items-center gap-3.5">
        <div className="grid h-9 w-9 shrink-0 place-items-center rounded border border-primary/30 bg-primary/10 text-primary">
          <Icon className="h-4 w-4" />
        </div>
        <div>
          <div className="text-mono ba-text-2xs text-fg-dim">start working</div>
          <div className="text-base font-medium leading-snug text-foreground">{label}</div>
          {desc && <div className="ba-text-sm text-muted-foreground">{desc}</div>}
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <ArrowRight className="h-4 w-4 text-primary opacity-50 transition-opacity group-hover:opacity-100" />
      </div>
    </button>
  );
}

export function HomeSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <div className="mb-2 flex items-center gap-2">
        <span className="text-mono ba-text-2xs font-medium uppercase tracking-wider text-muted-foreground">{title}</span>
        <span className="h-px flex-1 bg-divider" />
      </div>
      {children}
    </section>
  );
}

export function QuickLinks({ links, cols = 3 }: { links: { to: string; icon: import("lucide-react").LucideIcon; title: string; desc?: string }[]; cols?: 2 | 3 }) {
  const navigate = useNavigate();
  return (
    <div className={cn("grid gap-2", cols === 2 ? "grid-cols-1 sm:grid-cols-2" : "grid-cols-1 sm:grid-cols-2 lg:grid-cols-3")}>
      {links.map((l) => (
        <button
          key={l.to}
          onClick={() => navigate({ to: l.to })}
          className="group flex items-start gap-3 rounded-lg border border-subtle bg-surface-0 p-3 text-left transition-all duration-150 hover:-translate-y-px hover:border-primary/40 hover:bg-surface-1 hover:shadow-sm"
        >
          <span className="grid h-7 w-7 shrink-0 place-items-center rounded-md border border-subtle bg-surface-0 text-primary transition-colors group-hover:border-primary/40 group-hover:bg-primary/10">
            <l.icon className="h-3.5 w-3.5" />
          </span>
          <div className="min-w-0">
            <div className="truncate text-sm font-medium text-foreground group-hover:text-primary">{l.title}</div>
            {l.desc && <div className="truncate ba-text-2xs text-muted-foreground">{l.desc}</div>}
          </div>
        </button>
      ))}
    </div>
  );
}

export function KbdHints(_props: { items: [string, string][] }) {
  return null;
}

/* ── Recents (honest: read-only views over persisted stores) ── */

export function RecentSearches({ label, limit = 5, onPick }: { label?: string; limit?: number; onPick: (q: string) => void }) {
  const [log, setLog] = useState<{ q: string; ts: number }[]>([]);
  useEffect(() => {
    const seen = new Set<string>();
    const deduped: { q: string; ts: number }[] = [];
    for (const e of [...getSearchLog()].reverse()) {
      const q = e.q.trim().toLowerCase();
      if (seen.has(q)) continue;
      seen.add(q);
      deduped.push(e);
      if (deduped.length >= limit) break;
    }
    setLog(deduped);
  }, [limit]);
  if (log.length === 0) return null;
  const chips = (
    <div className="flex flex-wrap gap-1.5">
      {log.map((e, i) => (
        <button
          key={`${e.ts}-${e.q}-${i}`}
          onClick={() => onPick(e.q)}
          className="rounded border border-subtle bg-surface-0 px-2 py-1 font-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-primary"
          title={new Date(e.ts).toLocaleString()}
        >
          {e.q}
        </button>
      ))}
    </div>
  );
  if (!label) return chips;
  return <HomeSection title={label}>{chips}</HomeSection>;
}

export function RecentEntities({ label, limit = 4, onPick }: { label?: string; limit?: number; onPick: (q: string) => void }) {
  const [rows, setRows] = useState<{ q: string; title: string; type: string }[]>([]);
  useEffect(() => {
    const derived: { q: string; title: string; type: string }[] = [];
    const seen = new Set<string>();
    for (const e of [...getSearchLog()].reverse()) {
      if (derived.length >= limit) break;
      const res = searchIntel(e.q);
      const top = res.entityGroups[0]?.entities[0];
      if (!top) continue;
      const key = `${top.type}:${top.title.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      derived.push({ q: e.q, title: top.title, type: top.type });
    }
    setRows(derived);
  }, [limit]);
  if (rows.length === 0) return null;
  const list = (
    <div className="space-y-1.5">
      {rows.map((r, i) => (
        <button
          key={`${r.q}-${i}`}
          onClick={() => onPick(r.q)}
          className="flex w-full items-center justify-between gap-2 rounded border border-subtle bg-surface-0 px-3 py-2 text-left transition-colors duration-150 hover:border-primary/40 hover:bg-surface-1"
        >
          <span className="truncate text-sm text-foreground">{r.title}</span>
          <span className="shrink-0 rounded border border-subtle bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-fg-dim">
            {TYPE_LABEL[r.type] ?? r.type}
          </span>
        </button>
      ))}
    </div>
  );
  if (!label) return list;
  return <HomeSection title={label}>{list}</HomeSection>;
}

export function RecentCases({ limit = 5 }: { limit?: number }) {
  const cases = useCaseList().slice(0, limit);
  const navigate = useNavigate();
  if (cases.length === 0) return null;
  return (
    <div className="space-y-1.5">
      {cases.map((c) => (
        <button
          key={c.id}
          onClick={() => navigate({ to: "/case" })}
          className="flex w-full items-center justify-between gap-2 rounded border border-subtle bg-surface-0 px-3 py-2 text-left transition-colors duration-150 hover:border-primary/40 hover:bg-surface-1"
        >
          <span className="flex min-w-0 items-center gap-2">
            <CornerDownLeft className="h-3 w-3 shrink-0 text-fg-dim" />
            <span className="truncate text-sm text-foreground">{c.title}</span>
            {c.state === "active"
              ? <span className="shrink-0 rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-mono ba-text-3xs text-primary">active</span>
              : <span className="shrink-0 rounded border border-subtle bg-surface-1 px-1.5 py-0.5 text-mono ba-text-3xs text-fg-dim">closed</span>}
          </span>
          <span className="shrink-0 font-mono ba-text-2xs text-fg-dim">
            {c.entries.length} entries · {new Date(c.createdAt).toLocaleDateString()}
          </span>
        </button>
      ))}
    </div>
  );
}

export function RecentTools({ group, limit = 8, empty }: { group: string; limit?: number; empty: string }) {
  const [tools, setTools] = useState<{ url: string; title: string; icon: import("lucide-react").LucideIcon }[]>([]);
  const navigate = useNavigate();
  useEffect(() => {
    const seen = new Set<string>();
    const items: { url: string; title: string; icon: import("lucide-react").LucideIcon }[] = [];
    for (const url of readRecents()) {
      const item = findItem(url);
      if (!item || item.group !== group || seen.has(url)) continue;
      seen.add(url);
      items.push({ url, title: item.title, icon: item.icon });
      if (items.length >= limit) break;
    }
    setTools(items);
  }, [group, limit]);
  if (tools.length === 0) {
    return <Empty compact icon={History} title="Nothing recent yet" hint={empty} />;
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {tools.map((t) => (
        <button
          key={t.url}
          onClick={() => navigate({ to: t.url })}
          className="inline-flex items-center gap-1.5 rounded border border-subtle bg-surface-0 px-2 py-1 ba-text-2xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-primary"
        >
          <t.icon className="h-3 w-3" /> {t.title}
        </button>
      ))}
    </div>
  );
}
