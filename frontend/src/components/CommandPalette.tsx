import { useEffect, useMemo, useState, useCallback, useRef, useSyncExternalStore } from "react";
import { useNavigate } from "@tanstack/react-router";
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { useRecents } from "@/lib/recents";
import { useLocker } from "@/lib/locker";
import { useActiveCase } from "@/data/case";
import { useTheme, THEMES } from "@/lib/theme";
import { usePrefs } from "@/lib/prefs";
import { useSearch } from "@/lib/search-engine";
import { Search } from "lucide-react";
import { navigationProvider, searchProvider, investigationProvider, intakeProvider, detectionProvider, actionProvider, recentCommandProvider, macrosProvider } from "@/lib/palette/providers";
import { rankResults } from "@/lib/palette/engine";
import { recordRecentCommand } from "@/lib/palette/recent";
import type { PaletteContext, CommandResult } from "@/lib/palette/types";

const paletteState = { open: false, shortcutsOpen: false };
const paletteListeners = new Set<() => void>();
let paletteSnapshot = { ...paletteState };
let listenersRegistered = 0;

function emitPalette() {
  paletteSnapshot = { ...paletteState };
  for (const l of paletteListeners) l();
}

function setPaletteState(partial: Partial<typeof paletteState>) {
  Object.assign(paletteState, partial);
  emitPalette();
}

export function CommandPalette({ open, onOpenChange, onSearchInvestigations }: { open: boolean; onOpenChange: (o: boolean) => void; onSearchInvestigations?: (query: string) => void }) {
  const navigate = useNavigate();
  const { theme, setTheme } = useTheme();
  const recents = useRecents();
  const locker = useLocker();
  const { activeCase } = useActiveCase();
  const [searchValue, setSearchValue] = useState("");

  const investResults = useSearch(searchValue, { log: false });

  useEffect(() => {
    if (!open) setSearchValue("");
  }, [open]);

  const go = useCallback((url: string) => {
    onOpenChange(false);
    navigate({ to: url } as any);
  }, [navigate, onOpenChange]);

  const paletteCtx = useMemo<PaletteContext>(() => ({
    activeCase: activeCase ? { id: activeCase.id, title: activeCase.title } : null,
    recentPaths: recents,
    lockerCount: locker.count,
  }), [activeCase, recents, locker.count]);

  const cycleTheme = useCallback(() => {
    const ids = THEMES.map((t) => t.id);
    const next = ids[(ids.indexOf(theme) + 1) % ids.length];
    setTheme(next);
  }, [theme, setTheme]);

  const copyFirstIoc = useCallback(() => {
    const first = locker.items[0];
    if (!first) return;
    try { navigator.clipboard.writeText(first.value); } catch {}
  }, [locker.items]);

  // Macros re-resolve step ids against live providers at run time; the ref
  // breaks the construction cycle (providers need the resolver, the resolver
  // scans providers).
  const resolverRef = useRef<(id: string) => CommandResult | null>(() => null);

  const providers = useMemo(() => {
    const ctxFn = () => paletteCtx;
    return [
      recentCommandProvider(go),
      macrosProvider((id) => resolverRef.current(id)),
      navigationProvider(go),
      searchProvider(go),
      investigationProvider(go, investResults),
      intakeProvider(go),
      detectionProvider(go),
      actionProvider(go, ctxFn, cycleTheme, copyFirstIoc),
    ];
  }, [go, paletteCtx, investResults, cycleTheme, copyFirstIoc]);

  useEffect(() => {
    resolverRef.current = (id: string) => {
      for (const p of providers) {
        for (const r of p.getResults("", paletteCtx)) {
          if (r.id === id) return r;
        }
      }
      return null;
    };
  }, [providers, paletteCtx]);

  const grouped = useMemo(() => rankResults(providers, searchValue, paletteCtx), [providers, searchValue, paletteCtx]);

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange} label="Command palette">
      <CommandInput
        placeholder="What do you want to do? Navigate, search, analyze, create…"
        onValueChange={(v) => setSearchValue(v)}
        value={searchValue}
      />

      {searchValue && (
        <div className="flex items-center gap-2 border-b border-divider-soft bg-surface-0 px-3 py-1.5 text-mono ba-text-2xs text-muted-foreground">
          <Search className="h-3 w-3" />
          <span>
            Filtering for "<span className="text-fg-dim">{searchValue}</span>"
          </span>
          {onSearchInvestigations && (
            <button onClick={() => onSearchInvestigations(searchValue)} className="ml-auto rounded border border-subtle bg-surface-1 px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:bg-card/70 hover:text-foreground transition-colors duration-150">
              Full investigation search
            </button>
          )}
        </div>
      )}

      <CommandList className="max-h-[70vh]">
        <CommandEmpty>No matching actions. Try typing an IP, URL, CVE, hash, or domain.</CommandEmpty>

        {grouped.map((g) => (
          <CommandGroup key={g.header} heading={g.header}>
            {g.results.map((r) => {
              const Icon = r.icon;
              return (
                <CommandItem
                  key={r.id}
                  onSelect={() => { recordRecentCommand(r.id, r.title); r.run(); }}
                  value={`${r.title} ${r.subtitle ?? ""} ${r.keywords.join(" ")} ${g.header}`}
                >
                  <Icon className="h-4 w-4" />
                  <span className="text-mono text-[12.5px]">{r.title}</span>
                  {r.subtitle && (
                    <span className="ml-auto truncate ba-text-2xs text-muted-foreground">{r.subtitle}</span>
                  )}
                </CommandItem>
              );
            })}
          </CommandGroup>
        ))}
      </CommandList>

      <div className="flex items-center gap-3 border-t border-divider-soft bg-surface-0 px-3 py-1 text-mono ba-text-2xs text-muted-foreground">
        <span className="flex items-center gap-1"><kbd className="rounded border border-subtle bg-surface-1 px-1">↑↓</kbd> navigate</span>
        <span className="flex items-center gap-1"><kbd className="rounded border border-subtle bg-surface-1 px-1">↵</kbd> open</span>
        <span className="flex items-center gap-1"><kbd className="rounded border border-subtle bg-surface-1 px-1">Esc</kbd> close</span>
        <span className="ml-auto text-mono ba-text-3xs text-fg-dim/60">Type an IP, CVE, hash, or domain for contextual actions</span>
      </div>
    </CommandDialog>
  );
}

export function ShortcutsDialog(_props: { open?: boolean; onClose?: () => void }) {
  return null;
}

export function useCommandPalette() {
  const state = useSyncExternalStore(
    (cb) => { paletteListeners.add(cb); return () => paletteListeners.delete(cb); },
    () => paletteSnapshot,
    () => paletteSnapshot,
  );

  useEffect(() => {
    if (listenersRegistered > 0) { listenersRegistered++; return () => { listenersRegistered--; }; }
    listenersRegistered = 1;
    const onKey = (e: KeyboardEvent) => {
      const meta = e.metaKey || e.ctrlKey;
      // Only Command Palette (⌘K) remains as an active shortcut
      if (meta && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteState({ open: !paletteState.open });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); listenersRegistered = 0; };
  }, []);

  return {
    open: state.open,
    setOpen: (o: boolean) => setPaletteState({ open: o }),
    shortcutsOpen: false,
    setShortcutsOpen: (_o: boolean) => {},
  };
}
