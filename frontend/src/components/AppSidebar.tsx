import { useState, useEffect, useRef, useCallback } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import {
  Pin, Settings as SettingsIcon, ChevronDown, Notebook, FolderOpen,
} from "lucide-react";
import {
  Sidebar, SidebarContent, SidebarHeader, SidebarFooter, useSidebar,
} from "@/components/ui/sidebar";
import { GROUPS, findItem, type WorkspaceItem } from "@/lib/workspaces";
import { usePrefs, getBrandIcon } from "@/lib/prefs";
import { useActiveCase } from "@/data/case";
import { useTriageCounts } from "@/data/triage";
import { useLocker } from "@/lib/locker";
import { ThemeSwitcher } from "@/components/ThemeSwitcher";
import { cn } from "@/lib/utils";

function Row({
  item, active, pinned, onTogglePin, collapsed, badge,
}: {
  item: WorkspaceItem;
  active: boolean;
  pinned: boolean;
  onTogglePin: (url: string) => void;
  collapsed: boolean;
  badge?: React.ReactNode;
}) {
  const Icon = item.icon;
  return (
    <li className="relative">
      <Link
        to={item.url}
        title={collapsed ? item.title : undefined}
        className={cn(
          "group/row relative flex h-7 items-center gap-2 rounded-md px-2 transition-colors duration-150 focus-visible:outline-none",
          "text-mono ba-text-base tracking-tight",
          active
            ? "bg-sidebar-accent text-sidebar-accent-foreground font-medium"
            : "text-sidebar-foreground/75 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground",
          "focus-visible:ring-2 focus-visible:ring-sidebar-ring focus-visible:ring-offset-1 focus-visible:ring-offset-sidebar",
        )}
      >
        <span
          aria-hidden
          className={cn(
            "absolute left-0 top-1/2 h-4 w-[2px] -translate-y-1/2 rounded-r transition-all",
            active ? "bg-primary shadow-[0_0_8px_var(--primary)]" : "bg-transparent group-hover/row:bg-sidebar-border",
          )}
        />
        <Icon className={cn("h-4 w-4 shrink-0 transition-transform translate-y-[0.5px]", active ? "text-primary" : "group-hover/row:scale-110")} />
        {!collapsed && <span className="flex-1 truncate">{item.title}</span>}
        {!collapsed && badge}
        {!collapsed && (
          <button
            type="button"
            onClick={(e) => { e.preventDefault(); e.stopPropagation(); onTogglePin(item.url); }}
            aria-label={pinned ? "Unpin" : "Pin"}
            className={cn(
              "grid h-5 w-5 place-items-center rounded transition-all ml-1",
              pinned
                ? "text-primary opacity-100"
                : "text-sidebar-foreground/40 opacity-0 group-hover/row:opacity-100 hover:bg-sidebar-accent hover:text-sidebar-foreground",
            )}
          >
            {pinned ? <Pin className="h-3 w-3 fill-current" /> : <Pin className="h-3 w-3" />}
          </button>
        )}
      </Link>
    </li>
  );
}

function GroupBlock({
  label, count, badge, collapsed, defaultOpen, children,
}: {
  label: string;
  count: number;
  badge?: React.ReactNode;
  collapsed: boolean;
  defaultOpen: boolean;
  children: React.ReactNode;
}) {
  const storageKey = `ba.sidebar.group.${label}`;
  const [open, setOpen] = useState(() => {
    const saved = typeof window !== "undefined" ? localStorage.getItem(storageKey) : null;
    return saved !== null ? saved === "true" : defaultOpen;
  });
  useEffect(() => { localStorage.setItem(storageKey, String(open)); }, [open, storageKey]);
  if (collapsed) return <div className="px-1.5 py-1">{children}</div>;
  return (
    <div className="px-1.5 py-1">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="group/g flex w-full items-center gap-1.5 rounded px-1.5 py-0.5 text-mono ba-text-3xs font-semibold tracking-wider uppercase text-sidebar-foreground/50 hover:text-sidebar-foreground/80 transition-colors"
      >
        <ChevronDown className={cn("h-2.5 w-2.5 transition-transform text-sidebar-foreground/40", open ? "" : "-rotate-90")} />
        <span>{label}</span>
        {badge ? (
          <span className="ml-auto">{badge}</span>
        ) : (
          <span className="ml-auto rounded-sm border border-sidebar-border/60 bg-sidebar-accent/40 px-1 ba-text-3xs text-sidebar-foreground/50 font-normal">
            {count}
          </span>
        )}
      </button>
      {open && <ul className="mt-0.5 space-y-px">{children}</ul>}
    </div>
  );
}

export function AppSidebar() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const isActive = (url: string) => (url === "/" ? pathname === "/" : pathname === url || pathname.startsWith(url + "/"));
  const { prefs, togglePin } = usePrefs();
  const BrandIcon = getBrandIcon(prefs.brandIcon);
  const { state } = useSidebar();
  const collapsed = state === "collapsed";
  const { activeCase } = useActiveCase();
  const triageCounts = useTriageCounts();
  const { count: lockerCount } = useLocker();
  const contentRef = useRef<HTMLDivElement>(null);

  const handleSidebarKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const nav = contentRef.current;
    if (!nav) return;
    const foci = nav.querySelectorAll<HTMLElement>("a, button");
    const current = document.activeElement;
    const idx = Array.from(foci).indexOf(current as HTMLElement);
    if (idx === -1) return;
    const next = e.key === "ArrowDown"
      ? Math.min(idx + 1, foci.length - 1)
      : Math.max(idx - 1, 0);
    foci[next]?.focus();
  }, []);

  const order = prefs.sidebar.order.length ? prefs.sidebar.order : GROUPS.map((g) => g.label);
  const ordered = order
    .map((label) => GROUPS.find((g) => g.label === label))
    .filter((g): g is NonNullable<typeof g> => !!g && !prefs.sidebar.hiddenGroups.includes(g.label) && g.label !== "System");

  const pinnedItems = prefs.sidebar.pinned
    .map(findItem)
    .filter((x): x is NonNullable<typeof x> => !!x);

  const totalCount = ordered.reduce((s, g) => s + g.items.length, 0);

  const getItemBadge = (url: string) => {
    if (url === "/triage" && triageCounts.open > 0) {
      return (
        <span className="rounded-full bg-amber-500/15 border border-amber-500/35 px-1.5 py-0.2 text-mono text-[9px] font-semibold text-amber-400">
          {triageCounts.open} open
        </span>
      );
    }
    if ((url === "/case" || url === "/investigation") && activeCase) {
      return (
        <span className="rounded border border-primary/40 bg-primary/15 px-1 text-mono text-[8px] text-primary uppercase font-bold tracking-wider">
          {activeCase.state}
        </span>
      );
    }
    return null;
  };

  const getGroupBadge = (groupLabel: string) => {
    if (groupLabel === "Intake" && triageCounts.open > 0) {
      return (
        <span className="rounded-full bg-amber-500/15 border border-amber-500/35 px-1.5 py-0.2 text-mono text-[9px] font-semibold text-amber-400">
          {triageCounts.open}
        </span>
      );
    }
    if (groupLabel === "Investigation" && activeCase) {
      return (
        <span className="rounded border border-primary/40 bg-primary/20 px-1 text-mono text-[8px] text-primary uppercase font-medium">
          active
        </span>
      );
    }
    return null;
  };

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="border-b border-sidebar-border/70 p-0">
        <Link to="/" className="flex items-center gap-2 px-3 py-2.5">
          <div className="relative grid h-7 w-7 shrink-0 place-items-center rounded-md bg-gradient-to-br from-sidebar-primary to-accent text-sidebar-primary-foreground shadow-glow">
            <BrandIcon className="h-3.5 w-3.5" />
            <span className="absolute -bottom-0.5 -right-0.5 h-1.5 w-1.5 rounded-full bg-success ring-2 ring-sidebar ba-glow" aria-hidden />
          </div>
          <div className="min-w-0 group-data-[collapsible=icon]:hidden">
            <div className="text-mono ba-text-sm font-bold leading-tight tracking-tight truncate">{prefs.brandName}</div>
          </div>
        </Link>

        <div className="group-data-[collapsible=icon]:hidden px-2 pb-2 space-y-1">
          {activeCase ? (
            <Link
              to="/case"
              className="flex items-center gap-1.5 rounded-md border border-primary/30 bg-primary/10 px-2 py-1.5 text-mono ba-text-2xs text-sidebar-foreground/80 hover:text-sidebar-foreground hover:bg-primary/15 transition-all duration-150 group"
            >
              <Notebook className="h-3.5 w-3.5 shrink-0 text-primary" />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1">
                  <span className="text-[9px] font-bold text-primary uppercase tracking-wider">{activeCase.id}</span>
                  <span className="text-sidebar-foreground/40">·</span>
                  <span className="text-[9px] text-sidebar-foreground/60 truncate">{activeCase.title}</span>
                </div>
              </div>
              <span className="rounded border border-primary/40 bg-primary/20 px-1 text-[8px] text-primary font-semibold uppercase">{activeCase.state}</span>
            </Link>
          ) : (
            <Link
              to="/case"
              className="flex items-center gap-1.5 rounded-md border border-dashed border-sidebar-border/60 bg-sidebar-accent/10 px-2 py-1.5 text-mono ba-text-3xs text-sidebar-foreground/50 hover:text-sidebar-foreground hover:border-sidebar-border/90 hover:bg-sidebar-accent/20 transition-all duration-150"
            >
              <FolderOpen className="h-3 w-3 shrink-0 text-sidebar-foreground/40" />
              <span className="truncate">No active case · start new</span>
            </Link>
          )}
        </div>
      </SidebarHeader>

      <SidebarContent className="gap-0" ref={contentRef} onKeyDown={handleSidebarKeyDown}>
        {pinnedItems.length > 0 && (
          <GroupBlock label="Pinned" count={pinnedItems.length} collapsed={collapsed} defaultOpen>
            {pinnedItems.map((item) => (
              <Row
                key={`pin-${item.url}`}
                item={item}
                active={isActive(item.url)}
                pinned
                onTogglePin={togglePin}
                collapsed={collapsed}
                badge={getItemBadge(item.url)}
              />
            ))}
          </GroupBlock>
        )}

        {ordered.map((g, gi) => {
          return (
            <div key={g.label}>
              {gi > 0 && <div className="mx-2 border-t border-sidebar-border/15" />}
              <GroupBlock
                label={g.label}
                count={g.items.length}
                badge={getGroupBadge(g.label)}
                collapsed={collapsed}
                defaultOpen={g.label === "Dashboard" || g.label === "Intake" || g.label === "Investigation" || g.label === "SIEM"}
              >
                {g.items.map((item) => (
                  <Row
                    key={item.url}
                    item={item}
                    active={isActive(item.url)}
                    pinned={prefs.sidebar.pinned.includes(item.url)}
                    onTogglePin={togglePin}
                    collapsed={collapsed}
                    badge={getItemBadge(item.url)}
                  />
                ))}
              </GroupBlock>
            </div>
          );
        })}
      </SidebarContent>

      <SidebarFooter className="border-t border-sidebar-border/70 gap-1.5 p-2">
        <div className={cn("w-full flex", collapsed ? "justify-center" : "")}>
          <ThemeSwitcher collapsed={collapsed} />
        </div>

        <div className="flex items-center gap-1">
          <Link
            to="/settings"
            title="Settings"
            className={cn(
              "flex h-8 flex-1 items-center gap-2 rounded-md px-2 text-mono ba-text-base transition-colors duration-150 focus-visible:outline-none",
              "focus-visible:ring-2 focus-visible:ring-sidebar-ring focus-visible:ring-offset-1 focus-visible:ring-offset-sidebar",
              isActive("/settings")
                ? "bg-sidebar-accent text-sidebar-accent-foreground font-medium"
                : "text-sidebar-foreground/75 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground",
            )}
          >
            <SettingsIcon className="h-4 w-4 shrink-0" />
            <span className="group-data-[collapsible=icon]:hidden">Settings</span>
          </Link>
        </div>

        <div className="flex items-center justify-between px-1 text-mono ba-text-3xs text-sidebar-foreground/45 group-data-[collapsible=icon]:hidden">
          <span className="flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 shadow-[0_0_6px_var(--color-emerald-500)]" />
            <span>Offline-Safe</span>
          </span>
          {lockerCount > 0 && (
            <span className="rounded border border-sidebar-border/60 bg-sidebar-accent/40 px-1 text-sidebar-foreground/70">
              Locker: {lockerCount}
            </span>
          )}
          <span>{totalCount} workspaces</span>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
