import type { ReactNode } from "react";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { ChevronRight, Settings as SettingsIcon, Wifi, ShieldCheck, WifiOff } from "lucide-react";
import { useBackendStatus } from "@/lib/backend";
import { Link, useRouterState } from "@tanstack/react-router";
import { TopSearch } from "./TopSearch";
import { useCommandPalette } from "./CommandPalette";
import { usePrefs, getBrandIcon } from "@/lib/prefs";
import { getWorkspaceIntent, getWorkspaceLabel } from "@/lib/workspaces";
import { ReportSchedulerTicker } from "@/lib/report-schedule";

export type Crumb = { label: string; href?: string };
export type JumpLink = { label: string; to: string };

export function PageShell({
  eyebrow,
  title,
  description,
  actions,
  crumbs,
  meta,
  jumps,
  children,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
  crumbs?: Crumb[];
  meta?: { label: string; value: string; tone?: "default" | "primary" | "warning" | "destructive" | "success" | "info" | "accent" | "muted" }[];
  jumps?: JumpLink[];
  children: ReactNode;
}) {
  const { prefs } = usePrefs();
  const palette = useCommandPalette();
  const BrandIcon = getBrandIcon(prefs.brandIcon);
  const { status } = useBackendStatus();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const intent = getWorkspaceIntent(pathname);

  // Auto-derive workspace crumb from route if not already present
  const resolvedCrumbs = (() => {
    if (!crumbs || crumbs.length === 0) return undefined;
    const ws = getWorkspaceLabel(pathname);
    if (ws && crumbs[0]?.label !== ws) {
      return [{ label: ws }, ...crumbs];
    }
    return crumbs;
  })();

  return (
    <div className="flex min-h-screen flex-col">
      <ReportSchedulerTicker />
      {/* Top bar */}
      {prefs.showTopbar && (
      <header className="sticky top-0 z-30 flex h-[var(--ba-topbar-h)] items-center gap-2 border-b border-divider-strong bg-gradient-to-b from-background/90 to-background/70 px-4 backdrop-blur-md">

        <SidebarTrigger className="-ml-1 h-9 w-9 text-fg-dim hover:text-foreground" />
        <div className="mx-0.5 h-5 w-px bg-border/60" />

        {/* Brand chip (collapsed-friendly) */}
        <Link to="/" className="inline-flex items-center gap-1.5 rounded-md border border-divider-strong bg-surface-1 px-2 py-1 text-foreground hover:border-primary/40 hover:text-primary">
          <BrandIcon className="h-3.5 w-3.5 text-primary" />
          <span className="text-mono ba-text-sm font-semibold tracking-tight">{prefs.brandName}</span>
        </Link>

        {prefs.showBreadcrumb && resolvedCrumbs && resolvedCrumbs.length > 0 && (
          <nav
            aria-label="Breadcrumb"
            className="ml-1 hidden md:flex min-w-0 items-center rounded-md border border-divider-strong bg-surface-1 px-1.5 py-1 text-mono ba-text-sm text-muted-foreground elevation-flat"
          >
            {resolvedCrumbs.map((c, i) => {
              const last = i === resolvedCrumbs.length - 1;
              return (
                <span key={i} className="flex items-center gap-1 truncate">
                  {i > 0 && <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground/50" />}
                  {c.href && !last ? (
                    <Link
                      to={c.href}
                      className="group/crumb relative rounded px-1.5 py-0.5 ba-text-2xs text-muted-foreground transition-colors duration-150 hover:bg-primary/10 hover:text-primary"
                    >
                      {c.label}
                      <span className="pointer-events-none absolute inset-x-1.5 -bottom-px h-px scale-x-0 bg-primary transition-transform duration-200 group-hover/crumb:scale-x-100" />
                    </Link>
                  ) : (
                    <span
                      aria-current={last ? "page" : undefined}
                      className={
                        "truncate px-1.5 py-0.5 ba-text-2xs" +
                        (last ? "rounded bg-primary/10 font-semibold text-primary" : "text-fg-dim")
                      }
                    >
                      {c.label}
                    </span>
                  )}
                </span>
              );
            })}
          </nav>
        )}

        <div className="mx-auto hidden sm:flex flex-1 justify-center px-3">
          <TopSearch onOpenPalette={() => palette.setOpen(true)} />
        </div>

        {/* Status cluster */}
        <div className="hidden sm:flex items-center gap-1.5">
          <span className="inline-flex items-center gap-1 rounded-md border border-success/30 bg-success/10 px-1.5 py-1 text-mono ba-text-2xs text-success" title="All local — nothing sent over the wire">
            <ShieldCheck className="h-3 w-3" /> local
          </span>
          <span
            className={
              "inline-flex items-center gap-1 rounded-md border px-1.5 py-1 text-mono ba-text-2xs" +
              (status === "online"
                ? "border-success/30 bg-success/10 text-success"
                : status === "checking"
                  ? "border-warning/30 bg-warning/10 text-warning"
                  : "border-divider-strong bg-surface-1 text-muted-foreground")
            }
            title={
              status === "online"
                ? "Backend reachable"
                : status === "checking"
                  ? "Checking backend…"
                  : "Backend offline — start it with backend/run.sh. If it is running but the browser blocks requests, set BEYONDLABS_CORS_ORIGINS to this app's origin (see backend/.env.example). Analyzers that need the backend will say so."
            }
          >
            {status === "online" ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
            {status}
          </span>
        </div>

        <Link
          to="/settings"
          className="grid h-9 w-9 place-items-center rounded-md border border-divider-strong bg-surface-1 text-muted-foreground transition-colors duration-150 hover:border-primary/50 hover:bg-card hover:text-foreground"
          aria-label="Settings"
          title="Settings"
        >
          <SettingsIcon className="h-4 w-4" />
        </Link>
      </header>
      )}


      {/* Compact page toolbar — hero collapsed into a toolbar row */}
      <div className="border-b border-divider-strong bg-surface-1/30">
        <div className="mx-auto flex w-full max-w-full flex-wrap items-center justify-between gap-x-4 gap-y-2 px-6 pt-3 pb-2.5 ba-fade-in">
          <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
            {eyebrow && (
              <span className="inline-flex items-center gap-1.5 font-mono ba-text-3xs text-primary/80">
                {eyebrow}
              </span>
            )}
            <h1 className="truncate font-display text-lg font-semibold tracking-tight text-foreground">{title}</h1>
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </div>
        {(description || intent || (meta && meta.length > 0)) && (
          <div className="mx-auto flex w-full max-w-full flex-wrap items-center gap-x-4 gap-y-1.5 px-6 pb-2.5">
            {description && (
              <p className="max-w-3xl font-mono ba-text-xs leading-relaxed text-fg-dim">{description}</p>
            )}
            {intent && (
              <span className="flex items-center gap-1.5 font-mono ba-text-3xs text-muted-foreground">
                <span aria-hidden className="h-px w-5 bg-primary/60" />
                {intent}
              </span>
            )}
            {meta && meta.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5">
                {meta.map((m, i) => (
                  <span
                    key={i}
                    className="inline-flex items-center gap-1.5 rounded-sm border border-divider-soft bg-surface-1 px-1.5 py-0.5"
                  >
                    <span className="font-mono ba-text-3xs text-muted-foreground">{m.label}</span>
                    <span
                      className={
                        "font-mono ba-text-3xs font-semibold " +
                        (m.tone === "warning"
                          ? "text-warning"
                          : m.tone === "destructive"
                          ? "text-destructive"
                          : m.tone === "success"
                          ? "text-success"
                          : m.tone === "primary"
                          ? "text-primary"
                          : "text-foreground")
                      }
                    >
                      {m.value}
                    </span>
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
        {jumps && jumps.length > 0 && (
          <div className="mx-auto flex w-full max-w-full flex-wrap items-center gap-1.5 px-6 pb-3">
            <span className="font-mono ba-text-3xs text-muted-foreground">jump →</span>
            {jumps.map((j) => (
              <Link
                key={j.to}
                to={j.to}
                className="rounded border border-subtle bg-surface-1 px-2 py-0.5 font-mono ba-text-3xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-primary"
              >
                {j.label}
              </Link>
            ))}
          </div>
        )}
      </div>

      <main id="main" tabIndex={-1} className="min-w-0 flex-1 scroll-mt-16 px-6 py-6 focus:outline-none">
        <div className="mx-auto min-w-0 max-w-full space-y-6">{children}</div>
      </main>

      <footer className="border-t border-border px-6 py-4">
        <div className="mx-auto flex max-w-full flex-wrap items-center justify-between gap-2 text-mono ba-text-2xs text-muted-foreground">
          <span>beyondlabs</span>
          <span>analyst-led · no detonation · bounded scans</span>
        </div>
      </footer>
    </div>
  );
}
