import { useState, useEffect, useRef } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Outlet, Link, createRootRouteWithContext, useRouter } from "@tanstack/react-router";

import { ThemeProvider } from "@/lib/theme";
import { PrefsProvider } from "@/lib/prefs";
import { LockerProvider, useLocker } from "@/lib/locker";
import { useRouteRecorder } from "@/lib/recents";
import { SidebarProvider, SidebarInset, useSidebar } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/AppSidebar";
import { ActiveCaseBar } from "@/components/ActiveCaseBar";
import { Toaster } from "@/components/Toaster";
import { IocLockerTrigger, IocLockerPanel } from "@/components/IocLocker";
import { CommandPalette, useCommandPalette } from "@/components/CommandPalette";
import { GlobalSearch } from "@/components/GlobalSearch";


function NotFoundComponent() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="max-w-lg">
        <div className="mb-6 text-mono ba-text-2xs text-primary">
          beyondlabs / terminal
        </div>
        <div className="mb-2 text-mono ba-text-base text-muted-foreground">
          <span className="text-primary">$</span> navigate <span className="text-warning">/wild-path</span>
        </div>
        <div className="text-mono ba-text-base text-destructive">
          command not found: /wild-path
        </div>
        <pre className="my-4 text-mono ba-text-2xs leading-relaxed text-muted-foreground">
{`  hint: try one of
    /parser       — investigation
    /phishing     — email analysis
    /url          — URL analyzer
    /file         — file analysis
    /mitre        — ATT&CK coverage
    /case         — case notebook
    /detection    — detection workspace
    /settings     — preferences
  or run \`help\` for all routes`}
        </pre>
        <div className="mt-6">
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 py-1.5 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"
          >
            <span className="ba-text-base">$</span> cd ~
          </Link>
        </div>
      </div>
    </div>
  );
}

function ErrorComponent({ error, reset }: { error: Error; reset: () => void }) {
  console.error(error);
  const router = useRouter();

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="max-w-md text-center">
        <div className="mb-4 text-mono ba-text-2xs text-destructive">
          runtime / exception
        </div>
        <h1 className="text-xl font-semibold tracking-tight text-foreground">
          This page didn't load
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Something went wrong. Try refreshing or head back home.
        </p>
        <div className="mt-6 flex flex-wrap justify-center gap-2">
          <button
            onClick={() => { router.invalidate(); reset(); }}
            className="inline-flex items-center gap-1.5 rounded-md border border-primary/40 bg-primary/10 px-3 py-1.5 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"
          >
            $ retry
          </button>
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 rounded-md border border-divider-strong bg-surface-1 px-3 py-1.5 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:text-foreground"
          >
            $ cd ~
          </Link>
        </div>
      </div>
    </div>
  );
}

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: RootComponent,
  notFoundComponent: NotFoundComponent,
  errorComponent: ErrorComponent,
});

function RouteRecorder() {
  useRouteRecorder();
  return null;
}

function RootComponent() {
  const { queryClient } = Route.useRouteContext();
  const [lockerOpen, setLockerOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const palette = useCommandPalette();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const meta = e.metaKey || e.ctrlKey;
      if (meta && e.shiftKey && e.key.toLowerCase() === "f") {
        e.preventDefault();
        setSearchOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <PrefsProvider>
          <LockerProvider>
          <SidebarProvider>
            <a
              href="#main"
              onClick={(e) => {
                e.preventDefault();
                const main = document.getElementById("main");
                if (main) { main.scrollIntoView(); main.focus(); }
              }}
              className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[100] focus:rounded-md focus:border focus:border-primary/50 focus:bg-card focus:px-3 focus:py-2 focus:font-mono focus:text-sm focus:text-foreground focus:shadow-lg"
            >
              Skip to main content
            </a>
            <AppSidebar />
            <SidebarAutoFit />
            <SidebarInset className="w-full">
              <ActiveCaseBar />
              <RouteRecorder />
              <Outlet />
              <LockerUI open={lockerOpen} onOpenChange={setLockerOpen} />
              <Toaster />
            </SidebarInset>
            <CommandPalette open={palette.open} onOpenChange={palette.setOpen} onSearchInvestigations={(q) => { setSearchQuery(q); setSearchOpen(true); }} />
            <GlobalSearch open={searchOpen} onOpenChange={setSearchOpen} initialQuery={searchQuery} />
          </SidebarProvider>
          </LockerProvider>
        </PrefsProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

function SidebarAutoFit() {
  const { setOpen } = useSidebar();
  const collapsedByUs = useRef(false);
  useEffect(() => {
    const mql = window.matchMedia("(max-width: 1099px)");
    const apply = () => {
      if (mql.matches) {
        setOpen(false);
        collapsedByUs.current = true;
      } else if (collapsedByUs.current) {
        setOpen(true);
        collapsedByUs.current = false;
      }
    };
    apply();
    mql.addEventListener("change", apply);
    return () => mql.removeEventListener("change", apply);
  }, [setOpen]);
  return null;
}

function LockerUI({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { count } = useLocker();
  useEffect(() => {
    const fn = () => onOpenChange(true);
    window.addEventListener("ba:locker-open", fn);
    return () => window.removeEventListener("ba:locker-open", fn);
  }, [onOpenChange]);
  return (
    <>
      <IocLockerTrigger onClick={() => onOpenChange(true)} count={count} />
      <IocLockerPanel open={open} onClose={() => onOpenChange(false)} />
    </>
  );
}
