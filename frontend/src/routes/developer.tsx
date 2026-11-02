import { createFileRoute, Link, Outlet, useLocation } from "@tanstack/react-router";
import { PageShell } from "@/components/PageShell";
import { BookOpen, Boxes, Code, Palette } from "lucide-react";

export const Route = createFileRoute("/developer")({ component: DeveloperHub });

function DeveloperHub() {
  const { pathname } = useLocation();
  const isRoot = pathname === "/developer";
  return isRoot ? (
    <PageShell
      eyebrow="dev"
      title="Developer Hub"
      description="Internal tools, component inventory, and build notes for BeyondLabs frontend."
      crumbs={[{ label: "Dev" }]}
    >
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Card to="/developer/components" icon={Boxes} title="Component Showcase" desc="Live examples of every entity primitive — props, import paths, and rendering." />
        <Card to="/guide" icon={BookOpen} title="Investigation Guide" desc="Playbooks and runbooks — phish, C2, brute-force, and more." />
        <Card to="/settings" icon={Code} title="Settings" desc="Theme, fonts, sidebar, brand, and custom presets." />
        <div className="rounded-md border border-success/30 bg-success/5 p-4">
          <div className="flex items-center gap-2">
            <Palette className="h-4 w-4 text-success" />
            <h2 className="font-mono ba-text-2xs font-semibold text-success">Design System v1.0</h2>
          </div>
          <p className="mt-1.5 font-mono ba-text-2xs leading-relaxed text-muted-foreground">Frozen. <code className="rounded border border-subtle bg-surface-2 px-1 py-px ba-text-2xs">frontend/docs/DESIGN_SYSTEM.md</code> — primitives, layout, naming, tokens, anti-patterns.</p>
        </div>
      </div>
    </PageShell>
  ) : (
    <Outlet />
  );
}

function Card({ to, icon: Icon, title, desc }: { to: string; icon: typeof Boxes; title: string; desc: string }) {
  return (
    <Link
      to={to}
      className="group rounded-md border border-border/60 bg-surface-1 p-4 transition-colors duration-150 hover:border-primary/40 hover:bg-surface-2"
    >
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4 text-muted-foreground transition-colors duration-150 group-hover:text-primary" />
        <h2 className="font-mono ba-text-2xs font-semibold text-foreground">{title}</h2>
      </div>
      <p className="mt-1.5 font-mono ba-text-2xs leading-relaxed text-muted-foreground">{desc}</p>
    </Link>
  );
}
