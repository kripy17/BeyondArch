import { createFileRoute } from "@tanstack/react-router";
import { PageShell } from "@/components/PageShell";
import { useTheme, THEMES, type ThemeId } from "@/lib/theme";
import {
  usePrefs, SANS_OPTIONS, MONO_OPTIONS, BRAND_ICONS, getBrandIcon,
} from "@/lib/prefs";
import { GROUPS } from "@/lib/workspaces";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Palette, Type, Layers, Sliders, Pin, Eye, EyeOff, ArrowUp, ArrowDown, Sparkles,
  RotateCcw, Trash2, Check, Tag, Download, Upload, Sun, Moon,
  LayoutGrid, Shield, Network, Wifi,
  type LucideIcon,
} from "lucide-react";
import { getBackendUrl, setBackendUrl, useBackendStatus } from "@/lib/backend";
import { clearRecents } from "@/lib/recents";
import { backupFilename, collectWorkspace, parseBackup, restoreBackup, serializeBackup } from "@/lib/workspace-backup";
import { toast } from "sonner";
import { useEffect, useRef, useState } from "react";

export const Route = createFileRoute("/settings")({
  head: () => ({ meta: [{ title: "Settings — BeyondLabs" }] }),
  component: SettingsPage,
});

function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const { prefs, setPrefs, togglePin, toggleHidden, moveGroup, reset } = usePrefs();
  const fileRef = useRef<HTMLInputElement>(null);
  const backupFileRef = useRef<HTMLInputElement>(null);
  const [sectionFilter, setSectionFilter] = useState("");
  const SECTION_JUMP = [
    { id: "BR", label: "Brand" },
    { id: "TH", label: "Theme Gallery" },
    { id: "DR", label: "Density" },
    { id: "TY", label: "Typography" },
    { id: "SB", label: "Sidebar" },
    { id: "ACY", label: "Accessibility" },
    { id: "QL", label: "Motion & QoL" },
    { id: "DB", label: "Dashboard" },
    { id: "DP", label: "Data & Privacy" },
  ] as const;

  const [previewTheme, setPreviewTheme] = useState<ThemeId>(theme);
  useEffect(() => { setPreviewTheme(theme); }, [theme]);
  const themeDirty = previewTheme !== theme;
  const handleThemePreview = (id: ThemeId) => {
    setPreviewTheme(id);
  };
  const handleThemeApply = () => setTheme(previewTheme);
  const handleThemeCancel = () => {
    setPreviewTheme(theme);
    const t = THEMES.find((t) => t.id === theme);
    if (t) {
      document.documentElement.setAttribute("data-theme", theme);
      document.documentElement.classList.toggle("dark", !t.isLight);
    }
  };


  const exportPrefs = () => {
    const blob = new Blob([JSON.stringify(prefs, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `beyondlabs-prefs-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const importPrefs = async (file: File) => {
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      setPrefs(parsed);
    } catch { /* ignore bad file */ }
  };

  const clearAllData = () => {
    const keys = Object.keys(localStorage).filter((k) => k.startsWith("ba."));
    for (const k of keys) localStorage.removeItem(k);
    window.location.reload();
  };

  const exportBackup = () => {
    const backup = collectWorkspace();
    const blob = new Blob([serializeBackup(backup)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = backupFilename(backup);
    a.click();
    URL.revokeObjectURL(url);
    toast(`Workspace backed up — ${backup.entries.length} key${backup.entries.length === 1 ? "" : "s"}`);
  };

  const importBackup = async (file: File) => {
    try {
      const parsed = parseBackup(await file.text());
      const report = restoreBackup(parsed);
      toast.success(`Restored ${report.restored.length} key${report.restored.length === 1 ? "" : "s"}`, {
        description: report.skippedForeign.length ? `Skipped ${report.skippedForeign.length} foreign key${report.skippedForeign.length === 1 ? "" : "s"} (not ba.*)` : `Snapshot from ${parsed.exportedAt.slice(0, 10) || "unknown date"}`,
      });
      window.location.reload();
    } catch (err) {
      toast.error("Backup import failed", { description: err instanceof Error ? err.message : String(err) });
    }
  };


  return (
    <PageShell
      eyebrow="// settings"
      title="Workspace"
      description="Brand, theme, layout, accessibility, and storage. Everything persists locally — no account, no sync."
      crumbs={[{ label: "Settings" }]}
      actions={
        <div className="flex flex-wrap items-center gap-1.5">
          <input
            ref={fileRef}
            type="file"
            accept="application/json"
            className="hidden"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) { importPrefs(f); toast("Preferences imported"); } e.target.value = ""; }}
          />
          <Button variant="outline" size="sm" className="text-mono gap-1.5" onClick={() => fileRef.current?.click()}>
            <Upload className="h-3.5 w-3.5" /> import
          </Button>
          <Button variant="outline" size="sm" className="text-mono gap-1.5" onClick={() => { exportPrefs(); toast("Preferences exported"); }}>
            <Download className="h-3.5 w-3.5" /> export
          </Button>
          <Button variant="outline" size="sm" className="text-mono gap-1.5" onClick={() => { reset(); toast("Preferences reset to defaults"); }}>
            <RotateCcw className="h-3.5 w-3.5" /> reset
          </Button>
        </div>
      }

    >
      {/* Section quick-jump */}
      <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-divider-strong bg-surface-1 px-3 py-2">
        <input
          value={sectionFilter}
          onChange={(e) => setSectionFilter(e.target.value)}
          aria-label="Filter settings"
          placeholder="Filter settings…"
          className="text-mono h-7 min-w-0 flex-1 rounded border border-divider-strong bg-surface-0 px-2 ba-text-2xs text-foreground placeholder:text-fg-dim outline-none transition-colors duration-150 focus:border-primary/50 max-w-[200px]"
        />
        <div className="flex flex-wrap gap-1">
          {SECTION_JUMP.filter((s) => !sectionFilter || s.label.toLowerCase().includes(sectionFilter.toLowerCase())).map((s) => (
            <a
              key={s.id}
              href={`#panel-${s.id}`}
              onClick={(e) => { e.preventDefault(); document.getElementById(`panel-${s.id}`)?.scrollIntoView({ behavior: "smooth", block: "start" }); }}
              className="rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:border-primary/40 hover:text-primary"
            >
              {s.label}
            </a>
          ))}
        </div>
      </div>

      {/* BRAND */}
      <Panel id="BR" label="brand" icon={Tag}>
        <div className="grid gap-5 grid-cols-1 sm:grid-cols-[1fr_auto]">
          <div className="space-y-3">
            <div>
              <Label>app name</Label>
              <Input
                className="mt-2 text-mono"
                aria-label="App name"
                value={prefs.brandName}
                maxLength={32}
                onChange={(e) => setPrefs({ brandName: e.target.value || "BeyondLabs" })}
                placeholder="BeyondLabs"
              />
            </div>
            <div>
              <Label>icon</Label>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {BRAND_ICONS.map(({ key, icon: I }) => {
                  const active = prefs.brandIcon === key;
                  return (
                    <button
                      key={key}
                      onClick={() => setPrefs({ brandIcon: key })}
                      aria-label={key}
                      className={
                        "grid h-9 w-9 place-items-center rounded-md border transition-all hover:-translate-y-0.5 " +
                        (active
                          ? "border-primary/70 bg-primary/15 text-primary shadow-glow"
                          : "border-border bg-surface-1 text-muted-foreground hover:text-foreground")
                      }
                    >
                      <I className="h-4 w-4" />
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
          {/* Live preview chip */}
          <div className="flex flex-col items-stretch gap-2 rounded-md border border-divider-strong bg-surface-1 p-3 w-full sm:w-56 max-w-full">
            <div className="text-mono ba-text-3xs text-muted-foreground">preview</div>
            <div className="flex items-center gap-2.5 rounded-md border border-border bg-surface-0 p-2.5">
              <div className="relative grid h-9 w-9 shrink-0 place-items-center rounded-md bg-gradient-to-br from-primary to-accent text-primary-foreground shadow-glow">
                {(() => { const I = getBrandIcon(prefs.brandIcon); return <I className="h-4 w-4" />; })()}
              </div>
              <div className="min-w-0">
                <div className="text-mono ba-text-base font-bold leading-tight truncate">{prefs.brandName || "BeyondLabs"}</div>
              </div>
            </div>
            <Button
              variant="ghost" size="sm" className="text-mono ba-text-sm"
              onClick={() => setPrefs({ brandName: "BeyondLabs", brandIcon: "shield-half" })}
            >
              reset brand
            </Button>
          </div>
        </div>
      </Panel>

      {/* THEME — stage + list, sticky apply bar */}
      <Panel id="TH" label="theme · gallery" icon={Palette}
        right={
          <div className="flex items-center gap-2">
            {themeDirty && (
              <span className="text-mono inline-flex items-center gap-1 rounded-sm border border-primary/40 bg-primary/10 px-1.5 py-0.5 ba-text-3xs text-primary">
                <Eye className="h-2.5 w-2.5" /> previewing
              </span>
            )}
            <span className="text-mono ba-text-2xs text-muted-foreground">
              active · <span className="text-foreground">{theme}</span>
            </span>
          </div>
        }>
        <ThemeGallery
          previewTheme={previewTheme}
          activeTheme={theme}
          onPreview={handleThemePreview}
          onApply={handleThemeApply}
          onCancel={handleThemeCancel}
          dirty={themeDirty}
        />

      </Panel>


      {/* DENSITY + RADIUS */}
      <Panel id="DR" label="density & radius" icon={Sliders}>
        <div className="grid gap-5 grid-cols-1 sm:grid-cols-2">
          <div>
            <Label>density</Label>
            <div className="mt-2 inline-flex rounded-md border border-border bg-surface-1 p-0.5">
              {(["comfortable", "compact"] as const).map((d) => (
                <button
                  key={d}
                  onClick={() => setPrefs({ density: d })}
                  className={
                    "text-mono rounded px-3 py-1 ba-text-2xs transition-colors duration-150" +
                    (prefs.density === d ? "bg-primary/20 text-primary" : "text-muted-foreground hover:text-foreground")
                  }
                >
                  {d}
                </button>
              ))}
            </div>
          </div>
          <div>
            <Label>corner radius · {prefs.radius.toFixed(2)}rem</Label>
            <div className="mt-3 flex items-center gap-3">
              <Slider
                value={[prefs.radius]}
                onValueChange={(v) => setPrefs({ radius: v[0] })}
                min={0} max={1} step={0.05}
                className="flex-1"
              />
              <div className="grid h-10 w-14 place-items-center border border-border bg-surface-2 text-mono ba-text-2xs text-muted-foreground" style={{ borderRadius: `${prefs.radius}rem` }}>
                preview
              </div>
            </div>
          </div>
        </div>
      </Panel>

      {/* TYPOGRAPHY */}
      <Panel id="TY" label="typography" icon={Type}
        right={<span className="text-mono ba-text-2xs text-muted-foreground">sans · mono</span>}>
        <div className="space-y-5">
          <Row label="Monospace ligatures" desc="Turn on programming ligatures (&rarr;, !=, ===, ...) in code/data.">
            <Switch checked={prefs.monoLigatures} onCheckedChange={(v) => setPrefs({ monoLigatures: v })} aria-label="Monospace ligatures" />
          </Row>

          <div className="grid gap-5 grid-cols-1 sm:grid-cols-2 min-w-0">
            <FontPicker
              title="sans (UI)"
              options={SANS_OPTIONS}
              value={prefs.sansFont}
              onChange={(v) => setPrefs({ sansFont: v })}
              sample="The quick brown fox jumps over 1234567890"
              mono={false}
            />
            <FontPicker
              title="mono (data, IDs)"
              options={MONO_OPTIONS}
              value={prefs.monoFont}
              onChange={(v) => setPrefs({ monoFont: v })}
              sample="BA-7F · 0x1A3F · {ttp:T1059}"
              mono={true}
            />
          </div>
        </div>
      </Panel>

      {/* SIDEBAR LAYOUT */}
      <Panel id="SB" label="sidebar layout" icon={Layers}
        right={<span className="text-mono ba-text-2xs text-muted-foreground">drag-free reorder</span>}>
        <div className="mb-3 flex flex-wrap items-center gap-1.5">
          <span className="text-mono ba-text-3xs text-fg-dim">quick layout</span>
          {(
            [
              { id: "default", label: "Default", order: GROUPS.map((g) => g.label), hiddenGroups: [], pinned: [] },
              { id: "minimal", label: "Minimal", order: ["Dashboard", "Intake", "Investigation", "Operations", "System"], hiddenGroups: ["Detection", "SIEM"], pinned: [] },
              { id: "full", label: "Full", order: GROUPS.map((g) => g.label), hiddenGroups: [], pinned: GROUPS.flatMap((g) => g.items).map((it) => it.url) },
            ] as const
          ).map((preset) => (
            <button
              key={preset.id}
              onClick={() => setPrefs({ sidebar: { order: [...preset.order], hiddenGroups: [...preset.hiddenGroups], pinned: [...preset.pinned] } })}
              className="rounded border border-subtle bg-surface-0 px-2 py-0.5 font-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-primary"
            >
              {preset.label}
            </button>
          ))}
        </div>
        <div className="space-y-2">
          {prefs.sidebar.order.map((label, i) => {
            const grp = GROUPS.find((g) => g.label === label);
            if (!grp) return null;
            const hidden = prefs.sidebar.hiddenGroups.includes(label);
            return (
              <div key={label} className="rounded-md border border-divider-strong bg-surface-1">
                <div className="flex items-center gap-2 px-3 py-2">
                  {(() => { const GIcon = grp.items[0]?.icon; return GIcon ? (
                    <span className="grid h-5 w-5 place-items-center rounded-sm border border-primary/40 bg-primary/10 text-primary">
                      <GIcon className="h-3 w-3" strokeWidth={2.25} />
                    </span>
                  ) : null; })()}
                  <span className="text-mono ba-text-base font-semibold tracking-tight">{label}</span>
                  <span className="text-mono ba-text-2xs text-muted-foreground">{grp.items.length} items</span>
                  <div className="ml-auto flex items-center gap-1">
                    <IconBtn label="up" disabled={i === 0} onClick={() => moveGroup(label, -1)}><ArrowUp className="h-3 w-3" /></IconBtn>
                    <IconBtn label="down" disabled={i === prefs.sidebar.order.length - 1} onClick={() => moveGroup(label, 1)}><ArrowDown className="h-3 w-3" /></IconBtn>
                    <IconBtn label="visibility" onClick={() => toggleHidden(label)}>
                      {hidden ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                    </IconBtn>
                  </div>
                </div>
                {!hidden && (
                  <ul className="divide-y divide-border/50 border-t border-divider-strong">
                    {grp.items.map((it) => {
                      const pinned = prefs.sidebar.pinned.includes(it.url);
                      return (
                        <li key={it.url} className="flex items-center gap-2 px-3 py-1.5">
                          <it.icon className="h-3.5 w-3.5 text-primary/80" />
                          <span className="text-mono ba-text-2xs text-foreground">{it.title}</span>
                          <span className="truncate ba-text-2xs text-muted-foreground">— {it.desc}</span>
                          <button
                            onClick={() => togglePin(it.url)}
                            className={
                              "ml-auto inline-flex items-center gap-1 rounded border px-1.5 py-px text-mono ba-text-2xs transition-colors duration-150" +
                              (pinned ? "border-primary/50 bg-primary/15 text-primary" : "border-divider-strong text-muted-foreground hover:text-foreground")
                            }
                          >
                            <Pin className="h-2.5 w-2.5" /> {pinned ? "pinned" : "pin"}
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            );
          })}
        </div>
      </Panel>

      {/* ACCESSIBILITY */}
      <Panel id="ACY" label="accessibility" icon={Eye}
        right={<span className="text-mono ba-text-2xs text-muted-foreground">motion · contrast · scale</span>}>
        <div className="grid gap-3 sm:grid-cols-2">
          <Row label="Reduce motion" desc="Auto follows your OS reduced-motion setting; Reduce and Full override it.">
            <div className="flex items-center gap-1 rounded-md border border-divider-soft bg-surface-1 p-0.5">
              {(["auto", "reduce", "full"] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  aria-pressed={prefs.reduceMotion === m}
                  onClick={() => setPrefs({ reduceMotion: m })}
                  className={`rounded px-2 py-0.5 text-mono ba-text-2xs transition-colors ${
                    prefs.reduceMotion === m
                      ? "bg-primary/20 text-primary"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {m === "auto" ? "Auto" : m === "reduce" ? "Reduce" : "Full"}
                </button>
              ))}
            </div>
          </Row>
          <Row label="Reduced transparency" desc="Decrease backdrop blur &amp; panel translucency for readability.">
            <Switch checked={prefs.reducedTransparency} onCheckedChange={(v) => setPrefs({ reducedTransparency: v })} aria-label="Reduced transparency" />
          </Row>
          <Row label="High contrast" desc="Sharpen borders, deepen shadows, boost text contrast.">
            <Switch checked={prefs.highContrast} onCheckedChange={(v) => setPrefs({ highContrast: v })} aria-label="High contrast" />
          </Row>
          <Row label="Zebra rows" desc="Alternate shading on tables &amp; IOC inventories for scan-ability.">
            <Switch checked={prefs.zebraStripes} onCheckedChange={(v) => setPrefs({ zebraStripes: v })} aria-label="Zebra rows" />
          </Row>
          <Row label="High-contrast focus" desc="Thicker focus ring + glow for keyboard-only navigation.">
            <Switch checked={prefs.focusRingBoost} onCheckedChange={(v) => setPrefs({ focusRingBoost: v })} aria-label="High-contrast focus" />
          </Row>
          <Row label="Show topbar" desc="Toggle the topbar on screens that don't need it.">
            <Switch checked={prefs.showTopbar} onCheckedChange={(v) => setPrefs({ showTopbar: v })} aria-label="Show topbar" />
          </Row>
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <div className="rounded-md border border-divider-strong bg-surface-1 px-3 py-3">
            <Label>font scale &middot; {prefs.fontScale.toFixed(2)}x</Label>
            <div className="mt-2 flex items-center gap-3">
              <span className="text-mono ba-text-2xs text-muted-foreground">85%</span>
              <Slider
                value={[prefs.fontScale]}
                onValueChange={(v) => setPrefs({ fontScale: v[0] })}
                min={0.85} max={1.15} step={0.01}
                className="flex-1"
              />
              <span className="text-mono ba-text-2xs text-muted-foreground">115%</span>
            </div>
          </div>
          <div className="rounded-md border border-divider-strong bg-surface-1 px-3 py-3">
            <Label>letter spacing &middot; {prefs.letterSpacing > 0 ? "+" : ""}{prefs.letterSpacing.toFixed(2)}em</Label>
            <div className="mt-2 flex items-center gap-3">
              <span className="text-mono ba-text-2xs text-muted-foreground">-0.02</span>
              <Slider
                value={[prefs.letterSpacing]}
                onValueChange={(v) => setPrefs({ letterSpacing: v[0] })}
                min={-0.02} max={0.06} step={0.005}
                className="flex-1"
              />
              <span className="text-mono ba-text-2xs text-muted-foreground">+0.06</span>
            </div>
          </div>
        </div>
      </Panel>

      {/* MOTION + QOL */}
      <Panel id="QL" label="motion & qol" icon={Sparkles}>
        <div className="grid gap-3 sm:grid-cols-2">
          <Row label="Show breadcrumb" desc="Hide for the cleanest topbar.">
            <Switch checked={prefs.showBreadcrumb} onCheckedChange={(v) => setPrefs({ showBreadcrumb: v })} aria-label="Show breadcrumb" />
          </Row>
          <div className="rounded-md border border-divider-strong bg-surface-1 px-3 py-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-mono ba-text-base font-medium text-foreground">Panel opacity &middot; {Math.round(prefs.panelOpacity * 100)}%</div>
                <div className="ba-text-2xs text-muted-foreground">Blend workspace cards with the theme backdrop.</div>
              </div>
              <Button variant="ghost" size="sm" className="text-mono ba-text-sm" onClick={() => setPrefs({ panelOpacity: 1 })}>
                reset
              </Button>
            </div>
            <div className="mt-3 flex items-center gap-3">
              <span className="text-mono ba-text-2xs text-muted-foreground">75%</span>
              <Slider
                value={[prefs.panelOpacity]}
                onValueChange={(v) => setPrefs({ panelOpacity: v[0] })}
                min={0.75} max={1} step={0.01}
                className="flex-1"
              />
              <span className="text-mono ba-text-2xs text-muted-foreground">100%</span>
            </div>
          </div>
        </div>
      </Panel>

      {/* DASHBOARD LAYOUT */}
      <Panel id="DB" label="dashboard layout" icon={LayoutGrid}
        right={<span className="text-mono ba-text-2xs text-muted-foreground">toggle sections</span>}>
        <div className="grid gap-3 sm:grid-cols-2">
          <Row label="Command strip" desc="Session stats under the deck header — timeline, recoverable workspaces, last active.">
            <Switch checked={prefs.dashboardSections.commandStrip} onCheckedChange={(v) => setPrefs({ dashboardSections: { ...prefs.dashboardSections, commandStrip: v } })} aria-label="Command strip" />
          </Row>
          <Row label="Case load" desc="Cases by state, indicator/finding severity bars and recent cases.">
            <Switch checked={prefs.dashboardSections.metrics} onCheckedChange={(v) => setPrefs({ dashboardSections: { ...prefs.dashboardSections, metrics: v } })} aria-label="Case load" />
          </Row>
          <Row label="Continue row" desc="Resume your last workspace or investigation event.">
            <Switch checked={prefs.dashboardSections.continueRow} onCheckedChange={(v) => setPrefs({ dashboardSections: { ...prefs.dashboardSections, continueRow: v } })} aria-label="Continue row" />
          </Row>
          <Row label="Activity tracks" desc="Today's activity, detection status and recent alerts.">
            <Switch checked={prefs.dashboardSections.tracks} onCheckedChange={(v) => setPrefs({ dashboardSections: { ...prefs.dashboardSections, tracks: v } })} aria-label="Activity tracks" />
          </Row>
          <Row label="Workflow ribbon" desc="Quick intake links and operations workflows.">
            <Switch checked={prefs.dashboardSections.workflowRibbon} onCheckedChange={(v) => setPrefs({ dashboardSections: { ...prefs.dashboardSections, workflowRibbon: v } })} aria-label="Workflow ribbon" />
          </Row>
          <Row label="Pinned rail" desc="Pinned cases, detections, entities and hunts.">
            <Switch checked={prefs.dashboardSections.pinned} onCheckedChange={(v) => setPrefs({ dashboardSections: { ...prefs.dashboardSections, pinned: v } })} aria-label="Pinned rail" />
          </Row>
          <Row label="Recent inputs" desc="Recent parser inputs as one-click chips.">
            <Switch checked={prefs.dashboardSections.workspaces} onCheckedChange={(v) => setPrefs({ dashboardSections: { ...prefs.dashboardSections, workspaces: v } })} aria-label="Recent inputs" />
          </Row>
          <Row label="Scratch notes" desc="Quick local notes panel at the bottom of the deck.">
            <Switch checked={prefs.dashboardSections.footer} onCheckedChange={(v) => setPrefs({ dashboardSections: { ...prefs.dashboardSections, footer: v } })} aria-label="Scratch notes" />
          </Row>
        </div>
      </Panel>

      {/* BACKEND CONNECTION */}
      <BackendPanel />

      {/* DATA & PRIVACY */}
      <Panel id="DP" label="data & privacy" icon={Shield}
        right={<span className="text-mono ba-text-2xs text-muted-foreground">local storage · no sync</span>}>
        <div className="grid gap-3 sm:grid-cols-2">
          <Row label="Export workspace backup" desc="Download every ba.* key — cases, provenance, attachments, prefs — as one JSON snapshot.">
            <Button variant="outline" size="sm" className="text-mono gap-1.5" onClick={exportBackup}>
              <Download className="h-3.5 w-3.5" /> backup
            </Button>
          </Row>
          <Row label="Restore workspace backup" desc="Overwrite current local state from a backup file. Foreign keys are refused.">
            <input
              ref={backupFileRef}
              type="file"
              accept="application/json"
              className="hidden"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) void importBackup(f); e.target.value = ""; }}
            />
            <Button variant="outline" size="sm" className="text-mono gap-1.5" onClick={() => {
              if (window.confirm("Restore a workspace backup? Current ba.* data will be overwritten.")) backupFileRef.current?.click();
            }}>
              <Upload className="h-3.5 w-3.5" /> restore
            </Button>
          </Row>
          <Row label="Clear recents" desc="Wipe the recent-workspace history (ba.recents).">
            <Button variant="outline" size="sm" className="text-mono gap-1.5" onClick={() => { clearRecents(); toast("Recents cleared"); }}>
              <Trash2 className="h-3.5 w-3.5" /> clear
            </Button>
          </Row>
          <Row label="Clear all local data" desc="Remove all app preferences, themes, cached state and history.">
            <Button variant="outline" size="sm" className="text-mono gap-1.5 text-destructive hover:text-destructive" onClick={clearAllData}>
              <Trash2 className="h-3.5 w-3.5" /> wipe
            </Button>
          </Row>
        </div>
        <div className="mt-3 rounded-md border border-divider-strong bg-surface-1 px-3 py-3">
          <Label>storage</Label>
          <div className="mt-2 flex items-center justify-between">
            <span className="text-mono ba-text-sm text-muted-foreground">ba.prefs.v1 &middot; ba.recents.v1 &middot; per-route caches</span>
            <span className="text-mono ba-text-sm text-muted-foreground">localStorage</span>
          </div>
        </div>
        <div className="mt-3">
          <Label>note</Label>
          <p className="mt-1.5 ba-text-2xs leading-relaxed text-muted-foreground">
            BeyondLabs keeps everything in your browser's localStorage. No data is sent to any server,
            uploaded to the cloud, or shared with third parties. Clearing data is immediate and irreversible.
          </p>
        </div>
      </Panel>
    </PageShell>
  );
}
/* =========================================================
 *  ThemeGallery — stage + scrollable list + sticky apply
 * ========================================================= */
function ThemeGallery({
  previewTheme, activeTheme, onPreview, onApply, onCancel, dirty,
}: {
  previewTheme: ThemeId; activeTheme: ThemeId;
  onPreview: (id: ThemeId) => void; onApply: () => void; onCancel: () => void; dirty: boolean;
}) {
  const [filter, setFilter] = useState<"all" | "dark" | "light">("all");
  const previewMeta = THEMES.find((t) => t.id === previewTheme)!;
  const list = THEMES.filter((t) =>
    filter === "all" ? true : filter === "light" ? !!t.isLight : !t.isLight
  );


  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
      {/* LEFT — live stage */}
      <div className="relative overflow-hidden rounded-md border border-border bg-[var(--card)]" data-theme={previewTheme}>

        <div className="flex items-center justify-between border-b border-divider-strong bg-[var(--background)] px-3 py-2">
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-destructive/70" />
            <span className="h-2 w-2 rounded-full bg-warning/70" />
            <span className="h-2 w-2 rounded-full bg-success/70" />
            <span className="text-mono ml-3 ba-text-2xs text-muted-foreground">
              {previewMeta.name.toLowerCase()} · preview
            </span>
          </div>
          <div className="flex gap-0.5">
            {previewMeta.swatch.map((c, i) => (
              <span key={i} className="h-3.5 w-2 rounded-[1px] border border-divider-soft" style={{ background: c }} />
            ))}
          </div>
        </div>
        <div className="relative bg-[var(--background)] p-4">
          <div className="absolute inset-0 opacity-40 aurora-glow" aria-hidden />
          <div className="relative space-y-3">
            <div className="flex items-baseline justify-between">
              <div>
                <div className="text-mono ba-text-2xs text-[var(--muted-foreground)]">workspace</div>
                <div className="font-display text-xl text-[var(--foreground)]">{previewMeta.name}</div>
              </div>
              <span className="text-mono rounded-sm border border-[var(--border)] bg-[var(--card)] px-1.5 py-0.5 ba-text-3xs text-[var(--muted-foreground)]">
                {previewMeta.isLight ? "light" : "dark"}
              </span>
            </div>

            <div className="grid grid-cols-3 gap-2">
              {[
                { label: "primary",  v: "var(--primary)" },
                { label: "accent",   v: "var(--accent)" },
                { label: "success",  v: "var(--success)" },
                { label: "warning",  v: "var(--warning)" },
                { label: "destruct", v: "var(--destructive)" },
                { label: "muted",    v: "var(--muted)" },
              ].map((s) => (
                <div key={s.label} className="rounded-sm border border-[var(--border)] bg-[var(--card)] p-1.5">
                  <div className="h-6 w-full rounded-[2px]" style={{ background: s.v }} />
                  <div className="text-mono mt-1 ba-text-3xs text-[var(--muted-foreground)]">{s.label}</div>
                </div>
              ))}
            </div>

            <div className="rounded-sm border border-[var(--border)] bg-[var(--card)] p-2">
              <div className="text-mono ba-text-3xs text-[var(--muted-foreground)]">sample · panel</div>
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                <span className="text-mono rounded-sm bg-[var(--primary)] px-2 py-1 ba-text-2xs font-semibold text-[var(--primary-foreground)]">primary</span>
                <span className="text-mono rounded-sm border border-[var(--border)] px-2 py-1 ba-text-2xs text-[var(--foreground)]">outline</span>
                <span className="text-mono rounded-sm bg-[var(--accent)] px-2 py-1 ba-text-2xs font-semibold text-[var(--accent-foreground)]">accent</span>
                <span className="text-mono ml-auto rounded-sm bg-[var(--destructive)] px-2 py-1 ba-text-2xs font-semibold text-[var(--destructive-foreground)]">alert</span>
              </div>
              <div className="mt-2 grid grid-cols-[1fr_auto] items-center gap-2 border-t border-[var(--border)] pt-2">
                <div className="text-mono ba-text-2xs text-[var(--foreground)]">indicator.exe · severity high</div>
                <span className="text-mono rounded-sm border border-[var(--border)] px-1.5 py-0.5 ba-text-3xs text-[var(--muted-foreground)]">12 hits</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* RIGHT — filter + list + sticky apply */}
      <div className="flex flex-col overflow-hidden rounded-md border border-border bg-card">
        <div className="flex items-center justify-between gap-2 border-b border-divider-strong px-2 py-1.5">
          <div className="flex gap-1">
            {(["all", "dark", "light"] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={[
                  "text-mono rounded-sm border px-2 py-1 ba-text-2xs transition-colors duration-150",
                  filter === f
                    ? "border-primary/60 bg-primary/10 text-primary"
                    : "border-divider-strong text-muted-foreground hover:border-border hover:text-foreground",
                ].join(" ")}
              >
                {f === "dark" ? <Moon className="mr-1 inline h-3 w-3" /> : f === "light" ? <Sun className="mr-1 inline h-3 w-3" /> : null}
                {f}
              </button>
            ))}
          </div>
          <span className="text-mono ba-text-2xs text-muted-foreground">{list.length} themes</span>
        </div>

        <div className="max-h-[420px] overflow-y-auto p-1.5">
          {list.map((t) => {
            const isPreview = previewTheme === t.id;
            const isActive = activeTheme === t.id;
            return (
              <button
                key={t.id}
                onClick={() => onPreview(t.id)}
                className={[
                  "group flex w-full items-center gap-3 rounded-sm border px-2 py-2 text-left transition-all",
                  isPreview
                    ? "border-primary/60 bg-primary/5 shadow-[0_0_0_1px_var(--primary)]/10"
                    : "border-transparent hover:border-divider-strong hover:bg-muted/40",
                ].join(" ")}
              >
                <div className="flex gap-0.5">
                  {t.swatch.map((c, i) => (
                    <span key={i} className="h-9 w-2 rounded-[1px] border border-divider-soft" style={{ background: c }} />
                  ))}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-mono flex items-center gap-1.5 ba-text-base font-semibold tracking-tight">
                    {t.name}
                    {isActive && (
                      <span className="text-mono rounded-sm border border-divider-strong bg-muted/40 px-1 py-px ba-text-3xs text-muted-foreground">
                        active
                      </span>
                    )}
                    {isPreview && !isActive && (
                      <span className="text-mono inline-flex items-center gap-0.5 rounded-sm border border-primary/40 bg-primary/10 px-1 py-px ba-text-3xs text-primary">
                        <Eye className="h-2 w-2" /> preview
                      </span>
                    )}
                  </div>
                  <div className="ba-text-2xs text-muted-foreground">{t.description}</div>
                </div>
                {isPreview && <Check className="h-3.5 w-3.5 shrink-0 text-primary" />}
              </button>
            );
          })}
        </div>

        <div className="sticky bottom-0 flex flex-wrap items-center justify-between gap-2 border-t border-divider-strong bg-muted/30 px-3 py-2 backdrop-blur">
          <div className="text-mono ba-text-2xs text-muted-foreground">
            {dirty
              ? <>changes not saved · <span className="text-foreground">{previewTheme}</span></>
              : "click a theme to preview"}
          </div>
          <div className="flex gap-1.5">
            <Button variant="ghost" size="sm" className="text-mono h-7 gap-1 ba-text-2xs"
              disabled={!dirty} onClick={onCancel}>
              <RotateCcw className="h-3 w-3" /> cancel
            </Button>
            <Button size="sm" className="text-mono h-7 gap-1 ba-text-2xs"
              disabled={!dirty} onClick={onApply}>
              <Check className="h-3 w-3" /> apply
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

function FontPicker<T extends string>({ title, options, value, onChange, sample, mono }: {
  title: string; options: readonly T[]; value: T; onChange: (v: T) => void; sample: string; mono: boolean;
}) {
  return (
    <div className="min-w-0 max-w-full">
      <Label>{title}</Label>
      <div className="mt-2 grid gap-2 min-w-0 max-w-full">
        {options.map((opt) => (
          <button
            key={opt}
            onClick={() => onChange(opt)}
            className={
              "flex items-center gap-3 rounded-md border bg-surface-1 px-3 py-2 text-left transition-colors duration-150 hover:bg-card min-w-0 max-w-full " +
              (value === opt ? "border-primary/60 ring-1 ring-primary/40" : "border-divider-strong")
            }
          >
            <div className="min-w-0 flex-1 overflow-hidden">
              <div className="truncate text-mono ba-text-sm text-muted-foreground">{opt}</div>
              <div
                className="truncate ba-text-base text-foreground"
                style={{ fontFamily: mono ? `"${opt}", ui-monospace, monospace` : `"${opt}", ui-sans-serif, sans-serif` }}
              >
                {sample}
              </div>
            </div>
            {value === opt && <Check className="h-3.5 w-3.5 text-primary shrink-0" />}
          </button>
        ))}
      </div>
    </div>
  );
}

function Panel({ id, label, icon: Icon, right, children }: {
  id?: string; label: string; icon: LucideIcon; right?: React.ReactNode; children: React.ReactNode;
}) {
  return (
    <section id={id ? `panel-${id}` : undefined} className="rounded-md border border-border bg-surface-1 scroll-mt-24">
      <header className="flex items-center gap-2 border-b border-divider-strong px-3 py-2">
        <span className="grid h-5 w-5 place-items-center rounded-sm border border-primary/40 bg-primary/10 text-primary">
          <Icon className="h-3 w-3" strokeWidth={2.25} />
        </span>
        <h2 className="text-mono ba-text-sm text-foreground">{label}</h2>
        <div className="ml-auto">{right}</div>
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

function Label({ children }: { children: React.ReactNode }) {
  return <div className="text-mono ba-text-2xs text-muted-foreground">{children}</div>;
}

function Row({ label, desc, children }: { label: string; desc: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-md border border-divider-strong bg-surface-1 px-3 py-2.5 min-w-0 max-w-full">
      <div className="min-w-0 flex-1">
        <div className="text-mono ba-text-base font-medium text-foreground">{label}</div>
        <div className="ba-text-2xs text-muted-foreground">{desc}</div>
      </div>
      <div className="flex flex-wrap items-center gap-1.5 shrink-0 max-w-full">
        {children}
      </div>
    </div>
  );
}

function IconBtn({ children, onClick, disabled, label }: { children: React.ReactNode; onClick: () => void; disabled?: boolean; label: string }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      className="grid h-6 w-6 place-items-center rounded border border-border bg-surface-0 text-muted-foreground transition-colors duration-150 hover:border-primary/50 hover:text-foreground disabled:opacity-40"
    >
      {children}
    </button>
  );
}

function BackendPanel() {
  const [url, setUrl] = useState(getBackendUrl());
  const { status, latency, version, uptime, check } = useBackendStatus();

  const handleSave = () => {
    setBackendUrl(url);
    toast("Backend URL saved");
  };

  const handleReset = () => {
    const def = (() => { try { return (import.meta as any).env?.VITE_BEYONDLABS_API as string || "http://localhost:8000"; } catch { return "http://localhost:8000"; } })();
    setUrl(def);
    setBackendUrl(def);
    toast("Backend URL reset to default");
  };

  const pingState = status === "checking" ? "testing" : status === "online" ? "ok" : status === "offline" ? "fail" : "idle";

  return (
    <Panel label="backend health" icon={Network}
      right={
        <span className="inline-flex items-center gap-1.5 text-mono ba-text-2xs">
          <span className={"inline-block h-1.5 w-1.5 rounded-full " + (pingState === "ok" ? "bg-success shadow-[0_0_6px_hsl(var(--success))]" : pingState === "fail" ? "bg-destructive" : pingState === "testing" ? "bg-warning animate-pulse" : "bg-muted-foreground/40")} />
          {pingState === "ok" ? `${latency}ms` : pingState === "fail" ? "offline" : pingState === "testing" ? "…" : "unknown"}
        </span>
      }>
      <div className="grid gap-3 grid-cols-1 sm:grid-cols-2 min-w-0">
        <Row label="Backend URL" desc="API endpoint for tool execution & analysis.">
          <div className="flex flex-wrap items-center gap-1.5 max-w-full">
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              aria-label="Backend URL"
              className="h-8 w-36 sm:w-48 max-w-full rounded border border-border bg-surface-0 px-2 text-mono ba-text-sm text-foreground outline-none transition-colors duration-150 focus:border-primary/60"
            />
            <button onClick={handleSave} className="grid h-9 w-9 place-items-center rounded-md border border-border text-muted-foreground hover:border-primary/40 hover:text-primary transition-colors duration-150" title="Save URL" aria-label="Save URL"><Check className="h-3.5 w-3.5" /></button>
            <button onClick={handleReset} className="grid h-9 w-9 place-items-center rounded-md border border-border text-muted-foreground hover:border-primary/40 hover:text-primary transition-colors duration-150" title="Reset to default" aria-label="Reset to default"><RotateCcw className="h-3.5 w-3.5" /></button>
          </div>
        </Row>
        <Row label="Status" desc="Ping latency, version, and uptime.">
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded border border-divider-strong bg-surface-1 px-2 py-1 text-mono ba-text-2xs text-muted-foreground">
              <Wifi className={"h-3 w-3 " + (pingState === "ok" ? "text-success" : pingState === "fail" ? "text-destructive" : "text-fg-dim")} />
              {pingState === "ok" ? `${latency}ms` : pingState === "fail" ? "no response" : "—"}
            </span>
            {version && <span className="text-mono ba-text-2xs text-muted-foreground">v{version}</span>}
            {typeof uptime === "number" && uptime > 0 && (
              <span className="text-mono ba-text-2xs text-fg-dim">{uptime < 60 ? `${uptime}s` : `${Math.floor(uptime / 60)}m`} up</span>
            )}
            <button onClick={check} disabled={pingState === "testing"} className="inline-flex h-7 items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 text-mono ba-text-2xs text-primary hover:bg-primary/20 disabled:opacity-40 transition-colors duration-150">
              {pingState === "testing" ? "…" : "ping"}
            </button>
          </div>
        </Row>
      </div>
    </Panel>
  );
}
