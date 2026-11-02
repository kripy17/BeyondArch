import { useEffect, useRef, useState } from "react";
import { Check, Eye, Moon, Palette, Sun, X } from "lucide-react";
import { THEMES, useTheme, type ThemeId, type ThemeMode } from "@/lib/theme";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Button } from "@/components/ui/button";

/** Temporarily mutate the live <html data-theme> without persisting. */
function applyPreview(id: ThemeId) {
  if (typeof document === "undefined") return;
  const isLight = THEMES.find((t) => t.id === id)?.isLight ?? false;
  document.documentElement.setAttribute("data-theme", id);
  document.documentElement.classList.toggle("dark", !isLight);
}

const MODE_ICONS: Record<ThemeMode, typeof Sun> = { auto: Eye, light: Sun, dark: Moon };
const MODE_LABELS: Record<ThemeMode, string> = { auto: "Auto · follows system", light: "Light", dark: "Dark" };

export function ThemeSwitcher({
  compact = false,
  collapsed = false,
}: {
  compact?: boolean;
  collapsed?: boolean;
}) {
  const { theme, setTheme, mode, setMode } = useTheme();
  const current = THEMES.find((t) => t.id === theme) ?? THEMES[0];

  const [open, setOpen] = useState(false);
  const [preview, setPreview] = useState<ThemeId>(theme);
  const original = useRef<ThemeId>(theme);
  const applied = useRef(false);

  // Sync when popover opens, snapshot the applied theme.
  useEffect(() => {
    if (open) {
      original.current = theme;
      setPreview(theme);
      applied.current = false;
    }
  }, [open, theme]);

  const handlePreview = (id: ThemeId) => {
    setPreview(id);
    applyPreview(id);
  };

  const handleApply = () => {
    applied.current = true;
    setTheme(preview);
    setOpen(false);
  };

  const handleCancel = () => {
    applyPreview(original.current);
    setPreview(original.current);
    setOpen(false);
  };

  // If popover closes by outside-click, treat as cancel (revert preview).
  const handleOpenChange = (next: boolean) => {
    if (!next && preview !== original.current && !applied.current) {
      applyPreview(original.current);
      setPreview(original.current);
    }
    setOpen(next);
  };

  const dirty = preview !== original.current;
  const isIconOnly = collapsed || compact;

  return (
    <Popover open={open} onOpenChange={handleOpenChange}>
      <PopoverTrigger asChild>
        {isIconOnly ? (
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 rounded-md text-sidebar-foreground/75 hover:bg-sidebar-accent hover:text-sidebar-foreground transition-colors"
            title={`Theme: ${current.name}`}
            aria-label={`Theme: ${current.name}`}
          >
            <Palette className="h-4 w-4 text-primary" />
          </Button>
        ) : (
          <button
            type="button"
            className="group flex h-8 w-full items-center gap-2 rounded-md border border-sidebar-border/70 bg-sidebar-accent/30 px-2 text-mono ba-text-2xs text-sidebar-foreground/80 hover:border-sidebar-border/90 hover:bg-sidebar-accent/60 hover:text-sidebar-foreground transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sidebar-ring"
          >
            <Palette className="h-3.5 w-3.5 shrink-0 text-primary group-hover:scale-105 transition-transform" />
            <span className="truncate">
              Theme: <span className="font-semibold text-sidebar-foreground">{current.name}</span>
            </span>
            <div className="ml-auto flex items-center gap-0.5 shrink-0">
              {current.swatch.map((c, i) => (
                <span
                  key={i}
                  className="h-3 w-1.5 rounded-[1px] border border-sidebar-border/70 shadow-xs"
                  style={{ background: c }}
                />
              ))}
            </div>
          </button>
        )}
      </PopoverTrigger>
      <PopoverContent
        side={isIconOnly ? "right" : "top"}
        align={isIconOnly ? "start" : "center"}
        sideOffset={10}
        className="w-80 p-0 shadow-2xl border-border bg-popover elevation-floating"
      >
        <div className="flex items-center justify-between border-b border-divider-strong px-3 py-2 bg-surface-0/60">
          <div className="text-mono ba-text-2xs font-semibold text-muted-foreground uppercase tracking-wider">
            Workspace Themes · 8
          </div>
          {dirty && (
            <span className="text-mono inline-flex items-center gap-1 rounded-sm border border-primary/40 bg-primary/10 px-1.5 py-0.5 ba-text-3xs text-primary font-semibold">
              <Eye className="h-2.5 w-2.5" /> previewing
            </span>
          )}
        </div>

        <div className="max-h-[380px] overflow-y-auto p-1.5 space-y-1">
          {THEMES.map((t) => {
            const isPreview = preview === t.id;
            const isApplied = theme === t.id;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => handlePreview(t.id)}
                className={[
                  "group flex w-full items-center gap-3 rounded-md border px-2.5 py-2 text-left transition-all duration-150",
                  isPreview
                    ? "border-primary/60 bg-primary/10 shadow-xs"
                    : "border-transparent hover:border-divider-strong hover:bg-muted/40",
                ].join(" ")}
              >
                <div className="flex gap-0.5 shrink-0">
                  {t.swatch.map((c, i) => (
                    <span
                      key={i}
                      className="h-8 w-2 rounded-[1px] border border-divider-soft"
                      style={{ background: c }}
                    />
                  ))}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-mono flex items-center gap-1.5 text-xs font-semibold">
                    <span>{t.name}</span>
                    {isApplied && (
                      <span className="text-mono rounded-sm border border-divider-strong bg-surface-1 px-1 py-px text-[8px] text-primary uppercase font-bold">
                        active
                      </span>
                    )}
                  </div>
                  <div className="ba-text-3xs text-muted-foreground truncate">{t.description}</div>
                </div>
                {isPreview && <Check className="h-4 w-4 shrink-0 text-primary" />}
              </button>
            );
          })}
        </div>

        <div className="flex items-center justify-between gap-2 border-t border-divider-strong bg-muted/20 px-3 py-2">
          <div className="flex items-center gap-1 rounded-md border border-divider-soft bg-surface-1 p-0.5">
            {(["dark", "light", "auto"] as ThemeMode[]).map((m) => {
              const Icon = MODE_ICONS[m];
              return (
                <button
                  key={m}
                  type="button"
                  onClick={() => setMode(m)}
                  className={`grid h-6 w-6 place-items-center rounded ba-text-2xs transition-colors duration-150 ${
                    mode === m ? "bg-primary/20 text-primary font-semibold" : "text-muted-foreground hover:text-foreground"
                  }`}
                  title={MODE_LABELS[m]}
                >
                  <Icon className="h-3 w-3" />
                </button>
              );
            })}
          </div>
          <div className="text-mono ba-text-3xs text-muted-foreground truncate max-w-[90px]">
            {dirty ? "Unsaved" : "Applied"}
          </div>
          <div className="flex gap-1.5 shrink-0">
            <Button
              variant="ghost"
              size="sm"
              className="text-mono h-7 px-2 gap-1 ba-text-2xs"
              onClick={handleCancel}
            >
              <X className="h-3 w-3" /> Cancel
            </Button>
            <Button
              size="sm"
              className="text-mono h-7 px-2 gap-1 ba-text-2xs"
              disabled={!dirty}
              onClick={handleApply}
            >
              <Check className="h-3 w-3" /> Apply
            </Button>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}
