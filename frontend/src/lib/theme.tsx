import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { storageGet, storageSet } from "@/lib/storage";

export type ThemeId =
  | "dark"
  | "light"
  | "dark-hc"
  | "falcon"
  | "sentinel"
  | "phantom"
  | "matrix"
  | "nordic";

export type ThemeMode = "auto" | "light" | "dark";

export const THEMES: { id: ThemeId; name: string; description: string; swatch: string[]; isLight?: boolean }[] = [
  { id: "dark",     name: "Dark Slate",        description: "Neutral slate · cyber blue accent",   swatch: ["#0e1116", "#171b22", "#4d9fff"] },
  { id: "light",    name: "Paper Light",       description: "Crisp paper · ink · cobalt accent",   swatch: ["#fafafa", "#ffffff", "#2563eb"], isLight: true },
  { id: "dark-hc",  name: "High Contrast",     description: "OLED near-black · maximum contrast", swatch: ["#0a0a0a", "#141414", "#7cb8ff"] },
  { id: "falcon",   name: "Falcon Crimson",    description: "CrowdStrike obsidian · crimson red",  swatch: ["#0b0d12", "#131720", "#ef4444"] },
  { id: "sentinel", name: "Azure Sentinel",    description: "Midnight navy · electric azure",      swatch: ["#070d18", "#0f172a", "#0ea5e9"] },
  { id: "phantom",  name: "Phantom SOAR",      description: "Deep abyss · cyber violet & emerald", swatch: ["#0d0914", "#181124", "#a855f7"] },
  { id: "matrix",   name: "Matrix Terminal",   description: "Cathode black · phosphor green",      swatch: ["#050a06", "#0b150d", "#10b981"] },
  { id: "nordic",   name: "Nordic Frost",      description: "Polar midnight · arctic teal & ice",  swatch: ["#0b1219", "#111c26", "#14b8a6"] },
];

const STORAGE_KEY = "beyondlabs-theme";
const MODE_KEY = "beyondlabs-theme-mode";
const DEFAULT: ThemeId = "dark";

/** Old pre-redesign theme ids → migrated to the new system. */
const LEGACY_THEME_MAP: Record<string, ThemeId> = {
  "terminal-noir": "dark",
  "soc-console": "dark",
  "editorial-dark": "dark",
  "solar-flare": "dark",
  "synthwave-grid": "dark",
  "newsprint-dark": "dark",
  "brutalist-light": "light",
  custom: "dark",
};

type Ctx = { theme: ThemeId; setTheme: (t: ThemeId) => void; mode: ThemeMode; setMode: (m: ThemeMode) => void };
const ThemeCtx = createContext<Ctx>({ theme: DEFAULT, setTheme: () => {}, mode: "auto", setMode: () => {} });

function getInitialTheme(): ThemeId {
  const stored = storageGet<string>(STORAGE_KEY, DEFAULT);
  if (THEMES.some((t) => t.id === stored)) return stored as ThemeId;
  const migrated = LEGACY_THEME_MAP[stored];
  if (migrated) return migrated;
  return DEFAULT;
}

export type ResolvedMode = "light" | "dark";

/** Pure resolver so tests can cover both branches without a DOM. */
export function resolveModePref(mode: ThemeMode, systemLight: boolean): ResolvedMode {
  if (mode === "auto") return systemLight ? "light" : "dark";
  return mode;
}

function systemPrefersLight(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  return window.matchMedia("(prefers-color-scheme: light)").matches;
}

function applyThemeAndMode(theme: ThemeId, mode: ThemeMode) {
  const resolved = resolveModePref(mode, systemPrefersLight());
  document.documentElement.setAttribute("data-theme", theme);
  document.documentElement.setAttribute("data-mode", resolved);
  document.documentElement.classList.toggle("dark", resolved === "dark");
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeId>(getInitialTheme);
  const [mode, setModeState] = useState<ThemeMode>(() => storageGet<ThemeMode>(MODE_KEY, "auto"));

  useEffect(() => {
    applyThemeAndMode(theme, mode);
  }, [theme, mode]);

  // Re-resolve when the OS flips its color scheme while mode is "auto".
  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = () => applyThemeAndMode(theme, mode);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [theme, mode]);

  const setTheme = (t: ThemeId) => {
    setThemeState(t);
    storageSet(STORAGE_KEY, t);
  };

  const setMode = (m: ThemeMode) => {
    setModeState(m);
    storageSet(MODE_KEY, m);
  };

  return <ThemeCtx.Provider value={{ theme, setTheme, mode, setMode }}>{children}</ThemeCtx.Provider>;
}

export const useTheme = () => useContext(ThemeCtx);
