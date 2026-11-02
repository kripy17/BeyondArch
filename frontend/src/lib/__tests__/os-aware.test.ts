import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveModePref, type ThemeMode } from "@/lib/theme";
import { applyToDOM, DEFAULT_PREFS, resolveMotionData, type Prefs } from "@/lib/prefs";

describe("resolveModePref — OS color-scheme aware theme mode", () => {
  it("auto resolves light when the system prefers light", () => {
    expect(resolveModePref("auto", true)).toBe("light");
  });

  it("auto resolves dark when the system does not prefer light", () => {
    expect(resolveModePref("auto", false)).toBe("dark");
  });

  it("explicit modes win over the OS setting", () => {
    expect(resolveModePref("light", false)).toBe("light");
    expect(resolveModePref("dark", true)).toBe("dark");
  });
});

describe("resolveMotionData — tri-state reduce-motion pref", () => {
  it("explicit reduce wins even when the OS allows motion", () => {
    expect(resolveMotionData("reduce", false)).toBe("reduce");
  });

  it("explicit full wins even when the OS asks for reduced motion", () => {
    expect(resolveMotionData("full", true)).toBe("full");
  });

  it("auto defers to the OS reduced-motion preference", () => {
    expect(resolveMotionData("auto", true)).toBe("reduce");
    expect(resolveMotionData("auto", false)).toBe("full");
  });
});

function installDom(reduce: boolean): Record<string, string> {
  const dataset: Record<string, string> = {};
  vi.stubGlobal("document", {
    documentElement: {
      dataset,
      style: { setProperty() {} },
      setAttribute() {},
      classList: { toggle() {} },
    },
  });
  vi.stubGlobal("window", {
    matchMedia: (query: string) => ({
      matches: query.includes("prefers-reduced-motion") ? reduce : false,
      media: query,
    }),
  });
  return dataset;
}

describe("applyToDOM — data-motion reflects the resolved preference", () => {
  const base = { ...DEFAULT_PREFS } as Prefs;

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("auto + OS reduce sets data-motion=reduce", () => {
    installDom(true);
    applyToDOM({ ...base, reduceMotion: "auto" });
    expect(document.documentElement.dataset.motion).toBe("reduce");
  });

  it("auto without OS reduce keeps full motion", () => {
    installDom(false);
    applyToDOM({ ...base, reduceMotion: "auto" });
    expect(document.documentElement.dataset.motion).toBe("full");
  });

  it("full overrides an OS reduced-motion request", () => {
    installDom(true);
    applyToDOM({ ...base, reduceMotion: "full" });
    expect(document.documentElement.dataset.motion).toBe("full");
  });
});

describe("theme mode typing sanity", () => {
  it("covers all three ThemeMode values through resolveModePref", () => {
    const modes: ThemeMode[] = ["auto", "light", "dark"];
    expect(modes.map((m) => resolveModePref(m, true))).toEqual(["light", "light", "dark"]);
  });
});
