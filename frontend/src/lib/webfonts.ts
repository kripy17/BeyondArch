// Web-font lazy loading. Only Inter and JetBrains Mono (the defaults) ship
// eagerly in index.html; every other selectable family is fetched once,
// on first selection, then cached by the browser.

const EAGER_FAMILIES = new Set(["Inter", "JetBrains Mono"])

const FAMILY_QUERY: Record<string, string> = {
  "Space Grotesk": "Space+Grotesk:wght@400;500;600;700",
  Outfit: "Outfit:wght@400;500;600;700",
  Geist: "Geist:wght@400;500;600;700",
  "Geist Mono": "Geist+Mono:wght@400;500;600;700",
  "DM Sans": "DM+Sans:wght@400;500;600;700",
  Manrope: "Manrope:wght@400;500;600;700",
  "Plus Jakarta Sans": "Plus+Jakarta+Sans:wght@400;500;600;700",
  Sora: "Sora:wght@400;500;600;700",
  "IBM Plex Mono": "IBM+Plex+Mono:wght@400;500;600;700",
  "Fira Code": "Fira+Code:wght@400;500;600;700",
  "Source Code Pro": "Source+Code+Pro:wght@400;500;600;700",
  "Space Mono": "Space+Mono:wght@400;700",
}

export function fontStylesheetHref(family: string): string {
  const query = FAMILY_QUERY[family]
  return `https://fonts.googleapis.com/css2?family=${query}&display=swap`
}

export function isEagerFont(family: string): boolean {
  return EAGER_FAMILIES.has(family) || !(family in FAMILY_QUERY)
}

export function ensureWebFont(family: string): void {
  if (typeof document === "undefined" || isEagerFont(family)) return
  const id = `ba-font-${family.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`
  if (document.getElementById(id)) return
  const link = document.createElement("link")
  link.id = id
  link.rel = "stylesheet"
  link.href = fontStylesheetHref(family)
  document.head.appendChild(link)
}
