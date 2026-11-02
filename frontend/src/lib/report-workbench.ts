import { markdownToHtml } from "@/lib/export-bundle";

/** A heading parsed out of a report markdown document. */
export interface ReportOutlineItem {
  /** 1–4 — the markdown heading level. */
  level: number;
  text: string;
  /** Anchor id used by both the outline list and the rendered preview. */
  anchorId: string;
}

/** Deterministic slug for an outline anchor (stable across renders). */
export function reportAnchorSlug(text: string): string {
  const base = text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return base ? `rpt-${base}` : "rpt-section";
}

/** Shared dedupe so the outline and the rendered preview agree on ids even
 *  when two sections share a title. */
function uniqueSlug(slug: string, seen: Map<string, number>): string {
  if (!seen.has(slug)) {
    seen.set(slug, 0);
    return slug;
  }
  const n = seen.get(slug)! + 1;
  seen.set(slug, n);
  return `${slug}-${n}`;
}

/** Parse #/##/### headings from report markdown into a clickable outline. */
export function reportOutline(md: string): ReportOutlineItem[] {
  const items: ReportOutlineItem[] = [];
  const seen = new Map<string, number>();
  for (const line of md.split("\n")) {
    const m = line.match(/^(#{1,4})\s+(.+?)\s*$/);
    if (!m) continue;
    const text = m[2];
    items.push({
      level: m[1].length,
      text,
      anchorId: uniqueSlug(reportAnchorSlug(text), seen),
    });
  }
  return items;
}

export interface WorkbenchStats {
  lines: number;
  words: number;
  chars: number;
  headings: number;
  sections: number; // ## level
}

export function workbenchStats(md: string): WorkbenchStats {
  const lines = md.split("\n");
  const headings = md.split("\n").filter((l) => /^#{1,4}\s+/.test(l)).length;
  const sections = md.split("\n").filter((l) => /^##\s+/.test(l)).length;
  return {
    lines: lines.length,
    words: md.split(/\s+/).filter(Boolean).length,
    chars: md.length,
    headings,
    sections,
  };
}

/** Rendered preview HTML with deterministic ids injected on headings so the
 *  outline can scroll to them. Input is already HTML-escaped by
 *  markdownToHtml (no raw HTML passthrough), so this stays safe. */
export function renderPreviewHtml(md: string): string {
  const seen = new Map<string, number>();
  return markdownToHtml(md).replace(
    /<h([1-4])>([\s\S]*?)<\/h\1>/g,
    (_all, lvl: string, inner: string) => {
      const text = inner.replace(/<[^>]+>/g, "").trim();
      const id = uniqueSlug(reportAnchorSlug(text), seen);
      return `<h${lvl} id="${id}">${inner}</h${lvl}>`;
    },
  );
}
