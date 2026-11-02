import { describe, it, expect } from "vitest";
import { reportAnchorSlug, reportOutline, renderPreviewHtml, workbenchStats } from "@/lib/report-workbench";

describe("reportAnchorSlug", () => {
  it("slugs text deterministically", () => {
    expect(reportAnchorSlug("Executive Summary")).toBe("rpt-executive-summary");
    expect(reportAnchorSlug("  Claim → evidence appendix! ")).toBe("rpt-claim-evidence-appendix");
    expect(reportAnchorSlug("###")).toBe("rpt-section");
  });
});

describe("reportOutline", () => {
  const md = ["# Incident Response", "", "## Executive Summary", "body", "### Timing", "- a", "## IOC Summary"].join("\n");

  it("extracts headings with levels in order", () => {
    expect(reportOutline(md).map((h) => [h.level, h.text])).toEqual([
      [1, "Incident Response"],
      [2, "Executive Summary"],
      [3, "Timing"],
      [2, "IOC Summary"],
    ]);
  });

  it("dedupes repeated titles with -2 suffixes", () => {
    const dup = "# Notes\n\n## Same\n\n## Same";
    const ids = reportOutline(dup).map((h) => h.anchorId);
    expect(ids).toEqual(["rpt-notes", "rpt-same", "rpt-same-1"]);
  });

  it("ignores lines that merely contain # mid-line", () => {
    expect(reportOutline("not # a heading")).toEqual([]);
  });
});

describe("workbenchStats", () => {
  it("counts lines, words, chars and sections honestly", () => {
    const md = "# T\n\nintro words here\n\n## S1\n\none two\n\n## S2\n\nx";
    const s = workbenchStats(md);
    expect(s.lines).toBe(11);
    expect(s.words).toBe(12); // whitespace-split incl. # markers — honest count
    expect(s.chars).toBe(md.length);
    expect(s.headings).toBe(3);
    expect(s.sections).toBe(2);
  });

  it("is zero on empty input without throwing", () => {
    expect(workbenchStats("")).toEqual({ lines: 1, words: 0, chars: 0, headings: 0, sections: 0 });
  });
});

describe("renderPreviewHtml", () => {
  it("injects ids matching the outline anchors", () => {
    const md = "## Executive Summary\n\n- item one\n\n## Executive Summary";
    const outline = reportOutline(md);
    const html = renderPreviewHtml(md);
    for (const h of outline) {
      expect(html).toContain(`id="${h.anchorId}"`);
    }
    // ids are unique even for duplicate titles
    expect(html.match(/id="rpt-executive-summary"/g)?.length).toBe(1);
    expect(html).toContain('id="rpt-executive-summary-1"');
    expect(html).toContain("<li>item one</li>");
  });

  it("keeps markdownToHtml escaping — no raw HTML passthrough", () => {
    const html = renderPreviewHtml("## <script>x</script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>");
  });
});
