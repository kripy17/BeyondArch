import { describe, expect, it } from "vitest";
import { crc32, makeZip, type ZipEntry } from "@/lib/zip";
import { buildExportBundle, fnv1aBytes, markdownToHtml } from "@/lib/export-bundle";
import type { Case } from "@/data/case";
import type { NotebookHypothesis } from "@/data/notebook";

const encoder = new TextEncoder();

async function unzipNames(blob: Blob): Promise<string[]> {
  const buf = new Uint8Array(await blob.arrayBuffer());
  const names: string[] = [];
  let i = 0;
  while (i < buf.length - 4) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x03 && buf[i + 3] === 0x04) {
      const nameLen = buf[i + 26] | (buf[i + 27] << 8);
      names.push(new TextDecoder().decode(buf.slice(i + 30, i + 30 + nameLen)));
      const size = buf[i + 18] | (buf[i + 19] << 8) | (buf[i + 20] << 16) | (buf[i + 21] << 24);
      i = i + 30 + nameLen + size;
    } else {
      break;
    }
  }
  return names;
}

const mkCase = (): Case => ({
  id: "c1",
  title: "Phishing Wave",
  tags: [],
  state: "active",
  createdAt: "2026-08-01T00:00:00.000Z",
  entries: [],
  events: [],
  artifacts: [
    { id: "a1", kind: "email", title: "lure", raw: "Subject: urgent\n\npay", metadata: {}, created: "2026-08-01T00:00:00.000Z" },
    { id: "a2", kind: "text", title: "empty", metadata: {}, created: "2026-08-01T00:00:00.000Z" },
  ],
  findings: [],
  iocs: [],
});

describe("zip writer", () => {
  it("produces a blob whose local headers list every entry in order", async () => {
    const entries: ZipEntry[] = [
      { name: "b.txt", content: "world" },
      { name: "a.txt", content: "hello" },
    ];
    const blob = makeZip(entries);
    expect(blob.type).toBe("application/zip");
    const names = await unzipNames(blob);
    expect(names).toEqual(["b.txt", "a.txt"]);
  });

  it("is byte-stable for identical input regardless of call timing", async () => {
    const e: ZipEntry[] = [{ name: "f.txt", content: "stable content" }];
    const a = await makeZip(e).arrayBuffer();
    await new Promise((r) => setTimeout(r, 5));
    const b = await makeZip(e).arrayBuffer();
    expect(new Uint8Array(b)).toEqual(new Uint8Array(a));
  });

  it("computes known crc32 values", () => {
    expect(crc32(encoder.encode("123456789"))).toBe(0xcbf43926);
    expect(crc32(new Uint8Array(0))).toBe(0);
  });
});

describe("markdownToHtml", () => {
  it("escapes html and renders the emitted subset only", () => {
    const html = markdownToHtml("# T <script>x</script>\n\n- **bold** `c`\n- _i_\n\npara");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("<h1>");
    expect(html).toContain("<strong>bold</strong>");
    expect(html).toContain("<code>c</code>");
    expect(html).toContain("<em>i</em>");
    expect((html.match(/<ul>/g) ?? []).length).toBe(1);
  });

  it("handles fenced code blocks", () => {
    const html = markdownToHtml("```\nraw <b>text</b>\n```");
    expect(html).toContain("<pre><code>");
    expect(html).toContain("raw &lt;b&gt;text&lt;/b&gt;");
  });
});

describe("export bundle", () => {
  it("includes case json, md, html, non-empty artifacts, and manifest with fingerprints", () => {
    const hyps: NotebookHypothesis[] = [];
    const { blob, fileCount } = buildExportBundle({ case: mkCase(), reportType: "executive", hypotheses: hyps, generatedAt: "2026-08-07T12:30:00.000Z" });
    expect(fileCount).toBe(5); // case + md + html + 1 artifact (empty skipped) + manifest
    return unzipNames(blob).then((names) => {
      expect(names).toEqual([
        "case.beyondcase.json",
        "report.md",
        "report.html",
        "artifacts/email-a1.txt",
        "MANIFEST.txt",
      ]);
    });
  });

  it("fingerprints are deterministic and detect content changes", () => {
    const bytes = encoder.encode("same");
    expect(fnv1aBytes(bytes)).toBe(fnv1aBytes(encoder.encode("same")));
    expect(fnv1aBytes(bytes)).not.toBe(fnv1aBytes(encoder.encode("different")));
  });
});
