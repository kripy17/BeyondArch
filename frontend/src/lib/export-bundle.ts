import type { Case } from "@/data/case";
import { buildReportMarkdown, type ReportType } from "@/lib/report";
import { makeZip, crc32 } from "@/lib/zip";
import { decodeAttachment, entryAttachments } from "@/lib/attachments";
import type { NotebookHypothesis } from "@/data/notebook";

/** Deterministic markdown → HTML for the subset this project emits:
 *  #/##/### headings, tables, blockquotes, horizontal dividers,
 *  blank-line-separated paragraphs, - lists, **bold**, _italic_, `code`,
 *  and fenced code blocks. */
export function markdownToHtml(md: string): string {
  const esc = (s: string): string =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const inline = (s: string): string =>
    esc(s)
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/_([^_]+)_/g, "<em>$1</em>");

  const lines = md.split("\n");
  const out: string[] = [];
  let inCode = false;
  let inList = false;
  let inTable = false;
  let inTableBody = false;

  const closeList = () => {
    if (inList) { out.push("</ul>"); inList = false; }
  };
  const closeTable = () => {
    if (inTable) {
      out.push(inTableBody ? "</tbody></table></div>" : "</thead></table></div>");
      inTable = false;
      inTableBody = false;
    }
  };

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed.startsWith("```")) {
      closeList();
      closeTable();
      out.push(inCode ? "</code></pre>" : "<pre><code>");
      inCode = !inCode;
      continue;
    }
    if (inCode) { out.push(esc(line)); continue; }
    if (!trimmed) { closeList(); closeTable(); continue; }

    // Table row detection
    if (trimmed.startsWith("|") && trimmed.endsWith("|")) {
      closeList();
      if (/^\|(?:\s*:?-+:?\s*\|)+$/.test(trimmed)) {
        if (inTable && !inTableBody) {
          out.push("</thead><tbody>");
          inTableBody = true;
        }
        continue;
      }
      const cells = trimmed
        .slice(1, -1)
        .split("|")
        .map((c) => c.trim());

      if (!inTable) {
        out.push('<div class="report-table-wrapper"><table class="report-table"><thead><tr>');
        for (const cell of cells) {
          out.push(`<th>${inline(cell)}</th>`);
        }
        out.push("</tr>");
        inTable = true;
        inTableBody = false;
        continue;
      }

      if (inTable) {
        if (!inTableBody) {
          out.push("</thead><tbody>");
          inTableBody = true;
        }
        out.push("<tr>");
        for (const cell of cells) {
          out.push(`<td>${inline(cell)}</td>`);
        }
        out.push("</tr>");
        continue;
      }
    } else if (inTable) {
      closeTable();
    }

    // Dividers
    if (/^---+$/.test(trimmed)) {
      closeList();
      out.push('<hr class="report-divider" />');
      continue;
    }

    // Blockquotes
    if (trimmed.startsWith(">")) {
      closeList();
      const quoteText = trimmed.replace(/^>\s*/, "");
      out.push(`<blockquote class="report-callout">${inline(quoteText)}</blockquote>`);
      continue;
    }

    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      closeList();
      out.push(`<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`);
      continue;
    }
    if (/^\s*-\s+/.test(line)) {
      if (!inList) { out.push("<ul>"); inList = true; }
      out.push(`<li>${inline(line.replace(/^\s*-\s+/, ""))}</li>`);
      continue;
    }
    closeList();
    out.push(`<p>${inline(line)}</p>`);
  }
  closeList();
  closeTable();
  if (inCode) out.push("</code></pre>");
  return out.join("\n");
}

export function htmlShell(title: string, bodyMd: string): string {
  return [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8">',
    `<title>${title}</title>`,
    "<style>",
    "@page { size: A4; margin: 18mm 15mm; }",
    "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; margin: 2rem auto; max-width: 56rem; line-height: 1.6; color: #1e293b; background: #ffffff; padding: 0 1.5rem; }",
    "h1 { font-size: 1.8rem; font-weight: 800; border-bottom: 2px solid #0284c7; padding-bottom: 0.5rem; margin-top: 1.5rem; color: #0f172a; letter-spacing: -0.02em; }",
    "h2 { font-size: 1.3rem; font-weight: 700; border-bottom: 1px solid #cbd5e1; padding-bottom: 0.35rem; margin-top: 2rem; color: #1e293b; page-break-after: avoid; }",
    "h3 { font-size: 1.05rem; font-weight: 600; margin-top: 1.4rem; color: #334155; page-break-after: avoid; }",
    "h4 { font-size: 0.95rem; font-weight: 600; margin-top: 1.1rem; color: #475569; page-break-after: avoid; }",
    "p { margin: 0.65rem 0; font-size: 0.95rem; }",
    "blockquote.report-callout { border-left: 4px solid #0284c7; background: #f0f9ff; padding: 0.75rem 1.25rem; margin: 1.25rem 0; border-radius: 0 6px 6px 0; color: #0369a1; font-size: 0.9rem; }",
    "hr.report-divider { border: none; border-top: 1px solid #e2e8f0; margin: 1.75rem 0; }",
    "code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background: #f1f5f9; color: #0f172a; padding: 0.15em 0.4em; border-radius: 4px; font-size: 0.85em; border: 1px solid #e2e8f0; }",
    "pre { background: #0f172a; color: #f8fafc; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; margin: 1.25rem 0; page-break-inside: avoid; }",
    "pre code { background: transparent; color: inherit; border: none; padding: 0; }",
    ".report-table-wrapper { width: 100%; overflow-x: auto; margin: 1.25rem 0; }",
    "table.report-table { width: 100%; border-collapse: collapse; font-size: 0.88rem; page-break-inside: avoid; }",
    "table.report-table th { background: #f8fafc; color: #334155; font-weight: 600; text-align: left; padding: 0.65rem 0.85rem; border: 1px solid #cbd5e1; }",
    "table.report-table td { padding: 0.6rem 0.85rem; border: 1px solid #e2e8f0; vertical-align: top; }",
    "table.report-table tr:nth-child(even) td { background: #f8fafc; }",
    "ul { margin: 0.6rem 0; padding-left: 1.5rem; }",
    "li { margin: 0.3rem 0; font-size: 0.95rem; }",
    "@media print {",
    "  body { margin: 0; max-width: 100%; padding: 0; }",
    "  pre, blockquote, table, tr { page-break-inside: avoid; }",
    "  h1, h2, h3 { page-break-after: avoid; }",
    "}",
    "</style>",
    "</head><body>",
    markdownToHtml(bodyMd),
    "</body></html>",
  ].join("\n");
}

export interface BundleInput {
  case: Case;
  reportType: ReportType;
  hypotheses: NotebookHypothesis[];
  generatedAt?: string;
}

export interface BundleResult {
  blob: Blob;
  manifest: string[];
  fileCount: number;
}

const FNV_SEED = 0x811c9dc5;

/** fnv1a over bytes — used only to fingerprint bundle files in the manifest
 *  so a reader can detect corruption/truncation, not as a security control. */
export function fnv1aBytes(bytes: Uint8Array): string {
  let h = FNV_SEED;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

export function buildExportBundle(input: BundleInput): BundleResult {
  const c = input.case;
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const md = buildReportMarkdown(c, input.reportType, input.hypotheses);

  const caseJson = JSON.stringify({ version: 1, exportedAt: generatedAt, case: c }, null, 2);

  const files: { name: string; content: string | Uint8Array<ArrayBuffer> }[] = [
    { name: "case.beyondcase.json", content: caseJson },
    { name: "report.md", content: md },
    { name: "report.html", content: htmlShell(`${c.title} — ${input.reportType} report`, md) },
  ];

  for (const a of c.artifacts ?? []) {
    if (!a.raw || !a.raw.trim()) continue;
    const safe = a.id.replace(/[^a-zA-Z0-9_-]/g, "_");
    files.push({ name: `artifacts/${a.kind}-${safe}.txt`, content: a.raw });
  }

  for (const e of c.entries) {
    for (const att of entryAttachments(e)) {
      const bytes = decodeAttachment(att.id);
      if (!bytes) {
        files.push({ name: `attachments/${att.name}`, content: `[missing payload: ${att.id} — attachment was not found in local storage]` });
        continue;
      }
      const safeEntry = e.id.replace(/[^a-zA-Z0-9_-]/g, "_");
      const safeName = att.name.replace(/[^a-zA-Z0-9._-]/g, "_");
      files.push({ name: `attachments/${safeEntry}-${safeName}`, content: bytes });
    }
  }

  const encoder = new TextEncoder();
  const manifestLines = files.map((f) => {
    const bytes = typeof f.content === "string" ? encoder.encode(f.content) : f.content;
    return `${f.name}\t${bytes.length} bytes\tfnv1a:${fnv1aBytes(bytes)}\tcrc32:${crc32(bytes).toString(16).padStart(8, "0")}`;
  });

  const manifest = [
    `BeyondLabs export bundle`,
    `case: ${c.title} (${c.id})`,
    `report type: ${input.reportType}`,
    `generated at: ${generatedAt}`,
    `files: ${files.length + 1}`,
    ``,
    ...manifestLines,
    `MANIFEST.txt\tlisted inline (this file)`,
    ``,
    `Hashes are change-detection fingerprints (fnv1a-32 / crc32), not signatures.`,
    `Reproduce the report by re-running the same analyzer inputs against the attached case.beyondcase.json.`,
  ].join("\n");

  const blob = makeZip([...files.map((f) => ({ name: f.name, content: f.content })), { name: "MANIFEST.txt", content: manifest }]);
  return { blob, manifest: manifestLines, fileCount: files.length + 1 };
}
