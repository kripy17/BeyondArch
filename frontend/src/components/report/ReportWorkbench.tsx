import { useMemo } from "react";
import { Download, FileCode2, Eye, ListTree } from "lucide-react";
import { reportOutline, renderPreviewHtml, workbenchStats } from "@/lib/report-workbench";
import { notify } from "@/lib/notify";
import { downloadTextFile } from "@/lib/download";

const PREVIEW_CSS = `
.rw-preview { color: var(--color-foreground); font-size: 0.8rem; line-height: 1.6; }
.rw-preview h1 { font-size: 1.05rem; font-weight: 700; margin: 1.1em 0 0.4em; letter-spacing: -0.01em; }
.rw-preview h2 { font-size: 0.9rem; font-weight: 700; margin: 1.1em 0 0.35em; padding-bottom: 0.25em; border-bottom: 1px solid var(--color-border); scroll-margin-top: 0.5rem; }
.rw-preview h3 { font-size: 0.8rem; font-weight: 600; margin: 0.9em 0 0.3em; color: var(--color-muted-foreground); text-transform: uppercase; letter-spacing: 0.04em; scroll-margin-top: 0.5rem; }
.rw-preview h4 { font-size: 0.78rem; font-weight: 600; margin: 0.8em 0 0.3em; scroll-margin-top: 0.5rem; }
.rw-preview p { margin: 0.45em 0; }
.rw-preview ul { margin: 0.45em 0; padding-left: 1.1em; list-style: disc; }
.rw-preview li { margin: 0.2em 0; }
.rw-preview code { background: var(--color-muted); border-radius: 3px; padding: 0.05em 0.35em; font-size: 0.72rem; }
.rw-preview pre { background: var(--color-muted); border: 1px solid var(--color-border); border-radius: 6px; padding: 0.6em 0.75em; overflow-x: auto; margin: 0.6em 0; }
.rw-preview pre code { background: transparent; padding: 0; }
.rw-preview strong { font-weight: 700; }
`;

interface ReportWorkbenchProps {
  md: string;
  title: string;
  typeLabel: string;
}

export function ReportWorkbench({ md, title, typeLabel }: ReportWorkbenchProps) {
  const outline = useMemo(() => reportOutline(md), [md]);
  const stats = useMemo(() => workbenchStats(md), [md]);
  const preview = useMemo(() => renderPreviewHtml(md), [md]);
  const sourceLines = useMemo(() => md.split("\n"), [md]);

  const jumpTo = (anchorId: string) => {
    const el = document.getElementById(anchorId);
    el?.scrollIntoView({ block: "start", behavior: "smooth" });
    if (el) {
      el.animate?.(
        [{ backgroundColor: "var(--color-primary)" }, { backgroundColor: "transparent" }],
        { duration: 900, easing: "ease-out" },
      );
    }
  };

  const downloadMd = () => {
    try {
      downloadTextFile(`report-${typeLabel.toLowerCase().replace(/\s+/g, "-")}.md`, md, "text/markdown");
      notify.success("Report markdown downloaded");
    } catch {
      notify.error("Markdown download failed");
    }
  };

  return (
    <div>
      <style>{PREVIEW_CSS}</style>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 font-mono ba-text-2xs text-muted-foreground">
          <ListTree className="h-3 w-3" />
          <span>outline:</span>
          {outline.length === 0 ? (
            <span className="text-fg-dim">no headings</span>
          ) : (
            outline.map((h) => (
              <button
                key={h.anchorId}
                type="button"
                onClick={() => jumpTo(h.anchorId)}
                title={`Jump to ${h.text}`}
                className={`rounded border px-1.5 py-px transition-colors duration-150 hover:border-primary/40 hover:text-foreground ${
                  h.level === 1
                    ? "border-border bg-background/50 font-semibold text-foreground"
                    : "border-subtle text-muted-foreground"
                }`}
                style={{ marginLeft: h.level > 2 ? "0.15rem" : undefined }}
              >
                {h.level > 1 && <span className="mr-0.5 text-fg-dim">{"·".repeat(h.level - 1)}</span>}
                {h.text}
              </button>
            ))
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="font-mono ba-text-2xs text-muted-foreground" title="lines · words · characters · sections">
            {stats.lines} ln · {stats.words} words · {stats.chars} ch · {stats.sections} sections
          </span>
          <button
            type="button"
            onClick={downloadMd}
            title="Download the exact markdown behind this preview"
            className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 font-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:border-primary/40 hover:text-foreground"
          >
            <Download className="h-3 w-3" /> .md
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <div className="overflow-hidden rounded-lg border border-border bg-background/40">
          <div className="flex items-center gap-1.5 border-b border-subtle bg-surface-1/60 px-3 py-1.5 font-mono ba-text-2xs text-muted-foreground">
            <FileCode2 className="h-3 w-3" /> markdown source — deterministic output of buildReportMarkdown()
          </div>
          <div className="max-h-[70vh] overflow-auto p-3">
            <pre className="font-mono ba-text-2xs leading-relaxed text-foreground">
              {sourceLines.map((line, i) => (
                <div key={i} className="flex">
                  <span className="w-10 shrink-0 select-none pr-3 text-right text-fg-dim/60">{i + 1}</span>
                  <span className="whitespace-pre-wrap break-words">{line || " "}</span>
                </div>
              ))}
            </pre>
          </div>
        </div>

        <div className="overflow-hidden rounded-lg border border-border bg-background/40">
          <div className="flex items-center gap-1.5 border-b border-subtle bg-surface-1/60 px-3 py-1.5 font-mono ba-text-2xs text-muted-foreground">
            <Eye className="h-3 w-3" /> rendered preview — {title}
          </div>
          <div className="max-h-[70vh] overflow-auto p-4">
            <div className="rw-preview" dangerouslySetInnerHTML={{ __html: preview }} />
          </div>
        </div>
      </div>
      <p className="mt-1.5 font-mono ba-text-2xs text-fg-dim">
        Source and preview are two views of the same generated document — edits happen in the case, not here. Switch to Composed view before printing.
      </p>
    </div>
  );
}
