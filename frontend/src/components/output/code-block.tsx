import { useMemo } from "react";

type Lang = "json" | "shell" | "sigma" | "yara" | "plain";

const PATTERNS: Record<Lang, { regex: RegExp; cls: string }[]> = {
  json: [
    { regex: /("(?:[^"\\]|\\.)*")\s*:/g, cls: "text-[var(--ansi-cyan)]/90" },
    { regex: /:\s*("(?:[^"\\]|\\.)*")/g, cls: "text-[var(--ansi-green)]/80" },
    { regex: /:\s*(\d+\.?\d*)/g, cls: "text-[var(--ansi-yellow)]/90" },
    { regex: /\b(true|false|null)\b/g, cls: "text-[var(--ansi-magenta)]/80" },
  ],
  shell: [
    { regex: /(^|\s)(#.*?)$/gm, cls: "text-muted-foreground" },
    { regex: /\b(echo|cat|grep|ls|cd|rm|mv|cp|mkdir|touch|chmod|chown|ps|kill|sudo|apt|pip|npm|docker|curl|wget|nmap|dig|whois|python|ruby|perl|bash|sh|ssh|scp|tar|gzip|zip|unzip|make|cmake|git|jq|sed|awk|head|tail|sort|uniq|wc|find|xargs|tee|cut|tr|diff|patch|env|export|source|alias|unalias|exit|clear|history)\b/g,
      cls: "text-[var(--ansi-magenta)]/80" },
    { regex: /(\s|^)(-\w+|--[\w-]+)/g, cls: "text-[var(--ansi-cyan)]/80" },
    { regex: /"([^"]*)"/g, cls: "text-[var(--ansi-green)]/75" },
    { regex: /'([^']*)'/g, cls: "text-[var(--ansi-green)]/60" },
    { regex: /\b(\d+)\b/g, cls: "text-[var(--ansi-yellow)]/80" },
    { regex: /(https?:\/\/[^\s<>"']+)/g, cls: "text-[var(--ansi-blue)]/80 underline underline-offset-2 decoration-[var(--ansi-blue)]/30" },
  ],
  sigma: [
    { regex: /(title|id|description|author|date|logsource|detection|condition|falsepositives|level|status|tags|references|fields|filename|modified|license|category|product|service)/g, cls: "text-[var(--ansi-cyan)]/80" },
    { regex: /(selection|filter|main|all|generic)\b/g, cls: "text-[var(--ansi-yellow)]/80" },
    { regex: /(event_id|EventID|EventID|Image|ParentImage|CommandLine|ImagePath|TargetObject|Details|PipeName|ServiceName)\b/g, cls: "text-[var(--ansi-blue)]/80" },
    { regex: /"(?:[^"\\]|\\.)*"/g, cls: "text-[var(--ansi-green)]/75" },
    { regex: /(#.*)$/gm, cls: "text-muted-foreground" },
    { regex: /\b(low|medium|high|critical)\b/g, cls: "text-[var(--ansi-yellow)]/70" },
  ],
  yara: [
    { regex: /(rule|meta|strings|condition|import|include)\b/g, cls: "text-[var(--ansi-cyan)]/80 font-semibold" },
    { regex: /\$(?:[a-zA-Z_]\w*)/g, cls: "text-[var(--ansi-yellow)]/90" },
    { regex: /"(?:[^"\\]|\\.)*"/g, cls: "text-[var(--ansi-green)]/75" },
    { regex: /\/[^/]+\/[a-z]*/g, cls: "text-[var(--ansi-magenta)]/80" },
    { regex: /(#.*)$/gm, cls: "text-muted-foreground" },
  ],
  plain: [],
};

function tokenize(text: string, patterns: { regex: RegExp; cls: string }[]): (string | { text: string; cls: string })[] {
  if (patterns.length === 0) return [text];

  const segments: { text: string; cls: string; idx: number }[] = [];
  const combined = text.replace(/[<>]/g, (c) => ({ "<": "&lt;", ">": "&gt;" })[c] || c);

  for (const p of patterns) {
    let m: RegExpExecArray | null;
    const re = new RegExp(p.regex.source, p.regex.flags + (p.regex.global ? "" : "g"));
    while ((m = re.exec(combined)) !== null) {
      segments.push({ text: m[0], cls: p.cls, idx: m.index });
    }
  }

  segments.sort((a, b) => a.idx - b.idx);

  const merged: (string | { text: string; cls: string })[] = [];
  let pos = 0;
  for (const seg of segments) {
    if (seg.idx < pos) continue;
    if (seg.idx > pos) merged.push(combined.slice(pos, seg.idx));
    merged.push({ text: seg.text, cls: seg.cls });
    pos = seg.idx + seg.text.length;
  }
  if (pos < combined.length) merged.push(combined.slice(pos));
  return merged;
}

export function CodeBlock({
  language = "plain",
  children,
  className = "",
  maxHeight,
  wrap = true,
}: {
  language?: Lang;
  children: string;
  className?: string;
  maxHeight?: string;
  wrap?: boolean;
}) {
  const tokens = useMemo(() => tokenize(children, PATTERNS[language] ?? PATTERNS.plain), [children, language]);

  return (
    <pre
      className={`overflow-auto rounded border border-subtle bg-surface-0 p-3 text-mono ba-text-sm leading-relaxed ${wrap ? "whitespace-pre-wrap break-all" : "whitespace-pre"} ${className}`}
      style={maxHeight ? { maxHeight } : undefined}
    >
      <code>
        {tokens.map((t, i) =>
          typeof t === "string" ? (
            <span key={i}>{t}</span>
          ) : (
            <span key={i} className={t.cls}>{t.text}</span>
          )
        )}
      </code>
    </pre>
  );
}
