import { useState } from "react";
import type { LucideIcon } from "lucide-react";
import {
  Activity,
  Check,
  Copy,
  FileJson,
  FileText,
  Radar,
  ScrollText,
  Share2,
  ShieldAlert,
} from "lucide-react";
import { copyText } from "@/lib/copy";

export type WorkflowAction =
  | { kind: "pivot"; to: string; label?: string; icon?: LucideIcon; onClick?: () => void }
  | { kind: "investigation"; onClick: () => void }
  | { kind: "export-md"; onClick: () => void }
  | { kind: "export-json"; onClick: () => void }
  | { kind: "copy"; value: string; label?: string }
  | { kind: "share"; value?: string }
  | { kind: "detection"; to?: string; onClick?: () => void }
  | { kind: "report"; to?: string; onClick?: () => void }
  | {
      kind: "custom";
      label: string;
      icon?: LucideIcon;
      onClick?: () => void;
      to?: string;
      tone?: "default" | "primary" | "danger";
    };

type Defaults = { label: string; icon: LucideIcon; tone: "default" | "primary" | "danger" };

const DEFAULTS: Record<string, Defaults> = {
  pivot: { label: "Pivot to Intel", icon: Radar, tone: "default" },
  investigation: { label: "Investigation", icon: Activity, tone: "primary" },
  "export-md": { label: "Markdown", icon: FileText, tone: "default" },
  "export-json": { label: "JSON", icon: FileJson, tone: "default" },
  copy: { label: "Copy", icon: Copy, tone: "default" },
  share: { label: "Share", icon: Share2, tone: "default" },
  detection: { label: "Detection", icon: ShieldAlert, tone: "default" },
  report: { label: "Report", icon: ScrollText, tone: "default" },
};

const TONE_CLASS: Record<Defaults["tone"], string> = {
  default: "border-border text-muted-foreground hover:border-primary/40 hover:text-primary",
  primary: "border-primary/50 bg-primary/10 text-primary hover:bg-primary/20",
  danger: "border-border text-muted-foreground hover:border-destructive/50 hover:text-destructive",
};

export function WorkflowActions({
  actions,
  label = "workflow",
}: {
  actions: WorkflowAction[];
  label?: string;
}) {
  const [copied, setCopied] = useState<string | null>(null);

  const flash = (key: string) => {
    setCopied(key);
    window.setTimeout(() => setCopied((c) => (c === key ? null : c)), 1200);
  };

  const render = (a: WorkflowAction, i: number) => {
    const key = `${a.kind}-${i}`;
    const def = DEFAULTS[a.kind];
    const label = "label" in a && a.label ? a.label : def.label;
    const Icon = "icon" in a && a.icon ? a.icon : def.icon;
    const tone = "tone" in a && a.tone ? a.tone : def.tone;
    const copiedNow = copied === key;

    const cls =
      "inline-flex items-center gap-1.5 rounded border px-2.5 py-1 text-mono ba-text-2xs transition-colors duration-150 " +
      TONE_CLASS[tone];

    const content = (
      <>
        {copiedNow ? <Check className="h-3 w-3 text-success" /> : <Icon className="h-3 w-3" />}
        {copiedNow ? "copied" : label}
      </>
    );

    if (a.kind === "copy" || a.kind === "share") {
      return (
        <button
          key={key}
          type="button"
          onClick={() => {
            const value = a.kind === "share" ? (a.value ?? window.location.href) : a.value;
            copyText(value);
            flash(key);
          }}
          title={`Copy ${label.toLowerCase()}`}
          className={cls}
        >
          {content}
        </button>
      );
    }

    const href = "to" in a && a.to ? a.to : undefined;
    const onClick = "onClick" in a && typeof a.onClick === "function" ? a.onClick : undefined;

    if (href) {
      return (
        <a key={key} href={href} onClick={onClick} title={label} className={cls}>
          {content}
        </a>
      );
    }

    return (
      <button key={key} type="button" onClick={onClick} title={label} className={cls}>
        {content}
      </button>
    );
  };

  return (
    <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1.5 rounded-md border border-divider-strong bg-card/70 px-3 py-2">
      <span className="mr-1 text-mono ba-text-2xs text-muted-foreground">{label}</span>
      {actions.map(render)}
    </div>
  );
}
