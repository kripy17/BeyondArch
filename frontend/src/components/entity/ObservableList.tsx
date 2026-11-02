import { useCallback, useState } from "react";
import { Copy, Check, Database, Globe, Monitor, Fingerprint, Hash, Mail, Link2, FileText, AlertTriangle, HelpCircle, type LucideIcon } from "lucide-react";
import { notify } from "@/lib/notify";
import { useLocker, type LockerItem } from "@/lib/locker";
import { copyText } from "@/lib/copy";
import { cn } from "@/lib/utils";
import type { Observable } from "@/data/intel";

const OBSERVABLE_ICON: Record<string, LucideIcon> = {
  ipv4: Globe,
  ipv6: Globe,
  domain: Globe,
  url: Link2,
  email: Mail,
  sha256: Hash,
  sha1: Hash,
  md5: Hash,
  sha512: Hash,
  ja3: Fingerprint,
  ja4: Fingerprint,
  file: FileText,
  "registry-key": Monitor,
  process: Monitor,
  mutex: Monitor,
  cve: AlertTriangle,
  ua: Monitor,
  text: FileText,
  unknown: HelpCircle,
};

const OBSERVABLE_COLOR: Record<string, string> = {
  cve: "border-destructive/40 bg-destructive/10 text-destructive",
  ja3: "border-warning/40 bg-warning/10 text-warning",
  ja4: "border-warning/40 bg-warning/10 text-warning",
  ipv4: "border-info/40 bg-info/10 text-info",
  ipv6: "border-info/40 bg-info/10 text-info",
  domain: "border-info/40 bg-info/10 text-info",
  url: "border-info/40 bg-info/10 text-info",
  email: "border-info/40 bg-info/10 text-info",
  hash: "border-primary/40 bg-primary/10 text-primary",
};

function getObservableColor(type: string): string {
  if (type.startsWith("sha") || type.startsWith("md")) return OBSERVABLE_COLOR.hash!;
  return OBSERVABLE_COLOR[type] ?? "border-subtle bg-surface-1 text-fg-dim";
}

const LOCKER_TYPES: Record<string, LockerItem["type"]> = {
  sha512: "unknown",
  ja4: "unknown",
  "registry-key": "unknown",
  process: "unknown",
  mutex: "unknown",
};

function toLockerType(type: Observable["type"]): LockerItem["type"] {
  return LOCKER_TYPES[type] ?? type;
}

export function ObservableList({ observables }: { observables: Observable[] }) {
  const locker = useLocker();

  if (observables.length === 0) return null;

  return (
    <div className="divide-y divide-border/50">
      {observables.map((obs) => (
        <ObservableRow key={obs.id} observable={obs} locker={locker} />
      ))}
    </div>
  );
}

function ObservableRow({ observable: obs, locker }: { observable: Observable; locker: ReturnType<typeof useLocker> }) {
  const [copied, setCopied] = useState(false);
  const Icon = OBSERVABLE_ICON[obs.type] ?? HelpCircle;

  const handleCopy = useCallback(() => {
    copyText(obs.value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [obs.value]);

  return (
    <div className="flex items-center gap-2 px-1 py-2 transition-colors duration-150 hover:bg-surface-1">
      <span className={cn("grid h-6 w-6 shrink-0 place-items-center rounded border", getObservableColor(obs.type))}>
        <Icon className="h-3 w-3" />
      </span>
      <span className={cn(
        "shrink-0 rounded border px-1 py-px font-mono ba-text-3xs",
        getObservableColor(obs.type),
      )}>
        {obs.type}
      </span>
      <code className="flex-1 truncate font-mono ba-text-2xs text-fg-dim">{obs.value}</code>
      {obs.context && (
        <span className="hidden truncate font-mono ba-text-2xs text-fg-dim sm:block max-w-[120px]">
          {obs.context}
        </span>
      )}
      <div className="flex shrink-0 items-center gap-0.5">
        <button
          onClick={handleCopy}
          className="rounded p-1 text-muted-foreground/50 transition-colors duration-150 hover:text-foreground"
          title="Copy value"
        >
          {copied ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
        </button>
        <button
          onClick={() => { locker.add({ value: obs.value, type: toLockerType(obs.type), source: "/intel" }); notify.success("Added to locker"); }}
          className="rounded p-1 text-muted-foreground/50 transition-colors duration-150 hover:text-foreground"
          title="Add to locker"
        >
          <Database className="h-3 w-3" />
        </button>
      </div>
    </div>
  );
}
