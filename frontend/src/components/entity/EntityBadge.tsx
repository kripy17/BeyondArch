import { ShieldAlert, Users, Bug, Hash, Fingerprint, type LucideIcon } from "lucide-react";
import type { IntelEntityType, Confidence } from "@/data/intel";
import { cn } from "@/lib/utils";

const TYPE_ICON: Record<IntelEntityType, LucideIcon> = {
  vulnerability: ShieldAlert,
  "threat-actor": Users,
  malware: Bug,
  "file-hash": Hash,
  "tls-fingerprint": Fingerprint,
};

const TYPE_COLOR: Record<IntelEntityType, string> = {
  vulnerability: "border-destructive/40 bg-destructive/10 text-destructive",
  "threat-actor": "border-warning/40 bg-warning/10 text-warning",
  malware: "border-accent/40 bg-accent/10 text-accent",
  "file-hash": "border-info/40 bg-info/10 text-info",
  "tls-fingerprint": "border-primary/40 bg-primary/10 text-primary",
};

const TYPE_LABEL: Record<IntelEntityType, string> = {
  vulnerability: "CVE",
  "threat-actor": "Actor",
  malware: "Malware",
  "file-hash": "Hash",
  "tls-fingerprint": "TLS FP",
};

export function EntityTypeBadge({ type, className }: { type: IntelEntityType; className?: string }) {
  const Icon = TYPE_ICON[type];
  return (
    <span className={cn("inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-mono ba-text-3xs", TYPE_COLOR[type], className)}>
      <Icon className="h-3 w-3" />
      {TYPE_LABEL[type]}
    </span>
  );
}

export function EntityTypeIcon({ type, className }: { type: IntelEntityType; className?: string }) {
  const Icon = TYPE_ICON[type];
  return <Icon className={cn("h-4 w-4", className)} />;
}

const CONFIDENCE_COLOR: Record<Confidence, string> = {
  high: "border-success/40 bg-success/10 text-success",
  medium: "border-warning/40 bg-warning/10 text-warning",
  low: "border-subtle bg-surface-1 text-fg-dim",
  unknown: "border-subtle bg-surface-1 text-fg-dim",
};

export function ConfidenceBadge({ confidence, className }: { confidence: Confidence; className?: string }) {
  return (
    <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-mono ba-text-3xs", CONFIDENCE_COLOR[confidence], className)}>
      {confidence}
    </span>
  );
}

export function ScoreBadge({ score, className }: { score: number; className?: string }) {
  return (
    <span className={cn("rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-mono ba-text-2xs font-bold text-primary", className)}>
      {score}
    </span>
  );
}
