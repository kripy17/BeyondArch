import type { LucideIcon } from "lucide-react";

export type ObservableKind =
  | "ipv4" | "ipv6" | "url" | "domain" | "email"
  | "hash-md5" | "hash-sha1" | "hash-sha256" | "hash-sha512"
  | "cve" | "mitre" | "win-event-id" | "ja3"
  | "unknown";

export type CommandCategory =
  | "Go" | "Navigate"
  | "Search" | "Analyze" | "Create"
  | "Investigation" | "Intel" | "Intake" | "Detection"
  | "Recent" | "Actions" | "Macros";

export interface CommandResult {
  id: string;
  title: string;
  subtitle?: string;
  icon: LucideIcon;
  category: CommandCategory;
  keywords: string[];
  score: number;
  run: () => void;
}

export interface PaletteProvider {
  id: string;
  priority: number;
  getResults(input: string, ctx: PaletteContext): CommandResult[];
}

export interface PaletteContext {
  activeCase: { id: string; title: string } | null;
  recentPaths: string[];
  lockerCount: number;
}
