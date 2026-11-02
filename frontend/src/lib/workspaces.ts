import { MailWarning, Link2, Paperclip, Wand2,
  Activity, Wrench, Target, ShieldCheck, BookOpen, FileText,
  LayoutDashboard, Settings, Code2, Search,
  Bug, Globe, Bookmark, Clock, ListChecks, FlaskConical,
  File, ScrollText, PackageOpen, FolderOpen, LayoutGrid } from "lucide-react";

export type WorkspaceItem = {
  title: string;
  url: string;
  icon: import("lucide-react").LucideIcon;
  desc: string;
  group: string;
};

export type WorkspaceGroup = {
  label: string;
  items: WorkspaceItem[];
};

export const GROUPS: WorkspaceGroup[] = [
  {
    label: "Dashboard",
    items: [
      { title: "Command Deck", url: "/", icon: LayoutDashboard, desc: "Workbench home", group: "Dashboard" },
    ],
  },
  {
    label: "Intake",
    items: [
      { title: "Evidence Intake", url: "/intake", icon: PackageOpen, desc: "Choose an artifact to analyze", group: "Intake" },
      { title: "Triage", url: "/triage", icon: ListChecks, desc: "Review & disposition events", group: "Intake" },
      { title: "Phishing", url: "/phishing", icon: MailWarning, desc: "Auth, headers, body verdict", group: "Intake" },
      { title: "URL Analysis", url: "/url", icon: Link2, desc: "Heuristics, redirect trace, blocklist", group: "Intake" },
      { title: "Malware & File", url: "/file", icon: File, desc: "PE, docs, scripts & binaries", group: "Intake" },
      { title: "Windows Logs", url: "/logs", icon: ScrollText, desc: "Security & Sysmon analysis", group: "Intake" },
      { title: "PCAP Analysis", url: "/pcap", icon: Globe, desc: "Quick pcap triage & CLI tools", group: "Intake" },
    ],
  },
  {
    label: "Investigation",
    items: [
      { title: "Case Desk", url: "/investigation", icon: FolderOpen, desc: "Continue work in progress", group: "Investigation" },
      { title: "Cases", url: "/case", icon: FileText, desc: "Compose handoff brief", group: "Investigation" },
      { title: "Activity", url: "/activity", icon: Clock, desc: "Timeline of all tool runs & events", group: "Investigation" },
      { title: "Timeline", url: "/timeline", icon: Clock, desc: "Raw event log viewer", group: "Investigation" },
    ],
  },
  {
    label: "Detection",
    items: [
      { title: "Workspace", url: "/detection", icon: ShieldCheck, desc: "Author & simulate Sigma/YARA/Suricata", group: "Detection" },
      { title: "MITRE ATT&CK", url: "/mitre", icon: Target, desc: "14-Tactic Enterprise Navigator", group: "Detection" },
      { title: "Sigma Tester", url: "/sigma-tester", icon: FlaskConical, desc: "Rule AST testbench & transpiler", group: "Detection" },
    ],
  },
  {
    label: "SIEM",
    items: [
      { title: "Workspace", url: "/siem", icon: Activity, desc: "Search, correlate, pivot", group: "SIEM" },
    ],
  },
  {
    label: "Operations",
    items: [
      { title: "SOAR Deck", url: "/operations", icon: LayoutGrid, desc: "Playbooks & orchestration engine", group: "Operations" },
      { title: "Parser", url: "/parser", icon: Wand2, desc: "Universal IOC extractor", group: "Operations" },
      { title: "CyberChef", url: "/chef", icon: Wrench, desc: "Encode, decode, transform", group: "Operations" },
      { title: "Diff", url: "/diff", icon: Code2, desc: "Side-by-side artifact comparison", group: "Operations" },
      { title: "Regex", url: "/regex-playground", icon: Search, desc: "Build & test SOC regex patterns", group: "Operations" },
      { title: "Hunting Arsenal", url: "/snippets", icon: Bookmark, desc: "Production queries & checklists", group: "Operations" },
    ],
  },
  {
    label: "System",
    items: [
      { title: "Settings", url: "/settings", icon: Settings, desc: "Theme, layout, prefs", group: "System" },
    ],
  },
];

export const ALL_ITEMS: WorkspaceItem[] = GROUPS.flatMap((g) => g.items);

export const WORKSPACE_HOME_URLS = new Set(["/intake", "/investigation", "/operations"]);

export function findItem(url: string): WorkspaceItem | undefined {
  return ALL_ITEMS.find((i) => i.url === url);
}

const WORKSPACE_CRUMB: Record<string, string> = {
  Dashboard: "Deck",
  Intake: "Intake",
  Investigation: "Investigation",
  Detection: "Detection",
  SIEM: "SIEM",
  Operations: "Ops",
};

const WORKSPACE_ACCENT: Record<string, string> = {
  Intake: "intake",
  Investigation: "investigation",
  Detection: "detection",
  SIEM: "siem",
  Operations: "operations",
};

const WORKSPACE_INTENT: Record<string, string> = {
  Intake: "Analyze new evidence — triage, dissect, and score what comes in.",
  Investigation: "Build the case — connect artifacts into a defensible story.",
  Detection: "Convert knowledge into detections that catch the next one.",
  SIEM: "Hunt and validate — search, correlate, pivot.",
  Operations: "Supporting analyst utilities — parse, transform, compare.",
};

function workspaceItemFor(url: string): WorkspaceItem | undefined {
  return findItem(url) ?? ALL_ITEMS.find((i) => url.startsWith(i.url + "/"));
}

export function getWorkspaceLabel(url: string): string | null {
  const item = workspaceItemFor(url);
  if (!item) return null;
  return WORKSPACE_CRUMB[item.group] ?? item.group;
}

export function getWorkspaceAccent(url: string): string | null {
  const item = workspaceItemFor(url);
  if (!item) return null;
  return WORKSPACE_ACCENT[item.group] ?? null;
}

export function getWorkspaceIntent(url: string): string | null {
  const item = workspaceItemFor(url);
  if (!item) return null;
  return WORKSPACE_INTENT[item.group] ?? null;
}
