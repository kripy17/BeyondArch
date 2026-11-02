import type { Case } from "@/data/case";
import type { AlertLedgerEntry } from "@/lib/alerts/ingest";
import type { TimelineEvent } from "@/lib/timeline";
import type { IOC, Finding } from "@/types/security";

export type ThreatLevel = "critical" | "high" | "elevated" | "guarded" | "low";

export interface SocReadiness {
  threatLevel: ThreatLevel;
  defconLevel: number; // 1 (critical) to 5 (low)
  threatScore: number; // 0 - 100
  activeCasesCount: number;
  totalCasesCount: number;
  criticalIocsCount: number;
  highIocsCount: number;
  totalIocsCount: number;
  unhandledAlertsCount: number;
  mitreTechniquesCount: number;
  timelineEventsCount: number;
  mode: "offline-safe" | "connected";
}

export interface ActiveSentinel {
  id: string;
  title: string;
  state: "active" | "closed";
  createdAt: string;
  elapsedFormatted: string;
  leadIocs: IOC[];
  findingsCount: number;
  topFindings: Finding[];
  mitreTechniques: string[];
  tags: string[];
  entriesCount: number;
  evidenceCount: number;
}

export type ChronicleCategory = "all" | "alert" | "detection" | "case" | "workspace";

export interface ChronicleItem {
  id: string;
  ts: string;
  category: "alert" | "detection" | "case" | "workspace";
  title: string;
  detail: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  sourceBadge: string;
  pivotTo: string;
  pivotSearch?: Record<string, string>;
}

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/** Formats an elapsed duration between a past ISO timestamp and now into human readable format. */
export function formatElapsedTime(isoString: string, nowMs = Date.now()): string {
  try {
    const start = new Date(isoString).getTime();
    if (isNaN(start)) return "—";
    const diffSec = Math.max(0, Math.floor((nowMs - start) / 1000));
    if (diffSec < 60) return `${diffSec}s`;
    const min = Math.floor(diffSec / 60);
    if (min < 60) return `${min}m`;
    const hr = Math.floor(min / 60);
    const remMin = min % 60;
    if (hr < 24) return `${hr}h ${remMin}m`;
    const days = Math.floor(hr / 24);
    const remHr = hr % 24;
    return `${days}d ${remHr}h`;
  } catch {
    return "—";
  }
}

/** Pure deterministic function to evaluate SOC operational threat posture and DEFCON status. */
export function evaluateThreatPosture(
  cases: Case[],
  alerts: AlertLedgerEntry[],
  timelineEvents: TimelineEvent[]
): SocReadiness {
  let activeCasesCount = 0;
  let criticalIocsCount = 0;
  let highIocsCount = 0;
  let totalIocsCount = 0;
  const mitreSet = new Set<string>();

  for (const c of cases) {
    if (c.state === "active") activeCasesCount++;
    for (const ioc of c.iocs ?? []) {
      totalIocsCount++;
      if (ioc.severity === "critical") criticalIocsCount++;
      else if (ioc.severity === "high") highIocsCount++;
    }
    for (const f of c.findings ?? []) {
      if (f.technique) mitreSet.add(f.technique);
    }
  }

  // Count unhandled alerts
  const unhandledAlertsCount = alerts.length;

  // High / Critical timeline events
  let highCritEvents = 0;
  for (const ev of timelineEvents) {
    if (ev.severity === "critical" || ev.severity === "high") {
      highCritEvents++;
    }
  }

  // Threat score calculation (0 - 100)
  let score = 0;
  score += Math.min(60, criticalIocsCount * 10);
  score += Math.min(25, highIocsCount * 5);
  if (activeCasesCount > 0) {
    score += Math.min(30, 10 + (activeCasesCount - 1) * 5);
  }
  score += Math.min(20, unhandledAlertsCount * 4);
  score += Math.min(15, mitreSet.size * 3);
  score += Math.min(20, highCritEvents * 5);

  const clampedScore = Math.min(100, Math.max(0, score));

  let threatLevel: ThreatLevel = "low";
  let defconLevel = 5;

  if (clampedScore >= 75) {
    threatLevel = "critical";
    defconLevel = 1;
  } else if (clampedScore >= 50) {
    threatLevel = "high";
    defconLevel = 2;
  } else if (clampedScore >= 30) {
    threatLevel = "elevated";
    defconLevel = 3;
  } else if (clampedScore >= 15) {
    threatLevel = "guarded";
    defconLevel = 4;
  } else {
    threatLevel = "low";
    defconLevel = 5;
  }

  return {
    threatLevel,
    defconLevel,
    threatScore: clampedScore,
    activeCasesCount,
    totalCasesCount: cases.length,
    criticalIocsCount,
    highIocsCount,
    totalIocsCount,
    unhandledAlertsCount,
    mitreTechniquesCount: mitreSet.size,
    timelineEventsCount: timelineEvents.length,
    mode: "offline-safe",
  };
}

/** Extracts high-priority incident context for the Active Case Sentinel card. */
export function extractActiveSentinel(activeCase: Case | null, nowMs = Date.now()): ActiveSentinel | null {
  if (!activeCase) return null;

  // Prioritize lead IOCs: critical -> high -> medium -> low -> info
  const sortedIocs = [...(activeCase.iocs ?? [])].sort((a, b) => {
    const wa = SEVERITY_WEIGHT[a.severity] ?? 0;
    const wb = SEVERITY_WEIGHT[b.severity] ?? 0;
    return wb - wa;
  });

  const mitreSet = new Set<string>();
  for (const f of activeCase.findings ?? []) {
    if (f.technique) mitreSet.add(f.technique);
  }

  return {
    id: activeCase.id,
    title: activeCase.title,
    state: activeCase.state,
    createdAt: activeCase.createdAt,
    elapsedFormatted: formatElapsedTime(activeCase.createdAt, nowMs),
    leadIocs: sortedIocs.slice(0, 5),
    findingsCount: activeCase.findings?.length ?? 0,
    topFindings: (activeCase.findings ?? []).slice(0, 3),
    mitreTechniques: Array.from(mitreSet),
    tags: activeCase.tags ?? [],
    entriesCount: activeCase.entries?.length ?? 0,
    evidenceCount: activeCase.evidenceItems?.length ?? 0,
  };
}

/** Combines timeline events, alert ledger, and case updates into a unified security chronicle. */
export function aggregateChronicle(
  timelineEvents: TimelineEvent[],
  alerts: AlertLedgerEntry[],
  cases: Case[],
  categoryFilter: ChronicleCategory = "all",
  searchQuery = ""
): ChronicleItem[] {
  const items: ChronicleItem[] = [];

  // 1. Convert timeline events
  for (const ev of timelineEvents) {
    const source = ev.source.toLowerCase();
    let cat: "detection" | "case" | "workspace" = "workspace";
    if (source.includes("detection") || source.includes("sigma") || source.includes("yara")) {
      cat = "detection";
    } else if (source.includes("case") || source.includes("evidence")) {
      cat = "case";
    }

    const sourceMap: Record<string, string> = {
      parser: "/parser",
      detection: "/detection",
      siem: "/siem",
      phishing: "/phishing",
      url: "/url",
      intel: "/intel",
      case: "/case",
      timeline: "/timeline",
    };

    items.push({
      id: `ev-${ev.id}`,
      ts: ev.ts,
      category: cat,
      title: `${ev.source.toUpperCase()}: ${ev.verb}`,
      detail: ev.detail,
      severity: ev.severity ?? "info",
      sourceBadge: ev.source,
      pivotTo: sourceMap[ev.source] ?? "/timeline",
      pivotSearch: ev.target ? { q: ev.target } : undefined,
    });
  }

  // 2. Convert alerts
  for (const a of alerts) {
    items.push({
      id: `alert-${a.alertId}`,
      ts: a.ingestedAt,
      category: "alert",
      title: `Alert: ${a.title}`,
      detail: `Format: ${a.format}${a.ruleKey ? ` · Rule: ${a.ruleKey}` : ""}`,
      severity: "high",
      sourceBadge: "alert",
      pivotTo: "/case",
    });
  }

  // 3. Convert recent case milestones
  for (const c of cases) {
    for (const e of c.events ?? []) {
      items.push({
        id: `case-ev-${e.id}`,
        ts: e.ts,
        category: "case",
        title: `${c.title}: ${e.title}`,
        detail: e.detail || `Event in investigation ${c.id}`,
        severity: e.importance === "critical" ? "critical" : e.importance === "high" ? "high" : "medium",
        sourceBadge: "case",
        pivotTo: "/case",
      });
    }
  }

  // Deduplicate by ID
  const seen = new Set<string>();
  const uniqueItems = items.filter((it) => {
    if (seen.has(it.id)) return false;
    seen.add(it.id);
    return true;
  });

  // Sort descending by timestamp
  uniqueItems.sort((a, b) => b.ts.localeCompare(a.ts));

  // Filter by category
  let filtered = uniqueItems;
  if (categoryFilter !== "all") {
    filtered = filtered.filter((it) => it.category === categoryFilter);
  }

  // Filter by search query
  if (searchQuery.trim()) {
    const q = searchQuery.toLowerCase().trim();
    filtered = filtered.filter(
      (it) =>
        it.title.toLowerCase().includes(q) ||
        it.detail.toLowerCase().includes(q) ||
        it.sourceBadge.toLowerCase().includes(q)
    );
  }

  return filtered.slice(0, 50);
}

/** Generates a comprehensive Markdown Shift Handover Report. */
export function generateShiftHandoverReport(
  readiness: SocReadiness,
  activeCase: Case | null,
  recentAlerts: AlertLedgerEntry[],
  recentEvents: TimelineEvent[]
): string {
  const dateStr = new Date().toUTCString();
  const defconDesc =
    readiness.defconLevel === 1 ? "DEFCON 1 · CRITICAL THREAT"
    : readiness.defconLevel === 2 ? "DEFCON 2 · HIGH THREAT"
    : readiness.defconLevel === 3 ? "DEFCON 3 · ELEVATED POSTURE"
    : readiness.defconLevel === 4 ? "DEFCON 4 · GUARDED POSTURE"
    : "DEFCON 5 · NORMAL OPERATIONS";

  let report = `# BeyondLabs SOC Shift Handover Report\n`;
  report += `**Generated**: ${dateStr}\n`;
  report += `**Operational Threat Posture**: ${defconDesc} (Score: ${readiness.threatScore}/100)\n\n`;

  report += `## 1. Executive Operations Summary\n`;
  report += `- **Active Investigations**: ${readiness.activeCasesCount} (Total Cases: ${readiness.totalCasesCount})\n`;
  report += `- **Critical IOCs under Watch**: ${readiness.criticalIocsCount} (High IOCs: ${readiness.highIocsCount}, Total: ${readiness.totalIocsCount})\n`;
  report += `- **Ingested Alerts / Unhandled Telemetry**: ${readiness.unhandledAlertsCount}\n`;
  report += `- **Active MITRE ATT&CK Techniques**: ${readiness.mitreTechniquesCount}\n`;
  report += `- **Platform Mode**: ${readiness.mode} (Local-First Sandbox)\n\n`;

  report += `## 2. Active Incident Sentinel\n`;
  if (activeCase) {
    report += `### [${activeCase.id}] ${activeCase.title}\n`;
    report += `- **Status**: ${activeCase.state.toUpperCase()}\n`;
    report += `- **Opened**: ${new Date(activeCase.createdAt).toLocaleString()}\n`;
    report += `- **Entries**: ${activeCase.entries?.length ?? 0} | **Evidence Items**: ${activeCase.evidenceItems?.length ?? 0} | **Findings**: ${activeCase.findings?.length ?? 0}\n`;
    if (activeCase.tags?.length) {
      report += `- **Tags**: \`${activeCase.tags.join("`, `")}\`\n`;
    }

    if (activeCase.iocs?.length) {
      report += `\n**Key Indicators of Compromise (Lead IOCs)**:\n`;
      for (const ioc of (activeCase.iocs ?? []).slice(0, 8)) {
        report += `- \`[${ioc.severity.toUpperCase()}]\` **${ioc.type}**: \`${ioc.value}\` ${ioc.context ? `— ${ioc.context}` : ""}\n`;
      }
    }
  } else {
    report += `*No active primary investigation selected at time of handover.*\n`;
  }
  report += `\n`;

  report += `## 3. Ingested Alert Ledger (Recent ${Math.min(5, recentAlerts.length)})\n`;
  if (recentAlerts.length > 0) {
    for (const a of recentAlerts.slice(0, 5)) {
      report += `- **${a.title}** (\`${a.format}\`) — Ingested: ${new Date(a.ingestedAt).toLocaleTimeString()} ${a.ruleKey ? `[Rule: ${a.ruleKey}]` : ""}\n`;
    }
  } else {
    report += `*No external alerts queued.*\n`;
  }
  report += `\n`;

  report += `## 4. Notable Analyst Chronology & Detections\n`;
  if (recentEvents.length > 0) {
    for (const ev of recentEvents.slice(0, 5)) {
      report += `- \`[${ev.source.toUpperCase()}]\` **${ev.verb}**: ${ev.detail} (${new Date(ev.ts).toLocaleTimeString()})\n`;
    }
  } else {
    report += `*No recent events recorded in timeline session.*\n`;
  }
  report += `\n`;

  report += `---\n`;
  report += `*Confidential & Local-First — Generated by BeyondLabs Incident Command Deck*\n`;

  return report;
}

/** Formats a full JSON telemetry snapshot of the platform. */
export function exportDeckTelemetryJson(
  readiness: SocReadiness,
  activeCase: Case | null,
  cases: Case[],
  alerts: AlertLedgerEntry[]
): string {
  const payload = {
    exportedAt: new Date().toISOString(),
    readiness,
    activeCase: activeCase
      ? {
          id: activeCase.id,
          title: activeCase.title,
          state: activeCase.state,
          createdAt: activeCase.createdAt,
          tags: activeCase.tags,
          iocsCount: activeCase.iocs?.length ?? 0,
          findingsCount: activeCase.findings?.length ?? 0,
          evidenceCount: activeCase.evidenceItems?.length ?? 0,
        }
      : null,
    casesSummary: {
      total: cases.length,
      active: cases.filter((c) => c.state === "active").length,
      closed: cases.filter((c) => c.state === "closed").length,
    },
    alertsCount: alerts.length,
  };
  return JSON.stringify(payload, null, 2);
}
