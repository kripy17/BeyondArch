import { loadCases, saveCases, type CaseEvent, type EventImportance, type CaseEventKind, type EventCategory, type EventActor } from "@/data/case";

export type TimelineSeverity = "critical" | "high" | "medium" | "low" | "info";
export type TimelineActor = "analyst" | "system" | "automation";

export interface TimelineEvent {
  id: string;
  ts: string;
  source: string;
  verb: string;
  detail: string;
  target?: string;
  result?: string;
  severity?: TimelineSeverity;
  actor?: TimelineActor;
  caseId?: string;
  tags?: string[];
  evidenceId?: string;
  metadata?: Record<string, string | number | boolean>;
}

export const TIMELINE_STORAGE_KEY = "ba.timeline.v1";
export const TIMELINE_UPDATED_EVENT = "ba:timeline-updated";
const MAX_EVENTS = 500;

function fnv1a(str: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/** Intelligently infer event severity based on keywords and source/verb semantics. */
export function inferEventSeverity(event: Partial<TimelineEvent>): TimelineSeverity {
  if (event.severity) return event.severity;
  const combined = `${event.verb || ""} ${event.detail || ""} ${event.result || ""} ${event.target || ""}`.toLowerCase();

  if (
    combined.includes("critical") ||
    combined.includes("ransomware") ||
    combined.includes("exploit") ||
    combined.includes("exfiltration") ||
    combined.includes("c2 beacon") ||
    combined.includes("mimikatz") ||
    combined.includes("credential dump") ||
    event.verb === "quarantined" ||
    event.verb === "blocked" ||
    event.verb === "contained"
  ) {
    return "critical";
  }

  if (
    combined.includes("malicious") ||
    combined.includes("high") ||
    combined.includes("suspicious") ||
    combined.includes("phishing") ||
    combined.includes("alert") ||
    combined.includes("backdoor") ||
    combined.includes("reverse shell") ||
    event.verb === "flagged" ||
    event.verb === "detected"
  ) {
    return "high";
  }

  if (
    combined.includes("medium") ||
    combined.includes("warning") ||
    combined.includes("anomaly") ||
    combined.includes("deviation") ||
    combined.includes("modified") ||
    combined.includes("unusual")
  ) {
    return "medium";
  }

  if (
    combined.includes("low") ||
    combined.includes("clean") ||
    combined.includes("safe") ||
    combined.includes("benign") ||
    combined.includes("downloaded")
  ) {
    return "low";
  }

  return "info";
}

/** Intelligently infer event actor based on source and action semantics. */
export function inferEventActor(event: Partial<TimelineEvent>): TimelineActor {
  if (event.actor) return event.actor;
  const verb = (event.verb || "").toLowerCase();
  const source = (event.source || "").toLowerCase();

  if (
    source === "case" ||
    source === "analyst" ||
    verb.includes("note") ||
    verb.includes("decision") ||
    verb.includes("milestone") ||
    verb.includes("tag") ||
    verb.includes("review") ||
    verb.includes("manual")
  ) {
    return "analyst";
  }

  if (
    source === "detection" ||
    source === "sigma" ||
    verb.includes("matched") ||
    verb.includes("triggered") ||
    verb.includes("alert")
  ) {
    return "system";
  }

  return "automation";
}

export function pushTimelineEvent(event: Omit<TimelineEvent, "id" | "ts"> & { id?: string; ts?: string }): TimelineEvent {
  const events = getTimelineEvents();
  const enriched: TimelineEvent = {
    ...event,
    id: event.id || crypto.randomUUID(),
    ts: event.ts || new Date().toISOString(),
    severity: inferEventSeverity(event),
    actor: inferEventActor(event),
  };

  events.unshift(enriched);
  if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;

  try {
    localStorage.setItem(TIMELINE_STORAGE_KEY, JSON.stringify(events));
  } catch {}

  try {
    window.dispatchEvent(new CustomEvent(TIMELINE_UPDATED_EVENT, { detail: enriched }));
  } catch {}

  return enriched;
}

export const DEFAULT_TIMELINE_SCENARIO: TimelineEvent[] = [
  {
    id: "tl-scen-09",
    ts: "2026-09-13T09:50:30.000Z",
    source: "analyst",
    verb: "Perimeter Containment Executed",
    detail: "Firewall drop rule applied for C2 IP 51.15.0.100 and compromised host WS-SEC-092 isolated from subnet via Microsoft Defender API.",
    severity: "high",
    actor: "analyst",
    target: "51.15.0.100",
    result: "Host isolated; network egress terminated",
    tags: ["containment", "p1", "response"],
    caseId: "case-9d116285",
  },
  {
    id: "tl-scen-08",
    ts: "2026-09-13T09:45:00.000Z",
    source: "case",
    verb: "Escalated to P1 Incident Case",
    detail: "Alert triaged as True Positive and promoted to primary investigation Case case-9d116285 with 4 associated observables.",
    severity: "high",
    actor: "analyst",
    target: "case-9d116285",
    result: "Investigation initialized",
    tags: ["triage", "escalation", "soc"],
    caseId: "case-9d116285",
  },
  {
    id: "tl-scen-07",
    ts: "2026-09-13T09:40:15.000Z",
    source: "detection",
    verb: "Suricata IDS Alert Fired",
    detail: "ET MALWARE Win32/CobaltStrike.Beacon TLS Certificate Mismatch observed to 51.15.0.100:443 (SID: 2028911).",
    severity: "critical",
    actor: "system",
    target: "51.15.0.100:443",
    result: "Signature match SID:2028911",
    tags: ["suricata", "c2", "cobalt-strike"],
  },
  {
    id: "tl-scen-06",
    ts: "2026-09-13T09:35:20.000Z",
    source: "pcap",
    verb: "Deterministic C2 Beaconing Observed",
    detail: "Zeek conn telemetry reveals recurring TLS session handshake to external peer 51.15.0.100 with mean interval 30.2s and 4.2% jitter.",
    severity: "critical",
    actor: "system",
    target: "51.15.0.100",
    result: "High confidence C2 beacon cadence",
    tags: ["network", "beaconing", "zeek", "c2"],
  },
  {
    id: "tl-scen-05",
    ts: "2026-09-13T09:30:12.000Z",
    source: "siem",
    verb: "Internal Reconnaissance Port Sweep",
    detail: "Host WS-SEC-092 generated anomalous SYN flood sweeping TCP ports 445 (SMB), 135 (RPC), and 389 (LDAP) across domain controller 192.168.1.10.",
    severity: "medium",
    actor: "system",
    target: "192.168.1.10",
    result: "Port sweep flagged by SIEM rule",
    tags: ["discovery", "t1046", "lateral-recon"],
  },
  {
    id: "tl-scen-04",
    ts: "2026-09-13T09:24:45.000Z",
    source: "file",
    verb: "CAPA Capabilities Flagged Injection & Credential Access",
    detail: "Static binary inspection of dropped agent.exe detected injection capability (VirtualAllocEx + WriteProcessMemory) and LSASS memory access primitives.",
    severity: "critical",
    actor: "system",
    target: "agent.exe",
    result: "CAPA: inject code into peer process, dump lsass",
    tags: ["malware", "capa", "injection", "lsass"],
  },
  {
    id: "tl-scen-03",
    ts: "2026-09-13T09:21:10.000Z",
    source: "logs",
    verb: "Suspicious Encoded PowerShell Execution",
    detail: "Event ID 4688: powershell.exe spawned with encoded download cradle -enc SQBFAFgA... pulling remote staging script from auth-login-microsoft.com.",
    severity: "critical",
    actor: "system",
    target: "powershell.exe",
    result: "LOLBAS cradle execution detected",
    tags: ["logs", "sysmon", "t1059.001", "execution"],
  },
  {
    id: "tl-scen-02",
    ts: "2026-09-13T09:17:30.000Z",
    source: "url",
    verb: "Deceptive M365 Phishing Portal Contacted",
    detail: "User redirected to credential harvesting lure at https://auth-login-microsoft.com/sso/v2/login?auth_token=9a8f. Spoofed Microsoft login observed.",
    severity: "high",
    actor: "system",
    target: "https://auth-login-microsoft.com",
    result: "Brand impersonation detected",
    tags: ["phishing", "url", "credential-harvesting"],
  },
  {
    id: "tl-scen-01",
    ts: "2026-09-13T09:15:00.000Z",
    source: "phishing",
    verb: "Weaponized Phishing Email Received",
    detail: "Inbound email from billing@m1crosoft-support.com with subject 'Urgent Invoice Q3-2026 Payment Confirmation' received by victim finance_admin@corp.net.",
    severity: "high",
    actor: "system",
    target: "finance_admin@corp.net",
    result: "SPF/DKIM alignment failed",
    tags: ["initial-access", "email", "t1566.001"],
  },
];

export function getTimelineEvents(): TimelineEvent[] {
  try {
    const raw = localStorage.getItem(TIMELINE_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as TimelineEvent[];
    return parsed.map((e) => ({
      ...e,
      severity: e.severity || inferEventSeverity(e),
      actor: e.actor || inferEventActor(e),
    }));
  } catch {
    return [];
  }
}

export function clearTimeline(): void {
  try {
    localStorage.removeItem(TIMELINE_STORAGE_KEY);
    localStorage.setItem("ba.timeline.cleared", "true");
  } catch {}
  try {
    window.dispatchEvent(new CustomEvent(TIMELINE_UPDATED_EVENT));
  } catch {}
}

export function restoreDefaultTimelineScenario(): TimelineEvent[] {
  try {
    localStorage.removeItem("ba.timeline.cleared");
    localStorage.setItem(TIMELINE_STORAGE_KEY, JSON.stringify(DEFAULT_TIMELINE_SCENARIO));
  } catch {}
  try {
    window.dispatchEvent(new CustomEvent(TIMELINE_UPDATED_EVENT));
  } catch {}
  return DEFAULT_TIMELINE_SCENARIO;
}

export function deleteTimelineEvent(id: string): void {
  const events = getTimelineEvents().filter((e) => e.id !== id);
  try {
    localStorage.setItem(TIMELINE_STORAGE_KEY, JSON.stringify(events));
  } catch {}
  try {
    window.dispatchEvent(new CustomEvent(TIMELINE_UPDATED_EVENT, { detail: { deletedId: id } }));
  } catch {}
}

export interface AnalystMilestoneInput {
  title: string;
  detail: string;
  severity?: TimelineSeverity;
  target?: string;
  result?: string;
  ts?: string;
  tags?: string[];
  caseId?: string;
}

export function addAnalystMilestone(milestone: AnalystMilestoneInput): TimelineEvent {
  return pushTimelineEvent({
    source: "analyst",
    verb: milestone.title.trim() || "Milestone Logged",
    detail: milestone.detail.trim(),
    severity: milestone.severity || "high",
    actor: "analyst",
    target: milestone.target?.trim() || undefined,
    result: milestone.result?.trim() || undefined,
    ts: milestone.ts || new Date().toISOString(),
    tags: milestone.tags,
    caseId: milestone.caseId,
  });
}

export interface TimelineBucket {
  index: number;
  start: string;
  end: string;
  label: string;
  count: number;
  peakSeverity: TimelineSeverity;
  severityCounts: Record<TimelineSeverity, number>;
  sourceCounts: Record<string, number>;
  events: TimelineEvent[];
  heightPercent: number;
}

export function bucketEventsByTime(
  events: TimelineEvent[],
  options?: { bucketCount?: number; intervalMs?: number },
): TimelineBucket[] {
  if (!events.length) return [];

  const timestamps = events
    .map((e) => new Date(e.ts).getTime())
    .filter((t) => !Number.isNaN(t));

  if (!timestamps.length) return [];

  const minTs = Math.min(...timestamps);
  const maxTs = Math.max(...timestamps);
  const span = Math.max(maxTs - minTs, 60_000); // minimum 1 minute span

  const targetCount = options?.bucketCount ?? 24;
  const intervalMs = options?.intervalMs ?? Math.max(Math.ceil(span / targetCount), 60_000);
  const count = Math.max(1, Math.ceil(span / intervalMs) + 1);

  const buckets: TimelineBucket[] = [];
  for (let i = 0; i < count; i++) {
    const startMs = minTs + i * intervalMs;
    const endMs = startMs + intervalMs;
    const startDate = new Date(startMs);
    const label = `${String(startDate.getHours()).padStart(2, "0")}:${String(startDate.getMinutes()).padStart(2, "0")}`;

    buckets.push({
      index: i,
      start: new Date(startMs).toISOString(),
      end: new Date(endMs).toISOString(),
      label,
      count: 0,
      peakSeverity: "info",
      severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      sourceCounts: {},
      events: [],
      heightPercent: 0,
    });
  }

  const severityWeights: Record<TimelineSeverity, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };

  for (const event of events) {
    const t = new Date(event.ts).getTime();
    if (Number.isNaN(t)) continue;
    const bIndex = Math.min(count - 1, Math.max(0, Math.floor((t - minTs) / intervalMs)));
    const bucket = buckets[bIndex];
    if (!bucket) continue;

    bucket.count += 1;
    bucket.events.push(event);

    const sev = event.severity || "info";
    bucket.severityCounts[sev] = (bucket.severityCounts[sev] || 0) + 1;

    const src = event.source || "unknown";
    bucket.sourceCounts[src] = (bucket.sourceCounts[src] || 0) + 1;

    if (severityWeights[sev] > severityWeights[bucket.peakSeverity]) {
      bucket.peakSeverity = sev;
    }
  }

  const maxCount = Math.max(...buckets.map((b) => b.count), 1);
  for (const b of buckets) {
    b.heightPercent = Math.round((b.count / maxCount) * 100);
  }

  return buckets;
}

export interface TimelineFilters {
  searchQuery?: string;
  sources?: string[];
  severities?: TimelineSeverity[];
  verbs?: string[];
  actors?: TimelineActor[];
  timeRange?: "15m" | "1h" | "6h" | "24h" | "7d" | "30d" | "all" | { start: string; end: string };
}

export function filterTimelineEvents(events: TimelineEvent[], filters: TimelineFilters): TimelineEvent[] {
  let result = events;

  // Time range filter
  if (filters.timeRange && filters.timeRange !== "all") {
    const now = Date.now();
    let minMs = 0;
    let maxMs = Number.MAX_SAFE_INTEGER;

    if (typeof filters.timeRange === "string") {
      const windowMap: Record<string, number> = {
        "15m": 15 * 60 * 1000,
        "1h": 60 * 60 * 1000,
        "6h": 6 * 60 * 60 * 1000,
        "24h": 24 * 60 * 60 * 1000,
        "7d": 7 * 24 * 60 * 60 * 1000,
        "30d": 30 * 24 * 60 * 60 * 1000,
      };
      if (windowMap[filters.timeRange]) {
        minMs = now - windowMap[filters.timeRange];
      }
    } else if (typeof filters.timeRange === "object") {
      if (filters.timeRange.start) minMs = new Date(filters.timeRange.start).getTime();
      if (filters.timeRange.end) maxMs = new Date(filters.timeRange.end).getTime();
    }

    result = result.filter((e) => {
      const t = new Date(e.ts).getTime();
      return !Number.isNaN(t) && t >= minMs && t <= maxMs;
    });
  }

  // Source filter
  if (filters.sources && filters.sources.length > 0) {
    const set = new Set(filters.sources);
    result = result.filter((e) => set.has(e.source));
  }

  // Severity filter
  if (filters.severities && filters.severities.length > 0) {
    const set = new Set(filters.severities);
    result = result.filter((e) => set.has(e.severity || "info"));
  }

  // Verb filter
  if (filters.verbs && filters.verbs.length > 0) {
    const set = new Set(filters.verbs);
    result = result.filter((e) => set.has(e.verb));
  }

  // Actor filter
  if (filters.actors && filters.actors.length > 0) {
    const set = new Set(filters.actors);
    result = result.filter((e) => set.has(e.actor || "automation"));
  }

  // Search query
  if (filters.searchQuery && filters.searchQuery.trim()) {
    const q = filters.searchQuery.trim().toLowerCase();
    result = result.filter((e) => {
      return (
        e.verb.toLowerCase().includes(q) ||
        e.detail.toLowerCase().includes(q) ||
        e.source.toLowerCase().includes(q) ||
        (e.target && e.target.toLowerCase().includes(q)) ||
        (e.result && e.result.toLowerCase().includes(q)) ||
        (e.actor && e.actor.toLowerCase().includes(q)) ||
        (e.tags && e.tags.some((tag) => tag.toLowerCase().includes(q)))
      );
    });
  }

  return result;
}

function escapeCsv(value: unknown): string {
  if (value === null || value === undefined) return "";
  const s = String(value);
  if (s.includes(",") || s.includes('"') || s.includes("\n") || s.includes("\r")) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

/** Export timeline events in Timesketch / DFIR standard CSV format. */
export function exportTimelineCsv(events: TimelineEvent[]): string {
  const headers = [
    "datetime",
    "timestamp_desc",
    "message",
    "source",
    "verb",
    "severity",
    "actor",
    "target",
    "result",
    "tags",
  ];

  const rows = events.map((e) => [
    escapeCsv(e.ts),
    escapeCsv("Event Logged"),
    escapeCsv(e.detail),
    escapeCsv(e.source),
    escapeCsv(e.verb),
    escapeCsv(e.severity || "info"),
    escapeCsv(e.actor || "automation"),
    escapeCsv(e.target || ""),
    escapeCsv(e.result || ""),
    escapeCsv((e.tags || []).join(";")),
  ]);

  return [headers.join(","), ...rows.map((r) => r.join(","))].join("\r\n");
}

/** Export timeline events in newline-delimited JSONL format. */
export function exportTimelineJsonl(events: TimelineEvent[]): string {
  return events.map((e) => JSON.stringify(e)).join("\n");
}

/** Export timeline events in publication-grade DFIR Markdown format. */
export function exportTimelineMarkdown(events: TimelineEvent[], title = "Forensic Investigation Timeline"): string {
  const total = events.length;
  const critical = events.filter((e) => e.severity === "critical").length;
  const high = events.filter((e) => e.severity === "high").length;
  const sources = Array.from(new Set(events.map((e) => e.source))).sort();

  const timeRange =
    events.length > 0
      ? `${events[events.length - 1].ts} → ${events[0].ts}`
      : "No events recorded";

  const lines: string[] = [
    `# ${title}`,
    "",
    "## Investigation Chronicle Summary",
    "",
    `- **Total Events:** ${total}`,
    `- **Critical Alerts:** ${critical} · **High Alerts:** ${high}`,
    `- **Active Sources:** ${sources.length > 0 ? sources.join(", ") : "None"}`,
    `- **Chronicle Span:** ${timeRange}`,
    `- **Report Generated:** ${new Date().toISOString()}`,
    "",
    "## Chronological Forensic Log",
    "",
  ];

  if (events.length === 0) {
    lines.push("_No forensic timeline events recorded._");
    return lines.join("\n");
  }

  lines.push("| Timestamp (UTC) | Severity | Source | Actor | Verb | Detail | Target / Result |");
  lines.push("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |");

  for (const e of events) {
    const ts = e.ts.replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
    const sev = (e.severity || "info").toUpperCase();
    const actor = e.actor || "automation";
    const src = e.source;
    const verb = e.verb;
    const detail = e.detail.replace(/\|/g, "\\|").replace(/\n/g, " ");
    const targetResult = [e.target ? `\`${e.target.replace(/`/g, "")}\`` : "", e.result ? `→ ${e.result}` : ""]
      .filter(Boolean)
      .join(" ")
      .replace(/\|/g, "\\|");

    lines.push(`| ${ts} | ${sev} | ${src} | ${actor} | ${verb} | ${detail} | ${targetResult || "—"} |`);
  }

  return lines.join("\n");
}

/** 1-click promotion of a timeline event to a target case's defensible ledger. */
export function promoteEventToCase(event: TimelineEvent, caseId: string): boolean {
  try {
    const cases = loadCases();
    const targetCase = cases.find((c) => c.id === caseId);
    if (!targetCase) return false;

    const eventId = `evt-tm-${fnv1a(`${caseId}|${event.id}|${event.ts}`)}`;
    const existing = targetCase.events ?? [];
    if (existing.some((e) => e.id === eventId)) {
      return true; // Already promoted (idempotent)
    }

    let kind: CaseEventKind = "analysis_completed";
    let category: EventCategory = "analysis";
    let actor: EventActor = "automation";

    if (event.actor === "analyst") {
      kind = "analyst_action";
      category = "analyst";
      actor = "analyst";
    } else if (event.source === "detection" || event.source === "sigma") {
      kind = "alert_ingested";
      category = "detection";
      actor = "system";
    }

    let importance: EventImportance = "normal";
    if (event.severity === "critical") importance = "critical";
    else if (event.severity === "high") importance = "high";
    else if (event.severity === "low") importance = "low";

    const caseEvent: CaseEvent = {
      id: eventId,
      ts: event.ts,
      kind,
      category,
      importance,
      actor,
      origin: `/timeline (${event.source})`,
      title: `${event.verb}${event.target ? `: ${event.target}` : ""}`,
      detail: `${event.detail}${event.result ? ` [Result: ${event.result}]` : ""}`,
      references: event.target ? [{ kind: "ioc", id: event.target }] : [],
    };

    const updatedCase = {
      ...targetCase,
      events: [...existing, caseEvent],
    };

    saveCases(cases.map((c) => (c.id === caseId ? updatedCase : c)));
    return true;
  } catch {
    return false;
  }
}

export type IntrusionStage =
  | "initial_access"
  | "execution"
  | "persistence"
  | "defense_evasion"
  | "credential_access"
  | "discovery"
  | "lateral_movement"
  | "command_and_control"
  | "exfiltration"
  | "containment";

export interface StageProgression {
  stage: IntrusionStage;
  label: string;
  mitreTactic: string;
  tone: "primary" | "warning" | "destructive" | "success" | "info";
  eventCount: number;
  events: TimelineEvent[];
  firstSeen: string | null;
  lastSeen: string | null;
}

export function classifyEventIntrusionStage(e: TimelineEvent): IntrusionStage {
  const text = `${e.source} ${e.verb} ${e.detail} ${(e.tags || []).join(" ")}`.toLowerCase();
  if (text.includes("contain") || text.includes("isolated") || text.includes("block") || text.includes("quarantine")) {
    return "containment";
  }
  if (text.includes("exfil") || text.includes("archive") || text.includes("data transfer")) {
    return "exfiltration";
  }
  if (text.includes("beacon") || text.includes("c2") || text.includes("suricata") || text.includes("cobalt") || e.source === "pcap") {
    return "command_and_control";
  }
  if (text.includes("sweep") || text.includes("recon") || text.includes("port scan") || text.includes("discovery")) {
    return "discovery";
  }
  if (text.includes("lateral") || text.includes("remote execution") || text.includes("smb") || text.includes("rpc")) {
    return "lateral_movement";
  }
  if (text.includes("lsass") || text.includes("mimikatz") || text.includes("credential") || text.includes("dump")) {
    return "credential_access";
  }
  if (text.includes("inject") || text.includes("evasion") || text.includes("obfuscat") || text.includes("lolbas") || text.includes("capa")) {
    return "defense_evasion";
  }
  if (text.includes("powershell") || text.includes("cmd") || text.includes("cradle") || text.includes("execut")) {
    return "execution";
  }
  if (text.includes("phishing") || text.includes("email") || text.includes("lure") || text.includes("inbound") || e.source === "phishing") {
    return "initial_access";
  }
  return "execution";
}

const STAGE_METADATA: Record<IntrusionStage, { label: string; mitreTactic: string; tone: "primary" | "warning" | "destructive" | "success" | "info" }> = {
  initial_access: { label: "Initial Access", mitreTactic: "TA0001", tone: "warning" },
  execution: { label: "Execution", mitreTactic: "TA0002", tone: "destructive" },
  persistence: { label: "Persistence", mitreTactic: "TA0003", tone: "warning" },
  defense_evasion: { label: "Defense Evasion", mitreTactic: "TA0005", tone: "destructive" },
  credential_access: { label: "Credential Access", mitreTactic: "TA0006", tone: "destructive" },
  discovery: { label: "Discovery", mitreTactic: "TA0007", tone: "primary" },
  lateral_movement: { label: "Lateral Movement", mitreTactic: "TA0008", tone: "warning" },
  command_and_control: { label: "Command & Control", mitreTactic: "TA0011", tone: "destructive" },
  exfiltration: { label: "Exfiltration", mitreTactic: "TA0010", tone: "destructive" },
  containment: { label: "Containment", mitreTactic: "DEFENSE", tone: "success" },
};

const STAGE_ORDER: IntrusionStage[] = [
  "initial_access",
  "execution",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "command_and_control",
  "exfiltration",
  "containment",
];

export function computeIntrusionProgression(events: TimelineEvent[]): StageProgression[] {
  const stageMap = new Map<IntrusionStage, TimelineEvent[]>();
  for (const s of STAGE_ORDER) stageMap.set(s, []);

  for (const e of events) {
    const stage = classifyEventIntrusionStage(e);
    const list = stageMap.get(stage);
    if (list) list.push(e);
  }

  return STAGE_ORDER.map((s) => {
    const evts = stageMap.get(s) || [];
    const meta = STAGE_METADATA[s];
    const sorted = [...evts].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
    return {
      stage: s,
      label: meta.label,
      mitreTactic: meta.mitreTactic,
      tone: meta.tone,
      eventCount: evts.length,
      events: evts,
      firstSeen: sorted[0]?.ts || null,
      lastSeen: sorted[sorted.length - 1]?.ts || null,
    };
  });
}

export function computeAttackVelocity(events: TimelineEvent[]): {
  totalDwellTimeMinutes: number;
  dwellTimeFormatted: string;
  eventsPerMinute: number;
  rootCause: string;
  criticalMilestonesCount: number;
  activeStageLabel: string;
} {
  if (!events.length) {
    return {
      totalDwellTimeMinutes: 0,
      dwellTimeFormatted: "0m",
      eventsPerMinute: 0,
      rootCause: "None detected",
      criticalMilestonesCount: 0,
      activeStageLabel: "Normal Operations",
    };
  }

  const times = events.map((e) => new Date(e.ts).getTime()).filter((t) => !Number.isNaN(t)).sort((a, b) => a - b);
  const minTs = times[0] || Date.now();
  const maxTs = times[times.length - 1] || minTs;
  const spanMs = Math.max(maxTs - minTs, 60_000);
  const spanMin = Math.max(Math.round(spanMs / 60_000), 1);

  const hours = Math.floor(spanMin / 60);
  const mins = spanMin % 60;
  const dwellTimeFormatted = hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;

  const critCount = events.filter((e) => e.severity === "critical" || e.severity === "high").length;
  const eventsPerMin = parseFloat((events.length / spanMin).toFixed(2));

  const chronological = [...events].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
  const rootEvent = chronological[0];
  const rootCause = rootEvent ? `${rootEvent.verb} (${rootEvent.source.toUpperCase()})` : "External Intrusion";

  const stages = computeIntrusionProgression(events).filter((s) => s.eventCount > 0);
  const lastStage = stages[stages.length - 1];
  const activeStageLabel = lastStage ? lastStage.label : "Active Attack";

  return {
    totalDwellTimeMinutes: spanMin,
    dwellTimeFormatted,
    eventsPerMinute: eventsPerMin,
    rootCause,
    criticalMilestonesCount: critCount,
    activeStageLabel,
  };
}
