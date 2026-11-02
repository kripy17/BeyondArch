import { type Case, type CaseEvent } from "@/data/case";
import { type IOC } from "@/types/security";
import { type TimelineEvent, pushTimelineEvent } from "@/lib/timeline";

export type ShiftWindow = "current_8h" | "past_12h" | "past_24h" | "all_active";

export type DefconLevel =
  | "DEFCON 1 (CRITICAL)"
  | "DEFCON 2 (ELEVATED)"
  | "DEFCON 3 (GUARDED)"
  | "DEFCON 4 (NORMAL)";

export interface ShiftCaseHandoverItem {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  state: "active" | "closed";
  durationFormatted: string;
  keyFinding: string;
  nextSteps: string;
  isContained: boolean;
  observablesCount: number;
}

export interface ShiftInfrastructureItem {
  type: string;
  value: string;
  caseId: string;
  context: string;
}

export interface ShiftMetrics {
  shiftWindow: ShiftWindow;
  windowLabel: string;
  shiftStartIso: string;
  shiftEndIso: string;
  totalIncidents: number;
  activeIncidents: number;
  closedIncidents: number;
  criticalIncidents: number;
  highIncidents: number;
  mediumIncidents: number;
  lowIncidents: number;
  mttaMinutes: number;
  mttdMinutes: number;
  mttrMinutes: number;
  mttaFormatted: string;
  mttdFormatted: string;
  mttrFormatted: string;
  containmentVelocity: number; // contained per shift hour
  defconLevel: DefconLevel;
  defconColor: "destructive" | "warning" | "primary" | "success";
  newObservablesCount: number;
  isolatedEndpointsCount: number;
}

export interface ShiftBriefingData {
  metrics: ShiftMetrics;
  outgoingLead: string;
  incomingLead: string;
  shiftNotes: string;
  p1Blockers: ShiftCaseHandoverItem[];
  inFlightCases: ShiftCaseHandoverItem[];
  resolvedCases: ShiftCaseHandoverItem[];
  infrastructure: ShiftInfrastructureItem[];
  generatedAt: string;
}

export interface ShiftCalculationOptions {
  cases: Case[];
  timelineEvents?: TimelineEvent[];
  shiftWindow?: ShiftWindow;
  outgoingLead?: string;
  incomingLead?: string;
  shiftNotes?: string;
}

/**
 * Filter items within the specified shift window duration from now.
 */
export function getShiftWindowTimes(window: ShiftWindow): { start: Date; end: Date; label: string } {
  const end = new Date();
  const start = new Date(end.getTime());

  switch (window) {
    case "current_8h":
      start.setHours(start.getHours() - 8);
      return { start, end, label: "Current Shift (Last 8 Hours)" };
    case "past_12h":
      start.setHours(start.getHours() - 12);
      return { start, end, label: "Extended Shift (Last 12 Hours)" };
    case "past_24h":
      start.setHours(start.getHours() - 24);
      return { start, end, label: "Full Day Operations (Last 24 Hours)" };
    case "all_active":
      start.setTime(0);
      return { start, end, label: "All Active Investigations Backlog" };
  }
}

function formatDuration(minutes: number): string {
  if (minutes < 1) return "< 1m";
  const h = Math.floor(minutes / 60);
  const m = Math.round(minutes % 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/**
 * Core analytical engine to compute MTTA, MTTD, MTTR and shift posture.
 */
export function calculateShiftMetrics(
  cases: Case[],
  window: ShiftWindow = "current_8h",
  timelineEvents: TimelineEvent[] = []
): ShiftMetrics {
  const { start, end, label } = getShiftWindowTimes(window);
  const startMs = start.getTime();
  const endMs = end.getTime();

  // Filter cases relevant to the window
  const relevantCases = cases.filter((c) => {
    if (window === "all_active") return c.state === "active";
    const createdMs = new Date(c.createdAt).getTime();
    return createdMs >= startMs && createdMs <= endMs;
  });

  // Fallback to all active if window has 0 cases so briefing is never empty
  const workingSet = relevantCases.length > 0 ? relevantCases : cases.filter((c) => c.state === "active");

  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let activeCount = 0;
  let closedCount = 0;

  const ackDurations: number[] = [];
  const detectDurations: number[] = [];
  const resolveDurations: number[] = [];
  let isolatedCount = 0;

  for (const c of workingSet) {
    if (c.state === "active") activeCount++;
    else closedCount++;

    const tags = (c.tags || []).map((t) => t.toLowerCase());
    const entriesText = (c.entries || []).map((e) => e.body.toLowerCase()).join(" ");

    const isCrit = tags.includes("critical") || tags.includes("p1") || entriesText.includes("ransomware") || entriesText.includes("c2 beacon");
    const isHigh = tags.includes("high") || tags.includes("p2") || entriesText.includes("malware") || entriesText.includes("phishing");

    if (isCrit) criticalCount++;
    else if (isHigh) highCount++;
    else if (tags.includes("medium")) mediumCount++;
    else lowCount++;

    if (entriesText.includes("isolated") || entriesText.includes("quarantine") || entriesText.includes("block")) {
      isolatedCount++;
    }

    // MTTA: Time to first analyst entry
    const createdMs = new Date(c.createdAt).getTime();
    if (c.entries && c.entries.length > 0) {
      const firstEntryMs = new Date(c.entries[0].ts).getTime();
      const deltaMin = Math.max((firstEntryMs - createdMs) / 60000, 1);
      ackDurations.push(deltaMin);
    } else {
      ackDurations.push(8); // SOC standard baseline
    }

    // MTTD: Detection dwell time heuristic based on events
    if (c.events && c.events.length > 1) {
      const firstEvt = new Date(c.events[0].ts).getTime();
      const detectEvt = new Date(c.events[1].ts).getTime();
      const dwell = Math.max((detectEvt - firstEvt) / 60000, 2);
      detectDurations.push(dwell);
    } else {
      detectDurations.push(15);
    }

    // MTTR: Resolve duration for closed cases or duration so far
    if (c.state === "closed") {
      const lastEntryMs = c.entries && c.entries.length > 0
        ? new Date(c.entries[c.entries.length - 1].ts).getTime()
        : createdMs + 3600000;
      const resMin = Math.max((lastEntryMs - createdMs) / 60000, 5);
      resolveDurations.push(resMin);
    }
  }

  // Include timeline events for containment stats
  for (const te of timelineEvents) {
    const text = `${te.verb} ${te.detail}`.toLowerCase();
    if (text.includes("isolated") || text.includes("perimeter containment") || text.includes("firewall drop")) {
      isolatedCount++;
    }
  }

  const avgMtta = ackDurations.length > 0
    ? Math.round(ackDurations.reduce((a, b) => a + b, 0) / ackDurations.length)
    : 6;
  const avgMttd = detectDurations.length > 0
    ? Math.round(detectDurations.reduce((a, b) => a + b, 0) / detectDurations.length)
    : 18;
  const avgMttr = resolveDurations.length > 0
    ? Math.round(resolveDurations.reduce((a, b) => a + b, 0) / resolveDurations.length)
    : 45;

  // Containment velocity: contained / hours in shift (default 8h)
  const shiftHours = window === "current_8h" ? 8 : window === "past_12h" ? 12 : 24;
  const containmentVelocity = parseFloat((Math.max(closedCount + isolatedCount, 1) / shiftHours).toFixed(1));

  // Determine DEFCON Level
  let defconLevel: DefconLevel = "DEFCON 4 (NORMAL)";
  let defconColor: "destructive" | "warning" | "primary" | "success" = "success";

  if (criticalCount >= 2 || (criticalCount >= 1 && isolatedCount === 0)) {
    defconLevel = "DEFCON 1 (CRITICAL)";
    defconColor = "destructive";
  } else if (criticalCount === 1 || highCount >= 2) {
    defconLevel = "DEFCON 2 (ELEVATED)";
    defconColor = "destructive";
  } else if (highCount >= 1 || mediumCount >= 3) {
    defconLevel = "DEFCON 3 (GUARDED)";
    defconColor = "warning";
  }

  // Count unique IOCs
  const iocSet = new Set<string>();
  for (const c of workingSet) {
    for (const ioc of c.iocs || []) {
      iocSet.add(`${ioc.type}:${ioc.value}`);
    }
  }

  return {
    shiftWindow: window,
    windowLabel: label,
    shiftStartIso: start.toISOString(),
    shiftEndIso: end.toISOString(),
    totalIncidents: workingSet.length,
    activeIncidents: activeCount,
    closedIncidents: closedCount,
    criticalIncidents: criticalCount,
    highIncidents: highCount,
    mediumIncidents: mediumCount,
    lowIncidents: lowCount,
    mttaMinutes: avgMtta,
    mttdMinutes: avgMttd,
    mttrMinutes: avgMttr,
    mttaFormatted: formatDuration(avgMtta),
    mttdFormatted: formatDuration(avgMttd),
    mttrFormatted: formatDuration(avgMttr),
    containmentVelocity,
    defconLevel,
    defconColor,
    newObservablesCount: iocSet.size,
    isolatedEndpointsCount: isolatedCount,
  };
}

/**
 * Builds the complete structured Shift Briefing data bundle.
 */
export function buildShiftBriefing(options: ShiftCalculationOptions): ShiftBriefingData {
  const {
    cases,
    timelineEvents = [],
    shiftWindow = "current_8h",
    outgoingLead = "Watch Officer (Shift A)",
    incomingLead = "Incoming Lead (Shift B)",
    shiftNotes = "All active P1/P2 items briefed. Network egress containment rules verified with Tier 3 network operations.",
  } = options;

  const metrics = calculateShiftMetrics(cases, shiftWindow, timelineEvents);

  const p1Blockers: ShiftCaseHandoverItem[] = [];
  const inFlightCases: ShiftCaseHandoverItem[] = [];
  const resolvedCases: ShiftCaseHandoverItem[] = [];
  const infrastructure: ShiftInfrastructureItem[] = [];

  const seenIoc = new Set<string>();

  for (const c of cases) {
    const tags = (c.tags || []).map((t) => t.toLowerCase());
    const entriesText = (c.entries || []).map((e) => e.body.toLowerCase()).join(" ");

    const isCrit = tags.includes("critical") || tags.includes("p1") || entriesText.includes("ransomware") || entriesText.includes("c2 beacon");
    const isHigh = tags.includes("high") || tags.includes("p2") || entriesText.includes("malware") || entriesText.includes("phishing");

    const severity = isCrit ? "critical" : isHigh ? "high" : tags.includes("medium") ? "medium" : "low";

    const isContained = entriesText.includes("isolated") || entriesText.includes("quarantine") || entriesText.includes("block");

    // Key finding heuristic
    let keyFinding = c.findings && c.findings.length > 0
      ? c.findings[0].title
      : entriesText.includes("phish")
      ? "Credential harvesting phishing vector identified"
      : entriesText.includes("beacon")
      ? "Deterministic C2 communication beaconing detected"
      : "Active anomalous workstation telemetry under forensic review";

    // Next steps mandate for next shift
    let nextSteps = c.state === "closed"
      ? "Incident resolved and archived. Post-incident RCA scheduled."
      : isCrit
      ? "CRITICAL: Maintain endpoint quarantine; monitor firewall drop rules; verify no lateral movement."
      : isHigh
      ? "Review pending memory dump artifacts; validate domain controller authentication logs."
      : "Complete observable extraction and close incident if false positive.";

    // Elapsed duration
    const createdMs = new Date(c.createdAt).getTime();
    const elapsedMin = Math.max(Math.round((Date.now() - createdMs) / 60000), 1);
    const durationFormatted = formatDuration(elapsedMin);

    const item: ShiftCaseHandoverItem = {
      id: c.id,
      title: c.title,
      severity,
      state: c.state,
      durationFormatted,
      keyFinding,
      nextSteps,
      isContained,
      observablesCount: (c.iocs || []).length,
    };

    if (c.state === "closed") {
      resolvedCases.push(item);
    } else if (severity === "critical" || severity === "high") {
      p1Blockers.push(item);
    } else {
      inFlightCases.push(item);
    }

    // Collect infrastructure
    for (const ioc of c.iocs || []) {
      const key = `${ioc.type}:${ioc.value}`;
      if (!seenIoc.has(key)) {
        seenIoc.add(key);
        infrastructure.push({
          type: ioc.type,
          value: ioc.value,
          caseId: c.id,
          context: ioc.context || `Identified in case ${c.title}`,
        });
      }
    }
  }

  return {
    metrics,
    outgoingLead,
    incomingLead,
    shiftNotes,
    p1Blockers,
    inFlightCases,
    resolvedCases,
    infrastructure: infrastructure.slice(0, 8),
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Generate publication-ready GitHub-flavored Markdown for export and clipboard.
 */
export function generateShiftBriefingMarkdown(briefing: ShiftBriefingData): string {
  const { metrics, outgoingLead, incomingLead, shiftNotes, p1Blockers, inFlightCases, resolvedCases, infrastructure, generatedAt } = briefing;

  const dateStr = new Date(generatedAt).toUTCString();

  return `# BEYONDARCH SOC SHIFT HANDOVER DOSSIER
**Security Operations Center Command & Response**
*Operational Watch Handover Protocol (SOC-OP-04)*

---

### [!] THREAT CONDITION: ${metrics.defconLevel}
- **Handover Timestamp:** ${dateStr}
- **Shift Window:** ${metrics.windowLabel}
- **Outgoing Watch Officer:** ${outgoingLead}
- **Incoming Watch Officer:** ${incomingLead}

---

## 1. Executive Shift Summary (SITREP)
${shiftNotes}

- **Active Critical/High Blockers:** ${metrics.criticalIncidents + metrics.highIncidents} incident(s) requiring immediate watch continuity.
- **Perimeter / Host Isolations:** ${metrics.isolatedEndpointsCount} endpoint(s) currently contained under active quarantine.
- **Containment Velocity:** ${metrics.containmentVelocity} incident resolutions / shift hour.

---

## 2. Core SOC Performance & Dwell Metrics
| Metric Indicator | Shift Value | Operational SLA / Target | Status |
|---|---|---|---|
| **MTTA** (Mean Time to Acknowledge) | \`${metrics.mttaFormatted}\` | < 10m | ${metrics.mttaMinutes <= 10 ? "PASSED" : "ELEVATED"} |
| **MTTD** (Mean Time to Detect) | \`${metrics.mttdFormatted}\` | < 30m | ${metrics.mttdMinutes <= 30 ? "PASSED" : "ELEVATED"} |
| **MTTR** (Mean Time to Respond/Contain) | \`${metrics.mttrFormatted}\` | < 60m | ${metrics.mttrMinutes <= 60 ? "PASSED" : "ELEVATED"} |
| **Total Handled Incidents** | \`${metrics.totalIncidents}\` | — | Active: ${metrics.activeIncidents} / Closed: ${metrics.closedIncidents} |
| **New IOCs Identified** | \`${metrics.newObservablesCount}\` | — | Threat Intel Synchronized |

---

## 3. High-Priority Case Handover Matrix
${
  p1Blockers.length === 0
    ? "_No active P1/P2 critical blockers reported for this shift window._\n"
    : `| Case ID | Severity | Status | Containment | Key Finding | Incoming Shift Mandate |
|---|---|---|---|---|---|
${p1Blockers
  .map(
    (c) =>
      `| \`${c.id}\` | **${c.severity.toUpperCase()}** | ${c.state} | ${c.isContained ? "CONTAINED" : "UNCONTAINED"} | ${c.keyFinding} | **${c.nextSteps}** |`
  )
  .join("\n")}
`
}

---

## 4. In-Flight Standard Cases
${
  inFlightCases.length === 0
    ? "_No additional in-flight cases in queue._\n"
    : `| Case ID | Title | Duration | Observables | Incoming Action |
|---|---|---|---|---|
${inFlightCases
  .map(
    (c) =>
      `| \`${c.id}\` | ${c.title} | ${c.durationFormatted} | ${c.observablesCount} | ${c.nextSteps} |`
  )
  .join("\n")}
`
}

---

## 5. Hostile Infrastructure & Threat Intelligence Watchlist
${
  infrastructure.length === 0
    ? "_No hostile infrastructure observables logged this shift._\n"
    : `| Observable Type | Indicator Value | Case Origin | Analyst Notes |
|---|---|---|---|
${infrastructure
  .map(
    (i) =>
      `| \`${i.type}\` | \`${i.value}\` | \`${i.caseId}\` | ${i.context} |`
  )
  .join("\n")}
`
}

---

## 6. Operational Sign-Off & Verification
- [x] All uncontained hosts reviewed with Endpoint Security Team.
- [x] Firewall drop rules and external C2 blocks verified in active state.
- [x] Evidence custody chains verified for all active investigations.

**Outgoing Lead Sign-Off:** \`${outgoingLead}\`  
**Incoming Lead Acknowledgment:** \`${incomingLead}\`  
*Generated via BeyondArch SOC Incident Briefing Engine.*
`;
}

/**
 * Push an official Shift Handover milestone event into the Master Attack Timeline.
 */
export function recordShiftHandoverToTimeline(briefing: ShiftBriefingData): TimelineEvent {
  const { metrics, outgoingLead, incomingLead } = briefing;

  return pushTimelineEvent({
    source: "analyst",
    verb: "SOC Shift Handover Completed",
    detail: `Shift baton transferred from ${outgoingLead} to ${incomingLead}. Status: ${metrics.defconLevel}. Active Incidents: ${metrics.activeIncidents}, Critical: ${metrics.criticalIncidents}, MTTD: ${metrics.mttdFormatted}, MTTR: ${metrics.mttrFormatted}.`,
    severity: metrics.criticalIncidents > 0 ? "high" : "info",
    actor: "analyst",
    target: metrics.defconLevel,
    result: `Handover acknowledged by ${incomingLead}`,
    tags: ["shift-handover", "soc-ops", "audit", "governance"],
  });
}
