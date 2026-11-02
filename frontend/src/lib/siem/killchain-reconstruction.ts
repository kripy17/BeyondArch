import type { SiemEvent } from "@/data/siem";

export type KillChainPhaseId =
  | "recon"
  | "initial_access"
  | "execution"
  | "persistence_evasion"
  | "c2_exfil";

export interface KillChainPhase {
  id: KillChainPhaseId;
  name: string;
  mitreTactic: string;
  order: number;
  events: SiemEvent[];
  eventCount: number;
  severity: "info" | "low" | "medium" | "high" | "critical";
  summary: string;
  active: boolean;
}

export interface KillChainAnalysis {
  phases: KillChainPhase[];
  activePhaseCount: number;
  highestPhase: KillChainPhase | null;
  progressionScore: number; // 0 to 100
  threatNarrative: string;
}

const RX_RECON = /(?:404|web_probe|sqlmap|nikto|nmap|masscan|probe|scan|\/\.env|\/wp-admin)/i;
const RX_INITIAL_ACCESS = /(?:failed password|authentication failure|invalid user|4625|brute force|logon fail|login fail)/i;
const RX_EXECUTION = /(?:powershell|encodedcommand|downloadstring|cmd\.exe|wmic|rundll32|setcbprivilege|sedebugprivilege|sudo:|4688|4672|process_spawn)/i;
const RX_PERSISTENCE = /(?:service installed|scheduled task|4697|4698|4657|run key|registry|1102|104|event log was cleared|log file was cleared|wevtutil)/i;
const RX_C2_EXFIL = /(?:beacon|c2|outbound to|exfil|curl.*https|dns query|5156|meterpreter|cobalt)/i;

/**
 * Categorizes an individual SIEM event into a kill-chain phase.
 */
export function classifyEventPhase(event: SiemEvent): KillChainPhaseId | null {
  const text = `${event.sig} ${event.src} ${event.dst} ${event.user}`.toLowerCase();

  // Check in reverse progression order so high-impact actions take precedence
  if (RX_C2_EXFIL.test(text)) return "c2_exfil";
  if (RX_PERSISTENCE.test(text)) return "persistence_evasion";
  if (RX_EXECUTION.test(text)) return "execution";
  if (RX_INITIAL_ACCESS.test(text)) return "initial_access";
  if (RX_RECON.test(text)) return "recon";

  return null;
}

/**
 * Reconstructs the kill-chain attack progression from chronological SIEM events.
 */
export function reconstructKillChain(events: SiemEvent[]): KillChainAnalysis {
  const phaseMap: Record<KillChainPhaseId, SiemEvent[]> = {
    recon: [],
    initial_access: [],
    execution: [],
    persistence_evasion: [],
    c2_exfil: [],
  };

  for (const e of events) {
    const phase = classifyEventPhase(e);
    if (phase) {
      phaseMap[phase].push(e);
    }
  }

  const phaseDefs: Array<{
    id: KillChainPhaseId;
    name: string;
    mitreTactic: string;
    order: number;
    summary: string;
  }> = [
    {
      id: "recon",
      name: "Reconnaissance",
      mitreTactic: "TA0043 Reconnaissance",
      order: 1,
      summary: "Scanning, probing endpoints, and enumerating potential attack vectors.",
    },
    {
      id: "initial_access",
      name: "Initial Access & Auth",
      mitreTactic: "TA0001 Initial Access / TA0006 Credential Access",
      order: 2,
      summary: "Credential stuffing, brute-forcing accounts, and exploiting exposed services.",
    },
    {
      id: "execution",
      name: "Execution & Escalation",
      mitreTactic: "TA0002 Execution / TA0004 Privilege Escalation",
      order: 3,
      summary: "Executing scripts, invoking interpreters, and acquiring privileged tokens.",
    },
    {
      id: "persistence_evasion",
      name: "Persistence & Evasion",
      mitreTactic: "TA0003 Persistence / TA0005 Defense Evasion",
      order: 4,
      summary: "Installing services/tasks, modifying Run keys, or clearing security event logs.",
    },
    {
      id: "c2_exfil",
      name: "C2 & Exfiltration",
      mitreTactic: "TA0011 Command and Control / TA0010 Exfiltration",
      order: 5,
      summary: "Establishing external command channel, beaconing, and transmitting stolen data.",
    },
  ];

  const phases: KillChainPhase[] = phaseDefs.map((def) => {
    const matched = phaseMap[def.id];
    const active = matched.length > 0;
    const hasCritical = matched.some((e) => e.sev === "high" && (def.id === "c2_exfil" || def.id === "persistence_evasion"));
    const hasHigh = matched.some((e) => e.sev === "high");
    const hasMedium = matched.some((e) => e.sev === "medium");

    const severity: KillChainPhase["severity"] = hasCritical
      ? "critical"
      : hasHigh
      ? "high"
      : hasMedium
      ? "medium"
      : active
      ? "low"
      : "info";

    return {
      id: def.id,
      name: def.name,
      mitreTactic: def.mitreTactic,
      order: def.order,
      events: matched,
      eventCount: matched.length,
      severity,
      summary: def.summary,
      active,
    };
  });

  const activePhases = phases.filter((p) => p.active);
  const activePhaseCount = activePhases.length;
  const highestPhase = activePhases.length > 0 ? activePhases[activePhases.length - 1] : null;

  // Score progression from 0 to 100
  let progressionScore = 0;
  if (phaseMap.c2_exfil.length > 0) progressionScore = 100;
  else if (phaseMap.persistence_evasion.length > 0) progressionScore = 80;
  else if (phaseMap.execution.length > 0) progressionScore = 60;
  else if (phaseMap.initial_access.length > 0) progressionScore = 40;
  else if (phaseMap.recon.length > 0) progressionScore = 20;

  let threatNarrative = "No structured attack sequence detected.";
  if (progressionScore >= 80) {
    threatNarrative = `Critical breach progression observed. Adversary has reached ${highestPhase?.name ?? "late stage"} with persistent foothold or active C2. Immediate containment required.`;
  } else if (progressionScore >= 60) {
    threatNarrative = `Host compromise in progress. Execution and privilege activity detected on host. Isolate endpoint and verify execution parentage.`;
  } else if (progressionScore >= 40) {
    threatNarrative = `Active authentication attack underway. Potential password spraying or credential stuffing detected against environment accounts.`;
  } else if (progressionScore >= 20) {
    threatNarrative = `Early reconnaissance and probing activity observed. Host is under active external scanning.`;
  }

  return {
    phases,
    activePhaseCount,
    highestPhase,
    progressionScore,
    threatNarrative,
  };
}
