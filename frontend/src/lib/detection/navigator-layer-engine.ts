/**
 * MITRE ATT&CK® Navigator Layer Engine (v4.5 / v5.0 Specification)
 * Provides official MITRE ATT&CK Navigator JSON serialization, import validation,
 * technique atomic test emulation details, and preset coverage profiles.
 */

import { TACTICS, ALL_TECHNIQUES, type MitreTactic } from "@/data/mitre";

export interface NavigatorTechnique {
  techniqueID: string;
  tactic?: string;
  score?: number;
  color?: string;
  comment?: string;
  enabled?: boolean;
  metadata?: Array<{ name: string; value: string }>;
}

export interface NavigatorLayer {
  name: string;
  versions: {
    attack: string;
    navigator: string;
    layer: string;
  };
  domain: string;
  description: string;
  filters?: {
    platforms?: string[];
  };
  sorting?: number;
  layout?: {
    layout?: string;
    aggregateFunction?: string;
    showID?: boolean;
    showName?: boolean;
    showTechniqueCount?: boolean;
  };
  hideDisabled?: boolean;
  gradient?: {
    colors: string[];
    minValue: number;
    maxValue: number;
  };
  legendItems?: Array<{ label: string; color: string }>;
  techniques: NavigatorTechnique[];
}

export type CoverageLevel = "none" | "partial" | "full";

export interface AtomicTestInfo {
  name: string;
  description: string;
  platform: "Windows" | "Linux" | "macOS" | "Multi";
  command: string;
  cleanup?: string;
}

export interface TechniqueEnrichment {
  id: string;
  platforms: string[];
  dataSources: string[];
  atomicTest: AtomicTestInfo;
  detectionGuidance: string;
}

/**
 * Built-in enriched metadata and Atomic Red Team test commands for prominent techniques.
 */
export const TECHNIQUE_CATALOG: Record<string, TechniqueEnrichment> = {
  "T1059.001": {
    id: "T1059.001",
    platforms: ["Windows"],
    dataSources: ["Process: Process Creation", "Command: Command Execution", "Script: Script Execution"],
    atomicTest: {
      name: "PowerShell Encoded Command Execution",
      description: "Executes base64-encoded command via powershell.exe simulating stealthy download cradles.",
      platform: "Windows",
      command: "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AbABvAGMAYQBsAGgAbwBzAHQAOjgwODAvdGVzdAAiACkA",
      cleanup: "# No persistent artifacts created by encoded memory execution",
    },
    detectionGuidance: "Monitor for powershell.exe invocations containing flags like -EncodedCommand, -enc, or -e alongside hidden window styles.",
  },
  "T1566.001": {
    id: "T1566.001",
    platforms: ["Windows", "macOS", "Linux"],
    dataSources: ["Application Log: Application Evidence", "File: File Creation", "Network Traffic: Network Connection"],
    atomicTest: {
      name: "Simulated Malicious Attachment Drop",
      description: "Drops an encrypted payload archive masquerading as an invoice attachment in the user temp directory.",
      platform: "Windows",
      command: "powershell.exe -Command \"[IO.File]::WriteAllBytes('$env:TEMP\\urgent_invoice.iso', [Convert]::FromBase64String('TVoAAAA='))\"",
      cleanup: "powershell.exe -Command \"Remove-Item -Force '$env:TEMP\\urgent_invoice.iso' -ErrorAction SilentlyContinue\"",
    },
    detectionGuidance: "Inspect mail gateway attachment extensions (.iso, .vhd, .xlsm) and monitor process spawning from Outlook/Thunderbird.",
  },
  "T1003.001": {
    id: "T1003.001",
    platforms: ["Windows"],
    dataSources: ["Process: OS API Execution", "Process: Process Access"],
    atomicTest: {
      name: "LSASS Process Memory Dump via Rundll32 / Comsvcs",
      description: "Simulates native credential extraction using built-in Windows signed binary comsvcs.dll.",
      platform: "Windows",
      command: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\temp\\lsass.dmp full",
      cleanup: "Remove-Item -Force C:\\temp\\lsass.dmp -ErrorAction SilentlyContinue",
    },
    detectionGuidance: "Detect process handle opening with PROCESS_VM_READ and PROCESS_QUERY_INFORMATION against lsass.exe (Sysmon Event ID 10).",
  },
  "T1070.001": {
    id: "T1070.001",
    platforms: ["Windows"],
    dataSources: ["Command: Command Execution", "Windows Event Log: Security Log Cleared"],
    atomicTest: {
      name: "Clear Windows Security Event Log via wevtutil",
      description: "Adversaries clear security logs to erase forensic evidence and evade blue team detection.",
      platform: "Windows",
      command: "wevtutil cl Security",
      cleanup: "# Log clearing cannot be undone; validates generation of Event ID 1102",
    },
    detectionGuidance: "Alert immediately on Windows Security Event ID 1102 ('The audit log was cleared') or System Event ID 104.",
  },
  "T1071.004": {
    id: "T1071.004",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["Network Traffic: Network Connection", "Network Traffic: DNS Query"],
    atomicTest: {
      name: "DNS High-Entropy C2 Beacon Emulation",
      description: "Performs iterative sub-domain queries carrying base64 encoded stagers simulating DNS exfiltration.",
      platform: "Multi",
      command: "nslookup 68656c6c6f2e73656375726974792e6c6f63616c 127.0.0.1",
      cleanup: "# Ephemeral DNS query; check DNS server query logs",
    },
    detectionGuidance: "Calculate Shannon entropy of subdomains on DNS queries. Flag domains with length > 40 chars and entropy >= 3.8.",
  },
  "T1490": {
    id: "T1490",
    platforms: ["Windows"],
    dataSources: ["Command: Command Execution", "Process: Process Creation"],
    atomicTest: {
      name: "Inhibit System Recovery via vssadmin Shadow Deletion",
      description: "Ransomware precursor: deletes volume shadow copies to prevent victim self-recovery.",
      platform: "Windows",
      command: "vssadmin.exe delete shadows /all /quiet",
      cleanup: "# Test environment shadow deletion simulation",
    },
    detectionGuidance: "Monitor for vssadmin.exe, wmic.exe shadowcopy delete, or bcdedit /set {default} bootstatuspolicy ignoreallfailures.",
  },
  "T1053.005": {
    id: "T1053.005",
    platforms: ["Windows"],
    dataSources: ["Command: Command Execution", "Process: Process Creation", "Scheduled Job: Scheduled Job Creation"],
    atomicTest: {
      name: "Scheduled Task Creation with Elevated Privileges",
      description: "Creates persistent daily trigger task disguised as standard system telemetry updater.",
      platform: "Windows",
      command: "schtasks.exe /create /tn \"SystemHealthTelemetry\" /tr \"powershell.exe -WindowStyle Hidden -Command echo test\" /sc daily /st 09:00",
      cleanup: "schtasks.exe /delete /tn \"SystemHealthTelemetry\" /f",
    },
    detectionGuidance: "Alert on Security Event ID 4698 (A scheduled task was created) especially when launching cmd.exe or powershell.exe.",
  },
  "T1021.002": {
    id: "T1021.002",
    platforms: ["Windows"],
    dataSources: ["Logon Session: Logon Session Creation", "Network Traffic: Network Connection"],
    atomicTest: {
      name: "SMB / Windows Admin Share Access Simulation",
      description: "Attempts network connection to administrative IPC$ or C$ share on target host.",
      platform: "Windows",
      command: "net.exe use \\\\127.0.0.1\\C$ /user:Administrator",
      cleanup: "net.exe use \\\\127.0.0.1\\C$ /delete /y",
    },
    detectionGuidance: "Track Event ID 5140 (A network share object was accessed) focusing on ShareName: \\\\*\\C$ or ADMIN$.",
  },
};

/**
 * Returns enrichment details for any technique, falling back to heuristic defaults.
 */
export function getTechniqueEnrichment(id: string): TechniqueEnrichment {
  if (TECHNIQUE_CATALOG[id]) {
    return TECHNIQUE_CATALOG[id];
  }
  const t = ALL_TECHNIQUES.find((x) => x.id === id);
  const name = t ? t.name : id;
  return {
    id,
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["Process: Process Creation", "Command: Command Execution"],
    atomicTest: {
      name: `Generic Emulation for ${id} (${name})`,
      description: `Simulates execution patterns matching MITRE ATT&CK technique ${id}.`,
      platform: "Multi",
      command: `# Atomic test command for ${id} - ${name}\necho "Simulating ${id} execution at $(date)"`,
      cleanup: `# Cleanup command for ${id}`,
    },
    detectionGuidance: `Verify telemetry logging for ${id} (${name}) against your enterprise SIEM and EDR detection rules.`,
  };
}

/**
 * Serializes local coverage and notes into an official MITRE ATT&CK Navigator Layer v4.5 standard JSON.
 */
export function exportNavigatorLayerJson(
  coverageMap: Record<string, CoverageLevel>,
  notes: Record<string, string>,
  tactics: MitreTactic[] = TACTICS,
  layerName = "BeyondLabs Enterprise SOC Coverage",
): string {
  const techniques: NavigatorTechnique[] = [];

  for (const tactic of tactics) {
    const tacticId = tactic.id.toLowerCase();
    for (const tech of tactic.techniques) {
      const cov = coverageMap[`${tactic.id}::${tech.id}`] || coverageMap[tech.id] || "none";
      const note = notes[tech.id] || "";

      let score = 0;
      let color = "#1e293b"; // slate
      if (cov === "full") {
        score = 100;
        color = "#22c55e"; // green
      } else if (cov === "partial") {
        score = 50;
        color = "#eab308"; // amber
      }

      const entry: NavigatorTechnique = {
        techniqueID: tech.id,
        tactic: tacticId,
        score,
        color,
        comment: note || (cov === "full" ? "Fully covered by active detection" : cov === "partial" ? "Partially covered" : "Uncovered gap"),
        enabled: true,
      };

      const enrichment = TECHNIQUE_CATALOG[tech.id];
      if (enrichment) {
        entry.metadata = [
          { name: "Platforms", value: enrichment.platforms.join(", ") },
          { name: "DataSources", value: enrichment.dataSources.join("; ") },
        ];
      }

      techniques.push(entry);
    }
  }

  const layer: NavigatorLayer = {
    name: layerName,
    versions: {
      attack: "15",
      navigator: "4.5",
      layer: "4.5",
    },
    domain: "enterprise-attack",
    description: `Defensive coverage export from BeyondLabs SOC Workstation. Total: ${techniques.length} techniques.`,
    filters: {
      platforms: ["Windows", "Linux", "macOS", "IaaS", "SaaS", "Office 365", "Identity"],
    },
    sorting: 0,
    layout: {
      layout: "side",
      aggregateFunction: "average",
      showID: true,
      showName: true,
      showTechniqueCount: true,
    },
    hideDisabled: false,
    gradient: {
      colors: ["#1e293b", "#eab308", "#22c55e"],
      minValue: 0,
      maxValue: 100,
    },
    legendItems: [
      { label: "Full Deployed Detection", color: "#22c55e" },
      { label: "Partial / In Development", color: "#eab308" },
      { label: "Uncovered / Gap", color: "#1e293b" },
    ],
    techniques,
  };

  return JSON.stringify(layer, null, 2);
}

/**
 * Validates and parses an uploaded MITRE ATT&CK Navigator Layer JSON string.
 */
export function importNavigatorLayerJson(jsonStr: string): {
  success: boolean;
  name: string;
  totalTechniques: number;
  coverageMap: Record<string, CoverageLevel>;
  notes: Record<string, string>;
  stats: { full: number; partial: number; none: number };
  error?: string;
} {
  try {
    const data = JSON.parse(jsonStr) as NavigatorLayer;
    if (!data || typeof data !== "object") {
      return { success: false, name: "", totalTechniques: 0, coverageMap: {}, notes: {}, stats: { full: 0, partial: 0, none: 0 }, error: "Invalid JSON format" };
    }

    if (!Array.isArray(data.techniques)) {
      return { success: false, name: "", totalTechniques: 0, coverageMap: {}, notes: {}, stats: { full: 0, partial: 0, none: 0 }, error: "Missing 'techniques' array in Navigator layer" };
    }

    const coverageMap: Record<string, CoverageLevel> = {};
    const notes: Record<string, string> = {};
    const stats = { full: 0, partial: 0, none: 0 };

    for (const item of data.techniques) {
      const tid = (item.techniqueID || "").toUpperCase().trim();
      if (!tid) continue;

      const score = typeof item.score === "number" ? item.score : 0;
      let cov: CoverageLevel = "none";
      if (score >= 80) {
        cov = "full";
        stats.full++;
      } else if (score >= 20) {
        cov = "partial";
        stats.partial++;
      } else {
        cov = "none";
        stats.none++;
      }

      coverageMap[tid] = cov;
      if (item.comment) {
        notes[tid] = item.comment;
      }
    }

    return {
      success: true,
      name: data.name || "Imported Layer",
      totalTechniques: Object.keys(coverageMap).length,
      coverageMap,
      notes,
      stats,
    };
  } catch (err: any) {
    return {
      success: false,
      name: "",
      totalTechniques: 0,
      coverageMap: {},
      notes: {},
      stats: { full: 0, partial: 0, none: 0 },
      error: err?.message || "JSON parse error",
    };
  }
}

/**
 * Pre-defined Navigator Layer profiles for SOC threat modeling drills.
 */
export const PRESET_LAYERS = [
  {
    id: "ransomware",
    name: "Enterprise Ransomware Common TTPs",
    description: "Common techniques deployed by LockBit, BlackCat, and Conti operators",
    techniqueIds: ["T1566.001", "T1059.001", "T1003.001", "T1021.002", "T1490", "T1486", "T1070.001", "T1053.005"],
  },
  {
    id: "apt28",
    name: "APT28 / Fancy Bear Threat Profile",
    description: "State-sponsored cyber espionage group attributed to Russian GRU Unit 26165",
    techniqueIds: ["T1566.002", "T1059.001", "T1003.001", "T1071.001", "T1041", "T1110.003", "T1036.005", "T1027"],
  },
  {
    id: "cloud_threats",
    name: "Cloud & Identity Native Attack Path",
    description: "Attack vectors against Entra ID, AWS IAM, S3, and OAuth applications",
    techniqueIds: ["T1078", "T1526", "T1530", "T1190", "T1098", "T1556.006"],
  },
];
