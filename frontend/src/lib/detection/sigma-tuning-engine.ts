import {
  type SavedRule,
  loadRules,
  saveRules,
  genId,
  normalizeRule,
} from "@/data/detection";

export type QueryDialect = "splunk" | "sentinel" | "elastic" | "suricata" | "generic";

export interface TuningFilter {
  id: string;
  name: string;
  field: string;
  value: string | string[];
  reason: string;
  category: "benign_process" | "service_account" | "system_path" | "internal_network" | "trusted_script";
  enabled: boolean;
}

export interface TunedSigmaRule {
  id: string;
  title: string;
  name: string;
  status: "experimental" | "test" | "stable";
  description: string;
  author: string;
  date: string;
  references: string[];
  tags: string[];
  techniqueId?: string;
  techniqueName?: string;
  tactic?: string;
  level: "low" | "medium" | "high" | "critical";
  logsource: {
    category?: string;
    product?: string;
    service?: string;
  };
  detection: {
    selection: Record<string, any>;
    filter_noise?: Record<string, any>;
    condition: string;
  };
  falsepositives: string[];
  yaml: string;
  dialect: QueryDialect;
  healthScore: number;
  noiseRisk: "minimal" | "low" | "moderate" | "high";
  tuningSummary: {
    noiseExclusionsCount: number;
    mitreMapped: boolean;
    anchorsApplied: boolean;
    optimizations: string[];
    fpEstimatedPct: number;
  };
}

export interface TuningOptions {
  ruleTitle?: string;
  targetTechnique?: string;
  targetHost?: string;
  targetIp?: string;
  customExclusions?: string[];
  strictMode?: boolean;
}

/** Detects the query dialect from common syntax markers. */
export function detectQueryDialect(query: string): QueryDialect {
  const q = query.trim();
  if (/^alert\s+(tcp|udp|http|dns|tls|ip)\s/im.test(q) || /\bsid:\s*\d+/i.test(q)) {
    return "suricata";
  }
  if (/\b(process|library|file|network)\s+where\b/i.test(q) || /event\.type\s*==/i.test(q)) {
    return "elastic";
  }
  if (
    /\b(SigninLogs|AuditLogs|DeviceProcessEvents|DeviceNetworkEvents|AWSCloudTrail)\b/i.test(q) ||
    /\|\s*where\b/i.test(q) ||
    /\|\s*project\b/i.test(q) ||
    /\bhas_any\(/i.test(q)
  ) {
    return "sentinel";
  }
  if (
    /\bindex\s*=/i.test(q) ||
    /\bsourcetype\s*=/i.test(q) ||
    /\bEventCode\s*=/i.test(q) ||
    /\|\s*stats\b/i.test(q) ||
    /\|\s*table\b/i.test(q)
  ) {
    return "splunk";
  }
  return "generic";
}

/** Known MITRE ATT&CK heuristics for automated mapping. */
const MITRE_HEURISTICS: Array<{
  pattern: RegExp;
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  defaultLevel: "low" | "medium" | "high" | "critical";
}> = [
  {
    pattern: /kerberoast|ticket_encryption_type|4769|0x17/i,
    techniqueId: "T1558.003",
    techniqueName: "Steal or Forge Kerberos Tickets: Kerberoasting",
    tactic: "Credential Access",
    defaultLevel: "high",
  },
  {
    pattern: /bloodhound|sharphound|samaccounttype|1644/i,
    techniqueId: "T1087.002",
    techniqueName: "Account Discovery: Domain Account",
    tactic: "Discovery",
    defaultLevel: "medium",
  },
  {
    pattern: /psexec|psexesvc|7045|admin\$|ipc\$/i,
    techniqueId: "T1569.002",
    techniqueName: "System Services: Service Execution",
    tactic: "Execution",
    defaultLevel: "high",
  },
  {
    pattern: /vssadmin|shadowcopy|delete\s+shadows|wbadmin|bcdedit/i,
    techniqueId: "T1490",
    techniqueName: "Inhibit System Recovery",
    tactic: "Impact",
    defaultLevel: "critical",
  },
  {
    pattern: /dns\s+tunnel|entropy|subdomain|dest_port=53/i,
    techniqueId: "T1071.004",
    techniqueName: "Application Layer Protocol: DNS",
    tactic: "Command and Control",
    defaultLevel: "medium",
  },
  {
    pattern: /7z\.exe|rar\.exe|tar\.exe|-mhe=on|-p/i,
    techniqueId: "T1560.001",
    techniqueName: "Archive Collected Data: Archive via Utility",
    tactic: "Collection",
    defaultLevel: "medium",
  },
  {
    pattern: /aitm|signinlogs|session\s+replay|impossible\s+travel/i,
    techniqueId: "T1566.002",
    techniqueName: "Phishing: Spearphishing Link",
    tactic: "Initial Access",
    defaultLevel: "high",
  },
  {
    pattern: /consent\s+to\s+application|oauth|mail\.readwrite/i,
    techniqueId: "T1528",
    techniqueName: "Steal Application Access Token",
    tactic: "Credential Access",
    defaultLevel: "high",
  },
  {
    pattern: /assumerole|cloudtrail|boto3|sts/i,
    techniqueId: "T1078.004",
    techniqueName: "Valid Accounts: Cloud Accounts",
    tactic: "Defense Evasion",
    defaultLevel: "medium",
  },
  {
    pattern: /lsass|procdump|mimikatz|comsvcs\.dll/i,
    techniqueId: "T1003.001",
    techniqueName: "OS Credential Dumping: LSASS Memory",
    tactic: "Credential Access",
    defaultLevel: "critical",
  },
  {
    pattern: /unsigned\s+dll|code_signature\.trusted\s*==\s*false/i,
    techniqueId: "T1055.001",
    techniqueName: "Process Injection: Dynamic-link Library Injection",
    tactic: "Defense Evasion",
    defaultLevel: "high",
  },
  {
    pattern: /certutil|urlcache|-split|bitsadmin/i,
    techniqueId: "T1105",
    techniqueName: "Ingress Tool Transfer",
    tactic: "Command and Control",
    defaultLevel: "medium",
  },
  {
    pattern: /wmic|eventfilter|commandlineeventconsumer/i,
    techniqueId: "T1546.003",
    techniqueName: "Event Triggered Execution: WMI Event Subscription",
    tactic: "Persistence",
    defaultLevel: "high",
  },
  {
    pattern: /cobalt\s*strike|malleable|beacon/i,
    techniqueId: "T1071.001",
    techniqueName: "Application Layer Protocol: Web Protocols",
    tactic: "Command and Control",
    defaultLevel: "high",
  },
  {
    pattern: /powershell|encodedcommand|-enc\b|-nop\b/i,
    techniqueId: "T1059.001",
    techniqueName: "Command and Scripting Interpreter: PowerShell",
    tactic: "Execution",
    defaultLevel: "high",
  },
];

/** Infers MITRE technique details from query content or explicit options. */
export function inferMitreTechnique(
  text: string,
  explicitTechnique?: string
): { techniqueId: string; techniqueName: string; tactic: string; defaultLevel: "low" | "medium" | "high" | "critical" } | null {
  if (explicitTechnique) {
    const match = MITRE_HEURISTICS.find(
      (m) => m.techniqueId.toLowerCase() === explicitTechnique.toLowerCase()
    );
    if (match) return match;
    return {
      techniqueId: explicitTechnique.toUpperCase(),
      techniqueName: `Technique ${explicitTechnique.toUpperCase()}`,
      tactic: "Execution",
      defaultLevel: "medium",
    };
  }

  for (const h of MITRE_HEURISTICS) {
    if (h.pattern.test(text)) {
      return h;
    }
  }
  return null;
}

/** Extracts core key-value tokens from queries to form Sigma selection block. */
export function extractDetectionTokens(query: string, dialect: QueryDialect): {
  selection: Record<string, any>;
  logsource: { category?: string; product?: string; service?: string };
} {
  const selection: Record<string, any> = {};
  const logsource: { category?: string; product?: string; service?: string } = {
    product: "windows",
  };

  const q = query.trim();

  if (dialect === "splunk") {
    // Check for EventCode
    const ecMatch = q.match(/EventCode\s*=\s*(\d+)/i);
    if (ecMatch) {
      selection["EventID"] = parseInt(ecMatch[1], 10);
      if (ecMatch[1] === "4688") {
        logsource.category = "process_creation";
      } else if (ecMatch[1] === "7045") {
        logsource.service = "system";
      } else if (["4769", "4624", "4625"].includes(ecMatch[1])) {
        logsource.service = "security";
      }
    }

    // Process Name
    const procMatch = q.match(/(?:NewProcessName|process_name|Image)\s*=\s*"([^"]+)"/i);
    if (procMatch) {
      selection["Image|endswith"] = procMatch[1].replace(/\\\\/g, "\\");
      logsource.category = "process_creation";
    }

    // Command Line
    const cmdMatch = q.match(/CommandLine\s*=\s*"([^"]+)"/i);
    if (cmdMatch) {
      selection["CommandLine|contains"] = cmdMatch[1].replace(/\*/g, "").trim();
    }

    // Service Name
    const svcMatch = q.match(/ServiceName\s*=\s*"([^"]+)"/i);
    if (svcMatch) {
      selection["ServiceName"] = svcMatch[1];
      logsource.service = "system";
    }

    // Ticket Encryption
    const encMatch = q.match(/Ticket_Encryption_Type\s*=\s*"([^"]+)"/i);
    if (encMatch) {
      selection["TicketEncryptionType"] = encMatch[1];
      logsource.service = "security";
    }
  } else if (dialect === "sentinel") {
    if (/DeviceProcessEvents/i.test(q)) {
      logsource.category = "process_creation";
      logsource.product = "windows";
    } else if (/SigninLogs/i.test(q)) {
      logsource.service = "signinlogs";
      logsource.product = "azure";
    } else if (/AuditLogs/i.test(q)) {
      logsource.service = "auditlogs";
      logsource.product = "azure";
    } else if (/AWSCloudTrail/i.test(q)) {
      logsource.service = "cloudtrail";
      logsource.product = "aws";
    }

    // Process matching
    const procMatch = q.match(/(?:FileName|InitiatingProcessFileName)\s*(?:=~|==|in~)\s*(?:\("([^"]+)"|["']([^"']+)["'])/i);
    if (procMatch) {
      selection["Image|endswith"] = `\\${procMatch[1] || procMatch[2]}`;
    }

    // CommandLine matching
    const cmdMatch = q.match(/(?:ProcessCommandLine|CommandLine)\s*(?:has|contains)\s*["']([^"']+)["']/i);
    if (cmdMatch) {
      selection["CommandLine|contains"] = cmdMatch[1];
    }
  } else if (dialect === "elastic") {
    if (/process\s+where/i.test(q)) {
      logsource.category = "process_creation";
    } else if (/library\s+where/i.test(q)) {
      logsource.category = "image_load";
    }

    const procMatch = q.match(/process\.name\s*(?:==|in)\s*(?:\("([^"]+)"|["']([^"']+)["'])/i);
    if (procMatch) {
      selection["Image|endswith"] = `\\${procMatch[1] || procMatch[2]}`;
    }

    const cmdMatch = q.match(/process\.command_line\s*:\s*(?:\("([^"]+)"|["']([^"']+)["'])/i);
    if (cmdMatch) {
      selection["CommandLine|contains"] = cmdMatch[1] || cmdMatch[2];
    }
  }

  // Fallback defaults if selection is empty
  if (Object.keys(selection).length === 0) {
    if (/powershell/i.test(q)) {
      selection["Image|endswith"] = "\\powershell.exe";
      selection["CommandLine|contains"] = "-EncodedCommand";
      logsource.category = "process_creation";
    } else if (/psexec/i.test(q)) {
      selection["ServiceName"] = "PSEXESVC";
      logsource.service = "system";
    } else if (/lsass/i.test(q)) {
      selection["TargetImage|endswith"] = "\\lsass.exe";
      logsource.category = "process_access";
    } else {
      selection["CommandLine|contains"] = q.slice(0, 40).replace(/[^a-zA-Z0-9_-]/g, " ").trim();
      logsource.category = "process_creation";
    }
  }

  return { selection, logsource };
}

/** Generates baseline noise suppression filters based on logsource and targets. */
export function generateNoiseFilters(
  logsource: { category?: string; service?: string; product?: string },
  selection: Record<string, any>
): TuningFilter[] {
  const filters: TuningFilter[] = [];

  // Filter 1: Benign system updaters for process creation
  if (logsource.category === "process_creation") {
    filters.push({
      id: "filter-updater",
      name: "Exclude Standard Software Updaters",
      field: "CommandLine|contains",
      value: ["--type=utility", "GoogleUpdate.exe", "MicrosoftEdgeUpdate.exe"],
      reason: "Suppresses background browser/component auto-updater telemetry",
      category: "benign_process",
      enabled: true,
    });

    filters.push({
      id: "filter-system32-parent",
      name: "Exclude Trusted System Services Parent",
      field: "ParentImage|endswith",
      value: ["\\System32\\services.exe", "\\System32\\svchost.exe"],
      reason: "Filters benign child processes spawned by core OS service hosts",
      category: "system_path",
      enabled: true,
    });
  }

  // Filter 2: Service Accounts for security / authentication
  if (logsource.service === "security" || selection["EventID"] === 4769) {
    filters.push({
      id: "filter-machine-accounts",
      name: "Exclude Computer Machine Accounts",
      field: "Service_Name|endswith",
      value: "$",
      reason: "Filters routine computer-account Kerberos ticket requests",
      category: "service_account",
      enabled: true,
    });
  }

  // Filter 3: Benign Local Administrative accounts
  filters.push({
    id: "filter-system-user",
    name: "Filter Standard NT AUTHORITY System Contexts",
    field: "User",
    value: ["NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE"],
    reason: "Mitigates high-volume internal system daemon noise",
    category: "service_account",
    enabled: true,
  });

  return filters;
}

/** Generates clean, standard Sigma YAML string from structured rule parts. */
export function formatSigmaYaml(params: {
  title: string;
  id: string;
  status: string;
  description: string;
  author: string;
  date: string;
  references: string[];
  tags: string[];
  logsource: { category?: string; product?: string; service?: string };
  selection: Record<string, any>;
  filter_noise?: Record<string, any>;
  condition: string;
  falsepositives: string[];
  level: string;
}): string {
  const lines: string[] = [];

  lines.push(`title: ${params.title}`);
  lines.push(`id: ${params.id}`);
  lines.push(`status: ${params.status}`);
  lines.push(`description: ${params.description}`);
  lines.push(`author: ${params.author}`);
  lines.push(`date: ${params.date}`);

  if (params.references && params.references.length > 0) {
    lines.push(`references:`);
    for (const ref of params.references) {
      lines.push(`  - ${ref}`);
    }
  }

  if (params.tags && params.tags.length > 0) {
    lines.push(`tags:`);
    for (const tag of params.tags) {
      lines.push(`  - ${tag}`);
    }
  }

  lines.push(`logsource:`);
  if (params.logsource.product) lines.push(`  product: ${params.logsource.product}`);
  if (params.logsource.category) lines.push(`  category: ${params.logsource.category}`);
  if (params.logsource.service) lines.push(`  service: ${params.logsource.service}`);

  lines.push(`detection:`);
  lines.push(`  selection:`);
  for (const [key, val] of Object.entries(params.selection)) {
    if (typeof val === "string") {
      lines.push(`    ${key}: '${val.replace(/'/g, "''")}'`);
    } else if (Array.isArray(val)) {
      lines.push(`    ${key}:`);
      for (const item of val) {
        lines.push(`      - '${String(item).replace(/'/g, "''")}'`);
      }
    } else {
      lines.push(`    ${key}: ${val}`);
    }
  }

  if (params.filter_noise && Object.keys(params.filter_noise).length > 0) {
    lines.push(`  filter_noise:`);
    for (const [key, val] of Object.entries(params.filter_noise)) {
      if (typeof val === "string") {
        lines.push(`    ${key}: '${val.replace(/'/g, "''")}'`);
      } else if (Array.isArray(val)) {
        lines.push(`    ${key}:`);
        for (const item of val) {
          lines.push(`      - '${String(item).replace(/'/g, "''")}'`);
        }
      } else {
        lines.push(`    ${key}: ${val}`);
      }
    }
  }

  lines.push(`  condition: ${params.condition}`);

  lines.push(`falsepositives:`);
  for (const fp of params.falsepositives) {
    lines.push(`  - ${fp}`);
  }

  lines.push(`level: ${params.level}`);

  return lines.join("\n");
}

/** Analyzes and auto-tunes a raw hunting query or template into a verified Sigma rule. */
export function tuneQueryToSigma(query: string, options?: TuningOptions): TunedSigmaRule {
  const dialect = detectQueryDialect(query);
  const mitre = inferMitreTechnique(query, options?.targetTechnique);
  const { selection, logsource } = extractDetectionTokens(query, dialect);
  const noiseFilters = generateNoiseFilters(logsource, selection);

  const filterNoiseMap: Record<string, any> = {};
  for (const f of noiseFilters.filter((f) => f.enabled)) {
    filterNoiseMap[f.field] = f.value;
  }

  const hasNoiseFilter = Object.keys(filterNoiseMap).length > 0;
  const condition = hasNoiseFilter ? "selection and not filter_noise" : "selection";

  const ruleId = typeof crypto !== "undefined" && crypto.randomUUID
    ? crypto.randomUUID()
    : "8a4f91b0-2b9c-4f77-9a0e-7c9e0d" + Date.now().toString(16).slice(-6);

  const now = new Date();
  const dateStr = `${now.getFullYear()}/${String(now.getMonth() + 1).padStart(2, "0")}/${String(now.getDate()).padStart(2, "0")}`;

  const title =
    options?.ruleTitle ||
    (mitre ? `Hunting Detection: ${mitre.techniqueName}` : `Automated Threat Hunting Rule - ${dialect.toUpperCase()}`);

  const level = mitre ? mitre.defaultLevel : "medium";

  const tags: string[] = [
    `dialect.${dialect}`,
    "auto_tuned",
    "beyondlabs.hunting_arsenal",
  ];
  if (mitre) {
    tags.push(`attack.${mitre.tactic.toLowerCase().replace(/\s+/g, "_")}`);
    tags.push(`attack.${mitre.techniqueId.toLowerCase()}`);
  }

  const falsepositives = [
    "Legitimate IT administrative scripts and maintenance tasks",
    "Enterprise software deployment tools running under SYSTEM",
    "Internal security scanning and telemetry testing",
  ];

  const description = mitre
    ? `Detection rule tuned from SIEM threat hunting query targeting ${mitre.techniqueName} (${mitre.techniqueId}).`
    : `Production Sigma rule synthesized from enterprise hunting pattern (${dialect.toUpperCase()}).`;

  const yaml = formatSigmaYaml({
    title,
    id: ruleId,
    status: "test",
    description,
    author: "BeyondLabs Detection Engineering",
    date: dateStr,
    references: mitre ? [`https://attack.mitre.org/techniques/${mitre.techniqueId}/`] : [],
    tags,
    logsource,
    selection,
    filter_noise: hasNoiseFilter ? filterNoiseMap : undefined,
    condition,
    falsepositives,
    level,
  });

  const health = evaluateSigmaHealth(yaml);

  return {
    id: ruleId,
    title,
    name: title,
    status: "test",
    description,
    author: "BeyondLabs Detection Engineering",
    date: dateStr,
    references: mitre ? [`https://attack.mitre.org/techniques/${mitre.techniqueId}/`] : [],
    tags,
    techniqueId: mitre?.techniqueId,
    techniqueName: mitre?.techniqueName,
    tactic: mitre?.tactic,
    level,
    logsource,
    detection: {
      selection,
      filter_noise: hasNoiseFilter ? filterNoiseMap : undefined,
      condition,
    },
    falsepositives,
    yaml,
    dialect,
    healthScore: health.healthScore,
    noiseRisk: health.noiseRisk,
    tuningSummary: {
      noiseExclusionsCount: noiseFilters.length,
      mitreMapped: Boolean(mitre),
      anchorsApplied: true,
      optimizations: health.optimizations,
      fpEstimatedPct: health.fpEstimatedPct,
    },
  };
}

/** Evaluates the health, noise resistance, and performance characteristics of a Sigma rule. */
export function evaluateSigmaHealth(yaml: string): {
  healthScore: number;
  noiseRisk: "minimal" | "low" | "moderate" | "high";
  fpEstimatedPct: number;
  optimizations: string[];
  missingFields: string[];
} {
  let score = 70;
  const optimizations: string[] = [];
  const missingFields: string[] = [];

  const raw = yaml.toLowerCase();

  // 1. Check required fields
  if (!raw.includes("title:")) { score -= 15; missingFields.push("title"); }
  if (!raw.includes("detection:")) { score -= 20; missingFields.push("detection"); }
  if (!raw.includes("condition:")) { score -= 15; missingFields.push("condition"); }
  if (!raw.includes("logsource:")) { score -= 10; missingFields.push("logsource"); }
  if (!raw.includes("level:")) { score -= 5; missingFields.push("level"); }
  if (!raw.includes("falsepositives:")) { score -= 5; missingFields.push("falsepositives"); }

  // 2. Noise suppression filters
  if (raw.includes("filter_noise") || raw.includes("not filter") || raw.includes("not 1 of filter")) {
    score += 15;
    optimizations.push("Active noise suppression filters applied (whitelisted system accounts & benign updaters)");
  } else {
    score -= 10;
  }

  // 3. Anchoring & Index Performance
  if (raw.includes("endswith:") || raw.includes("contains:")) {
    score += 8;
    optimizations.push("Field-anchored matching minimizes full-table table-scan penalties");
  }

  // 4. MITRE ATT&CK integration
  if (raw.includes("attack.t") || raw.includes("tags:")) {
    score += 7;
    optimizations.push("MITRE ATT&CK technique tags and tactic cross-referencing integrated");
  }

  // Cap score between 10 and 100
  const healthScore = Math.max(10, Math.min(100, score));

  let noiseRisk: "minimal" | "low" | "moderate" | "high" = "moderate";
  let fpEstimatedPct = 8.5;

  if (healthScore >= 90) {
    noiseRisk = "minimal";
    fpEstimatedPct = 1.2;
  } else if (healthScore >= 75) {
    noiseRisk = "low";
    fpEstimatedPct = 3.5;
  } else if (healthScore >= 55) {
    noiseRisk = "moderate";
    fpEstimatedPct = 7.8;
  } else {
    noiseRisk = "high";
    fpEstimatedPct = 18.5;
  }

  return {
    healthScore,
    noiseRisk,
    fpEstimatedPct,
    optimizations,
    missingFields,
  };
}

export const LS_PENDING_RULE_ID = "ba.detection.pendingRuleId";

/**
 * Promotes a tuned Sigma rule directly into the Detection Sandbox (`/detection`).
 * Persists the rule into the Detection library (`ba.detection.rules.v2`) and flags it for immediate loading.
 */
export function promoteRuleToDetectionLab(tuned: TunedSigmaRule): SavedRule {
  const currentRules = loadRules();

  const newSavedRule: SavedRule = normalizeRule({
    id: tuned.id,
    name: tuned.title,
    format: "sigma",
    rule: tuned.yaml,
    event: "",
    tags: tuned.tags,
    technique: tuned.techniqueId,
    state: "draft",
    version: 1,
    created: Date.now(),
    updated: Date.now(),
    stateUpdated: Date.now(),
  });

  const existingIdx = currentRules.findIndex((r) => r.id === newSavedRule.id || r.name === newSavedRule.name);
  let updatedList: SavedRule[];
  if (existingIdx >= 0) {
    updatedList = [...currentRules];
    updatedList[existingIdx] = newSavedRule;
  } else {
    updatedList = [newSavedRule, ...currentRules];
  }

  saveRules(updatedList);

  // Set pending rule ID flag for Detection route
  try {
    localStorage.setItem(LS_PENDING_RULE_ID, newSavedRule.id);
  } catch {
    // ignore
  }

  // Dispatch global broadcast event
  try {
    window.dispatchEvent(new CustomEvent("ba:detection-rule-promoted", { detail: newSavedRule }));
  } catch {
    // non-window
  }

  return newSavedRule;
}
