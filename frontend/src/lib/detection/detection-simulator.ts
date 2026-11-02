/**
 * Detection Telemetry Simulation Engine
 * Runs Sigma, YARA, and KQL rules against enterprise log telemetry,
 * diagnosing field-by-field matches, false positives, and execution latency.
 */

export interface TelemetryScenario {
  id: string;
  title: string;
  category: "process" | "credential" | "defense_evasion" | "network" | "web" | "auth";
  expected: "match" | "benign";
  event: string;
  source: string;
  fields: Record<string, string | number>;
}

export const ENTERPRISE_TELEMETRY_SUITE: TelemetryScenario[] = [
  {
    id: "scen-ps-encoded",
    title: "Malicious PowerShell Encoded Download Cradle",
    category: "process",
    expected: "match",
    source: "Sysmon EID 1 (Process Creation)",
    event: "Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine=\"powershell.exe -NoP -NonI -W Hidden -EncodedCommand SQBFAFgA\" ParentImage=C:\\Windows\\explorer.exe User=CONTOSO\\krish IntegrityLevel=Medium",
    fields: {
      Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      CommandLine: "powershell.exe -NoP -NonI -W Hidden -EncodedCommand SQBFAFgA",
      User: "CONTOSO\\krish",
      ParentImage: "C:\\Windows\\explorer.exe",
    },
  },
  {
    id: "scen-ps-admin-backup",
    title: "Benign Admin PowerShell Backup Script",
    category: "process",
    expected: "benign",
    source: "Sysmon EID 1 (Process Creation)",
    event: "Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine=\"powershell.exe -ExecutionPolicy RemoteSigned -File C:\\Scripts\\DailyBackup.ps1\" ParentImage=C:\\Windows\\System32\\taskeng.exe User=NT AUTHORITY\\SYSTEM",
    fields: {
      Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      CommandLine: "powershell.exe -ExecutionPolicy RemoteSigned -File C:\\Scripts\\DailyBackup.ps1",
      User: "NT AUTHORITY\\SYSTEM",
      ParentImage: "C:\\Windows\\System32\\taskeng.exe",
    },
  },
  {
    id: "scen-mimikatz-lsass",
    title: "Mimikatz LSASS Process Memory Handle Access",
    category: "credential",
    expected: "match",
    source: "Sysmon EID 10 (Process Access)",
    event: "SourceImage=C:\\Users\\Public\\mimikatz.exe TargetImage=C:\\Windows\\System32\\lsass.exe GrantedAccess=0x1010 CallTrace=C:\\Windows\\SYSTEM32\\ntdll.dll+9d484|C:\\Users\\Public\\mimikatz.exe+14b20",
    fields: {
      SourceImage: "C:\\Users\\Public\\mimikatz.exe",
      TargetImage: "C:\\Windows\\System32\\lsass.exe",
      GrantedAccess: "0x1010",
      CommandLine: "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
    },
  },
  {
    id: "scen-wevtutil-clear",
    title: "Defense Evasion: Security Event Log Cleared",
    category: "defense_evasion",
    expected: "match",
    source: "Security EID 1102 (Audit Log Cleared)",
    event: "EventID=1102 Channel=Security SubjectUserName=Administrator SubjectDomainName=CONTOSO Image=C:\\Windows\\System32\\wevtutil.exe CommandLine=\"wevtutil.exe cl Security\"",
    fields: {
      EventID: 1102,
      CommandLine: "wevtutil.exe cl Security",
      Channel: "Security",
      SubjectUserName: "Administrator",
    },
  },
  {
    id: "scen-dns-tunnel",
    title: "DNS High-Entropy C2 Tunnel Query",
    category: "network",
    expected: "match",
    source: "Sysmon EID 22 (DNS Query)",
    event: "QueryName=7a8b9c0d1e2f3a4b5c6d7e8f.stage2.attacker-c2.net QueryStatus=0 Image=C:\\Windows\\System32\\svchost.exe User=NT AUTHORITY\\NETWORK SERVICE",
    fields: {
      QueryName: "7a8b9c0d1e2f3a4b5c6d7e8f.stage2.attacker-c2.net",
      Entropy: 4.25,
      QueryStatus: 0,
      Image: "C:\\Windows\\System32\\svchost.exe",
    },
  },
  {
    id: "scen-normal-ad-dns",
    title: "Benign Active Directory Domain Controller DNS Lookup",
    category: "network",
    expected: "benign",
    source: "Sysmon EID 22 (DNS Query)",
    event: "QueryName=dc01.corp.contoso.internal QueryStatus=0 Image=C:\\Windows\\System32\\lsass.exe User=NT AUTHORITY\\SYSTEM",
    fields: {
      QueryName: "dc01.corp.contoso.internal",
      Entropy: 2.1,
      QueryStatus: 0,
    },
  },
];

export interface ScenarioResult {
  id: string;
  title: string;
  category: string;
  expected: "match" | "benign";
  hit: boolean;
  verdict: "tp" | "tn" | "fp" | "fn";
  matchedTokens: string[];
  eventSnippet: string;
}

export interface SimulationReport {
  format: string;
  durationMs: number;
  totalScenarios: number;
  totalMatches: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  precision: number;
  recall: number;
  results: ScenarioResult[];
  tuningSuggestions: Array<{
    scenarioId: string;
    suggestion: string;
    filterSnippet: string;
  }>;
}

export function runClientSimulation(
  ruleContent: string,
  format: "sigma" | "yara" | "kql" | "suricata",
  scenarios: TelemetryScenario[] = ENTERPRISE_TELEMETRY_SUITE,
): SimulationReport {
  const startTime = performance.now();

  const tokens = extractTokens(ruleContent, format);
  const exclusions = extractExclusions(ruleContent, format);

  let tp = 0;
  let fp = 0;
  let fn = 0;
  let tn = 0;
  const results: ScenarioResult[] = [];
  const tuningSuggestions: Array<{ scenarioId: string; suggestion: string; filterSnippet: string }> = [];

  for (const scen of scenarios) {
    const text = scen.event.toLowerCase();
    let isExcluded = false;

    for (const ex of exclusions) {
      if (text.includes(ex.toLowerCase())) {
        isExcluded = true;
        break;
      }
    }

    const matchedTokens: string[] = [];
    if (!isExcluded) {
      for (const tok of tokens) {
        if (text.includes(tok.toLowerCase())) {
          matchedTokens.push(tok);
        }
      }
    }

    let hit = false;
    if (!isExcluded && tokens.length > 0) {
      if (format === "sigma") {
        hit = tokens.length >= 2 ? matchedTokens.length >= 2 : matchedTokens.length >= 1;
      } else if (format === "yara") {
        hit = matchedTokens.length === tokens.length;
      } else {
        hit = matchedTokens.length >= 1;
      }
    }

    let verdict: "tp" | "tn" | "fp" | "fn";
    if (hit) {
      if (scen.expected === "match") {
        verdict = "tp";
        tp++;
      } else {
        verdict = "fp";
        fp++;
        tuningSuggestions.push({
          scenarioId: scen.id,
          suggestion: `Add exclusion filter for benign event "${scen.title}"`,
          filterSnippet: `filter:\n  - Image|endswith: \x27${scen.fields.Image || "system32\\taskeng.exe"}\x27\ncondition: selection and not filter`,
        });
      }
    } else {
      if (scen.expected === "match") {
        verdict = "fn";
        fn++;
      } else {
        verdict = "tn";
        tn++;
      }
    }

    results.push({
      id: scen.id,
      title: scen.title,
      category: scen.category,
      expected: scen.expected,
      hit,
      verdict,
      matchedTokens,
      eventSnippet: scen.event.slice(0, 160) + (scen.event.length > 160 ? "..." : ""),
    });
  }

  const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
  const precision = tp + fp > 0 ? Math.round((tp / (tp + fp)) * 100) / 100 : 0;
  const recall = tp + fn > 0 ? Math.round((tp / (tp + fn)) * 100) / 100 : 0;

  return {
    format,
    durationMs,
    totalScenarios: scenarios.length,
    totalMatches: tp + fp,
    truePositives: tp,
    falsePositives: fp,
    falseNegatives: fn,
    trueNegatives: tn,
    precision,
    recall,
    results,
    tuningSuggestions,
  };
}

function extractTokens(rule: string, format: string): string[] {
  const tokens: string[] = [];
  if (format === "sigma") {
    for (const line of rule.split("\n")) {
      const trimmed = line.trim();
      if (trimmed.startsWith("-") && !trimmed.includes("attack.")) {
        const cleaned = trimmed.replace(/^-\s*['"]?/, "").replace(/['"]$/, "").trim();
        if (cleaned && cleaned.length >= 2) tokens.push(cleaned);
      }
      const mVal = trimmed.match(/:\s*['"]([^'"]+)['"]/);
      if (mVal && !mVal[1].startsWith("attack.")) {
        const clean = mVal[1].replace(/\\\\/g, "\\").replace(/^[\\\/]+/, "").trim();
        if (clean.length >= 2) tokens.push(clean);
      }
    }
  } else if (format === "yara") {
    for (const line of rule.split("\n")) {
      const m = line.match(/\$[a-zA-Z0-9_]+\s*=\s*"([^"]+)"/);
      if (m) tokens.push(m[1].trim());
    }
  } else if (format === "suricata") {
    const matches = rule.match(/content\s*:\s*"([^"]+)"/gi) || [];
    for (const m of matches) {
      const val = m.replace(/content\s*:\s*"/i, "").replace(/"$/, "").replace(/\|/g, "").trim();
      if (val.length >= 2) tokens.push(val);
    }
  } else {
    // KQL
    const matches = rule.match(/"([^"]+)"/g) || [];
    for (const m of matches) {
      const val = m.replace(/"/g, "").trim();
      if (val) tokens.push(val);
    }
  }

  if (tokens.length === 0) {
    const words = (rule.match(/\b[A-Za-z0-9_.-]{4,}\b/g) || []).filter(
      (w) => !["title", "status", "logsource", "detection", "condition", "level", "where", "project"].includes(w.toLowerCase()),
    );
    tokens.push(...words.slice(0, 3));
  }

  return Array.from(new Set(tokens));
}

function extractExclusions(rule: string, format: string): string[] {
  const exclusions: string[] = [];
  if (format === "sigma") {
    let inFilter = false;
    for (const line of rule.split("\n")) {
      if (/^\s*filter\w*:/i.test(line)) {
        inFilter = true;
        continue;
      }
      if (inFilter && /^\s*(selection|condition):/i.test(line)) {
        inFilter = false;
      }
      if (inFilter) {
        const matches = line.match(/['"]([^'"]+)['"]/g) || [];
        for (const m of matches) exclusions.push(m.replace(/['"]/g, "").trim());
      }
    }
  }
  return Array.from(new Set(exclusions));
}
