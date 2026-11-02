import type { FilterChip, Range } from "@/data/siem";

export interface TranslatedQueries {
  splunkSpl: string;
  elasticKql: string;
  sigmaYaml: string;
  velociraptorVql: string;
  sentinelKql: string;
}

/** Mapping of BeyondLabs internal fields to Splunk CIM, Elastic ECS, and Sentinel fields. */
const FIELD_MAP = {
  src: { splunk: "src_ip", ecs: "source.ip", vql: "SourceAddress", sentinel: "IpAddress" },
  dst: { splunk: "dest_ip", ecs: "destination.ip", vql: "DestAddress", sentinel: "DestinationIpAddress" },
  user: { splunk: "user", ecs: "user.name", vql: "TargetUserName", sentinel: "TargetUserName" },
  sig: { splunk: "signature", ecs: "rule.name", vql: "Message", sentinel: "Activity" },
  sev: { splunk: "severity", ecs: "event.severity", vql: "Level", sentinel: "SeverityLevel" },
  event_type: { splunk: "event_type", ecs: "event.action", vql: "EventID", sentinel: "EventID" },
  process: { splunk: "process_name", ecs: "process.name", vql: "NewProcessName", sentinel: "Process" },
  status: { splunk: "status", ecs: "http.response.status_code", vql: "StatusCode", sentinel: "Status" },
} as const;

const KNOWN_PIPE_COMMANDS = new Set([
  "stats", "sort", "where", "head", "tail", "eval", "table", "dedup",
  "rex", "fields", "top", "rare", "rename", "lookup", "chart", "timechart", "search",
]);

/**
 * Parses user query into keyword terms, field filters, and piped commands.
 * Example: `user:admin "mimikatz" | stats count by src`
 */
export function parseQuery(rawQuery: string): {
  terms: string[];
  fieldFilters: { field: string; value: string }[];
  pipeCommands: string[];
} {
  const q = (rawQuery || "").trim();
  if (!q) return { terms: [], fieldFilters: [], pipeCommands: [] };

  const rawParts = q.split("|");
  let baseSearch = "";
  const pipeCommands: string[] = [];

  let foundPipe = false;
  for (let i = 0; i < rawParts.length; i++) {
    const part = rawParts[i].trim();
    if (!part) continue;
    const firstWord = part.split(/\s+/)[0]?.toLowerCase();

    if (!foundPipe && i > 0 && firstWord && KNOWN_PIPE_COMMANDS.has(firstWord)) {
      foundPipe = true;
    }

    if (foundPipe) {
      pipeCommands.push(part);
    } else {
      baseSearch = baseSearch ? `${baseSearch} | ${part}` : part;
    }
  }

  // Handle OR terms within baseSearch separated by |
  const orSegments = baseSearch.split("|").map((s) => s.trim()).filter(Boolean);
  const terms: string[] = [];
  const fieldFilters: { field: string; value: string }[] = [];

  if (orSegments.length > 1) {
    // There are multiple OR segments: each segment can have words/tokens
    terms.push(orSegments.join(" | "));
  } else {
    const tokens = baseSearch.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
    for (const token of tokens) {
      const clean = token.replace(/^["']|["']$/g, "");
      if (clean.includes(":")) {
        const [f, ...rest] = clean.split(":");
        const val = rest.join(":");
        if (f && val) {
          fieldFilters.push({ field: f.toLowerCase(), value: val });
          continue;
        }
      }
      if (clean) terms.push(clean);
    }
  }

  return { terms, fieldFilters, pipeCommands };
}

/**
 * Translates query and filter chips into Splunk Search Processing Language (SPL).
 */
export function toSplunkSPL(query: string, chips: FilterChip[] = [], range: Range = "all"): string {
  const { terms, fieldFilters, pipeCommands } = parseQuery(query);
  const clauses: string[] = [];

  // Range filter
  if (range === "15m") clauses.push("earliest=-15m");
  else if (range === "1h") clauses.push("earliest=-1h");
  else if (range === "24h") clauses.push("earliest=-24h");

  // Filter chips
  for (const c of chips) {
    const targetField = FIELD_MAP[c.field as keyof typeof FIELD_MAP]?.splunk || c.field;
    clauses.push(`${targetField}="${c.value}"`);
  }

  // Query field filters
  for (const ff of fieldFilters) {
    const targetField = FIELD_MAP[ff.field as keyof typeof FIELD_MAP]?.splunk || ff.field;
    clauses.push(`${targetField}="${ff.value}"`);
  }

  // Keyword terms (supports OR with |)
  if (terms.length > 0) {
    const orGroups = terms.join(" ").split("|").map((g) => g.trim()).filter(Boolean);
    if (orGroups.length > 1) {
      clauses.push(`(${orGroups.map((g) => `*${g}*`).join(" OR ")})`);
    } else {
      clauses.push(`(${terms.map((t) => `*${t}*`).join(" AND ")})`);
    }
  }

  const base = clauses.length > 0 ? `index=* ${clauses.join(" ")}` : "index=*";

  if (pipeCommands.length > 0) {
    return `${base} | ${pipeCommands.join(" | ")}`;
  }
  return `${base} | stats count by src_ip, user, signature | sort -count`;
}

/**
 * Translates query and filter chips into Elastic Kibana Query Language (KQL).
 */
export function toElasticKQL(query: string, chips: FilterChip[] = []): string {
  const { terms, fieldFilters } = parseQuery(query);
  const clauses: string[] = [];

  for (const c of chips) {
    const targetField = FIELD_MAP[c.field as keyof typeof FIELD_MAP]?.ecs || c.field;
    clauses.push(`${targetField}: "${c.value}"`);
  }

  for (const ff of fieldFilters) {
    const targetField = FIELD_MAP[ff.field as keyof typeof FIELD_MAP]?.ecs || ff.field;
    clauses.push(`${targetField}: "${ff.value}"`);
  }

  if (terms.length > 0) {
    const orGroups = terms.join(" ").split("|").map((g) => g.trim()).filter(Boolean);
    if (orGroups.length > 1) {
      clauses.push(`(${orGroups.map((g) => `*${g}*`).join(" or ")})`);
    } else {
      clauses.push(`(${terms.map((t) => `*${t}*`).join(" and ")})`);
    }
  }

  return clauses.length > 0 ? clauses.join(" and ") : "*";
}

/**
 * Compiles query, filter chips, and findings into a standard Sigma detection rule YAML.
 */
export function toSigmaRule(
  query: string,
  chips: FilterChip[] = [],
  title = "Ad-Hoc SIEM Hunt Detection",
  mitreTechniques: string[] = []
): string {
  const { terms, fieldFilters } = parseQuery(query);
  const cleanTitle = title.replace(/[^\w\s-]/g, "").slice(0, 60) || "Suspicious Activity Pattern";
  const ruleId = `sigma-${Math.random().toString(36).slice(2, 10)}`;

  const selections: Record<string, string | string[]> = {};

  for (const c of chips) {
    const ecsField = FIELD_MAP[c.field as keyof typeof FIELD_MAP]?.ecs || c.field;
    selections[ecsField] = c.value;
  }

  for (const ff of fieldFilters) {
    const ecsField = FIELD_MAP[ff.field as keyof typeof FIELD_MAP]?.ecs || ff.field;
    selections[ecsField] = ff.value;
  }

  if (terms.length > 0) {
    selections["keywords|contains"] = terms;
  }

  const selectionYaml = Object.entries(selections)
    .map(([k, v]) => {
      if (Array.isArray(v)) {
        return `      ${k}:\n` + v.map((item) => `        - "${item}"`).join("\n");
      }
      return `      ${k}: "${v}"`;
    })
    .join("\n") || "      keywords|contains:\n        - \"suspicious\"";

  const tagsYaml = (mitreTechniques.length > 0 ? mitreTechniques : ["attack.t1110", "attack.t1059"])
    .map((t) => `  - ${t.toLowerCase().replace(/\s.*$/, "").replace(/^t/, "attack.t")}`)
    .join("\n");

  return `title: ${cleanTitle}
id: ${ruleId}
status: experimental
description: Generated from BeyondLabs SIEM hunt analysis. Detects suspicious activity matching the analyst query.
references:
  - https://github.com/SigmaHQ/sigma
author: BeyondLabs SOC Platform
date: ${new Date().toISOString().slice(0, 10)}
tags:
${tagsYaml}
logsource:
  category: security
  product: windows
detection:
  selection:
${selectionYaml}
  condition: selection
falsepositives:
  - Administrative maintenance or legitimate automated scripts
level: high
`;
}

/**
 * Translates query and filter chips into a Velociraptor VQL hunting artifact.
 */
export function toVelociraptorVQL(query: string, chips: FilterChip[] = []): string {
  const { terms, fieldFilters } = parseQuery(query);
  const conditions: string[] = [];

  for (const c of chips) {
    const vqlField = FIELD_MAP[c.field as keyof typeof FIELD_MAP]?.vql || c.field;
    conditions.push(`${vqlField} =~ "${c.value}"`);
  }

  for (const ff of fieldFilters) {
    const vqlField = FIELD_MAP[ff.field as keyof typeof FIELD_MAP]?.vql || ff.field;
    conditions.push(`${vqlField} =~ "${ff.value}"`);
  }

  if (terms.length > 0) {
    conditions.push(`(${terms.map((t) => `Message =~ "${t}"`).join(" OR ")})`);
  }

  const whereClause = conditions.length > 0 ? `\nWHERE ${conditions.join(" AND ")}` : "";

  return `name: Custom.Hunt.BeyondLabs
description: Hunt for suspicious events identified in BeyondLabs SIEM
sources:
  - query: |
      SELECT EventData, System.TimeCreated.SystemTime AS Timestamp,
             System.EventID.Value AS EventID
      FROM Artifact.Windows.EventLogs.EvtxHunter(
          Path="C:/Windows/System32/winevt/Logs/Security.evtx"
      )${whereClause}
      LIMIT 100
`;
}

/**
 * Translates query and filter chips into Microsoft Sentinel / Azure Monitor Kusto Query Language (KQL).
 */
export function toSentinelKQL(query: string, chips: FilterChip[] = []): string {
  const { terms, fieldFilters } = parseQuery(query);
  const whereClauses: string[] = [];

  for (const c of chips) {
    const targetField = FIELD_MAP[c.field as keyof typeof FIELD_MAP]?.sentinel || c.field;
    whereClauses.push(`${targetField} =~ "${c.value}"`);
  }

  for (const ff of fieldFilters) {
    const targetField = FIELD_MAP[ff.field as keyof typeof FIELD_MAP]?.sentinel || ff.field;
    whereClauses.push(`${targetField} =~ "${ff.value}"`);
  }

  if (terms.length > 0) {
    const orGroups = terms.join(" ").split("|").map((g) => g.trim()).filter(Boolean);
    if (orGroups.length > 1) {
      whereClauses.push(`(${orGroups.map((g) => `* has "${g}"`).join(" or ")})`);
    } else {
      whereClauses.push(`(${terms.map((t) => `* has "${t}"`).join(" and ")})`);
    }
  }

  const wherePart = whereClauses.length > 0 ? `\n| where ${whereClauses.join(" and ")}` : "";
  return `SecurityEvent${wherePart}\n| summarize count() by TargetUserName, EventID, IpAddress\n| order by count_ desc`;
}

/**
 * Returns all 5 translated query formats in a single pass.
 */
export function translateAll(
  query: string,
  chips: FilterChip[] = [],
  range: Range = "all",
  mitre: string[] = []
): TranslatedQueries {
  return {
    splunkSpl: toSplunkSPL(query, chips, range),
    elasticKql: toElasticKQL(query, chips),
    sigmaYaml: toSigmaRule(query, chips, "Ad-Hoc SIEM Hunt Detection", mitre),
    velociraptorVql: toVelociraptorVQL(query, chips),
    sentinelKql: toSentinelKQL(query, chips),
  };
}

