import type { Finding, IOC, IocType } from "@/types/security";
import type { Severity } from "@/lib/severity";
import type { CaseEvent, Entry, Case, EventImportance } from "@/data/case";

function parseSeverity(body: string): { severity: string | null; clean: string } {
  const m = body.match(/^\[(\w+)\]\s*/);
  if (m) return { severity: m[1].toLowerCase(), clean: body.slice(m[0].length) };
  return { severity: null, clean: body };
}

function parseSource(body: string): { source: string | null } {
  const m = body.match(/\s*\(from:\s*([^)]+)\)\s*/);
  if (m) return { source: m[1] };
  return { source: null };
}

function entryBodyToSeverity(body: string): EventImportance {
  const { severity } = parseSeverity(body);
  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (severity === "medium" || severity === "warning") return "normal";
  return "low";
}

export function legacyEntryToEvent(entry: Entry): CaseEvent {
  const { source } = parseSource(entry.body);
  const origin = source || "legacy";

  switch (entry.kind) {
    case "decision": {
      const lines = entry.body.split("\n");
      const verdict = lines.find(l => l.startsWith("Verdict:"))?.replace("Verdict:", "").trim();
      return {
        id: `legacy-${entry.id}`,
        ts: entry.ts,
        kind: "case_decision_made",
        category: "case",
        importance: "critical",
        actor: "analyst",
        origin,
        title: verdict ? `Verdict: ${verdict}` : "Decision recorded",
        detail: entry.body.slice(0, 200),
        references: [],
      };
    }
    case "ioc": {
      const lines = entry.body.split("\n");
      const colon = lines[0].indexOf(":");
      const iocType = colon > 0 ? lines[0].slice(0, colon).trim() : "unknown";
      const iocValue = colon > 0 ? lines[0].slice(colon + 1).trim() : lines[0];
      return {
        id: `legacy-${entry.id}`,
        ts: entry.ts,
        kind: "ioc_created",
        category: "ioc",
        importance: "high",
        actor: "analyst",
        origin,
        title: `IOC: ${iocType}`,
        detail: `${iocValue}`,
        references: [{ kind: "ioc" as const, id: entry.id }],
      };
    }
    case "evidence": {
      const { severity, clean } = parseSeverity(entry.body);
      const firstLine = clean.split("\n")[0];
      const tag = severity ? `[${severity.toUpperCase()}] ` : "";
      return {
        id: `legacy-${entry.id}`,
        ts: entry.ts,
        kind: "finding_created",
        category: "finding",
        importance: entryBodyToSeverity(entry.body),
        actor: "system",
        origin,
        title: `${tag}${firstLine || "Finding recorded"}`,
        detail: clean.slice(0, 200),
        references: [],
      };
    }
    case "action": {
      const firstLine = entry.body.split("\n")[0];
      return {
        id: `legacy-${entry.id}`,
        ts: entry.ts,
        kind: "analyst_action",
        category: "analyst",
        importance: "normal",
        actor: "analyst",
        origin,
        title: firstLine.slice(0, 80),
        detail: entry.body.length > 80 ? entry.body.slice(80, 200) : "",
        references: [],
      };
    }
    case "note":
    default: {
      const firstLine = entry.body.split("\n")[0];
      return {
        id: `legacy-${entry.id}`,
        ts: entry.ts,
        kind: "case_note_added",
        category: "analyst",
        importance: "low",
        actor: "analyst",
        origin,
        title: firstLine.slice(0, 80) || "Note",
        detail: entry.body.slice(0, 200),
        references: [],
      };
    }
  }
}

export function legacyEntriesToEvents(entries: Entry[]): CaseEvent[] {
  return entries.map(legacyEntryToEvent);
}

/* ── unified adapter for findings ── */

function parseIocEntry(body: string): { type: string; value: string; source: string } | null {
  const lines = body.split("\n");
  const first = lines[0];
  const colon = first.indexOf(":");
  if (colon === -1) return null;
  return {
    type: first.slice(0, colon).trim(),
    value: first.slice(colon + 1).trim(),
    source: (lines[1] || "").replace("Source:", "").trim(),
  };
}

const MITRE_RE = /\b(TA\d{4}|T\d{4}(?:\.\d{1,3})?)\b/;

function legacyEvidenceToFinding(entry: Entry, structuredFindings?: Finding[]): Finding {
  const { severity, clean: noSev } = parseSeverity(entry.body);
  const { source } = parseSource(noSev);
  const body = noSev.replace(/\s*\(from:\s*([^)]+)\)\s*/, " ").trim();
  const lines = body.split("\n");
  const title = lines[0];
  const detail = lines.slice(1).filter(l => l.trim()).join("\n");

  let technique: string | undefined;
  if (structuredFindings?.length) {
    for (const f of structuredFindings) {
      if (f.technique && f.source === source && f.title === title) {
        technique = f.technique;
        break;
      }
    }
  }
  if (!technique) {
    const m = entry.body.match(MITRE_RE);
    if (m) technique = m[1];
  }

  return {
    id: entry.id,
    severity: (severity || "info") as Severity,
    title,
    detail,
    source: source || "legacy",
    technique,
  };
}

export function getUnifiedFindings(c: Case): Finding[] {
  if (c.findings?.length) return c.findings;
  const evidence = c.entries.filter(e => e.kind === "evidence");
  return evidence.map(e => legacyEvidenceToFinding(e, c.findings));
}

/* ── unified adapter for IOCs ── */

const IOC_RX: Record<string, RegExp> = {
  ipv4: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
  url: /https?:\/\/[^\s)"']+/g,
  md5: /\b[a-f0-9]{32}\b/gi,
  sha1: /\b[a-f0-9]{40}\b/gi,
  sha256: /\b[a-f0-9]{64}\b/gi,
};

function guessIocType(value: string): IocType {
  if (IOC_RX.ipv4.test(value)) return "ipv4";
  if (IOC_RX.url.test(value)) return "url";
  if (IOC_RX.md5.test(value)) return "md5";
  if (IOC_RX.sha1.test(value)) return "sha1";
  if (IOC_RX.sha256.test(value)) return "sha256";
  return "unknown";
}

export function getUnifiedIOCs(c: Case): IOC[] {
  if (c.iocs?.length) return c.iocs;

  const seen = new Set<string>();
  const result: IOC[] = [];

  const add = (value: string, type: string, source: string) => {
    if (seen.has(value)) return;
    seen.add(value);
    result.push({ value, type: type as IocType, context: "", source, severity: "unknown" as Severity });
  };

  for (const entry of c.entries) {
    if (entry.kind !== "ioc") continue;
    const parsed = parseIocEntry(entry.body);
    if (parsed) {
      add(parsed.value, parsed.type, parsed.source || "legacy");
    } else {
      const value = entry.body.trim();
      const type = guessIocType(value);
      add(value, type, "legacy");
    }
  }

  return result;
}
