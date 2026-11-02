import { detectObservable } from "@/lib/palette/intent";
import {
  type Case, type Entry, newId, ensureIocId,
  loadCases, saveCases,
} from "@/data/case";
import { addEdge } from "@/lib/provenance";
import type { IocType, IOC } from "@/types/security";
import type { Severity } from "@/lib/severity";
import type { TriageIoc, TriageItem } from "@/data/triage";

const KIND_TO_IOC_TYPE: Record<string, IocType> = {
  ipv4: "ipv4",
  ipv6: "ipv6",
  url: "url",
  domain: "domain",
  email: "email",
  "hash-md5": "md5",
  "hash-sha1": "sha1",
  "hash-sha256": "sha256",
};

const CANDIDATE_RE = new RegExp(
  [
    "https?:\\/\\/[^\\s\"'<>()\\[\\]]+",
    "\\b[a-fA-F0-9]{32}\\b|\\b[a-fA-F0-9]{40}\\b|\\b[a-fA-F0-9]{64}\\b",
    "[^\\s<>@\"'()]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
    "\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b",
    "(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}",
  ].join("|"),
  "g",
);

function isPlausibleDomain(value: string): boolean {
  const labels = value.split(".");
  const body = labels.slice(0, -1);
  if (body.some((l) => l.length >= 3)) return true;
  return body.length >= 2 && body.every((l) => l.length >= 2);
}

export function extractIocsFromText(...texts: (string | undefined)[]): TriageIoc[] {
  const seen = new Set<string>();
  const out: TriageIoc[] = [];
  for (const text of texts) {
    if (!text) continue;
    for (const match of text.matchAll(CANDIDATE_RE)) {
      const raw = match[0].replace(/[.,;:]+$/, "");
      const kind = detectObservable(raw);
      const iocType = kind ? KIND_TO_IOC_TYPE[kind] : undefined;
      if (!iocType) continue;
      const value = iocType === "url" || iocType === "email" ? raw : raw.toLowerCase();
      if (iocType === "domain" && !isPlausibleDomain(value)) continue;
      const key = `${iocType}:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ type: iocType, value });
    }
  }
  return out;
}

export type EscalateResult = {
  ok: true;
  existing: boolean;
  caseId: string;
  iocCount: number;
  edgeWritten: boolean;
};

function toIoc(r: TriageIoc, item: Pick<TriageItem, "id" | "source" | "severity">): IOC {
  return ensureIocId({
    value: r.value,
    type: r.type as IocType,
    context: `Triage item ${item.id}`,
    source: `triage:${item.source}`,
    severity: item.severity as Severity,
  });
}

export function escalateToCase(item: TriageItem, now = new Date().toISOString()): EscalateResult {
  const cases = loadCases();
  if (item.caseId && cases.some((c) => c.id === item.caseId)) {
    return { ok: true, existing: true, caseId: item.caseId, iocCount: 0, edgeWritten: false };
  }

  const extracted = item.iocs?.length
    ? item.iocs
    : extractIocsFromText(item.title, item.description);
  const iocs = extracted.map((r) => toIoc(r, item));

  const entries: Entry[] = [
    {
      id: newId("entry"),
      ts: now,
      kind: "decision",
      body: `**Escalated from Triage**\n\n${item.description}\n\n*Source: ${item.source}*`,
    },
  ];
  if (item.notes) entries.push({ id: newId("entry"), ts: now, kind: "note", body: item.notes });

  const c: Case = {
    id: newId("case"),
    title: item.title,
    tags: [...new Set(["triage", item.source, item.severity].filter(Boolean))],
    createdAt: now,
    state: "active",
    entries,
    iocs,
    events: [
      {
        id: newId("evt"),
        ts: now,
        kind: "case_created",
        category: "case",
        importance: item.severity === "critical" || item.severity === "high" ? "high" : "normal",
        actor: "analyst",
        origin: "triage-escalation",
        title: "Case opened from triage escalation",
        detail: `${item.source} · ${item.title}${iocs.length > 0 ? ` · ${iocs.length} IOC(s) carried` : " · no IOCs extracted"}`,
        references: item.alertNodeId ? [{ kind: "alert", id: item.alertNodeId }] : [],
      },
    ],
  };

  saveCases([...cases, c]);

  let edgeWritten = false;
  if (item.alertNodeId) {
    addEdge({
      relation: "creates",
      from: { kind: "alert", id: item.alertNodeId },
      to: { kind: "case", id: c.id },
      source: `triage:${item.source}`,
      reason: "triage escalation opened the investigation",
    });
    edgeWritten = true;
  }

  return { ok: true, existing: false, caseId: c.id, iocCount: iocs.length, edgeWritten };
}

export type BulkEscalateSummary = {
  created: number;
  linked: number;
  failed: number;
  iocsCarried: number;
  edgesWritten: number;
};

export function escalateItems(items: TriageItem[], now = Date.now()): {
  summary: BulkEscalateSummary;
  updated: TriageItem[];
} {
  const summary: BulkEscalateSummary = { created: 0, linked: 0, failed: 0, iocsCarried: 0, edgesWritten: 0 };
  const updated: TriageItem[] = [];
  for (const item of items) {
    try {
      const res = escalateToCase(item, new Date(now).toISOString());
      updated.push({ ...item, status: "escalated" as const, caseId: res.caseId, updated: now });
      if (res.existing) {
        summary.linked += 1;
      } else {
        summary.created += 1;
        summary.iocsCarried += res.iocCount;
        summary.edgesWritten += res.edgeWritten ? 1 : 0;
      }
    } catch {
      summary.failed += 1;
      updated.push(item);
    }
  }
  return { summary, updated };
}
