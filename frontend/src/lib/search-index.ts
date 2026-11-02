import { loadCases } from "@/data/case";
import { ALL_ITEMS } from "@/lib/workspaces";
import { loadRules } from "@/data/detection";
import { loadItems } from "@/data/triage";
import { ALL_TECHNIQUES } from "@/data/mitre";
import { ALL_ENTITIES } from "@/data/intel";

export type SearchItemType = "case" | "finding" | "ioc" | "event" | "note" | "artifact" | "page" | "report" | "detection" | "mitre" | "entity" | "alert";

export type SearchItem = {
  id: string;
  type: SearchItemType;
  label: string;
  description: string;
  tags: string;
  caseId: string | null;
  caseTitle: string;
  tab?: "findings" | "ioc" | "activity" | "notebook";
  refIdx?: number;
  url?: string;
  route?: string;
  objectId?: string;
  metadata?: Record<string, string>;
  scoreWeight?: number;
};

export function buildSearchIndex(): SearchItem[] {
  const items: SearchItem[] = [];

  for (const item of ALL_ITEMS) {
    items.push({
      id: `page-${item.url}`,
      type: "page",
      label: item.title,
      description: item.desc,
      tags: `${item.title} ${item.desc} ${item.group}`,
      caseId: null,
      caseTitle: "",
      url: item.url,
      route: item.url,
      scoreWeight: 3,
    });
  }

  const cases = loadCases();
  for (const c of cases) {
    items.push({
      id: `case-${c.id}`,
      type: "case",
      label: c.title,
      description: `${c.tags.join(", ")} — ${c.state}`,
      tags: `${c.title} ${c.tags.join(" ")} ${c.state} ${c.id}`,
      caseId: c.id,
      caseTitle: c.title,
      route: "/case",
      objectId: c.id,
      scoreWeight: 10,
      metadata: { state: c.state, age: String(Math.floor((Date.now() - new Date(c.createdAt).getTime()) / 86400000)) },
    });

    for (const [idx, f] of (c.findings ?? []).entries()) {
      items.push({
        id: `finding-${c.id}-${f.id}`,
        type: "finding",
        label: f.title,
        description: `${f.severity} — ${(f.detail ?? "").slice(0, 150)}`,
        tags: `${f.title} ${f.detail ?? ""} ${f.severity} ${f.source ?? ""} ${f.technique ?? ""} ${c.title}`,
        caseId: c.id,
        caseTitle: c.title,
        tab: "findings",
        refIdx: idx,
        route: "/case",
        objectId: f.id,
        scoreWeight: 8,
        metadata: { severity: f.severity, source: f.source ?? "", technique: f.technique ?? "" },
      });
    }

    for (const [idx, ioc] of (c.iocs ?? []).entries()) {
      items.push({
        id: `ioc-${c.id}-${ioc.value}`,
        type: "ioc",
        label: ioc.value,
        description: `${ioc.type} — ${(ioc.context ?? "").slice(0, 150)}`,
        tags: `${ioc.value} ${ioc.type} ${ioc.context ?? ""} ${ioc.source ?? ""} ${c.title}`,
        caseId: c.id,
        caseTitle: c.title,
        tab: "ioc",
        refIdx: idx,
        route: "/case",
        objectId: ioc.value,
        scoreWeight: 9,
        metadata: { iocType: ioc.type, severity: ioc.severity, source: ioc.source },
      });
    }

    for (const ev of c.events ?? []) {
      items.push({
        id: `event-${c.id}-${ev.id}`,
        type: "event",
        label: ev.title,
        description: `${ev.kind} — ${(ev.detail ?? "").slice(0, 150)}`,
        tags: `${ev.title} ${ev.detail ?? ""} ${ev.kind} ${ev.category ?? ""} ${c.title}`,
        caseId: c.id,
        caseTitle: c.title,
        tab: "activity",
        route: "/case",
        objectId: ev.id,
        scoreWeight: 5,
        metadata: { kind: ev.kind, category: ev.category ?? "", importance: ev.importance ?? "" },
      });
    }

    for (const e of c.entries) {
      if (e.kind === "note") {
        items.push({
          id: `note-${c.id}-${e.id}`,
          type: "note",
          label: e.body.slice(0, 120),
          description: `Note — ${c.title}`,
          tags: `${e.body} ${c.title}`,
          caseId: c.id,
          caseTitle: c.title,
          tab: "activity",
          route: "/case",
          objectId: e.id,
          scoreWeight: 4,
        });
      }
    }

    for (const [idx, a] of (c.artifacts ?? []).entries()) {
      items.push({
        id: `artifact-${c.id}-${a.id}`,
        type: "artifact",
        label: a.title,
        description: `${a.kind} — ${Object.values(a.metadata ?? {}).join(", ").slice(0, 150)}`,
        tags: `${a.title} ${a.kind} ${Object.values(a.metadata ?? {}).join(" ")} ${c.title}`,
        caseId: c.id,
        caseTitle: c.title,
        refIdx: idx,
        route: "/case",
        objectId: a.id,
        scoreWeight: 7,
        metadata: { kind: a.kind },
      });
    }

    items.push({
      id: `report-${c.id}`,
      type: "report",
      label: `${c.title} — Report`,
      description: `Incident report for ${c.title}`,
      tags: `${c.title} report incident ${c.tags.join(" ")} ${c.id}`,
      caseId: c.id,
      caseTitle: c.title,
      url: `/report/${c.id}`,
      route: `/report/${c.id}`,
      scoreWeight: 6,
      metadata: { state: c.state },
    });
  }

  for (const r of loadRules()) {
    items.push({
      id: `detection-${r.id}`,
      type: "detection",
      label: r.name,
      description: `${r.format} rule — ${(r.event ?? "").slice(0, 120)}`,
      tags: `${r.name} ${r.event ?? ""} ${r.format} ${r.tags.join(" ")}`,
      caseId: null,
      caseTitle: "",
      url: "/detection",
      route: "/detection",
      objectId: r.id,
      scoreWeight: 5,
      metadata: { format: r.format, tags: r.tags.join(", ") },
    });
  }

  for (const t of ALL_TECHNIQUES) {
    items.push({
      id: `mitre-${t.tacticId}-${t.id}`,
      type: "mitre",
      label: `${t.id} ${t.name}`,
      description: `${t.tactic} — MITRE ATT&CK technique`,
      tags: `${t.id} ${t.name} ${t.tactic} mitre attack`,
      caseId: null,
      caseTitle: "",
      url: "/mitre",
      route: "/mitre",
      objectId: t.id,
      scoreWeight: 4,
      metadata: { tactic: t.tactic },
    });
  }

  for (const e of ALL_ENTITIES) {
    items.push({
      id: `entity-${e.id}`,
      type: "entity",
      label: e.title,
      description: `${e.type} — ${(e.summary ?? "").slice(0, 150)}`,
      tags: `${e.title} ${e.summary ?? ""} ${e.type} ${e.tags.join(" ")} ${e.confidence}`,
      caseId: null,
      caseTitle: "",
      url: `/intel?q=${encodeURIComponent(e.title)}`,
      route: "/intel",
      objectId: e.id,
      scoreWeight: 4,
      metadata: { entityType: e.type, confidence: e.confidence, score: String(e.score) },
    });
  }

  for (const a of loadItems()) {
    items.push({
      id: `alert-${a.id}`,
      type: "alert",
      label: a.title,
      description: `${a.severity} · ${a.status} — ${(a.description ?? "").slice(0, 150)}`,
      tags: `${a.title} ${a.description ?? ""} ${a.severity} ${a.status} ${a.source} ${a.tags.join(" ")}`,
      caseId: null,
      caseTitle: "",
      url: "/triage",
      route: "/triage",
      objectId: a.id,
      scoreWeight: 5,
      metadata: { severity: a.severity, status: a.status, source: a.source },
    });
  }

  return items;
}
