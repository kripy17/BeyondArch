import type { IntelEntity, Observable } from "@/data/intel";
import type { Finding, IOC, IocType } from "@/types/security";
import type { Severity } from "@/lib/severity";
import { loadCases, saveCases, newId, LS_ACTIVE, ensureIocId } from "@/data/case";
import { addEdge } from "@/lib/provenance";

const OBSERVABLE_TO_IOC_TYPE: Record<string, IocType> = {
  ipv4: "ipv4",
  ipv6: "ipv6",
  domain: "domain",
  url: "url",
  email: "email",
  sha256: "sha256",
  sha1: "sha1",
  md5: "md5",
  cve: "cve",
  ja3: "ja3",
};

function observableToIocType(ot: string): IocType {
  return OBSERVABLE_TO_IOC_TYPE[ot] ?? "unknown";
}

function scoreToSeverity(score: number): Severity {
  if (score >= 80) return "high";
  if (score >= 50) return "medium";
  if (score >= 30) return "low";
  return "info";
}

function entityToFinding(entity: IntelEntity): Finding {
  const finding: Finding = {
    id: newId("fnd"),
    severity: scoreToSeverity(entity.score),
    title: entity.title,
    detail: entity.summary,
    source: "/intel",
    iocs: entity.observables.map(observableToIoc),
  };
  return finding;
}

function observableToIoc(obs: Observable): IOC {
  const ioc: IOC = {
    value: obs.value,
    type: observableToIocType(obs.type),
    context: obs.context ?? obs.source,
    source: "/intel",
    severity: scoreToSeverity(0),
  };
  return ensureIocId(ioc);
}

export function getActiveCaseId(): string | null {
  try {
    return localStorage.getItem(LS_ACTIVE);
  } catch {
    return null;
  }
}

export function getAllCases() {
  return loadCases();
}

export function addIntelFindingToCase(
  caseId: string,
  entity: IntelEntity,
  note?: string,
): boolean {
  const list = loadCases();
  const idx = list.findIndex((c) => c.id === caseId);
  if (idx === -1) return false;

  const c = list[idx];
  const finding = entityToFinding(entity);

  const entryBody = note
    ? `## Intel Finding: ${entity.title}\n\n${entity.summary}\n\n**Note:** ${note}`
    : `## Intel Finding: ${entity.title}\n\n${entity.summary}`;

  const entry = {
    id: newId("e"),
    ts: new Date().toISOString(),
    kind: (finding.severity === "high" || finding.severity === "critical"
      ? "evidence"
      : "note") as "evidence" | "note",
    body: entryBody,
  };

  c.findings = [...(c.findings ?? []), finding];
  c.entries = [...c.entries, entry];
  saveCases(list);
  addEdge({
    relation: "creates",
    from: { kind: "entity", id: entity.id },
    to: { kind: "finding", id: finding.id },
    source: "/intel",
    confidence: entity.score / 100,
    reason: "analyst added intel finding to case",
  });
  return true;
}

export function addIntelObservablesToCase(
  caseId: string,
  entity: IntelEntity,
): boolean {
  const list = loadCases();
  const idx = list.findIndex((c) => c.id === caseId);
  if (idx === -1) return false;

  const c = list[idx];
  const iocs = entity.observables.map(observableToIoc);

  const body =
    iocs.length > 0
      ? `## IOCs from ${entity.title}\n\n${iocs
          .map((i) => `- \`${i.value}\` (${i.type})`)
          .join("\n")}`
      : "";

  if (!body) return true;

  c.entries = [
    ...c.entries,
    {
      id: newId("e"),
      ts: new Date().toISOString(),
      kind: "ioc",
      body,
    },
  ];
  c.iocs = [...(c.iocs ?? []), ...iocs];
  saveCases(list);
  for (const ioc of iocs) {
    addEdge({
      relation: "creates",
      from: { kind: "entity", id: entity.id },
      to: { kind: "ioc", id: ioc.id! },
      source: "/intel",
      confidence: entity.score / 100,
      reason: "entity observables added to case",
    });
  }
  return true;
}
