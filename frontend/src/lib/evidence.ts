import type { Case, CaseEvent } from "@/data/case";
import { addCaseEvent, ensureEvidenceId } from "@/data/case";
import type { EvidenceItem } from "@/types/analysis";

export const EVIDENCE_TYPES = ["log", "file", "email", "pcap", "url", "screenshot", "note", "other"] as const;
export type EvidenceType = (typeof EVIDENCE_TYPES)[number];

export type EvidenceInput = {
  type: string;
  title: string;
  detail: string;
  source: string;
};

/** Normalizes intake input into a stable-id EvidenceItem. Trims all fields; empty source becomes "manual". */
export function createEvidenceItem(input: EvidenceInput): EvidenceItem {
  return ensureEvidenceId({
    type: EVIDENCE_TYPES.includes(input.type as EvidenceType) ? input.type : "other",
    title: input.title.trim(),
    detail: input.detail.trim(),
    source: input.source.trim() || "manual",
  });
}

/** Same normalized id ⇒ same evidence. Prevents accidental double-filing. */
export function findDuplicateEvidence(items: EvidenceItem[], candidate: EvidenceItem): EvidenceItem | null {
  return items.find((e) => e.id === candidate.id) ?? null;
}

export function appendEvidence(c: Case, item: EvidenceItem): Case {
  const event: CaseEvent = {
    id: `evt-${crypto.randomUUID().slice(0, 8)}`,
    ts: new Date().toISOString(),
    kind: "analyst_action",
    category: "artifact",
    importance: "normal",
    actor: "analyst",
    origin: "/case evidence-intake",
    title: `Evidence filed: ${item.title}`,
    detail: item.detail,
    references: [{ kind: "evidence", id: item.id! }],
  };
  return addCaseEvent({ ...c, evidenceItems: [...(c.evidenceItems ?? []), item] }, event);
}

/**
 * Edges implied by an intake submission. `artifactId` produces artifact→evidence
 * ("produced"); `findingId` produces evidence→finding ("supports"). Pure — the
 * caller persists them via addEdge.
 */
export function evidenceLinks(item: EvidenceItem, links: { artifactId?: string; findingId?: string }): { relation: "produced" | "supports"; from: { kind: "artifact" | "evidence"; id: string }; to: { kind: "evidence" | "finding"; id: string } }[] {
  const out: { relation: "produced" | "supports"; from: { kind: "artifact" | "evidence"; id: string }; to: { kind: "evidence" | "finding"; id: string } }[] = [];
  if (links.artifactId) out.push({ relation: "produced", from: { kind: "artifact", id: links.artifactId }, to: { kind: "evidence", id: item.id! } });
  if (links.findingId) out.push({ relation: "supports", from: { kind: "evidence", id: item.id! }, to: { kind: "finding", id: links.findingId } });
  return out;
}
