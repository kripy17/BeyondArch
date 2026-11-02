import type { Severity } from "@/lib/severity";
import type { NodeRef, ProvenanceRelation } from "@/lib/provenance";

/**
 * Canonical Investigation Objects (INVESTIGATION_OBJECTS.md, frozen 2026-08-07).
 * Pure contract layer: no UI deps, no stores, no logic. Existing analyzers still
 * use `types/security.ts` until the analyzer migration step; these are the v1
 * objects the Analysis Engine will produce and every consumer will read.
 *
 * Invariants (contract §1):
 * - deterministic identity (never write-time `crypto.randomUUID()`)
 * - immutable after creation; evolution via new objects + supersession edges
 * - no presentation fields (color/layout/ordering) — Analysis never stores UI state
 * - every conclusion carries a confidence explanation + evidence reference
 * - every object carries a schema version for storage migrations
 */

export const INVESTIGATION_OBJECTS_V1 = 1;

/** Object envelope schema version (frozen §17). */
export type SchemaVersion = typeof INVESTIGATION_OBJECTS_V1;

/* ── §3 Artifact ───────────────────────────────────────────── */

export type ArtifactKind = "email" | "file" | "pcap" | "log" | "url" | "text";

export interface Artifact {
  id: string;
  kind: ArtifactKind;
  title: string;
  raw?: string;
  metadata: Record<string, string>;
  created: string;
  schemaVersion: SchemaVersion;
}

/* ── §4 Observation ────────────────────────────────────────── */

export type ObservationKind =
  | "url" | "url-part" | "domain" | "ip" | "hash" | "email" | "header" | "string"
  | "file" | "macro" | "import" | "registry-key" | "process" | "command" | "user-agent"
  | "ja3" | "certificate" | "dns" | "asn" | "mutex" | "unknown";

export interface Observation {
  /** deterministic: fnv1a(`observation|kind|value`) — re-assertions reconnect, never duplicate */
  id: string;
  kind: ObservationKind;
  value: string;
  meta: Record<string, string>;
  source: string;
  ts: string;
  schemaVersion: SchemaVersion;
}

/* ── §4 Evidence ───────────────────────────────────────────── */

export interface Evidence {
  id: string;
  artifact: Artifact;
  observations: Observation[];
  findings: Finding[];
  iocs: IOC[];
  notes: string;
  created: string;
  schemaVersion: SchemaVersion;
}

/* ── §6 Finding ────────────────────────────────────────────── */

export interface ConfidenceExplanation {
  level: "high" | "medium" | "low" | "unknown";
  contributors: string[];
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  source: string;
  technique?: string;
  observations?: Observation[];
  iocs?: IOC[];
  confidence?: ConfidenceExplanation;
  schemaVersion: SchemaVersion;
}

/* ── §7 IOC / Observable ───────────────────────────────────── */

export type IocType = "ipv4" | "ipv6" | "domain" | "url" | "md5" | "sha1" | "sha256" | "email" | "cve" | "ja3" | "ua" | "unknown";

export interface IOC {
  id: string;
  value: string;
  type: IocType;
  context: string;
  source: string;
  severity: Severity;
  schemaVersion: SchemaVersion;
}

/* ── §8 Entity ─────────────────────────────────────────────── */

export type EntityKind = "actor" | "campaign" | "malware" | "infrastructure" | "organization" | "tool" | "unknown";

export interface Entity {
  id: string;
  name: string;
  kind: EntityKind;
  aliases: string[];
  attributes: Record<string, string>;
  confidence?: ConfidenceExplanation;
  source: string;
  observables: string[];
  schemaVersion: SchemaVersion;
}

/* ── §9 Technique ──────────────────────────────────────────── */

export interface Technique {
  id: string;
  name: string;
  tactic: string;
  source: string;
  schemaVersion: SchemaVersion;
}

/* ── §10 Relationship ──────────────────────────────────────── */

export type RelationshipOrigin = "extraction" | "analysis" | "correlation" | "backfill" | "analyst";

export interface Relationship {
  id: string;
  relation: ProvenanceRelation;
  from: NodeRef;
  to: NodeRef;
  confidence?: number;
  evidenceRefs: string[];
  origin: RelationshipOrigin;
  source: string;
  ts: string;
  schemaVersion: SchemaVersion;
}

/* ── §11 DetectionOpportunity ──────────────────────────────── */

export type RuleFormat = "sigma" | "yara" | "kql";

export interface DetectionOpportunity {
  id: string;
  technique: string;
  behavior: string;
  coverage: "detected" | "gap" | "unknown";
  existingRule?: string;
  suggestedRule?: { fmt: RuleFormat; name: string; draft: string };
  suggestedHunt?: string;
  priority: "low" | "medium" | "high";
  confidence?: number;
  status: "open" | "dismissed" | "rule-created";
  schemaVersion: SchemaVersion;
}

/* ── §12 Recommendation ────────────────────────────────────── */

export type RecommendationKind =
  | "enrich-ioc" | "create-rule" | "generate-report" | "attach-evidence"
  | "add-mitre" | "close" | "collect-logs" | "next-step";

export interface Recommendation {
  id: string;
  kind: RecommendationKind;
  priority: "low" | "medium" | "high";
  statement: string;
  reason: string;
  evidenceRefs: string[];
  confidence?: number;
  target?: { route: string } | { kind: NodeRef["kind"]; id: string };
  status: "open" | "dismissed" | "done";
  schemaVersion: SchemaVersion;
}

/* ── §13 Decision ──────────────────────────────────────────── */

export interface Decision {
  id: string;
  caseId: string;
  conclusion: string;
  confidenceRef: string;
  options: string[];
  chosen: string;
  reason: string;
  ts: string;
  schemaVersion: SchemaVersion;
}

/* ── §14 TimelineEvent ─────────────────────────────────────── */

export type TimelineKind =
  | "analysis" | "finding" | "ioc" | "note" | "action" | "decision"
  | "status" | "detection" | "intel" | "system";

export interface TimelineEvent {
  id: string;
  kind: TimelineKind;
  ts: string;
  title: string;
  detail: string;
  source: string;
  references: NodeRef[];
  schemaVersion: SchemaVersion;
}

/* ── §15 AnalysisQuality ───────────────────────────────────── */

export interface AnalysisQuality {
  coverage: { score: number; gaps: string[] };
  confidence?: number;
  weakSignals: string[];
  conflictingSignals: string[];
  recommendedNextStep: string;
  missing: string[];
  notes: string[];
  schemaVersion: SchemaVersion;
}

/* ── §16 transitional — AnalysisSummary kept until migration ─ */