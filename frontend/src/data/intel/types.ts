/* ── Domain Types ────────────────────────────────────────── */

export type ObservableType =
  | "ipv4" | "ipv6" | "domain" | "url" | "email"
  | "sha256" | "sha1" | "md5" | "sha512"
  | "ja3" | "ja4"
  | "file" | "registry-key" | "process" | "mutex"
  | "cve" | "ua" | "text" | "unknown";

export interface Observable {
  id: string;
  type: ObservableType;
  value: string;
  source: string;
  timestamp: string;
  context?: string;
}

/* ── Intel Entity ───────────────────────────────────────── */

export type IntelEntityType =
  | "vulnerability"
  | "threat-actor"
  | "malware"
  | "file-hash"
  | "tls-fingerprint";

export type Confidence = "high" | "medium" | "low" | "unknown";

export interface IntelEntityBase {
  id: string;
  type: IntelEntityType;
  title: string;
  summary: string;
  score: number;
  confidence: Confidence;
  tags: string[];
  lastSeen?: string;
  observables: Observable[];
}

export interface VulnerabilityEntity extends IntelEntityBase {
  type: "vulnerability";
  cvss: number;
  epss: number;
  kev: boolean;
  exploits: { metasploit: boolean; nuclei: boolean; exploitDb: boolean };
  vendor: string;
  published: string;
  affected: string;
}

export interface ThreatActorEntity extends IntelEntityBase {
  type: "threat-actor";
  aliases: string[];
  origin: string;
  motivation: string;
  firstSeen: string;
  techniques: string[];
  campaigns: string[];
  tools: string[];
  targets: string[];
  targetedCves?: string[];
  observedInfrastructure?: { type: ObservableType; value: string; label?: string }[];
}

export interface MalwareEntity extends IntelEntityBase {
  type: "malware";
  aliases: string[];
  category: string;
  platforms: string[];
  firstSeen: string;
  capabilities: string[];
}

export interface FileHashEntity extends IntelEntityBase {
  type: "file-hash";
  hashType: "MD5" | "SHA1" | "SHA256" | "SHA512";
  hash: string;
  verdict: "malicious" | "suspicious";
  avDetections: number;
  avTotal: number;
  malware: string;
  firstSeen: string;
}

export interface TlsFingerprintEntity extends IntelEntityBase {
  type: "tls-fingerprint";
  hashType: "JA3" | "JA4";
  hash: string;
  malware: string;
  firstSeen: string;
  lastSeen: string;
}

export type IntelEntity =
  | VulnerabilityEntity
  | ThreatActorEntity
  | MalwareEntity
  | FileHashEntity
  | TlsFingerprintEntity;

/* ── Relationship ───────────────────────────────────────── */

export type RelationshipType =
  | "uses-tool"
  | "used-by"
  | "associated-with"
  | "linked-to"
  | "implements"
  | "resolves-to"
  | "originates-from"
  | "targets"
  | "targets-cve"
  | "exploited-by"
  | "matches-case-ioc"
  | "related-to";

export interface Relationship {
  sourceId: string;
  targetId: string;
  targetType: IntelEntityType;
  relationshipType: RelationshipType;
  confidence: Confidence;
  source: string;
  reason: string;
}

/* ── Lookup ─────────────────────────────────────────────── */

export interface LookupResultField {
  label: string;
  value: string;
}

export interface LookupResult {
  toolId: string;
  input: string;
  parsed: LookupResultField[];
  done: boolean;
}

export interface LookupTool {
  id: string;
  label: string;
  icon: string;
  description: string;
  detect: (input: string) => boolean;
  execute: (input: string) => LookupResult;
}

/* ── Enrichment ─────────────────────────────────────────── */

export interface EnrichmentResult {
  source: string;
  entityId: string;
  data: Record<string, unknown>;
  timestamp: string;
  error?: string;
}

export interface EnrichmentProvider {
  id: string;
  label: string;
  enrich: (entity: IntelEntity) => Promise<EnrichmentResult>;
}

/* ── Search ─────────────────────────────────────────────── */

export interface IntelEntityGroup {
  entityType: IntelEntityType;
  label: string;
  icon: string;
  count: number;
  entities: IntelEntity[];
}

export interface IntelSearchResult {
  query: string;
  detectedType?: ObservableType;
  totalHits: number;
  entityGroups: IntelEntityGroup[];
  relationships: Relationship[];
  lookups: LookupResult[];
}

/* ── Detail ─────────────────────────────────────────────── */

export interface IntelEntityDetail {
  entity: IntelEntity;
  overview: { label: string; value: string }[];
  observables: Observable[];
  relationships: Relationship[];
  mitre: { id: string; name: string }[];
  evidence: { source: string; label: string; value: string }[];
  timeline: { time: string; event: string }[];
  externalSources: { name: string; url: string }[];
}
