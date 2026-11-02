import type { ObservableType, IntelEntity, IntelSearchResult, IntelEntityGroup } from "./types";
import { ALL_ENTITIES } from "./sources";

export type { ObservableType, IntelSearchResult, IntelEntityGroup };

const ENTITY_LABELS: Record<string, { label: string; icon: string }> = {
  vulnerability: { label: "Vulnerabilities", icon: "ShieldAlert" },
  "threat-actor": { label: "Threat Actors", icon: "Users" },
  malware: { label: "Malware", icon: "Bug" },
  "file-hash": { label: "File Hashes", icon: "Hash" },
  "tls-fingerprint": { label: "TLS Fingerprints", icon: "Fingerprint" },
};

/* ── Pattern detection ──────────────────────────────────── */

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const JA3_RE = /^[a-f0-9]{32}$/i;
const JA4_RE = /^ja4_[a-f0-9]+$/i;
const MD5_RE = /^[a-f0-9]{32}$/i;
const SHA1_RE = /^[a-f0-9]{40}$/i;
const SHA256_RE = /^[a-f0-9]{64}$/i;
const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function detectObservableType(input: string): ObservableType | undefined {
  const s = input.trim();
  if (CVE_RE.test(s)) return "cve";
  if (JA4_RE.test(s)) return "ja4";
  if (JA3_RE.test(s)) return "ja3";
  if (SHA256_RE.test(s)) return "sha256";
  if (SHA1_RE.test(s)) return "sha1";
  if (MD5_RE.test(s)) return "md5";
  if (IPV4_RE.test(s)) return "ipv4";
  if (DOMAIN_RE.test(s)) return "domain";
  if (EMAIL_RE.test(s)) return "email";
  return undefined;
}

/* ── Scoring ────────────────────────────────────────────── */

function scoreQuery(
  entity: IntelEntity,
  query: string,
): number {
  const q = query.toLowerCase();
  let score = 0;

  if (entity.title.toLowerCase().includes(q)) score += 50;
  if (entity.summary.toLowerCase().includes(q)) score += 20;

  if (entity.tags.some((t) => t.includes(q))) score += 10;

  for (const obs of entity.observables) {
    const v = obs.value.toLowerCase();
    if (v === q) score += 60;
    else if (v.includes(q)) score += 35;
  }

  if (entity.type === "threat-actor") {
    const a = entity as import("./types").ThreatActorEntity;
    if (a.aliases.some((al) => al.toLowerCase().includes(q))) score += 30;
    if (a.tools.some((t) => t.toLowerCase().includes(q))) score += 15;
    if (a.campaigns.some((c) => c.toLowerCase().includes(q))) score += 15;
    if (a.targets.some((t) => t.toLowerCase().includes(q))) score += 10;
    if (a.techniques.some((t) => t.toLowerCase().includes(q))) score += 10;
    if (a.targetedCves?.some((cve) => cve.toLowerCase().includes(q))) score += 25;
  }

  if (entity.type === "vulnerability") {
    const v = entity as import("./types").VulnerabilityEntity;
    if (v.vendor.toLowerCase().includes(q)) score += 15;
    if (v.affected.toLowerCase().includes(q)) score += 10;
  }

  if (entity.type === "malware") {
    const m = entity as import("./types").MalwareEntity;
    if (m.aliases.some((al) => al.toLowerCase().includes(q))) score += 20;
  }

  if (entity.type === "tls-fingerprint") {
    const t = entity as import("./types").TlsFingerprintEntity;
    if (t.malware.toLowerCase().includes(q)) score += 30;
  }

  if (entity.type === "file-hash") {
    const h = entity as import("./types").FileHashEntity;
    if (h.malware.toLowerCase().includes(q)) score += 30;
  }

  return score;
}

/* ── Search ─────────────────────────────────────────────── */

export function searchIntel(query: string): IntelSearchResult {
  const q = query.trim();
  if (!q) {
    return {
      query: q,
      totalHits: 0,
      entityGroups: [],
      relationships: [],
      lookups: [],
    };
  }

  const detectedType = detectObservableType(q);

  const scored = ALL_ENTITIES
    .map((entity) => ({ entity, score: scoreQuery(entity, q) }))
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score);

  const groupsMap = new Map<string, IntelEntity[]>();

  for (const { entity } of scored) {
    const key = entity.type;
    if (!groupsMap.has(key)) groupsMap.set(key, []);
    groupsMap.get(key)!.push(entity);
  }

  const entityGroups: IntelEntityGroup[] = [];
  for (const [entityType, entities] of groupsMap) {
    const meta = ENTITY_LABELS[entityType];
    entityGroups.push({
      entityType: entityType as any,
      label: meta?.label ?? entityType,
      icon: meta?.icon ?? "FileSearch",
      count: entities.length,
      entities,
    });
  }

  /* Sort groups: highest average score first */
  entityGroups.sort((a, b) => {
    const avgA = a.entities.reduce((s, e) => s + e.score, 0) / a.entities.length;
    const avgB = b.entities.reduce((s, e) => s + e.score, 0) / b.entities.length;
    return avgB - avgA;
  });

  const totalHits = scored.length;

  return {
    query: q,
    detectedType,
    totalHits,
    entityGroups,
    relationships: [],
    lookups: [],
  };
}

/* ── Get single entity ──────────────────────────────────── */

export function getEntityById(id: string): IntelEntity | undefined {
  return ALL_ENTITIES.find((e) => e.id === id);
}
