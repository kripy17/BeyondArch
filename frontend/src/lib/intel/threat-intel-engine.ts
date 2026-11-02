/**
 * Threat Intelligence & Adversary Profiling Engine
 * Implements Diamond Model construction, passive infrastructure generation,
 * STIX 2.1 intelligence bundle serialization, and IOC parsing.
 */

import type { ThreatActorEntity, ObservableType } from "@/data/intel/types";

export interface DiamondModel {
  adversary: {
    actor: string;
    motivation: string;
    origin: string;
    threatScore: number;
    countryFlag: string;
    sponsoringAgency?: string;
  };
  capability: {
    arsenal: string[];
    exploits: string[];
    tactics: string[];
  };
  infrastructure: {
    type: string;
    indicator: string;
    hostingProvider: string;
    coHostedCount: number;
    tlsProfile?: string;
  };
  victim: {
    targetedSectors: string[];
    geographies: string[];
    impactPotential: "Low" | "Medium" | "High" | "Critical";
  };
  confidence: "high" | "medium" | "low";
}

export interface PassiveDnsRecord {
  id: string;
  recordType: "A" | "AAAA" | "MX" | "NS" | "TXT" | "SOA";
  host: string;
  value: string;
  firstSeen: string;
  lastSeen: string;
  ttl: number;
  asn: string;
}

export interface WhoisData {
  domain: string;
  registrar: string;
  registeredDate: string;
  expiryDate: string;
  updatedDate: string;
  domainAgeDays: number;
  privacyProtected: boolean;
  registrantOrg: string;
  registrantCountry: string;
  nameservers: string[];
  status: string[];
}

export interface SslCertificateData {
  subjectCn: string;
  issuer: string;
  sanList: string[];
  validFrom: string;
  validUntil: string;
  ja3Fingerprint: string;
  ja3Hash: string;
  ja4Fingerprint: string;
  fingerprintSha256: string;
  serialNumber: string;
}

export interface CampaignRecord {
  id: string;
  name: string;
  timeRange: string;
  targets: string[];
  tools: string[];
  techniques: string[];
  outcome: string;
  active: boolean;
}

export const ORIGIN_FLAGS: Record<string, string> = {
  Russia: "🇷🇺",
  China: "🇨🇳",
  "North Korea": "🇰🇵",
  Iran: "🇮🇷",
  Western: "🌐",
  "Eastern Europe": "🇪🇺",
  Unknown: "🏴",
};

export const SPONSORING_AGENCIES: Record<string, string> = {
  APT28: "GRU 85th Main Special Service Center (Military Unit 26165)",
  APT29: "SVR Russian Foreign Intelligence Service",
  "Lazarus Group": "RGB Reconnaissance General Bureau (Lab 110 / Bureau 121)",
  APT41: "MSS Ministry of State Security (Chengdu 404 Network)",
  APT10: "MSS Tianjin State Security Bureau",
  Turla: "FSB Center 16 (Federal Security Service)",
  MuddyWater: "MOIS Iranian Ministry of Intelligence",
  APT33: "IRGC Aerospace Force Cyber Command",
  UNC1878: "Decentralized Cybercrime Syndicate (Scattered Spider / Muddled Libra)",
  FIN7: "Eastern European Cybercrime Syndicate (Carbanak / Navigator)",
};

/**
 * Generate a complete Diamond Model of Intrusion Analysis for a Threat Actor.
 */
export function generateDiamondModelForActor(actor: ThreatActorEntity): DiamondModel {
  const flag = ORIGIN_FLAGS[actor.origin] || "🏴";
  const agency = SPONSORING_AGENCIES[actor.title];
  const primaryObs = actor.observables[0]?.value || actor.title.toLowerCase() + "-c2.net";

  return {
    adversary: {
      actor: actor.title,
      motivation: actor.motivation,
      origin: actor.origin,
      threatScore: actor.score,
      countryFlag: flag,
      sponsoringAgency: agency,
    },
    capability: {
      arsenal: actor.tools.length > 0 ? actor.tools : ["Custom Stager", "Cobalt Strike"],
      exploits: actor.targetedCves && actor.targetedCves.length > 0 ? actor.targetedCves : ["Spearphishing Attachments", "Zero-Day Exploits"],
      tactics: ["Initial Access", "Execution", "Defense Evasion", "Command & Control"],
    },
    infrastructure: {
      type: actor.observables[0]?.type || "domain",
      indicator: primaryObs,
      hostingProvider: "Bulletproof VPS / Fast-Flux Relay",
      coHostedCount: actor.observables.length || 3,
      tlsProfile: "Let's Encrypt / Dynamic TLS",
    },
    victim: {
      targetedSectors: actor.targets.length > 0 ? actor.targets : ["Government", "Defense", "Energy"],
      geographies: ["North America", "European Union", "Asia-Pacific"],
      impactPotential: actor.score >= 90 ? "Critical" : actor.score >= 75 ? "High" : "Medium",
    },
    confidence: (actor.confidence === "high" || actor.confidence === "medium" || actor.confidence === "low")
      ? actor.confidence
      : "medium",
  };
}

/**
 * Generate chronological campaigns for a threat actor.
 */
export function generateActorCampaigns(actor: ThreatActorEntity): CampaignRecord[] {
  return actor.campaigns.map((camp, idx) => {
    const isRecent = idx === 0;
    const year = 2024 - idx * 2;
    return {
      id: `camp-${actor.id}-${idx}`,
      name: camp,
      timeRange: `${year} — ${isRecent ? "Ongoing" : year + 1}`,
      targets: actor.targets.slice(0, 3),
      tools: actor.tools.slice(0, 2),
      techniques: actor.techniques.slice(0, 3),
      outcome: isRecent ? "Active monitoring & threat hunting" : "Disrupted / Attributed by CTI",
      active: isRecent,
    };
  });
}

/**
 * Generate simulated or deterministic passive DNS records for a target.
 */
export function generatePassiveDnsRecords(target: string): PassiveDnsRecord[] {
  const clean = target.trim().toLowerCase();
  const isIp = clean.replace(/[.:]/g, "").split("").every((c) => "0123456789abcdef".includes(c));

  return [
    {
      id: "dns-1",
      recordType: "A",
      host: isIp ? `node-${clean.replace(/[.:]/g, "-")}.edge-cdn.org` : clean,
      value: isIp ? clean : "185.220.101.4",
      firstSeen: "2024-01-15T08:00:00Z",
      lastSeen: "2024-09-01T12:00:00Z",
      ttl: 300,
      asn: "AS200077 (SafeHost / Bulletproof)",
    },
    {
      id: "dns-2",
      recordType: "MX",
      host: clean,
      value: `mail.${clean}`,
      firstSeen: "2024-01-20T10:30:00Z",
      lastSeen: "2024-08-28T14:20:00Z",
      ttl: 3600,
      asn: "AS13335 (Cloudflare)",
    },
    {
      id: "dns-3",
      recordType: "NS",
      host: clean,
      value: "ns1.privacy-nameserver.net",
      firstSeen: "2024-01-10T00:00:00Z",
      lastSeen: "2024-09-02T18:00:00Z",
      ttl: 86400,
      asn: "AS16509 (Amazon AWS)",
    },
    {
      id: "dns-4",
      recordType: "TXT",
      host: clean,
      value: "v=spf1 include:_spf.google.com ~all",
      firstSeen: "2024-02-01T14:00:00Z",
      lastSeen: "2024-08-30T11:00:00Z",
      ttl: 3600,
      asn: "AS15169 (Google)",
    },
  ];
}

/**
 * Generate WHOIS registration data for domain.
 */
export function generateWhoisData(domain: string): WhoisData {
  const dom = domain.trim().toLowerCase();
  return {
    domain: dom,
    registrar: "NameCheap Inc. / Porkbun LLC",
    registeredDate: "2023-11-14T10:20:00Z",
    expiryDate: "2025-11-14T10:20:00Z",
    updatedDate: "2024-05-18T08:15:00Z",
    domainAgeDays: 295,
    privacyProtected: true,
    registrantOrg: "Withheld for Privacy Purpose",
    registrantCountry: "IS (Iceland)",
    nameservers: ["ns1.privacy-nameserver.net", "ns2.privacy-nameserver.net"],
    status: ["clientTransferProhibited", "clientUpdateProhibited"],
  };
}

/**
 * Generate passive SSL/TLS certificate profile.
 */
export function generateSslCertData(domain: string): SslCertificateData {
  const dom = domain.trim().toLowerCase();
  return {
    subjectCn: dom,
    issuer: "Let's Encrypt Authority X3",
    sanList: [dom, `www.${dom}`, `api.${dom}`, `auth.${dom}`],
    validFrom: "2024-06-01T00:00:00Z",
    validUntil: "2024-09-01T23:59:59Z",
    ja3Fingerprint: "771,4865-4866-4867-49195,0-23-65281-10-11,29-23-24,0",
    ja3Hash: "a0e9f5d64349fb13191bc781f81f42e1",
    ja4Fingerprint: "t13d1516h2_8daaf6152771_b756148c48a8",
    fingerprintSha256: "4a72e811c0807b5a19842886f4a8b79b2938e55c6d3fa96ef4c5496b0f1a6f02",
    serialNumber: "03:9A:8B:E7:F4:11:4C:90",
  };
}

/**
 * Build a valid STIX 2.1 intelligence bundle for an entity or threat actor.
 */
export function buildStix21Bundle(entity: {
  title: string;
  type: string;
  observables?: { type: ObservableType; value: string; context?: string }[];
  summary?: string;
  techniques?: string[];
}) {
  const now = new Date().toISOString();
  const baseId = entity.title.toLowerCase().replace(/[^a-z0-9]/g, "-");
  const bundleId = `bundle--${baseId}-${Date.now()}`;
  const actorId = `threat-actor--${baseId}`;

  const objects: any[] = [
    {
      type: entity.type === "threat-actor" ? "threat-actor" : "identity",
      spec_version: "2.1",
      id: actorId,
      created: now,
      modified: now,
      name: entity.title,
      description: entity.summary || `Intelligence dossier for ${entity.title}`,
      confidence: 85,
    },
  ];

  // Map observables into STIX indicators & relationships
  if (entity.observables && entity.observables.length > 0) {
    entity.observables.forEach((obs, idx) => {
      const indId = `indicator--${baseId}-ioc-${idx}`;
      const patternMap: Record<string, string> = {
        ipv4: `[ipv4-addr:value = '${obs.value}']`,
        ipv6: `[ipv6-addr:value = '${obs.value}']`,
        domain: `[domain-name:value = '${obs.value}']`,
        url: `[url:value = '${obs.value}']`,
        sha256: `[file:hashes.'SHA-256' = '${obs.value}']`,
        md5: `[file:hashes.MD5 = '${obs.value}']`,
      };

      const pattern = patternMap[obs.type] || `[x-observable:value = '${obs.value}']`;

      objects.push({
        type: "indicator",
        spec_version: "2.1",
        id: indId,
        created: now,
        modified: now,
        name: `${obs.type.toUpperCase()}: ${obs.value}`,
        pattern,
        pattern_type: "stix",
        valid_from: now,
        indicator_types: ["malicious-activity"],
      });

      objects.push({
        type: "relationship",
        spec_version: "2.1",
        id: `relationship--${baseId}-rel-${idx}`,
        created: now,
        modified: now,
        relationship_type: "indicates",
        source_ref: indId,
        target_ref: actorId,
      });
    });
  }

  // Map techniques into STIX attack-pattern objects
  if (entity.techniques && entity.techniques.length > 0) {
    entity.techniques.forEach((techId) => {
      const apId = `attack-pattern--${techId.toLowerCase()}`;
      objects.push({
        type: "attack-pattern",
        spec_version: "2.1",
        id: apId,
        created: now,
        modified: now,
        name: `MITRE ATT&CK ${techId}`,
        external_references: [
          {
            source_name: "mitre-attack",
            external_id: techId,
            url: `https://attack.mitre.org/techniques/${techId}`,
          },
        ],
      });

      objects.push({
        type: "relationship",
        spec_version: "2.1",
        id: `relationship--${actorId}-${techId.toLowerCase()}`,
        created: now,
        modified: now,
        relationship_type: "uses",
        source_ref: actorId,
        target_ref: apId,
      });
    });
  }

  return {
    type: "bundle",
    id: bundleId,
    spec_version: "2.1",
    objects,
  };
}

/**
 * Trigger browser download of STIX 2.1 JSON file.
 */
export function exportStix21Json(bundle: any, filename: string) {
  const jsonStr = JSON.stringify(bundle, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename.endsWith(".json") ? filename : `${filename}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
