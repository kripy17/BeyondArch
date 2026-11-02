import { getThreatActors, type ThreatActorEntity, TLS_FINGERPRINTS, MALWARE } from "@/data/intel";
import { TACTICS } from "@/data/mitre";
import { type IOC } from "@/types/security";
import { type Case } from "@/data/case";

export interface MatchedTechniqueInfo {
  id: string;
  name: string;
  tactic: string;
  tacticId: string;
}

export interface AttributionMatchEvidence {
  matchedIocs: { value: string; type: string; label: string }[];
  matchedTechniques: MatchedTechniqueInfo[];
  matchedTools: string[];
  matchedTargeting: boolean;
  targetSectorName?: string;
  c2Alignment: string | null;
}

export interface ThreatActorCandidate {
  actor: ThreatActorEntity;
  confidenceScore: number; // 0 to 100
  confidenceLevel: "High Confidence" | "Probable" | "Plausible" | "Low";
  confidenceTone: "destructive" | "warning" | "primary" | "default";
  evidence: AttributionMatchEvidence;
  primaryVector: string;
}

export interface AttributionReport {
  primaryCandidate: ThreatActorCandidate | null;
  rankedCandidates: ThreatActorCandidate[];
  inputObservablesCount: number;
  inputTechniquesCount: number;
  generatedAt: string;
}

export interface C2ProfileInput {
  ja3?: string;
  ja4?: string;
  serverIp?: string;
  port?: number;
  beaconIntervalSec?: number;
  jitterPct?: number;
  domain?: string;
  payloadHash?: string;
  observedStrings?: string[];
}

export interface C2ProfileResult {
  framework: "Cobalt Strike" | "Sliver" | "Brute Ratel C4" | "Havoc" | "Mythic" | "PlugX RAT" | "Generic / Custom";
  confidence: number;
  profileType: "TLS JA3/JA4 Fingerprint" | "Heuristic Cadence" | "Artifact Signature" | "Multi-Vector";
  detectedJa3: string | null;
  detectedJa4: string | null;
  meanIntervalSec: number | null;
  jitterPct: number | null;
  killChainPhase: string;
  evasionScore: number; // 0 to 100
  recommendedMitigations: string[];
  sigmaRuleMatches: string[];
}

/** Lookup technique name and tactic from Mitre dataset */
export function lookupTechniqueMeta(techId: string): MatchedTechniqueInfo {
  const norm = techId.trim().toUpperCase();
  for (const t of TACTICS) {
    const found = t.techniques.find((tech) => tech.id === norm || tech.id === norm.split(".")[0]);
    if (found) {
      return {
        id: norm,
        name: found.name,
        tactic: t.name,
        tacticId: t.id,
      };
    }
  }
  return {
    id: norm,
    name: "Unknown Technique",
    tactic: "Execution",
    tacticId: "TA0002",
  };
}

/**
 * Perform deep heuristic and observable correlation to attribute an attack to known threat actors.
 */
export function calculateAdversaryAttribution(
  observables: IOC[] = [],
  techniques: string[] = [],
  targetedIndustry?: string
): AttributionReport {
  const allActors = getThreatActors();
  const inputIocValues = new Set(observables.map((i) => i.value.toLowerCase().trim()));
  const inputTechSet = new Set(techniques.map((t) => t.toUpperCase().trim()));

  const candidates: ThreatActorCandidate[] = [];

  for (const actor of allActors) {
    let score = 0;
    const matchedIocs: AttributionMatchEvidence["matchedIocs"] = [];
    const matchedTechniques: MatchedTechniqueInfo[] = [];
    const matchedTools: string[] = [];
    let matchedTargeting = false;

    // 1. Observable Infrastructure Matching (Up to 45 pts)
    for (const infra of actor.observedInfrastructure || []) {
      if (inputIocValues.has(infra.value.toLowerCase().trim())) {
        matchedIocs.push({
          value: infra.value,
          type: infra.type,
          label: infra.label || "Known threat actor C2/staging infrastructure",
        });
        score += 35; // Direct infrastructure match is high fidelity
      }
    }

    // 2. MITRE Technique (TTP) Overlap (Up to 35 pts)
    const actorTechs = (actor.techniques || []).map((t) => t.toUpperCase().trim());
    const sharedTechs = actorTechs.filter((t) => {
      if (inputTechSet.has(t)) return true;
      // Also match base technique if sub-technique provided (e.g. T1059 matches T1059.001)
      const base = t.split(".")[0];
      return Array.from(inputTechSet).some((it) => it.startsWith(base));
    });

    for (const st of sharedTechs) {
      matchedTechniques.push(lookupTechniqueMeta(st));
    }

    if (actorTechs.length > 0 && inputTechSet.size > 0) {
      const overlapRatio = sharedTechs.length / Math.max(inputTechSet.size, 1);
      score += Math.min(Math.round(overlapRatio * 40), 35);
    }

    // 3. Tool & Malware Overlap (Up to 20 pts)
    const actorTools = (actor.tools || []).map((t) => t.toLowerCase());
    for (const ioc of observables) {
      const val = ioc.value.toLowerCase();
      const ctx = (ioc.context || "").toLowerCase();
      for (const tool of actorTools) {
        if (val.includes(tool) || ctx.includes(tool)) {
          if (!matchedTools.includes(tool)) {
            matchedTools.push(tool);
            score += 15;
          }
        }
      }
    }

    // 4. Target Industry Alignment (Up to 10 pts)
    if (targetedIndustry) {
      const normInd = targetedIndustry.toLowerCase();
      const actorTargets = (actor.targets || []).map((tgt) => tgt.toLowerCase());
      if (actorTargets.some((tgt) => normInd.includes(tgt) || tgt.includes(normInd))) {
        matchedTargeting = true;
        score += 10;
      }
    }

    // Baseline minimum if techniques matched
    if (matchedTechniques.length >= 3 && score < 30) {
      score = 30;
    }

    const finalScore = Math.min(Math.max(score, 5), 98);

    let confidenceLevel: ThreatActorCandidate["confidenceLevel"] = "Low";
    let confidenceTone: ThreatActorCandidate["confidenceTone"] = "default";

    if (finalScore >= 70 || matchedIocs.length > 0) {
      confidenceLevel = "High Confidence";
      confidenceTone = "destructive";
    } else if (finalScore >= 45) {
      confidenceLevel = "Probable";
      confidenceTone = "warning";
    } else if (finalScore >= 25) {
      confidenceLevel = "Plausible";
      confidenceTone = "primary";
    }

    const primaryVector =
      actor.campaigns && actor.campaigns.length > 0
        ? actor.campaigns[0]
        : `${actor.origin || "Unknown"} Advanced Persistent Threat`;

    candidates.push({
      actor,
      confidenceScore: finalScore,
      confidenceLevel,
      confidenceTone,
      evidence: {
        matchedIocs,
        matchedTechniques,
        matchedTools,
        matchedTargeting,
        targetSectorName: targetedIndustry,
        c2Alignment: actor.tools?.find((t) => t.toLowerCase().includes("strike") || t.toLowerCase().includes("sliver")) || null,
      },
      primaryVector,
    });
  }

  candidates.sort((a, b) => b.confidenceScore - a.confidenceScore);

  const primaryCandidate = candidates.length > 0 && candidates[0].confidenceScore >= 20 ? candidates[0] : null;

  return {
    primaryCandidate,
    rankedCandidates: candidates.slice(0, 6),
    inputObservablesCount: observables.length,
    inputTechniquesCount: techniques.length,
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Profile C2 communication patterns, TLS fingerprints, and beacon cadence.
 */
export function profileC2Traffic(input: C2ProfileInput): C2ProfileResult {
  const { ja3, ja4, beaconIntervalSec = 30, jitterPct = 5, observedStrings = [] } = input;

  let framework: C2ProfileResult["framework"] = "Generic / Custom";
  let confidence = 40;
  let profileType: C2ProfileResult["profileType"] = "Heuristic Cadence";
  let detectedJa3: string | null = ja3 || null;
  let detectedJa4: string | null = ja4 || null;
  let evasionScore = 50;

  // Check known JA3/JA4 database
  if (ja3) {
    const known = TLS_FINGERPRINTS.find((f) => f.hash.toLowerCase() === ja3.toLowerCase());
    if (known) {
      detectedJa3 = ja3;
      profileType = "TLS JA3/JA4 Fingerprint";
      confidence = 88;
      if (known.malware?.toLowerCase().includes("cobalt")) framework = "Cobalt Strike";
      else if (known.malware?.toLowerCase().includes("sliver")) framework = "Sliver";
      else if (known.malware?.toLowerCase().includes("plugx")) framework = "PlugX RAT";
    }
  }

  if (ja4) {
    const known4 = TLS_FINGERPRINTS.find((f) => f.hash.toLowerCase() === ja4.toLowerCase());
    if (known4) {
      detectedJa4 = ja4;
      profileType = "TLS JA3/JA4 Fingerprint";
      confidence = 92;
      if (known4.malware?.toLowerCase().includes("sliver")) framework = "Sliver";
      else if (known4.malware?.toLowerCase().includes("brute ratel")) framework = "Brute Ratel C4";
      else if (known4.malware?.toLowerCase().includes("cobalt")) framework = "Cobalt Strike";
    }
  }

  // Check text signatures
  const joinedStrings = observedStrings.join(" ").toLowerCase();
  if (joinedStrings.includes("beacon") || joinedStrings.includes("cobaltstrike") || joinedStrings.includes("c2_profile")) {
    framework = "Cobalt Strike";
    confidence = Math.max(confidence, 85);
    profileType = "Artifact Signature";
    evasionScore = 78;
  } else if (joinedStrings.includes("sliver") || joinedStrings.includes("mtls") || joinedStrings.includes("wireguard")) {
    framework = "Sliver";
    confidence = Math.max(confidence, 80);
    profileType = "Artifact Signature";
    evasionScore = 82;
  }

  // Beaconing heuristic
  if (beaconIntervalSec > 0 && jitterPct <= 15) {
    evasionScore += 10;
  }

  return {
    framework,
    confidence,
    profileType,
    detectedJa3,
    detectedJa4,
    meanIntervalSec: beaconIntervalSec,
    jitterPct,
    killChainPhase: "Command and Control (TA0011)",
    evasionScore: Math.min(evasionScore, 95),
    recommendedMitigations: [
      `Deploy Suricata SID rule for ${framework} TLS negotiation handshake`,
      "Apply border firewall egress block on port 443 destination IP",
      "Isolate endpoint process via Microsoft Defender EDR API",
      "Inspect memory space for reflective DLL injection (VirtualAllocEx)",
    ],
    sigmaRuleMatches: [
      `proc_creation_win_susp_${framework.toLowerCase().replace(/[^a-z0-9]+/g, "_")}_staging.yml`,
      "net_connection_win_c2_periodic_beaconing.yml",
      "tls_susp_ja3_fingerprint_handshake.yml",
    ],
  };
}

/**
 * Automatically attributes an active case by extracting its IOCs and findings.
 */
export function attributeActiveCase(c: Case): AttributionReport {
  const iocs = c.iocs || [];
  const techniques: string[] = [];

  // Extract techniques from findings and entries
  for (const f of c.findings || []) {
    if (f.technique) techniques.push(f.technique);
    const m = (f.detail || "").match(/T\d{4}(?:\.\d{3})?/gi);
    if (m) techniques.push(...m);
  }

  for (const e of c.entries || []) {
    const m = (e.body || "").match(/T\d{4}(?:\.\d{3})?/gi);
    if (m) techniques.push(...m);
  }

  for (const ev of c.events || []) {
    const m = `${ev.title} ${ev.detail}`.match(/T\d{4}(?:\.\d{3})?/gi);
    if (m) techniques.push(...m);
  }

  // Look for target sector in tags
  const tags = (c.tags || []).join(" ").toLowerCase();
  let industry: string | undefined;
  if (tags.includes("finance") || tags.includes("banking")) industry = "Financial";
  else if (tags.includes("energy") || tags.includes("water")) industry = "Energy";
  else if (tags.includes("health") || tags.includes("hospital")) industry = "Healthcare";
  else if (tags.includes("gov") || tags.includes("defense")) industry = "Government";

  return calculateAdversaryAttribution(iocs, techniques, industry);
}

/**
 * Generate formatted Markdown report for adversary attribution.
 */
export function generateAttributionMarkdown(
  report: AttributionReport,
  c2Profile?: C2ProfileResult
): string {
  const { primaryCandidate, rankedCandidates, generatedAt } = report;

  if (!primaryCandidate) {
    return "# THREAT ACTOR ATTRIBUTION REPORT\n*Status: Insufficient IOC telemetry for definitive attribution.*\n";
  }

  const { actor, confidenceScore, confidenceLevel, evidence, primaryVector } = primaryCandidate;

  return `# THREAT ACTOR ATTRIBUTION & C2 PROFILE DOSSIER
**BeyondArch Threat Intelligence & Attribution Engine**
*Generated: ${new Date(generatedAt).toUTCString()}*

---

### Primary Attributed Adversary: **${actor.title}** (${confidenceScore}% Confidence · ${confidenceLevel})
- **Origin / Nation-State:** ${actor.origin || "Unknown"}
- **Primary Motivation:** ${actor.motivation || "Espionage"}
- **Known Aliases:** ${(actor.aliases || []).join(", ") || "None"}
- **Primary Campaign:** ${primaryVector}

---

## 1. Attribution Evidence Matrix
- **Observed Infrastructure Matches:** ${evidence.matchedIocs.length}
${
  evidence.matchedIocs.length > 0
    ? evidence.matchedIocs.map((i) => `  - \`${i.type}\`: \`${i.value}\` (${i.label})`).join("\n")
    : "  - _No direct IP/domain infrastructure overlap._"
}
- **Shared MITRE ATT&CK TTPs:** ${evidence.matchedTechniques.length}
${
  evidence.matchedTechniques.length > 0
    ? evidence.matchedTechniques.map((t) => `  - **${t.id}** (${t.name}) — *${t.tactic}*`).join("\n")
    : "  - _No technique overlap identified._"
}
- **Common Tooling & Malware:** ${evidence.matchedTools.join(", ") || "Generic LOLBAS"}
- **Target Sector Alignment:** ${evidence.matchedTargeting ? `MATCHED (${evidence.targetSectorName})` : "Broad Enterprise"}

${
  c2Profile
    ? `---

## 2. Command & Control (C2) Architecture Profiling
- **Detected C2 Framework:** \`${c2Profile.framework}\` (${c2Profile.confidence}% confidence)
- **Profile Method:** ${c2Profile.profileType}
- **JA3 Fingerprint:** \`${c2Profile.detectedJa3 || "N/A"}\`
- **JA4 Fingerprint:** \`${c2Profile.detectedJa4 || "N/A"}\`
- **Beacon Interval / Jitter:** \`${c2Profile.meanIntervalSec}s\` (${c2Profile.jitterPct}% jitter)
- **Evasion Score:** \`${c2Profile.evasionScore} / 100\`

### Recommended Defensive Mitigations:
${c2Profile.recommendedMitigations.map((m) => `- ${m}`).join("\n")}
`
    : ""
}

---

## 3. Alternative Threat Actor Contenders
| Actor | Origin | Confidence | Overlap Highlights |
|---|---|---|---|
${rankedCandidates
  .map(
    (c) =>
      `| **${c.actor.title}** | ${c.actor.origin} | \`${c.confidenceScore}%\` | ${c.evidence.matchedTechniques.length} TTPs, ${c.evidence.matchedIocs.length} IOCs |`
  )
  .join("\n")}
`;
}
