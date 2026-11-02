import { objectId } from "@/lib/ids";
import type { DetectionOpportunity, Finding } from "@/types/objects";
import { INVESTIGATION_OBJECTS_V1 } from "@/types/objects";

/**
 * Detection Opportunities (ANALYSIS_ENGINE §5, module 7).
 * First-class output: behavior → technique → coverage (existing rule?) →
 * suggested rule (Sigma scaffold) + suggested hunt. Rule lookup is injected —
 * modules never read storage directly (ANALYSIS_ENGINE §4d).
 */

export interface OpportunityContext {
  /** injected store query: returns the name of a rule already covering a technique */
  lookupRule?: (technique: string) => string | undefined;
}

export const HUNTS: Record<string, string> = {
  "T1059.001": "Query the PowerShell Operational log for EncodedCommand (-enc) executions",
  "T1105": "Review web-proxy egress and DownloadString/Invoke-WebRequest activity",
  "T1562.001": "Check AMSI provider / Event Tracing for Windows enablement across endpoints",
  "T1566": "Review sender-domain authentication results and header lineage for the campaign",
  "T1078": "Audit credential usage for the embedded account against sign-in logs",
  "T1564": "Search process-creation for Hidden window flags via WindowsEvent security audit",
  "T1190": "Correlate WAF / front-end 4xx-5xx spikes with the referenced CVE",
  "T1204": "Trace attachment + macro execution trail in EDR process trees",
};

function huntFor(technique: string): string {
  return HUNTS[technique] ?? `Correlate ${technique} occurrences against local event history`;
}

export function buildOpportunities(
  findings: Finding[],
  ctx?: OpportunityContext,
): DetectionOpportunity[] {
  const byTechnique = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!f.technique) continue;
    const list = byTechnique.get(f.technique) ?? [];
    list.push(f);
    byTechnique.set(f.technique, list);
  }
  const out: DetectionOpportunity[] = [];
  for (const [technique, fs] of byTechnique) {
    const highest = [...fs].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])[0];
    const existing = ctx?.lookupRule?.(technique);
    const coverage = existing ? "detected" : !ctx?.lookupRule ? "unknown" : "gap";
    const behavior = highest.detail;
    const priority = highSeverity(highest.severity) ? "high" : highest.severity === "medium" ? "medium" : "low";
    const id = objectId("opportunity", technique, behavior);
    out.push({
      id,
      technique,
      behavior,
      coverage,
      existingRule: existing,
      suggestedRule: coverage === "gap" ? { fmt: "sigma", name: `Sigma for ${technique}`, draft: sigmaScaffold(technique, highest) } : undefined,
      suggestedHunt: huntFor(technique),
      priority,
      confidence: highest.confidence?.level === "high" ? 0.9 : highest.confidence?.level === "medium" ? 0.7 : highest.confidence?.level === "low" ? 0.5 : undefined,
      status: "open",
      schemaVersion: INVESTIGATION_OBJECTS_V1,
    });
  }
  return out;
}

const SEVERITY_RANK: Record<Finding["severity"], number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function highSeverity(s: Finding["severity"]): boolean {
  return s === "high" || s === "critical";
}

function sigmaScaffold(technique: string, finding: Finding): string {
  const name = `Suspicious ${technique} behavior`;
  return `title: ${name}\nid: ${finding.id.slice(0, 8)}-0000-0000-0000-000000000000\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: '${finding.detail.split(" — ")[0]}'\n  condition: selection\nlevel: ${finding.severity === "critical" || finding.severity === "high" ? "high" : "medium"}`;
}