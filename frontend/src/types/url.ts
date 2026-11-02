import type { Artifact, Finding, IOC, Evidence } from "./security";
import type { AnalysisSummary, EvidenceItem } from "./analysis";

export interface UrlObservable {
  kind: "ipv4" | "email" | "hash";
  value: string;
  source: "path" | "query";
}

export interface UrlKnowledgeRow {
  label: string;
  value: string;
  derived?: boolean;
  tone?: "warning" | "destructive" | "default";
}

export interface UrlKnowledge {
  canonicalUrl: { value: string; changes: string[] };
  redirectChainNote: string;
  whois: { derived: UrlKnowledgeRow[]; unavailable: string[] };
  certificate: { derived: UrlKnowledgeRow[]; unavailable: string[] };
  asn: UrlKnowledgeRow[];
  relatedDomains: { value: string; note: string; verified: boolean }[];
  observables: UrlObservable[];
  relatedEntities: UrlKnowledgeRow[];
  passiveDns: { configured: boolean; note: string };
}

export interface UrlAnalysisResult {
  id: string;
  analyzer: string;
  raw: string;
  artifact: Artifact;
  parsed: URL;
  findings: Finding[];
  iocs: IOC[];
  evidence: Evidence[];
  summary: AnalysisSummary;
  evidenceItems: EvidenceItem[];
  generatedAt: string;
  displayFindings: { severity: "destructive" | "warning" | "info"; title: string; reason: string; action: string }[];
  suspiciousPaths: string[];
  pathSignals: string[];
  trackingParams: [string, string][];
  suspiciousChars: { char: string; pos: number }[];
  secrets: { type: string; value: string }[];
  mitre: { id: string; name: string }[];
  domainEnt: number;
  tld: string;
  portNum: string | null;
  portReason: string | null;
  isHttp: boolean;
  punycode: boolean;
  isShortener: boolean;
  defangedOriginal: boolean;
  fileExt: string | null;
  downloadName: string | null;
  hasEmbeddedCreds: boolean;
  hasPathTraversal: boolean;
  isNumericDomain: boolean;
  isSuspiciousTLD: boolean;
  hasNonStandardPort: boolean;
  knowledge: UrlKnowledge;
}
