
import { type Finding, type IOC, type Artifact, type Evidence } from "@/types/security";
import { type AuthState } from "@/data/phishing";
import type { AnalysisSummary, EvidenceItem } from "@/types/analysis";

export type PhishingFindingDisplay = {
  severity: "info" | "warning" | "destructive"
  title: string
  reason: string
  action: string
  source: string
};

export type PhishingBreakdownItem = {
  signal: string
  weight: number
  state: string
};

export type PhishingMitreItem = {
  id: string
  name: string
  source: string
};

export type PhishingUrlAnalysis = {
  value: string
  badges: { label: string; tone: string }[]
};

export type PhishingHopItem = {
  from: string
  ip: string
  by: string
  protocol: string
};

export type PhishingAuth = {
  spf: AuthState
  dkim: AuthState
  dmarc: AuthState
};

export type PhishingVerdict = {
  label: string
  tone: "destructive" | "warning" | "success"
};

export type PhishingAnalysisResult = {
  id: string
  analyzer: string
  raw: string
  artifact: Artifact
  findings: Finding[]
  iocs: IOC[]
  evidence: Evidence
  summary: AnalysisSummary
  evidenceItems: EvidenceItem[]
  generatedAt: string

  auth: PhishingAuth
  verdict: PhishingVerdict
  breakdown: PhishingBreakdownItem[]
  mitre: PhishingMitreItem[]
  urlAnalysis: PhishingUrlAnalysis[]

  body: string
  headers: string
  fromLine: string
  replyLine: string
  pathLine: string
  fromDomain?: string
  brandMatch?: string
  replyMismatch: boolean
  defangedUrl: boolean
  urgency: boolean
  hasForm: boolean
  hasPasswordField: boolean
  hasHtmlForm: boolean
  hasLookalike: boolean
  envelopeFlags: string[]
  hasAttachment: { hasAttachments: boolean; detail: string[] }
  displaySpoofs: { kind: string; detail: string; brand?: string }[]
  authResults: { headerCount: number; spf: PhishingAuth["spf"]; dkim: PhishingAuth["dkim"]; dmarc: PhishingAuth["dmarc"]; conflict: { spf: boolean; dkim: boolean; dmarc: boolean } }
  attachmentFiles: string[]
  displayFindings: PhishingFindingDisplay[]
  secrets: { type: string; value: string }[]
  hops: PhishingHopItem[]
  iocsByCategory: Record<string, string[]>
  language?: { script: string; label: string; samples: string[] } | null
  brandClaims?: { brand: string; claim: string; typosquat: boolean }[]
  recommendations?: { text: string; sev: "info" | "warning" | "destructive"; source: string }[]
};
