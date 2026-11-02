import { type Severity } from "@/lib/severity";

export type IocType = "ipv4" | "ipv6" | "domain" | "url" | "md5" | "sha1" | "sha256" | "email" | "cve" | "ja3" | "ua" | "unknown";

export type IOC = {
  value: string
  type: IocType
  context: string
  source: string
  severity: Severity
  id?: string
};

export type Finding = {
  id: string
  severity: Severity
  title: string
  detail: string
  source: string
  technique?: string
  iocs?: IOC[]
};

export type ArtifactKind = "email" | "file" | "pcap" | "log" | "url" | "text";

export type Artifact = {
  id: string
  kind: ArtifactKind
  title: string
  raw?: string
  metadata: Record<string, string>
  created: string
};

export type Evidence = {
  id: string
  artifact: Artifact
  findings: Finding[]
  iocs: IOC[]
  notes: string
  created: string
};
