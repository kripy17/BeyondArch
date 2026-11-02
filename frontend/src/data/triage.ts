import { useState, useEffect } from "react";
import { type Severity } from "@/lib/severity";

export type TriageStatus = "open" | "in_review" | "escalated" | "dismissed";

export type TriageVerdict = "true_positive" | "benign_positive" | "false_positive" | "test";

export type TriageIoc = { type: string; value: string };

export type TriageItem = {
  id: string;
  ts: string;
  title: string;
  description: string;
  severity: Severity;
  source: string;
  sourceUrl?: string;
  status: TriageStatus;
  notes: string;
  tags: string[];
  updated: number;
  alertNodeId?: string;
  caseId?: string;
  iocs?: TriageIoc[];
  verdict?: TriageVerdict;
  verdictReason?: string;
  verdictBy?: string;
  dispositionAt?: number;
};

export const LS_KEY = "ba.triage.v1";

export const STATUS_TONE: Record<TriageStatus, "default" | "warning" | "success" | "destructive" | "info"> = {
  open: "default",
  in_review: "warning",
  escalated: "destructive",
  dismissed: "info",
};

export const STATUS_ORDER: Record<TriageStatus, number> = {
  open: 0,
  in_review: 1,
  escalated: 2,
  dismissed: 3,
};

export const DEFAULT_TRIAGE_ITEMS: TriageItem[] = [
  {
    id: "trg-falcon-01",
    ts: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
    title: "CrowdStrike Falcon: PowerShell Download Cradle & Process Injection",
    description: "DetectId: d74f1b-29402. DetectName: SuspiciousProcessExecution. Hostname: WS-014. User: CORP\\krish. Parent: winword.exe -> powershell.exe -NoP -EncodedCommand SQBFAFgA...",
    severity: "critical",
    source: "crowdstrike",
    status: "open",
    notes: "",
    tags: ["execution", "t1059.001", "defense-evasion", "falcon"],
    updated: Date.now() - 1000 * 60 * 18,
    iocs: [
      { type: "ipv4", value: "185.220.101.44" },
      { type: "domain", value: "update-cdn-service.com" },
      { type: "sha256", value: "8f3d1b94c25983e0ac6719b02a77f9e8a514d3c2b1e0987654321fedcba01234" },
    ],
  },
  {
    id: "trg-def-02",
    ts: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    title: "Microsoft Defender 365: LSASS Memory Dumping Attempt via Mimikatz",
    description: "AlertId: DEF-2026-904. Category: CredentialAccess. Compromised Entity: CORP\\svc-admin on DC-PROD-01. Activity: lsass.exe process access with PROCESS_VM_READ permissions.",
    severity: "high",
    source: "defender",
    status: "open",
    notes: "",
    tags: ["credential-access", "t1003.001", "m365"],
    updated: Date.now() - 1000 * 60 * 45,
    iocs: [
      { type: "ipv4", value: "192.168.1.100" },
      { type: "sha256", value: "4a2b6c8d0e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3b" },
    ],
  },
  {
    id: "trg-suri-03",
    ts: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    title: "Suricata IDS: ET MALWARE Cobalt Strike Beaconing Detected",
    description: "Signature: ET MALWARE Possible Cobalt Strike Malleable C2 HTTP Traffic. Flow: 192.168.1.100:49152 -> 185.220.101.44:4443. Protocol: TCP. Repeated periodic beacons.",
    severity: "high",
    source: "suricata",
    status: "in_review",
    notes: "",
    tags: ["c2", "t1071.001", "network"],
    updated: Date.now() - 1000 * 60 * 90,
    iocs: [
      { type: "ipv4", value: "185.220.101.44" },
    ],
  },
];

export function loadItems(): TriageItem[] {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    }
    return DEFAULT_TRIAGE_ITEMS;
  } catch {
    return DEFAULT_TRIAGE_ITEMS;
  }
}

export function saveItems(items: TriageItem[]) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(items));
  } catch {}
  try {
    window.dispatchEvent(new Event("search-index-invalidate"));
    window.dispatchEvent(new Event("triage-items-changed"));
  } catch {}
}

export function genId(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

export function statusLabel(s: TriageStatus): string {
  switch (s) {
    case "open": return "open";
    case "in_review": return "in review";
    case "escalated": return "escalated";
    case "dismissed": return "dismissed";
  }
}

export const STATUSES: TriageStatus[] = ["open", "in_review", "escalated", "dismissed"];

export const SOURCE_OPTIONS = ["manual", "siem", "detection", "phishing", "parser", "case"];

export function useTriageCounts() {
  const [counts, setCounts] = useState(() => {
    const all = loadItems();
    return {
      open: all.filter((i) => i.status === "open").length,
      inReview: all.filter((i) => i.status === "in_review").length,
      escalated: all.filter((i) => i.status === "escalated").length,
      total: all.length,
    };
  });

  useEffect(() => {
    const handler = () => {
      const all = loadItems();
      setCounts({
        open: all.filter((i) => i.status === "open").length,
        inReview: all.filter((i) => i.status === "in_review").length,
        escalated: all.filter((i) => i.status === "escalated").length,
        total: all.length,
      });
    };
    window.addEventListener("triage-items-changed", handler);
    window.addEventListener("storage", handler);
    return () => {
      window.removeEventListener("triage-items-changed", handler);
      window.removeEventListener("storage", handler);
    };
  }, []);

  return counts;
}

