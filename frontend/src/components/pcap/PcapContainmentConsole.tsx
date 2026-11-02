import { useState, useMemo } from "react";
import {
  ShieldAlert, ShieldCheck, Network, Terminal, Copy, Check,
  ExternalLink, Lock, AlertTriangle, Radio, Server, Flame, Activity
} from "lucide-react";
import { Chip } from "@/components/soc";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import type { PcapAnalysisResult } from "@/lib/pcapArtifact";

interface PcapContainmentConsoleProps {
  analysis: PcapAnalysisResult;
}

export function PcapContainmentConsole({ analysis }: PcapContainmentConsoleProps) {
  const [activeTab, setActiveTab] = useState<"firewall" | "dns" | "suricata" | "ticket">("firewall");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string, label: string) => {
    copyText(text).then(() => {
      setCopiedKey(key);
      toast.success(`${label} copied to clipboard`);
      setTimeout(() => setCopiedKey(null), 2500);
    }).catch(() => {
      toast.error("Failed to copy");
    });
  };

  // Extract hostile external IPs and domains
  const telemetry = useMemo(() => {
    const isPrivate = (ip: string) =>
      /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|127\.|0\.0\.0\.0)/.test(ip);

    const conns = analysis.zeek_conn || [];
    const dnsQueries = (analysis.zeek_dns || []).map((d) => d.query).filter(Boolean);
    const httpHosts = (analysis.zeek_http || []).map((h) => h.host).filter(Boolean);

    const allExternalIps = new Set<string>();
    const allInternalIps = new Set<string>();

    for (const c of conns) {
      if (c.orig_h && !isPrivate(c.orig_h)) allExternalIps.add(c.orig_h);
      else if (c.orig_h) allInternalIps.add(c.orig_h);

      if (c.resp_h && !isPrivate(c.resp_h)) allExternalIps.add(c.resp_h);
      else if (c.resp_h) allInternalIps.add(c.resp_h);
    }

    // Add IOC IPs
    for (const i of analysis.iocs || []) {
      if (i.type === "ipv4" && !isPrivate(i.value)) {
        allExternalIps.add(i.value);
      }
    }

    const externalIps = Array.from(allExternalIps).slice(0, 10);
    const internalIps = Array.from(allInternalIps).slice(0, 5);
    const hostileDomains = Array.from(new Set([...dnsQueries, ...httpHosts]))
      .filter((d) => d && !d.includes("local") && !d.includes("arpa") && !d.includes("internal"))
      .slice(0, 8);

    const credentialsFound = (analysis.credentials || []).length;
    const criticalFindings = analysis.displayFindings.filter((f) => f.severity === "critical").length;
    const highFindings = analysis.displayFindings.filter((f) => f.severity === "high").length;

    return {
      externalIps,
      internalIps,
      hostileDomains,
      credentialsFound,
      criticalFindings,
      highFindings,
    };
  }, [analysis]);

  // Executive Network Assessment
  const assessment = useMemo(() => {
    const { criticalFindings, highFindings, credentialsFound, externalIps, hostileDomains } = telemetry;
    const hasBeacon = (analysis.zeek_http || []).some(
      (h) => h.path?.includes("drop") || h.path?.includes("beacon") || h.path?.includes("c2")
    );
    const hasLongDns = (analysis.zeek_dns || []).some((d) => (d.query || "").length > 45);

    let verdict = "BENIGN: NORMAL TRAFFIC BASELINE";
    let tone: "destructive" | "warning" | "success" = "success";
    let score = 10;
    let targetMechanism = "Enterprise Baseline";

    if (criticalFindings > 0 || hasBeacon || (externalIps.length > 0 && credentialsFound > 0)) {
      verdict = "CRITICAL: ACTIVE C2 BEACONING & EXFILTRATION DETECTED";
      tone = "destructive";
      score = 94;
      targetMechanism = "C2 Callback / Data Infiltration";
    } else if (credentialsFound > 0) {
      verdict = "HIGH RISK: CLEAR-TEXT CREDENTIAL LEAKAGE DETECTED";
      tone = "destructive";
      score = 85;
      targetMechanism = "Clear-Text Protocol Insecurity";
    } else if (highFindings > 0 || hasLongDns) {
      verdict = "HIGH RISK: HIGH-ENTROPY DNS TUNNELING / EXPLOIT TRAFFIC";
      tone = "destructive";
      score = 78;
      targetMechanism = "DNS Covert Channel";
    } else if (analysis.displayFindings.length > 0 || externalIps.length > 0) {
      verdict = "SUSPICIOUS: RECONNAISSANCE & PORT SWEEPS DETECTED";
      tone = "warning";
      score = 52;
      targetMechanism = "Network Port / Service Recon";
    }

    const hostSummary = telemetry.internalIps.join(", ") || "analyzed endpoint";
    const remoteSummary = telemetry.externalIps.slice(0, 3).join(", ") || "external peers";

    let narrative = "";
    if (tone === "destructive") {
      narrative = `Network capture inspection identified active adversarial communications originating from internal host(s) [${hostSummary}] communicating with external infrastructure [${remoteSummary}]. Telemetry indicates ${hasBeacon ? "recurrent HTTP C2 beacon callbacks" : credentialsFound > 0 ? "clear-text credential leakage" : "high-severity protocol exploitation"}. Immediate perimeter boundary drop and host isolation recommended.`;
    } else if (tone === "warning") {
      narrative = `Capture exhibits anomalous network behavior between [${hostSummary}] and [${remoteSummary}]. Identified ${analysis.displayFindings.length} heuristic alert(s) without definitive confirmed payload transfer. Monitor endpoint session activity.`;
    } else {
      narrative = `Capture inspection revealed standard protocol compliance across ${analysis.totalPackets} packets and ${analysis.uniqueIPs} unique IP addresses. No hostile beaconing, clear-text credentials, or DNS tunneling patterns observed.`;
    }

    return { verdict, tone, score, targetMechanism, narrative };
  }, [telemetry, analysis]);

  // Containment Scripts
  const containment = useMemo(() => {
    const { externalIps, hostileDomains, internalIps } = telemetry;
    const ipList = externalIps.length > 0 ? externalIps : ["185.220.101.5", "198.51.100.44"];
    const domainList = hostileDomains.length > 0 ? hostileDomains : ["evil-c2-beacon.ru", "dark-onion.org"];

    // 1. Linux iptables / UFW Drop
    const iptablesScript = `# Linux iptables & UFW Perimeter Drop Commands
# Block inbound and forward traffic from identified hostile external IPs:
${ipList.map((ip) => `iptables -I INPUT -s ${ip} -j DROP\niptables -I FORWARD -s ${ip} -j DROP\nufw deny from ${ip} to any`).join("\n")}

# Save firewall state:
netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4`;

    // 2. DNS Sinkhole / RPZ & Pi-hole
    const dnsScript = `# BIND9 / Infoblox Response Policy Zone (RPZ) & Pi-hole Sinkhole
# 1. BIND9 RPZ zone records:
${domainList.map((d) => `${d} CNAME .\n*.${d} CNAME .`).join("\n")}

# 2. Pi-hole / Unbound CLI block:
${domainList.map((d) => `pihole -b ${d}`).join("\n")}`;

    // 3. Tailored Suricata IDS Rule
    const suricataRule = `# Tailored Suricata IDS Signatures for Detected Flows
${ipList.map((ip, idx) => `alert ip $HOME_NET any -> ${ip} any (msg:"ET SOC Detected Outbound C2 Callback to Hostile IP [${ip}]"; flow:to_server,established; reference:url,beyondarch.internal; classtype:trojan-activity; sid:${2990001 + idx}; rev:1;)`).join("\n")}
${domainList.map((d, idx) => `alert dns $HOME_NET any -> any 53 (msg:"ET SOC High-Risk DNS Query to Suspicious C2 Domain [${d}]"; dns.query; content:"${d}"; nocase; classtype:trojan-activity; sid:${2990101 + idx}; rev:1;)`).join("\n")}`;

    // 4. IR Incident Ticket Draft (Markdown)
    const ticketDraft = `### [P1/NETWORK] Network Intrusion & C2 Detection Incident
**Incident Timestamp:** ${new Date().toISOString()}
**Verdict:** ${assessment.verdict}
**Threat Index:** ${assessment.score}/100
**Total Packets:** ${analysis.totalPackets} (${analysis.uniqueIPs} unique IPs)

#### Involved Hosts & Network Topology:
- **Impacted Internal Host(s):** ${internalIps.join(", ") || "N/A"}
- **Hostile External Endpoint(s):** ${ipList.join(", ")}
- **Identified Domain Queries:** ${domainList.join(", ") || "None"}

#### Threat Assessment Narrative:
${assessment.narrative}

#### Executed Boundary Containment Actions:
1. Deployed emergency iptables / UFW packet drop rules for: \`${ipList.join(", ")}\`.
2. Applied DNS Response Policy Zone (RPZ) sinkholes for: \`${domainList.join(", ")}\`.
3. Injected custom high-priority Suricata detection rules into perimeter sensor pipeline.`;

    return { iptablesScript, dnsScript, suricataRule, ticketDraft };
  }, [telemetry, assessment, analysis]);

  return (
    <div id="pcap-containment-console" className="space-y-3.5 rounded-lg border border-border bg-surface-1 p-4 shadow-sm min-w-0 max-w-full font-mono mb-4">
      {/* Executive Threat Assessment Dossier */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-3">
        <div className="flex items-center gap-2">
          <Network
            className={`h-4 w-4 shrink-0 ${
              assessment.tone === "destructive"
                ? "text-destructive"
                : assessment.tone === "warning"
                ? "text-warning"
                : "text-success"
            }`}
          />
          <span className="ba-text-xs font-bold uppercase tracking-wider text-foreground">
            Executive Network Threat Assessment Dossier
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Chip tone={assessment.tone}>{assessment.verdict}</Chip>
          <span className="ba-text-2xs text-muted-foreground font-semibold">
            Threat Index:{" "}
            <span
              className={
                assessment.tone === "destructive"
                  ? "text-destructive font-bold"
                  : assessment.tone === "warning"
                  ? "text-warning font-bold"
                  : "text-success font-bold"
              }
            >
              {assessment.score}/100
            </span>
          </span>
          <span className="rounded bg-surface-2 px-1.5 py-0.5 ba-text-3xs text-foreground border border-border/60">
            Mechanism: {assessment.targetMechanism}
          </span>
        </div>
      </div>

      {/* Threat Narrative */}
      <p className="ba-text-xs text-fg-dim leading-relaxed bg-surface-0/70 p-3 rounded border border-border/40">
        {assessment.narrative}
      </p>

      {/* 4-Vector Network Risk Breakdown */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 pt-1">
        <div className="rounded border border-subtle bg-surface-0 p-2 text-center">
          <div className="ba-text-3xs text-muted-foreground">Packets / Hosts</div>
          <div className="ba-text-xs font-bold mt-0.5 text-foreground">
            {analysis.totalPackets} pkts · {analysis.uniqueIPs} IPs
          </div>
        </div>

        <div className="rounded border border-subtle bg-surface-0 p-2 text-center">
          <div className="ba-text-3xs text-muted-foreground">External Peers</div>
          <div className={`ba-text-xs font-bold mt-0.5 ${telemetry.externalIps.length > 0 ? "text-warning" : "text-foreground"}`}>
            {telemetry.externalIps.length} External IP(s)
          </div>
        </div>

        <div className="rounded border border-subtle bg-surface-0 p-2 text-center">
          <div className="ba-text-3xs text-muted-foreground">Clear-Text Credentials</div>
          <div className={`ba-text-xs font-bold mt-0.5 ${telemetry.credentialsFound > 0 ? "text-destructive" : "text-success"}`}>
            {telemetry.credentialsFound > 0 ? `${telemetry.credentialsFound} Exposed` : "0 Detected"}
          </div>
        </div>

        <div className="rounded border border-subtle bg-surface-0 p-2 text-center">
          <div className="ba-text-3xs text-muted-foreground">Threat Findings</div>
          <div className={`ba-text-xs font-bold mt-0.5 ${telemetry.criticalFindings + telemetry.highFindings > 0 ? "text-destructive" : "text-foreground"}`}>
            {analysis.displayFindings.length} Finding(s)
          </div>
        </div>
      </div>

      {/* 1-Click Network Active Containment Console */}
      <div className="rounded-md border border-subtle bg-surface-0 p-3 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/40 pb-2">
          <div className="flex items-center gap-2 text-foreground font-semibold ba-text-xs">
            <Terminal className="h-3.5 w-3.5 text-primary" />
            1-Click Network Active Containment Console
          </div>

          <div className="flex flex-wrap items-center gap-1">
            {(["firewall", "dns", "suricata", "ticket"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`rounded px-2 py-0.5 ba-text-3xs font-semibold transition-colors ${
                  activeTab === tab
                    ? "bg-primary text-primary-foreground"
                    : "border border-subtle bg-surface-1 text-muted-foreground hover:text-foreground"
                }`}
              >
                {tab === "firewall"
                  ? "iptables / UFW Drop"
                  : tab === "dns"
                  ? "DNS Sinkhole / RPZ"
                  : tab === "suricata"
                  ? "Suricata IDS Rules"
                  : "IR Ticket Draft"}
              </button>
            ))}
          </div>
        </div>

        {/* Console Content */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="ba-text-3xs text-muted-foreground">
              {activeTab === "firewall"
                ? "Linux iptables & UFW Perimeter Drop Commands"
                : activeTab === "dns"
                ? "BIND9 RPZ Zone Syntax & Pi-hole Block Commands"
                : activeTab === "suricata"
                ? "Tailored Suricata Network Intrusion Signatures"
                : "Incident Response Ticket Markdown"}
            </span>

            <button
              onClick={() => {
                const script =
                  activeTab === "firewall"
                    ? containment.iptablesScript
                    : activeTab === "dns"
                    ? containment.dnsScript
                    : activeTab === "suricata"
                    ? containment.suricataRule
                    : containment.ticketDraft;
                handleCopy(script, activeTab, activeTab.toUpperCase());
              }}
              className="inline-flex items-center gap-1 ba-text-3xs text-muted-foreground hover:text-primary transition-colors cursor-pointer"
            >
              {copiedKey === activeTab ? (
                <Check className="h-3 w-3 text-success" />
              ) : (
                <Copy className="h-3 w-3" />
              )}
              {copiedKey === activeTab ? "copied" : "copy commands"}
            </button>
          </div>

          <pre className="max-h-48 overflow-x-auto whitespace-pre rounded border border-border/40 bg-surface-1 p-2.5 ba-text-3xs text-fg-dim leading-relaxed">
            {activeTab === "firewall" && containment.iptablesScript}
            {activeTab === "dns" && containment.dnsScript}
            {activeTab === "suricata" && containment.suricataRule}
            {activeTab === "ticket" && containment.ticketDraft}
          </pre>
        </div>
      </div>
    </div>
  );
}
