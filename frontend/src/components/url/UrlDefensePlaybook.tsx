import { useState } from "react";
import {
  ShieldAlert, ShieldCheck, Copy, Check, Terminal, Globe,
  Lock, Server, AlertTriangle, Code2, Database, Shield
} from "lucide-react";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import { Chip } from "@/components/soc";
import type {
  BrandImpersonationFinding,
  DecodedPayload,
  DefensivePlaybook,
  SimulatedHttpProfile,
  ExecutiveThreatNarrative,
  ContainmentConsole,
} from "@/lib/url/smart-heuristics";

interface UrlDefensePlaybookProps {
  brandFinding: BrandImpersonationFinding | null;
  decodedPayloads: DecodedPayload[];
  playbook: DefensivePlaybook;
  httpProfile: SimulatedHttpProfile;
  narrative?: ExecutiveThreatNarrative;
  containment?: ContainmentConsole;
}

export function UrlDefensePlaybook({
  brandFinding,
  decodedPayloads,
  playbook,
  httpProfile,
  narrative,
  containment,
}: UrlDefensePlaybookProps) {
  const [activeTab, setActiveTab] = useState<"playbook" | "payloads" | "http" | "hunting" | "containment">("playbook");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string, label: string) => {
    copyText(text);
    setCopiedKey(key);
    toast.success(`${label} copied to clipboard`);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="space-y-4 rounded-lg border border-subtle bg-surface-0 p-3.5 shadow-xs">
      {/* Executive Threat Assessment & Incident Synthesis Dossier */}
      {narrative && (
        <div className="rounded-lg border border-border/80 bg-surface-1/80 p-3.5 shadow-xs space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border/40">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-mono ba-text-xs font-bold ${
                narrative.verdict === "MALICIOUS" ? "bg-destructive/20 text-destructive border border-destructive/40" :
                narrative.verdict === "SUSPICIOUS" ? "bg-amber-500/20 text-amber-400 border border-amber-500/40" :
                "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
              }`}>
                {narrative.verdict === "MALICIOUS" ? <ShieldAlert className="h-3.5 w-3.5" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                {narrative.verdict} · {narrative.compositeScore}/100 RISK
              </span>
              <span className="text-mono ba-text-sm font-semibold text-foreground">
                {narrative.threatCategory}
              </span>
            </div>
            <span className="text-mono ba-text-2xs text-muted-foreground">
              Target Scope: <strong className="text-foreground">{narrative.targetPersona}</strong>
            </span>
          </div>

          <p className="text-mono ba-text-xs text-foreground/90 leading-relaxed">
            {narrative.executiveSummary}
          </p>

          {/* Explainable Risk Factors */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 pt-1">
            {narrative.riskFactors.map((rf, idx) => (
              <div key={idx} className="rounded border border-subtle bg-surface-0 p-2 text-mono ba-text-3xs">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-muted-foreground font-medium">{rf.name}</span>
                  <span className={`font-bold ${
                    rf.severity === "critical" ? "text-destructive" :
                    rf.severity === "high" ? "text-amber-400" :
                    rf.severity === "medium" ? "text-warning" : "text-emerald-400"
                  }`}>{rf.score}%</span>
                </div>
                <div className="text-muted-foreground truncate" title={rf.detail}>{rf.detail}</div>
              </div>
            ))}
          </div>

          {narrative.adversaryTTPs.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-border/30">
              <span className="text-mono ba-text-3xs text-muted-foreground">MITRE ATT&CK:</span>
              {narrative.adversaryTTPs.map((ttp, idx) => (
                <Chip key={idx} tone="default">{ttp}</Chip>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Brand Spoofing Alert Banner if detected */}
      {brandFinding && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-destructive shrink-0" />
              <div>
                <span className="text-mono ba-text-xs font-bold uppercase tracking-wider text-destructive">
                  Targeted Phishing Brand Spoofing Detected
                </span>
                <div className="text-mono ba-text-sm text-foreground mt-0.5">
                  Impersonating: <strong className="text-destructive font-bold">{brandFinding.targetBrand}</strong> ({brandFinding.confidence}% confidence)
                </div>
              </div>
            </div>
            <Chip tone="destructive">{brandFinding.attackTechnique}</Chip>
          </div>
          <p className="mt-2 text-mono ba-text-2xs text-muted-foreground leading-relaxed border-t border-destructive/20 pt-2">
            {brandFinding.evidence} The real destination server is anchored to apex domain <code className="text-destructive font-bold">.{brandFinding.trueApexDomain}</code>.
          </p>
        </div>
      )}

      {/* Navigation tabs */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-2">
        <div className="flex flex-wrap gap-1">
          <button
            onClick={() => setActiveTab("playbook")}
            className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-mono ba-text-2xs font-medium transition-colors ${
              activeTab === "playbook"
                ? "bg-primary text-primary-foreground"
                : "border border-subtle bg-surface-1 text-muted-foreground hover:text-foreground"
            }`}
          >
            <Shield className="h-3.5 w-3.5" />
            Firewall & DNS Block Playbook
          </button>

          <button
            onClick={() => setActiveTab("containment")}
            className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-mono ba-text-2xs font-medium transition-colors ${
              activeTab === "containment"
                ? "bg-primary text-primary-foreground"
                : "border border-subtle bg-surface-1 text-muted-foreground hover:text-foreground"
            }`}
          >
            <Terminal className="h-3.5 w-3.5" />
            1-Click SOC Containment
          </button>

          <button
            onClick={() => setActiveTab("hunting")}
            className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-mono ba-text-2xs font-medium transition-colors ${
              activeTab === "hunting"
                ? "bg-primary text-primary-foreground"
                : "border border-subtle bg-surface-1 text-muted-foreground hover:text-foreground"
            }`}
          >
            <Database className="h-3.5 w-3.5" />
            SIEM & EDR Hunt Queries
          </button>

          <button
            onClick={() => setActiveTab("payloads")}
            className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-mono ba-text-2xs font-medium transition-colors ${
              activeTab === "payloads"
                ? "bg-primary text-primary-foreground"
                : "border border-subtle bg-surface-1 text-muted-foreground hover:text-foreground"
            }`}
          >
            <Code2 className="h-3.5 w-3.5" />
            Decoded Query Payloads ({decodedPayloads.length})
          </button>

          <button
            onClick={() => setActiveTab("http")}
            className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-mono ba-text-2xs font-medium transition-colors ${
              activeTab === "http"
                ? "bg-primary text-primary-foreground"
                : "border border-subtle bg-surface-1 text-muted-foreground hover:text-foreground"
            }`}
          >
            <Server className="h-3.5 w-3.5" />
            Simulated HTTP Detonation
          </button>
        </div>
      </div>

      {/* TAB 1: DEFENSIVE PLAYBOOK */}
      {activeTab === "playbook" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {/* Palo Alto Rule */}
          <div className="rounded-md border border-subtle bg-surface-1 p-2.5">
            <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-border/40">
              <span className="font-mono ba-text-xs font-semibold text-foreground">Palo Alto Networks (PAN-OS)</span>
              <button
                onClick={() => handleCopy(playbook.paloAlto, "pa", "Palo Alto rule")}
                className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
              >
                {copiedKey === "pa" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                {copiedKey === "pa" ? "copied" : "copy"}
              </button>
            </div>
            <pre className="font-mono ba-text-3xs text-muted-foreground overflow-x-auto whitespace-pre p-1.5 bg-surface-0 rounded border border-border/30">
              {playbook.paloAlto}
            </pre>
          </div>

          {/* Fortinet FortiGate Rule */}
          <div className="rounded-md border border-subtle bg-surface-1 p-2.5">
            <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-border/40">
              <span className="font-mono ba-text-xs font-semibold text-foreground">Fortinet FortiGate CLI</span>
              <button
                onClick={() => handleCopy(playbook.fortinet, "fg", "Fortinet rule")}
                className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
              >
                {copiedKey === "fg" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                {copiedKey === "fg" ? "copied" : "copy"}
              </button>
            </div>
            <pre className="font-mono ba-text-3xs text-muted-foreground overflow-x-auto whitespace-pre p-1.5 bg-surface-0 rounded border border-border/30">
              {playbook.fortinet}
            </pre>
          </div>

          {/* DNS Sinkhole RPZ */}
          <div className="rounded-md border border-subtle bg-surface-1 p-2.5">
            <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-border/40">
              <span className="font-mono ba-text-xs font-semibold text-foreground">DNS Sinkhole (RPZ / BIND)</span>
              <button
                onClick={() => handleCopy(playbook.dnsRpz, "rpz", "DNS Sinkhole RPZ")}
                className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
              >
                {copiedKey === "rpz" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                {copiedKey === "rpz" ? "copied" : "copy"}
              </button>
            </div>
            <pre className="font-mono ba-text-3xs text-muted-foreground overflow-x-auto whitespace-pre p-1.5 bg-surface-0 rounded border border-border/30">
              {playbook.dnsRpz}
            </pre>
          </div>

          {/* Pi-Hole / DNSMasq */}
          <div className="rounded-md border border-subtle bg-surface-1 p-2.5">
            <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-border/40">
              <span className="font-mono ba-text-xs font-semibold text-foreground">Pi-hole / DNSMasq Blacklist</span>
              <button
                onClick={() => handleCopy(playbook.pihole, "pihole", "Pi-hole syntax")}
                className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
              >
                {copiedKey === "pihole" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                {copiedKey === "pihole" ? "copied" : "copy"}
              </button>
            </div>
            <pre className="font-mono ba-text-3xs text-muted-foreground overflow-x-auto whitespace-pre p-1.5 bg-surface-0 rounded border border-border/30">
              {playbook.pihole}
            </pre>
          </div>
        </div>
      )}

      {/* TAB 2: SIEM & EDR HUNTING */}
      {activeTab === "hunting" && (
        <div className="space-y-3">
          {/* Splunk SPL */}
          <div className="rounded-md border border-subtle bg-surface-1 p-3">
            <div className="flex items-center justify-between pb-2 mb-2 border-b border-border/40">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-primary" />
                <span className="font-mono ba-text-xs font-semibold text-foreground">Splunk Enterprise Security (SPL)</span>
              </div>
              <button
                onClick={() => handleCopy(playbook.splunkSpl, "splunk", "Splunk query")}
                className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-primary"
              >
                {copiedKey === "splunk" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                {copiedKey === "splunk" ? "copied query" : "copy spl"}
              </button>
            </div>
            <pre className="font-mono ba-text-xs text-foreground overflow-x-auto whitespace-pre p-2 bg-surface-0 rounded border border-border/40 leading-relaxed">
              {playbook.splunkSpl}
            </pre>
          </div>

          {/* Microsoft Defender for Endpoint (KQL) */}
          <div className="rounded-md border border-subtle bg-surface-1 p-3">
            <div className="flex items-center justify-between pb-2 mb-2 border-b border-border/40">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-primary" />
                <span className="font-mono ba-text-xs font-semibold text-foreground">Microsoft Defender for Endpoint / Sentinel (KQL)</span>
              </div>
              <button
                onClick={() => handleCopy(playbook.defenderKql, "kql", "Defender KQL query")}
                className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-0 px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-primary"
              >
                {copiedKey === "kql" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                {copiedKey === "kql" ? "copied query" : "copy kql"}
              </button>
            </div>
            <pre className="font-mono ba-text-xs text-foreground overflow-x-auto whitespace-pre p-2 bg-surface-0 rounded border border-border/40 leading-relaxed">
              {playbook.defenderKql}
            </pre>
          </div>
        </div>
      )}

      {/* TAB 3: DECODED QUERY PAYLOADS */}
      {activeTab === "payloads" && (
        <div className="space-y-2.5">
          {decodedPayloads.length === 0 ? (
            <div className="py-6 text-center text-mono ba-text-xs text-muted-foreground">
              No encoded query parameters (Base64/Hex/URL script injection) discovered in URL.
            </div>
          ) : (
            decodedPayloads.map((payload, idx) => (
              <div key={idx} className="rounded-md border border-subtle bg-surface-1 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2 pb-1.5 mb-1.5 border-b border-border/40">
                  <div className="flex items-center gap-2">
                    <span className="font-mono ba-text-xs font-bold text-foreground">
                      Param: <code className="text-primary">{payload.paramKey}</code>
                    </span>
                    <Chip tone="warning">{payload.encoding.toUpperCase()} ENCODED</Chip>
                    {payload.isExecutable && <Chip tone="destructive">EXECUTABLE SCRIPT CRADLE</Chip>}
                    {payload.isEmail && <Chip tone="info">TARGET RECIPIENT EMAIL</Chip>}
                    {payload.isUrl && <Chip tone="warning">NESTED TARGET URL</Chip>}
                  </div>
                  <button
                    onClick={() => handleCopy(payload.decoded, `p-${idx}`, "Decoded payload")}
                    className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
                  >
                    {copiedKey === `p-${idx}` ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                    copy decoded
                  </button>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2">
                  <div>
                    <span className="text-mono ba-text-3xs text-muted-foreground block mb-0.5">Raw Encoded Value:</span>
                    <pre className="font-mono ba-text-3xs text-fg-dim overflow-x-auto p-1.5 bg-surface-0 rounded border border-border/30 truncate">
                      {payload.raw}
                    </pre>
                  </div>
                  <div>
                    <span className="text-mono ba-text-3xs text-primary font-bold block mb-0.5">Deobfuscated Analyst View:</span>
                    <pre className="font-mono ba-text-3xs text-foreground overflow-x-auto p-1.5 bg-surface-0 rounded border border-primary/30">
                      {payload.decoded}
                    </pre>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* TAB 4: SIMULATED HTTP PROFILE */}
      {activeTab === "http" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {/* Response Headers & Status */}
          <div className="rounded-md border border-subtle bg-surface-1 p-3">
            <div className="flex items-center justify-between pb-1.5 mb-2 border-b border-border/40">
              <span className="font-mono ba-text-xs font-semibold text-foreground">HTTP Response Profile</span>
              <span className={`font-mono ba-text-2xs font-bold px-1.5 py-0.5 rounded ${
                httpProfile.responseStatus >= 300 ? "bg-amber-500/20 text-amber-400" : "bg-emerald-500/20 text-emerald-400"
              }`}>
                {httpProfile.responseStatus} {httpProfile.responseStatusText}
              </span>
            </div>
            <div className="space-y-1 text-mono ba-text-2xs">
              {Object.entries(httpProfile.responseHeaders).map(([k, v]) => (
                <div key={k} className="flex items-baseline justify-between gap-2 py-0.5 border-b border-border/20">
                  <span className="text-muted-foreground">{k}:</span>
                  <span className="text-foreground truncate max-w-[240px]">{v}</span>
                </div>
              ))}
            </div>
          </div>

          {/* TLS Certificate Heuristics */}
          <div className="rounded-md border border-subtle bg-surface-1 p-3">
            <div className="flex items-center justify-between pb-1.5 mb-2 border-b border-border/40">
              <div className="flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5 text-primary" />
                <span className="font-mono ba-text-xs font-semibold text-foreground">TLS / SSL Heuristic Certificate</span>
              </div>
              {httpProfile.tlsCert.isEphemeral && (
                <Chip tone="warning">EPHEMERAL ({httpProfile.tlsCert.validityDays}D)</Chip>
              )}
            </div>
            <div className="space-y-1 text-mono ba-text-2xs">
              <div className="flex justify-between py-0.5 border-b border-border/20">
                <span className="text-muted-foreground">Subject:</span>
                <span className="text-foreground">{httpProfile.tlsCert.subject}</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-border/20">
                <span className="text-muted-foreground">Issuer:</span>
                <span className="text-foreground">{httpProfile.tlsCert.issuer}</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-border/20">
                <span className="text-muted-foreground">Validity Span:</span>
                <span className="text-foreground">{httpProfile.tlsCert.validityDays} Days (Free automated cert)</span>
              </div>
              <div className="flex justify-between py-0.5 border-b border-border/20">
                <span className="text-muted-foreground">SAN Mismatch:</span>
                <span className={httpProfile.tlsCert.sanMismatch ? "text-destructive font-bold" : "text-success"}>
                  {httpProfile.tlsCert.sanMismatch ? "POTENTIAL MISMATCH" : "Matches"}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB: 1-CLICK SOC CONTAINMENT CONSOLE */}
      {activeTab === "containment" && containment && (
        <div className="space-y-3">
          <div className="rounded-md border border-subtle bg-surface-1 p-3">
            <div className="flex items-center justify-between pb-1.5 mb-2 border-b border-border/40">
              <span className="font-mono ba-text-xs font-semibold text-foreground">
                Identity & User Session Revocation (Entra ID / M365)
              </span>
              <button
                onClick={() => handleCopy(containment.entraIdSessionRevoke || "", "entra", "Entra session revoke script")}
                className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
              >
                {copiedKey === "entra" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                {copiedKey === "entra" ? "copied" : "copy"}
              </button>
            </div>
            <pre className="font-mono ba-text-3xs text-muted-foreground overflow-x-auto whitespace-pre p-2 bg-surface-0 rounded border border-border/30">
              {containment.entraIdSessionRevoke}
            </pre>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {/* Exchange Online TABL */}
            <div className="rounded-md border border-subtle bg-surface-1 p-3">
              <div className="flex items-center justify-between pb-1.5 mb-2 border-b border-border/40">
                <span className="font-mono ba-text-xs font-semibold text-foreground">
                  Exchange Online Tenant Allow/Block List (TABL)
                </span>
                <button
                  onClick={() => handleCopy(containment.exchangeMailFlowBlock, "tabl", "Exchange block rule")}
                  className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
                >
                  {copiedKey === "tabl" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                  {copiedKey === "tabl" ? "copied" : "copy"}
                </button>
              </div>
              <pre className="font-mono ba-text-3xs text-muted-foreground overflow-x-auto whitespace-pre p-2 bg-surface-0 rounded border border-border/30">
                {containment.exchangeMailFlowBlock}
              </pre>
            </div>

            {/* Defender for Endpoint Custom Indicator */}
            <div className="rounded-md border border-subtle bg-surface-1 p-3">
              <div className="flex items-center justify-between pb-1.5 mb-2 border-b border-border/40">
                <span className="font-mono ba-text-xs font-semibold text-foreground">
                  Defender for Endpoint Custom IOC Indicator
                </span>
                <button
                  onClick={() => handleCopy(containment.defenderCustomIoc, "mde", "Defender IOC block")}
                  className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
                >
                  {copiedKey === "mde" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                  {copiedKey === "mde" ? "copied" : "copy"}
                </button>
              </div>
              <pre className="font-mono ba-text-3xs text-muted-foreground overflow-x-auto whitespace-pre p-2 bg-surface-0 rounded border border-border/30">
                {containment.defenderCustomIoc}
              </pre>
            </div>
          </div>

          {/* Incident Response Ticket Draft */}
          <div className="rounded-md border border-subtle bg-surface-1 p-3">
            <div className="flex items-center justify-between pb-1.5 mb-2 border-b border-border/40">
              <span className="font-mono ba-text-xs font-semibold text-foreground">
                Incident Response Ticket Summary (Jira / ServiceNow / TheHive)
              </span>
              <button
                onClick={() => handleCopy(containment.irTicketMarkdown, "irticket", "IR ticket draft")}
                className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
              >
                {copiedKey === "irticket" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                {copiedKey === "irticket" ? "copied" : "copy markdown"}
              </button>
            </div>
            <pre className="font-mono ba-text-3xs text-muted-foreground overflow-x-auto whitespace-pre p-2 bg-surface-0 rounded border border-border/30">
              {containment.irTicketMarkdown}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
