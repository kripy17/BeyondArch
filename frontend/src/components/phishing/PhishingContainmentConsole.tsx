import { useState, useMemo } from "react";
import {
  ShieldAlert, ShieldCheck, Mail, Terminal, Copy, Check,
  ExternalLink, Lock, AlertTriangle, UserCheck, Server
} from "lucide-react";
import { Chip } from "@/components/soc";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import type { EmailArtifactResult } from "@/lib/emailArtifact";
import type { ParsedEmailForensics } from "@/lib/phishing/email-header-parser";

interface PhishingContainmentConsoleProps {
  data: EmailArtifactResult;
  rawInput: string;
  emailForensics?: ParsedEmailForensics | null;
}

export function PhishingContainmentConsole({
  data,
  rawInput,
  emailForensics,
}: PhishingContainmentConsoleProps) {
  const [activeTab, setActiveTab] = useState<"m365" | "gam" | "identity" | "ticket">("m365");
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

  // 1. Executive Phishing Assessment & Narrative
  const assessment = useMemo(() => {
    const spfFail = data.auth.spf === "fail";
    const dmarcFail = data.auth.dmarc === "fail";
    const dkimFail = data.auth.dkim === "fail";
    const hasForms = data.hasForm || data.hasPasswordField;
    const hasDiscrepantLinks = (emailForensics?.linkDiscrepancies || []).some(
      (d) => d.status === "DECEPTIVE MISMATCH" || d.status === "SUBDOMAIN SPOOF"
    );
    const hasBrandSpoof = (data.brandClaims || []).length > 0 && (spfFail || dmarcFail);
    const isUrgent = data.urgency;
    const hasAttachment = data.hasAttachment.hasAttachments;
    const replyMismatch = data.replyMismatch;

    let verdict = "BENIGN / LEGITIMATE COMMUNICATION";
    let tone: "destructive" | "warning" | "success" = "success";
    let score = 12;
    let targetPersona = "Standard Recipient";

    if (hasForms || (hasBrandSpoof && hasDiscrepantLinks)) {
      verdict = "CRITICAL: CREDENTIAL HARVESTING & BRAND SPOOFING";
      tone = "destructive";
      score = 96;
      targetPersona = "Corporate SSO / M365 Credentials";
    } else if (hasBrandSpoof || (replyMismatch && isUrgent)) {
      verdict = "HIGH RISK: EXECUTIVE IMPERSONATION / BEC WIRE FRAUD";
      tone = "destructive";
      score = 88;
      targetPersona = "Finance / Accounts Payable / Wire Authorizers";
    } else if (hasAttachment) {
      verdict = "HIGH RISK: WEAPONIZED ATTACHMENT DROPPER";
      tone = "destructive";
      score = 82;
      targetPersona = "Corporate Workstation Endpoints";
    } else if (spfFail || dmarcFail || dkimFail || isUrgent) {
      verdict = "SUSPICIOUS: HEURISTIC AUTHENTICATION ANOMALIES";
      tone = "warning";
      score = 58;
      targetPersona = "General Employee Mailbox";
    }

    // Synthesize natural language narrative
    const sender = data.fromLine || emailForensics?.headers.fromAddress || "unknown sender";
    const brand = data.brandClaims?.[0]?.brand || data.brandMatch || "trusted platform";
    const authSummary = `SPF: ${data.auth.spf.toUpperCase()}, DKIM: ${data.auth.dkim.toUpperCase()}, DMARC: ${data.auth.dmarc.toUpperCase()}`;
    
    let narrative = "";
    if (tone === "destructive") {
      narrative = `Adversary email originating from ${sender} impersonating ${brand} failed cryptographic domain validation (${authSummary}). Message weaponizes ${hasForms ? "embedded HTML authentication forms" : hasDiscrepantLinks ? "deceptive credential harvesting hyperlinks" : "social engineering urgency"} to induce unauthorized credential leakage or fraudulent action. Immediate tenant-wide mailbox purge and sender domain block recommended.`;
    } else if (tone === "warning") {
      narrative = `Message from ${sender} presents authentication irregularities (${authSummary})${replyMismatch ? " with mismatched Reply-To routing" : ""}. Sender exhibits heightened urgency indicators without definitive weaponized payloads. Exercise containment caution before user engagement.`;
    } else {
      narrative = `Cryptographic sender authentication passed (${authSummary}). No credential harvesting forms, deceptive link mismatches, or high-risk brand lures detected in email body or headers.`;
    }

    return { verdict, tone, score, targetPersona, narrative };
  }, [data, emailForensics]);

  // 2. Extracted Incident Parameters
  const params = useMemo(() => {
    const rawMsgId = emailForensics?.headers.messageId || rawInput.match(/Message-ID:\s*<([^>]+)>/i)?.[1] || "";
    const cleanMsgId = rawMsgId.replace(/[<>]/g, "").trim() || `phish-${Date.now()}@domain.com`;
    const senderEmail = emailForensics?.headers.fromAddress || data.fromLine.match(/<([^>]+)>/)?.[1] || data.fromLine || "attacker@hostile-domain.com";
    const senderDomain = data.fromDomain || emailForensics?.domains.fromDomain || "hostile-domain.com";
    const recipient = emailForensics?.headers.to || rawInput.match(/To:\s*<([^>]+)>/i)?.[1] || "user@organization.com";
    const subject = emailForensics?.headers.subject || rawInput.match(/Subject:\s*(.+)/i)?.[1]?.trim() || "Urgent Notification";
    return { cleanMsgId, senderEmail, senderDomain, recipient, subject };
  }, [data, emailForensics, rawInput]);

  // 3. Containment Scripts
  const containment = useMemo(() => {
    // A. Microsoft 365 Exchange Online (PowerShell)
    const m365Script = `# Microsoft 365 Exchange Online - Automated Phishing Purge
Connect-ExchangeOnline -UserPrincipalName admin@org.onmicrosoft.com

# 1. Create Tenant-Wide Compliance Search across all inboxes
$SearchName = "PhishPurge_${Date.now()}"
New-ComplianceSearch -Name $SearchName -ExchangeLocation All -ContentMatchQuery 'MessageId:"${params.cleanMsgId}"'
Start-ComplianceSearch -Identity $SearchName

# 2. Monitor Search Completion & Execute Hard Delete Action
New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType HardDelete -Confirm:$false

# 3. Block Sender in Tenant Allow/Block List (TABL) for 90 Days
New-TenantAllowBlockListItems -ListType Sender -Block -Entries "${params.senderEmail}", "*@${params.senderDomain}" -ExpirationDate (Get-Date).AddDays(90) -Notes "Automated SOC Block from BeyondArch Phishing Triage"`;

    // B. Google Workspace (GAM CLI)
    const gamScript = `# Google Workspace GAM / Workspace Admin CLI Purge
# 1. Purge message across all organization mailboxes via Message-ID
gam all users delete messages query "rfc822msgid:${params.cleanMsgId}" doit

# 2. Block sender domain at Google Workspace Inbound Gateway
gam create datapolicy block_sender address "${params.senderEmail}" domain "${params.senderDomain}"`;

    // C. Identity Session Kill (Entra ID / Azure AD)
    const identityScript = `# Microsoft Graph PowerShell - Compromised Recipient Session Revocation
Connect-MgGraph -Scopes "User.ReadWrite.All"

# Revoke active refresh tokens and sign-out user across all devices
Revoke-MgUserSignOutSession -UserId "${params.recipient}"
Write-Host "Active OAuth sessions terminated for target recipient: ${params.recipient}"`;

    // D. IR Incident Ticket Draft (Markdown)
    const ticketDraft = `### [P1/PHISH] Enterprise Mailbox Phishing Incident - Automated Triage
**Incident Timestamp:** ${new Date().toISOString()}
**Verdict:** ${assessment.verdict}
**Composite Risk Index:** ${assessment.score}/100
**Target Persona:** ${assessment.targetPersona}

#### Header & Provenance Telemetry:
- **Subject:** ${params.subject}
- **Sender Address:** \`${params.senderEmail}\` (Domain: \`${params.senderDomain}\`)
- **Target Recipient:** \`${params.recipient}\`
- **Message-ID:** \`<${params.cleanMsgId}>\`
- **Authentication Verdicts:** SPF=${data.auth.spf.toUpperCase()} | DKIM=${data.auth.dkim.toUpperCase()} | DMARC=${data.auth.dmarc.toUpperCase()}

#### Threat Narrative:
${assessment.narrative}

#### Executed SOC Containment Actions:
1. Initiated tenant-wide mailbox hard purge for Message-ID: \`<${params.cleanMsgId}>\`.
2. Appended sender \`${params.senderEmail}\` to Tenant Block List (TABL).
3. Revoked active session refresh tokens for recipient \`${params.recipient}\`.`;

    return { m365Script, gamScript, identityScript, ticketDraft };
  }, [params, assessment, data.auth]);

  return (
    <div id="phishing-containment-console" className="space-y-3.5 rounded-lg border border-border bg-surface-1 p-4 shadow-sm min-w-0 max-w-full font-mono mb-4">
      {/* Executive Threat Assessment Dossier */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-3">
        <div className="flex items-center gap-2">
          <ShieldAlert
            className={`h-4 w-4 shrink-0 ${
              assessment.tone === "destructive"
                ? "text-destructive"
                : assessment.tone === "warning"
                ? "text-warning"
                : "text-success"
            }`}
          />
          <span className="ba-text-xs font-bold uppercase tracking-wider text-foreground">
            Executive Phishing Threat Assessment Dossier
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Chip tone={assessment.tone}>{assessment.verdict}</Chip>
          <span className="ba-text-2xs text-muted-foreground font-semibold">
            Risk Score:{" "}
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
            Target: {assessment.targetPersona}
          </span>
        </div>
      </div>

      {/* Threat Narrative */}
      <p className="ba-text-xs text-fg-dim leading-relaxed bg-surface-0/70 p-3 rounded border border-border/40">
        {assessment.narrative}
      </p>

      {/* 4-Vector Explainable Risk Factors */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 pt-1">
        <div className="rounded border border-subtle bg-surface-0 p-2 text-center">
          <div className="ba-text-3xs text-muted-foreground">Sender Identity</div>
          <div className={`ba-text-xs font-bold mt-0.5 ${data.replyMismatch ? "text-warning" : "text-foreground"}`}>
            {data.replyMismatch ? "Reply Mismatch" : "Aligned"}
          </div>
        </div>

        <div className="rounded border border-subtle bg-surface-0 p-2 text-center">
          <div className="ba-text-3xs text-muted-foreground">Lure Pretext</div>
          <div className={`ba-text-xs font-bold mt-0.5 ${data.urgency ? "text-destructive" : "text-foreground"}`}>
            {data.urgency ? "High Coercion" : "Standard"}
          </div>
        </div>

        <div className="rounded border border-subtle bg-surface-0 p-2 text-center">
          <div className="ba-text-3xs text-muted-foreground">Payload / Form</div>
          <div className={`ba-text-xs font-bold mt-0.5 ${data.hasForm || data.hasPasswordField ? "text-destructive" : "text-foreground"}`}>
            {data.hasForm || data.hasPasswordField ? "HTML Form Trap" : "None"}
          </div>
        </div>

        <div className="rounded border border-subtle bg-surface-0 p-2 text-center">
          <div className="ba-text-3xs text-muted-foreground">Authentication</div>
          <div className={`ba-text-xs font-bold mt-0.5 ${data.auth.spf === "fail" || data.auth.dmarc === "fail" ? "text-destructive" : "text-success"}`}>
            {data.auth.spf === "fail" || data.auth.dmarc === "fail" ? "Auth Failed" : "Verified"}
          </div>
        </div>
      </div>

      {/* 1-Click SOC Containment Console */}
      <div className="rounded-md border border-subtle bg-surface-0 p-3 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/40 pb-2">
          <div className="flex items-center gap-2 text-foreground font-semibold ba-text-xs">
            <Terminal className="h-3.5 w-3.5 text-primary" />
            1-Click Mailbox & Tenant Containment Console
          </div>

          <div className="flex flex-wrap items-center gap-1">
            {(["m365", "gam", "identity", "ticket"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`rounded px-2 py-0.5 ba-text-3xs font-semibold transition-colors ${
                  activeTab === tab
                    ? "bg-primary text-primary-foreground"
                    : "border border-subtle bg-surface-1 text-muted-foreground hover:text-foreground"
                }`}
              >
                {tab === "m365"
                  ? "Exchange Online Purge"
                  : tab === "gam"
                  ? "Google Workspace GAM"
                  : tab === "identity"
                  ? "Entra ID Session Kill"
                  : "IR Ticket Draft"}
              </button>
            ))}
          </div>
        </div>

        {/* Console Action Script Display */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="ba-text-3xs text-muted-foreground">
              {activeTab === "m365"
                ? "PowerShell Exchange Online Compliance Search Purge & TABL Block"
                : activeTab === "gam"
                ? "Google Workspace GAM CLI Tenant-Wide Inactive Mailbox Purge"
                : activeTab === "identity"
                ? "Microsoft Graph Session Revocation & Sign-Out Command"
                : "Markdown Incident Report Summary"}
            </span>

            <button
              onClick={() => {
                const script =
                  activeTab === "m365"
                    ? containment.m365Script
                    : activeTab === "gam"
                    ? containment.gamScript
                    : activeTab === "identity"
                    ? containment.identityScript
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
              {copiedKey === activeTab ? "copied" : "copy command"}
            </button>
          </div>

          <pre className="max-h-48 overflow-x-auto whitespace-pre rounded border border-border/40 bg-surface-1 p-2.5 ba-text-3xs text-fg-dim leading-relaxed">
            {activeTab === "m365" && containment.m365Script}
            {activeTab === "gam" && containment.gamScript}
            {activeTab === "identity" && containment.identityScript}
            {activeTab === "ticket" && containment.ticketDraft}
          </pre>
        </div>
      </div>
    </div>
  );
}
