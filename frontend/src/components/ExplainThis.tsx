import { useState } from "react";
import { Lightbulb, X } from "lucide-react";

function explainPcap(raw: string): string {
  const lines: string[] = [];
  const ips = raw.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g);
  const uniqueIPs = ips ? [...new Set(ips)] : [];
  if (uniqueIPs.length) lines.push(`Contains ${uniqueIPs.length} unique IP address(es).`);
  const protocols = ["HTTP", "DNS", "HTTPS", "SMB", "RDP", "SSH", "FTP", "SMTP", "TLS"];
  const found = protocols.filter((p) => new RegExp(p, "i").test(raw));
  if (found.length) lines.push(`Detected protocols: ${found.join(", ")}.`);
  if (/suspicious|malicious|alert|malware|c2|beacon/i.test(raw)) lines.push("Suspicious indicators present — investigate further.");
  if (/dns|resolve|query/i.test(raw)) lines.push("DNS activity detected — check for suspicious domains or data exfiltration.");
  if (/tls|ssl|certificate|handshake/i.test(raw)) lines.push("Encrypted traffic (TLS) detected — inspect certificates for suspicious issuers.");
  if (!lines.length) lines.push("No structured packet data found. Use tshark for deeper protocol analysis.");
  lines.push("", "Tip: Focus on external IPs and unusual protocol combinations for initial triage.");
  return lines.join("\n");
}

function explainEmail(raw: string): string {
  const lines: string[] = [];
  const spf = raw.match(/spf=(\w+)/i) || raw.match(/SPF:\s*(\w+)/i);
  if (spf) lines.push(`SPF result: ${spf[1].toUpperCase()} — ${spf[1].toLowerCase() === "pass" ? "sender authorized" : spf[1].toLowerCase() === "fail" ? "sender NOT authorized (spoof risk)" : "neutral/soft — review headers"}.`);
  const dkim = raw.match(/dkim=(\w+)/i) || raw.match(/DKIM:\s*(\w+)/i);
  if (dkim) lines.push(`DKIM result: ${dkim[1].toUpperCase()} — ${dkim[1].toLowerCase() === "pass" ? "email integrity verified" : "signature invalid or missing — possible tampering"}.`);
  const dmarc = raw.match(/dmarc=(\w+)/i) || raw.match(/DMARC:\s*(\w+)/i);
  if (dmarc) lines.push(`DMARC result: ${dmarc[1].toUpperCase()} — ${dmarc[1].toLowerCase() === "pass" ? "domain alignment confirmed" : "policy failure — domain may be spoofed"}.`);
  if (/(reply-to|return-path)/i.test(raw)) lines.push("Reply-To / Return-Path present — check for mismatch with From address (common phish indicator).");
  if (/received.*from/i.test(raw)) {
    const hops = raw.match(/received:\s*from\s+\S+/gi);
    if (hops) lines.push(`${hops.length} hop(s) in delivery path — trace the originating IP.`);
  }
  if (/(form|password|credential|login|verify|update.*account)/i.test(raw)) lines.push("Body contains credential-harvesting lures (form/password/login keywords).");
  if (/(invoice|payment|overdue|urgent)/i.test(raw)) lines.push("Urgency/invoice lures detected — common in BEC and invoice fraud.");
  if (!lines.length) lines.push("Review headers for authentication failures (SPF/DKIM/DMARC) and body for social-engineering lures.");
  lines.push("", "Tip: Cross-check sender domain age and MX records for lookalike domains.");
  return lines.join("\n");
}

export function ExplainThisButton({ kind, input }: { kind: "pcap" | "email"; input: string }) {
  const [open, setOpen] = useState(false);
  if (!input.trim()) return null;

  const explain = kind === "pcap" ? explainPcap : explainEmail;
  const text = explain(input);

  return (
    <div className="relative inline-block">
      <button onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-1 rounded border border-warning/40 bg-warning/10 px-1.5 py-0.5 text-mono ba-text-2xs text-warning hover:bg-warning/20"
        title="Explain this output"
      >
        <Lightbulb className="h-3 w-3" /> explain
      </button>
      {open && (
        <div className="absolute right-0 top-full z-50 mt-1 w-80 rounded border border-warning/30 bg-popover p-3 shadow-lg">
          <div className="mb-1.5 flex items-center justify-between">
            <span className="text-mono ba-text-2xs text-warning">what this means</span>
            <button onClick={() => setOpen(false)} aria-label="Close explanation" title="Close" className="text-muted-foreground hover:text-foreground"><X className="h-3 w-3" /></button>
          </div>
          <pre className="whitespace-pre-wrap text-mono ba-text-sm text-fg-dim leading-relaxed">{text}</pre>
        </div>
      )}
    </div>
  );
}
