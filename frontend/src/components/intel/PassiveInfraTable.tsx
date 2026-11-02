import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import {
  Globe,
  Server,
  Lock,
  Copy,
  Check,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  BookmarkPlus,
  RefreshCw,
  Clock,
  Fingerprint,
} from "lucide-react";
import type { PassiveDnsRecord, WhoisData, SslCertificateData } from "@/lib/intel/threat-intel-engine";
import { defang } from "@/lib/ioc-patterns";
import { useLocker } from "@/lib/locker";
import { notify } from "@/lib/notify";
import { cn } from "@/lib/utils";

interface PassiveInfraTableProps {
  indicator: string;
  indicatorType: string;
  passiveDns: PassiveDnsRecord[];
  whois?: WhoisData | null;
  sslCert?: SslCertificateData | null;
  coHosted?: { domain: string; ip: string; status: string }[];
  className?: string;
}

type TabType = "dns" | "whois" | "ssl" | "cohosted";

export function PassiveInfraTable({
  indicator,
  indicatorType,
  passiveDns,
  whois,
  sslCert,
  coHosted,
  className,
}: PassiveInfraTableProps) {
  const navigate = useNavigate();
  const locker = useLocker();
  const [activeTab, setActiveTab] = useState<TabType>("dns");
  const [defangEnabled, setDefangEnabled] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  function copyText(text: string, id: string) {
    const toCopy = defangEnabled ? defang(text) : text;
    navigator.clipboard.writeText(toCopy);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
    notify.success("Copied indicator to clipboard");
  }

  function handleStashToLocker(val: string, type: any = "domain") {
    locker.add({
      value: val,
      type: type,
      source: `/intel (${indicator})`,
    });
    notify.success(`Stashed ${val} to Locker`);
  }

  const displayTarget = defangEnabled ? defang(indicator) : indicator;

  return (
    <div className={cn("rounded-lg border border-subtle bg-surface-1/60 p-4", className)}>
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-subtle pb-3">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-sky-400" />
          <h3 className="font-mono text-sm font-bold uppercase tracking-wider text-foreground">
            Passive Infrastructure & Attribution Footprint
          </h3>
          <span className="rounded border border-subtle bg-surface-2 px-1.5 py-px font-mono ba-text-3xs text-muted-foreground uppercase">
            {indicatorType}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <label className="flex cursor-pointer items-center gap-1.5 font-mono ba-text-2xs text-muted-foreground">
            <input
              type="checkbox"
              checked={defangEnabled}
              onChange={(e) => setDefangEnabled(e.target.checked)}
              className="accent-[var(--primary)]"
            />
            Defang Indicators
          </label>

          <button
            onClick={() => navigate({ to: "/url", search: { url: indicator } })}
            className="inline-flex items-center gap-1 rounded border border-subtle bg-surface-0 px-2 py-1 font-mono ba-text-2xs text-muted-foreground hover:border-primary/40 hover:text-foreground"
          >
            Triage in URL Workbench <ArrowRight className="h-3 w-3" />
          </button>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="mt-3 flex flex-wrap gap-1 border-b border-subtle/70 pb-2">
        <button
          onClick={() => setActiveTab("dns")}
          className={cn(
            "flex items-center gap-1.5 rounded px-2.5 py-1 font-mono ba-text-2xs transition-colors",
            activeTab === "dns"
              ? "bg-primary/20 text-primary font-semibold border border-primary/40"
              : "text-muted-foreground hover:text-foreground hover:bg-surface-0"
          )}
        >
          <Server className="h-3.5 w-3.5" /> Passive DNS ({passiveDns.length})
        </button>

        {whois && (
          <button
            onClick={() => setActiveTab("whois")}
            className={cn(
              "flex items-center gap-1.5 rounded px-2.5 py-1 font-mono ba-text-2xs transition-colors",
              activeTab === "whois"
                ? "bg-primary/20 text-primary font-semibold border border-primary/40"
                : "text-muted-foreground hover:text-foreground hover:bg-surface-0"
            )}
          >
            <Clock className="h-3.5 w-3.5" /> WHOIS / Registration
          </button>
        )}

        {sslCert && (
          <button
            onClick={() => setActiveTab("ssl")}
            className={cn(
              "flex items-center gap-1.5 rounded px-2.5 py-1 font-mono ba-text-2xs transition-colors",
              activeTab === "ssl"
                ? "bg-primary/20 text-primary font-semibold border border-primary/40"
                : "text-muted-foreground hover:text-foreground hover:bg-surface-0"
            )}
          >
            <Lock className="h-3.5 w-3.5" /> SSL/TLS & Fingerprints
          </button>
        )}

        {coHosted && coHosted.length > 0 && (
          <button
            onClick={() => setActiveTab("cohosted")}
            className={cn(
              "flex items-center gap-1.5 rounded px-2.5 py-1 font-mono ba-text-2xs transition-colors",
              activeTab === "cohosted"
                ? "bg-primary/20 text-primary font-semibold border border-primary/40"
                : "text-muted-foreground hover:text-foreground hover:bg-surface-0"
            )}
          >
            <Fingerprint className="h-3.5 w-3.5" /> Co-Hosted Subnet ({coHosted.length})
          </button>
        )}
      </div>

      {/* TAB 1: PASSIVE DNS */}
      {activeTab === "dns" && (
        <div className="mt-3 overflow-x-auto">
          <table className="w-full text-left font-mono ba-text-2xs border-collapse">
            <thead>
              <tr className="border-b border-subtle bg-surface-0/60 text-muted-foreground">
                <th className="py-2 px-2.5">Type</th>
                <th className="py-2 px-2.5">Host</th>
                <th className="py-2 px-2.5">Resolved Value</th>
                <th className="py-2 px-2.5">First Seen / Last Seen</th>
                <th className="py-2 px-2.5">ASN / Organization</th>
                <th className="py-2 px-2.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-subtle/50">
              {passiveDns.map((record) => {
                const hostDisplay = defangEnabled ? defang(record.host) : record.host;
                const valDisplay = defangEnabled ? defang(record.value) : record.value;
                return (
                  <tr key={record.id} className="hover:bg-surface-0/40 transition-colors">
                    <td className="py-2 px-2.5">
                      <span className="rounded border border-sky-500/40 bg-sky-500/10 px-1.5 py-0.5 font-bold text-sky-400">
                        {record.recordType}
                      </span>
                    </td>
                    <td className="py-2 px-2.5 text-foreground truncate max-w-[180px]" title={record.host}>
                      {hostDisplay}
                    </td>
                    <td className="py-2 px-2.5 font-medium text-foreground truncate max-w-[220px]" title={record.value}>
                      {valDisplay}
                    </td>
                    <td className="py-2 px-2.5 text-muted-foreground text-[11px]">
                      {record.firstSeen.split("T")[0]} → {record.lastSeen.split("T")[0]}
                    </td>
                    <td className="py-2 px-2.5 text-fg-dim text-[11px] truncate max-w-[180px]">
                      {record.asn}
                    </td>
                    <td className="py-2 px-2.5 text-right space-x-1.5 whitespace-nowrap">
                      <button
                        onClick={() => copyText(record.value, record.id)}
                        className="rounded p-1 text-muted-foreground hover:bg-surface-2 hover:text-foreground"
                        title="Copy resolved value"
                      >
                        {copiedId === record.id ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                      </button>
                      <button
                        onClick={() => handleStashToLocker(record.value, record.recordType === "A" ? "ipv4" : "domain")}
                        className="rounded p-1 text-muted-foreground hover:bg-surface-2 hover:text-foreground"
                        title="Stash to Locker"
                      >
                        <BookmarkPlus className="h-3 w-3" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* TAB 2: WHOIS & REGISTRATION */}
      {activeTab === "whois" && whois && (
        <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3 font-mono ba-text-xs">
          <div className="rounded border border-subtle bg-surface-0/60 p-3 space-y-2">
            <div className="font-bold text-foreground border-b border-subtle pb-1">
              Registration Lifecycle
            </div>
            <div>
              <span className="text-muted-foreground">Domain: </span>
              <span className="text-foreground font-semibold">{displayTarget}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Registrar: </span>
              <span className="text-foreground">{whois.registrar}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Created: </span>
              <span className="text-foreground">{whois.registeredDate}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Expires: </span>
              <span className="text-foreground">{whois.expiryDate}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Domain Age: </span>
              <span className="text-amber-400 font-bold">{whois.domainAgeDays} days old</span>
            </div>
          </div>

          <div className="rounded border border-subtle bg-surface-0/60 p-3 space-y-2">
            <div className="font-bold text-foreground border-b border-subtle pb-1">
              Privacy & Authority
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-muted-foreground">Privacy Protection: </span>
              {whois.privacyProtected ? (
                <span className="inline-flex items-center gap-1 text-amber-400 font-semibold ba-text-2xs">
                  <ShieldAlert className="h-3 w-3" /> WHOIS Guard Enabled
                </span>
              ) : (
                <span className="text-emerald-400 font-semibold ba-text-2xs">Publicly Disclosed</span>
              )}
            </div>
            <div>
              <span className="text-muted-foreground">Country: </span>
              <span className="text-foreground">{whois.registrantCountry}</span>
            </div>
            <div>
              <span className="text-muted-foreground block mb-1">Nameservers:</span>
              <div className="flex flex-wrap gap-1">
                {whois.nameservers.map((ns) => (
                  <span key={ns} className="rounded border border-subtle bg-surface-2 px-1.5 py-0.5 ba-text-3xs text-fg-dim">
                    {defangEnabled ? defang(ns) : ns}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: SSL / TLS CERTIFICATE */}
      {activeTab === "ssl" && sslCert && (
        <div className="mt-3 rounded border border-subtle bg-surface-0/60 p-3 font-mono ba-text-xs space-y-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-subtle pb-1.5">
            <div className="font-bold text-foreground">
              X.509 TLS Certificate & Client Fingerprints
            </div>
            <div className="ba-text-2xs text-emerald-400 font-semibold">
              Valid: {sslCert.validFrom.split("T")[0]} → {sslCert.validUntil.split("T")[0]}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <div>
              <span className="text-muted-foreground">Subject CN: </span>
              <span className="text-foreground font-semibold">{defangEnabled ? defang(sslCert.subjectCn) : sslCert.subjectCn}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Issuer: </span>
              <span className="text-foreground">{sslCert.issuer}</span>
            </div>
            <div className="sm:col-span-2">
              <span className="text-muted-foreground block mb-1">Subject Alternative Names (SANs):</span>
              <div className="flex flex-wrap gap-1">
                {sslCert.sanList.map((san) => (
                  <span key={san} className="rounded border border-subtle bg-surface-2 px-1.5 py-0.5 ba-text-3xs text-fg-dim">
                    {defangEnabled ? defang(san) : san}
                  </span>
                ))}
              </div>
            </div>
          </div>

          <div className="border-t border-subtle/80 pt-2 grid grid-cols-1 sm:grid-cols-2 gap-2">
            <div className="rounded border border-subtle bg-surface-1 p-2">
              <div className="ba-text-3xs text-muted-foreground font-bold">JA3 CLIENT HASH</div>
              <div className="mt-0.5 text-amber-400 font-bold select-all">{sslCert.ja3Hash}</div>
            </div>
            <div className="rounded border border-subtle bg-surface-1 p-2">
              <div className="ba-text-3xs text-muted-foreground font-bold">JA4 TLS FINGERPRINT</div>
              <div className="mt-0.5 text-sky-400 font-bold select-all">{sslCert.ja4Fingerprint}</div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: CO-HOSTED INFRASTRUCTURE */}
      {activeTab === "cohosted" && coHosted && (
        <div className="mt-3 space-y-1.5">
          <div className="font-mono ba-text-2xs text-muted-foreground mb-2">
            Known hostnames sharing the same IP address or bulletproof ASN subnet:
          </div>
          {coHosted.map((item, idx) => (
            <div
              key={idx}
              className="flex items-center justify-between rounded border border-subtle bg-surface-0 px-3 py-2 font-mono ba-text-xs"
            >
              <div className="flex items-center gap-2">
                <Globe className="h-3.5 w-3.5 text-sky-400" />
                <span className="font-semibold text-foreground">
                  {defangEnabled ? defang(item.domain) : item.domain}
                </span>
                <span className="ba-text-3xs text-muted-foreground">({item.ip})</span>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={cn(
                    "rounded px-1.5 py-0.5 font-mono ba-text-3xs font-semibold",
                    item.status === "active" ? "bg-rose-500/20 text-rose-300" : "bg-surface-2 text-muted-foreground"
                  )}
                >
                  {item.status.toUpperCase()}
                </span>
                <button
                  onClick={() => navigate({ to: "/intel", search: { q: item.domain } })}
                  className="rounded p-1 text-muted-foreground hover:bg-surface-2 hover:text-foreground"
                  title="Pivot to Intel lookup"
                >
                  <ExternalLink className="h-3 w-3" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
