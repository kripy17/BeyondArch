import React, { useState } from 'react';
import { LinkDiscrepancy } from '../../lib/phishing/email-header-parser';
import {
  Link2,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Compass,
  Copy,
  Check,
  ArrowRight,
} from 'lucide-react';
import { useNavigate } from '@tanstack/react-router';

interface LinkDiscrepancyGridProps {
  discrepancies: LinkDiscrepancy[];
  onTriageUrl?: (url: string) => void;
}

export const LinkDiscrepancyGrid: React.FC<LinkDiscrepancyGridProps> = ({
  discrepancies,
  onTriageUrl,
}) => {
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleCopy = (url: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    navigator.clipboard.writeText(url);
    setCopiedUrl(url);
    setTimeout(() => setCopiedUrl(null), 1800);
  };

  const handleNavigateToUrlWorkbench = (href: string) => {
    if (onTriageUrl) {
      onTriageUrl(href);
    } else {
      navigate({ to: '/url' });
    }
  };

  if (!discrepancies || discrepancies.length === 0) {
    return null;
  }

  const mismatchCount = discrepancies.filter((d) => d.status === 'DECEPTIVE MISMATCH').length;

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-5 shadow-2xl backdrop-blur">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div
            className={`flex h-8 w-8 items-center justify-center rounded-lg ring-1 ${
              mismatchCount > 0
                ? 'bg-rose-500/10 text-rose-400 ring-rose-500/30'
                : 'bg-indigo-500/10 text-indigo-400 ring-indigo-500/30'
            }`}
          >
            <Link2 className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold tracking-wide text-zinc-100 uppercase">
                Hyperlink Discrepancy & Masking Inspector
              </h3>
              <span
                className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                  mismatchCount > 0
                    ? 'bg-rose-500/20 text-rose-300 ring-1 ring-rose-500/30'
                    : 'bg-emerald-500/20 text-emerald-300 ring-1 ring-emerald-500/30'
                }`}
              >
                {mismatchCount > 0 ? `${mismatchCount} Deceptive Link(s)` : 'All Links Align'}
              </span>
            </div>
            <p className="text-xs text-zinc-400">
              Compares anchor display text seen by victim vs destination href clicked by browser
            </p>
          </div>
        </div>
      </div>

      {/* Discrepancy List / Grid */}
      <div className="mt-4 space-y-3">
        {discrepancies.map((item, index) => {
          const isMismatch = item.status === 'DECEPTIVE MISMATCH';
          const isRedirect = item.status === 'OPEN REDIRECT';

          return (
            <div
              key={index}
              className={`rounded-lg border p-3.5 transition-colors ${
                isMismatch
                  ? 'border-rose-500/30 bg-rose-500/5 hover:border-rose-500/50'
                  : isRedirect
                  ? 'border-amber-500/30 bg-amber-500/5 hover:border-amber-500/50'
                  : 'border-zinc-800/80 bg-zinc-900/40 hover:border-zinc-700'
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800/60 pb-2.5">
                <div className="flex items-center gap-2">
                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-mono font-bold uppercase ring-1 ${
                      isMismatch
                        ? 'bg-rose-500/20 text-rose-300 ring-rose-500/30 animate-pulse'
                        : isRedirect
                        ? 'bg-amber-500/20 text-amber-300 ring-amber-500/30'
                        : 'bg-emerald-500/20 text-emerald-300 ring-emerald-500/30'
                    }`}
                  >
                    {item.status}
                  </span>

                  <span className="text-xs text-zinc-400">
                    {item.reason}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={(e) => handleCopy(item.href, e)}
                    className="flex items-center gap-1 text-[11px] text-zinc-400 hover:text-zinc-200 transition-colors"
                    title="Copy destination link"
                  >
                    {copiedUrl === item.href ? (
                      <>
                        <Check className="h-3 w-3 text-emerald-400" />
                        <span className="text-emerald-400">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" />
                        <span>Copy Href</span>
                      </>
                    )}
                  </button>

                  <button
                    onClick={() => handleNavigateToUrlWorkbench(item.href)}
                    className="flex items-center gap-1 rounded bg-indigo-600/20 px-2 py-0.5 text-[11px] font-semibold text-indigo-300 ring-1 ring-indigo-500/30 hover:bg-indigo-600/30 transition-colors"
                    title="Send URL to URL Forensic Workbench for dissection"
                  >
                    <Compass className="h-3 w-3" />
                    Triage in URL Workbench →
                  </button>
                </div>
              </div>

              {/* Side-by-Side Comparison */}
              <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                {/* Left: What Victim Sees */}
                <div className="rounded bg-zinc-950/70 p-2.5 border border-zinc-800/80">
                  <div className="flex items-center justify-between text-[10px] uppercase text-zinc-500 font-sans font-semibold mb-1">
                    <span>What Victim Sees (Display Text):</span>
                    {item.anchorDomain && (
                      <span className="text-indigo-400 lowercase font-mono">
                        domain: {item.anchorDomain}
                      </span>
                    )}
                  </div>
                  <div className="text-zinc-200 font-medium break-all select-all">
                    {item.anchorText || '<No visible text>'}
                  </div>
                </div>

                {/* Right: Where Browser Navigates */}
                <div
                  className={`rounded p-2.5 border ${
                    isMismatch
                      ? 'bg-rose-950/20 border-rose-500/40 text-rose-200'
                      : 'bg-zinc-950/70 border-zinc-800/80 text-zinc-200'
                  }`}
                >
                  <div className="flex items-center justify-between text-[10px] uppercase text-zinc-500 font-sans font-semibold mb-1">
                    <span className={isMismatch ? 'text-rose-400 font-bold' : ''}>
                      Where It Actually Goes (Destination Href):
                    </span>
                    <span className="text-zinc-400 lowercase font-mono">
                      domain: {item.hrefDomain}
                    </span>
                  </div>
                  <div className="font-semibold break-all select-all">
                    {item.href}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
