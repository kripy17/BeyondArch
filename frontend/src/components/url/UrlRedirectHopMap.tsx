import React, { useState } from 'react';
import { RedirectHop } from '../../lib/url/url-dissector';
import {
  CornerDownRight,
  ExternalLink,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  Server,
  Network,
  Copy,
  Check,
  Compass,
} from 'lucide-react';

interface UrlRedirectHopMapProps {
  redirectChain: RedirectHop[];
  onSelectTarget?: (url: string) => void;
}

export const UrlRedirectHopMap: React.FC<UrlRedirectHopMapProps> = ({
  redirectChain,
  onSelectTarget,
}) => {
  const [copiedHop, setCopiedHop] = useState<number | null>(null);

  const handleCopy = (url: string, hop: number, e?: React.MouseEvent) => {
    e?.stopPropagation();
    navigator.clipboard.writeText(url);
    setCopiedHop(hop);
    setTimeout(() => setCopiedHop(null), 1800);
  };

  if (!redirectChain || redirectChain.length === 0) {
    return null;
  }

  const isMultiHop = redirectChain.length > 1;
  const finalHop = redirectChain[redirectChain.length - 1];

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-5 shadow-2xl backdrop-blur">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-500/10 text-sky-400 ring-1 ring-sky-500/30">
            <Network className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold tracking-wide text-zinc-100 uppercase">
                HTTP Redirect Hop Explorer & Delivery Chain
              </h3>
              <span
                className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                  isMultiHop
                    ? 'bg-amber-500/20 text-amber-300 ring-1 ring-amber-500/30'
                    : 'bg-emerald-500/20 text-emerald-300 ring-1 ring-emerald-500/30'
                }`}
              >
                {isMultiHop ? `${redirectChain.length} Hops Detected` : 'Direct Destination'}
              </span>
            </div>
            <p className="text-xs text-zinc-400">
              Traces HTTP status codes, shortener expansions, and open redirect evasion relays
            </p>
          </div>
        </div>

        {isMultiHop && onSelectTarget && (
          <button
            onClick={() => onSelectTarget(finalHop.url)}
            className="flex items-center gap-1.5 rounded-md bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white shadow hover:bg-indigo-500 transition-colors"
          >
            <Compass className="h-3.5 w-3.5" />
            Analyze Final Landing Page
          </button>
        )}
      </div>

      {/* Hop Chain List */}
      <div className="mt-4 space-y-3">
        {redirectChain.map((hop, index) => {
          const isLast = index === redirectChain.length - 1;
          const statusColor =
            hop.statusCode >= 300 && hop.statusCode < 400
              ? 'bg-amber-500/20 text-amber-300 ring-amber-500/30'
              : hop.statusCode === 200
              ? 'bg-emerald-500/20 text-emerald-300 ring-emerald-500/30'
              : 'bg-zinc-800 text-zinc-300 ring-zinc-700';

          return (
            <div key={hop.hop} className="relative">
              {/* Connector line between hops */}
              {!isLast && (
                <div className="absolute left-4 top-11 bottom-0 w-0.5 bg-gradient-to-b from-sky-500/50 to-zinc-800" />
              )}

              <div className="flex items-start gap-3 rounded-lg border border-zinc-800/80 bg-zinc-900/50 p-3 hover:border-zinc-700 transition-colors">
                {/* Hop Number Badge */}
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-zinc-800 text-xs font-bold font-mono text-zinc-200 ring-1 ring-zinc-700">
                  {hop.hop}
                </div>

                {/* Hop Details */}
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className={`rounded px-2 py-0.5 text-[11px] font-mono font-bold ring-1 ${statusColor}`}>
                        {hop.statusCode} {hop.statusText}
                      </span>

                      <span className="rounded bg-zinc-800 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-zinc-400">
                        {hop.hopType.replace('_', ' ')}
                      </span>

                      <span className="flex items-center gap-1 text-xs font-semibold text-zinc-200">
                        <Server className="h-3 w-3 text-zinc-400" />
                        {hop.host}
                      </span>
                    </div>

                    <button
                      onClick={(e) => handleCopy(hop.url, hop.hop, e)}
                      className="flex items-center gap-1 text-[11px] text-zinc-400 hover:text-zinc-200 transition-colors"
                      title="Copy hop target URL"
                    >
                      {copiedHop === hop.hop ? (
                        <>
                          <Check className="h-3 w-3 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                  </div>

                  <div className="mt-1.5 font-mono text-xs text-zinc-300 break-all select-all">
                    {hop.url}
                  </div>

                  <div className="mt-1 text-xs text-zinc-500">
                    <span className="text-zinc-400 font-medium">Notes: </span>
                    {hop.notes}
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
