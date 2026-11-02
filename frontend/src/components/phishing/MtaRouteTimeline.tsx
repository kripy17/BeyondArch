import React, { useState } from 'react';
import { MtaHop } from '../../lib/phishing/email-header-parser';
import {
  GitCommit,
  Clock,
  AlertTriangle,
  Server,
  Shield,
  Copy,
  Check,
  ArrowDown,
  Layers,
} from 'lucide-react';

interface MtaRouteTimelineProps {
  mtaHops: MtaHop[];
}

export const MtaRouteTimeline: React.FC<MtaRouteTimelineProps> = ({ mtaHops }) => {
  const [copiedHop, setCopiedHop] = useState<number | null>(null);

  const handleCopy = (text: string, hopNum: number) => {
    navigator.clipboard.writeText(text);
    setCopiedHop(hopNum);
    setTimeout(() => setCopiedHop(null), 1800);
  };

  if (!mtaHops || mtaHops.length === 0) {
    return null;
  }

  // Chronological order: 1 = origin (oldest), N = recipient (newest)
  const chronologicalHops = [...mtaHops].sort((a, b) => a.chronologicalIndex - b.chronologicalIndex);

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-5 shadow-2xl backdrop-blur">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-purple-500/10 text-purple-400 ring-1 ring-purple-500/30">
            <Layers className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold tracking-wide text-zinc-100 uppercase">
                MTA Route Hop Timeline & Transit Latency
              </h3>
              <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] font-mono text-zinc-400">
                {mtaHops.length} Relay Hops
              </span>
            </div>
            <p className="text-xs text-zinc-400">
              Chronological mail transfer path from originating submission client to final recipient MX
            </p>
          </div>
        </div>
      </div>

      {/* Timeline Steps */}
      <div className="mt-5 relative">
        <div className="space-y-4">
          {chronologicalHops.map((hop, index) => {
            const isOrigin = index === 0;
            const isDestination = index === chronologicalHops.length - 1;
            const isLastInList = index === chronologicalHops.length - 1;

            return (
              <div key={hop.hop} className="relative flex items-start gap-3.5">
                {/* Connecting vertical line */}
                {!isLastInList && (
                  <div className="absolute left-[15px] top-8 bottom-[-16px] w-0.5 bg-gradient-to-b from-purple-500/60 via-zinc-700 to-zinc-800" />
                )}

                {/* Node icon */}
                <div
                  className={`relative z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-xs font-bold ring-2 ${
                    isOrigin
                      ? 'bg-amber-500/20 text-amber-300 ring-amber-500/40'
                      : isDestination
                      ? 'bg-emerald-500/20 text-emerald-300 ring-emerald-500/40'
                      : 'bg-zinc-800 text-zinc-300 ring-zinc-700'
                  }`}
                >
                  {hop.chronologicalIndex}
                </div>

                {/* Hop Card */}
                <div className="min-w-0 flex-1 rounded-lg border border-zinc-800/80 bg-zinc-900/50 p-3 hover:border-zinc-700 transition-colors">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                          isOrigin
                            ? 'bg-amber-500/20 text-amber-300 ring-1 ring-amber-500/30'
                            : isDestination
                            ? 'bg-emerald-500/20 text-emerald-300 ring-1 ring-emerald-500/30'
                            : 'bg-zinc-800 text-zinc-400'
                        }`}
                      >
                        {isOrigin ? 'Originating Client' : isDestination ? 'Recipient Inbound MX' : 'Intermediate Relay'}
                      </span>

                      {/* Transit delay badge */}
                      <span
                        className={`flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-mono font-medium ring-1 ${
                          hop.delayAnomaly
                            ? 'bg-rose-500/20 text-rose-300 ring-rose-500/40'
                            : hop.clockSkew
                            ? 'bg-yellow-500/20 text-yellow-300 ring-yellow-500/30'
                            : 'bg-zinc-800 text-zinc-300 ring-zinc-700'
                        }`}
                        title={hop.delayAnomaly ? 'Abnormal delay > 1 hour detected between hops' : undefined}
                      >
                        <Clock className="h-3 w-3" />
                        {hop.delayHuman}
                      </span>
                    </div>

                    <button
                      onClick={() => handleCopy(hop.raw, hop.hop)}
                      className="flex items-center gap-1 text-[11px] text-zinc-400 hover:text-zinc-200 transition-colors"
                      title="Copy raw Received header line"
                    >
                      {copiedHop === hop.hop ? (
                        <>
                          <Check className="h-3 w-3 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" />
                          <span>Copy Raw</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* Host and Protocol Details */}
                  <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                    <div className="rounded bg-zinc-950/60 p-2 border border-zinc-800/60">
                      <span className="text-zinc-500 block text-[10px] uppercase">Relayed From:</span>
                      <span className="text-zinc-200 font-semibold truncate block" title={hop.fromHost || 'Unknown'}>
                        {hop.fromHost || 'Unknown sender host'}
                      </span>
                      {hop.ips.length > 0 && (
                        <span className="text-[11px] text-zinc-400 block mt-0.5">
                          IP: {hop.ips.join(', ')}
                        </span>
                      )}
                    </div>

                    <div className="rounded bg-zinc-950/60 p-2 border border-zinc-800/60">
                      <span className="text-zinc-500 block text-[10px] uppercase">Relayed By:</span>
                      <span className="text-zinc-200 font-semibold truncate block" title={hop.byHost || 'Unknown'}>
                        {hop.byHost || 'Unknown receiving MTA'}
                      </span>
                      {hop.withProtocol && (
                        <span className="text-[11px] text-purple-300 block mt-0.5">
                          Protocol: {hop.withProtocol}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Timestamp */}
                  {hop.timestamp && (
                    <div className="mt-2 flex items-center gap-1.5 text-[11px] text-zinc-400 font-mono">
                      <span className="text-zinc-500">Timestamp:</span>
                      <span>{hop.timestamp}</span>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
