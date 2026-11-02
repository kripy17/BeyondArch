import React, { useState } from 'react';
import { HomographResult } from '../../lib/url/url-dissector';
import {
  Globe,
  AlertOctagon,
  Copy,
  Check,
  ShieldAlert,
  HelpCircle,
  Code,
  ArrowRight,
} from 'lucide-react';

interface HomographInspectorProps {
  homograph: HomographResult;
  apexDomain: string;
}

export const HomographInspector: React.FC<HomographInspectorProps> = ({
  homograph,
  apexDomain,
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const isSuspicious = homograph.isPunycode || homograph.hasConfusables || homograph.isMixedScript;

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-5 shadow-2xl backdrop-blur">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div
            className={`flex h-8 w-8 items-center justify-center rounded-lg ring-1 ${
              isSuspicious
                ? 'bg-rose-500/10 text-rose-400 ring-rose-500/30'
                : 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30'
            }`}
          >
            <Globe className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold tracking-wide text-zinc-100 uppercase">
                IDN Homograph & Punycode Imposter Inspector
              </h3>
              <span
                className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                  isSuspicious
                    ? 'bg-rose-500/20 text-rose-300 ring-1 ring-rose-500/30'
                    : 'bg-zinc-800 text-zinc-400'
                }`}
              >
                {isSuspicious ? 'Homoglyph Attack Detected' : 'Clean Latin Script'}
              </span>
            </div>
            <p className="text-xs text-zinc-400">
              Identifies Cyrillic, Greek, and Unicode lookalike glyphs used to spoof trusted brand domains
            </p>
          </div>
        </div>
      </div>

      {/* Impersonated Brand Alert Card */}
      {homograph.impersonatedBrand && (
        <div className="mt-4 flex items-start gap-3 rounded-lg border border-rose-500/40 bg-rose-500/10 p-3.5 text-rose-200">
          <AlertOctagon className="h-5 w-5 shrink-0 text-rose-400 mt-0.5" />
          <div>
            <div className="font-semibold text-sm text-rose-200">
              Brand Lookalike Impersonation: Target is '{homograph.impersonatedBrand.toUpperCase()}'
            </div>
            <div className="text-xs text-rose-300/90 mt-0.5">
              This domain uses internationalized characters to visually impersonate{' '}
              <span className="font-bold underline">{homograph.impersonatedBrand}</span> while resolving to an
              unrelated infrastructure controlled by the adversary.
            </div>
          </div>
        </div>
      )}

      {/* Side by Side Comparison Cards */}
      <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* Card 1: Punycode Wire Format */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3">
          <div className="flex items-center justify-between text-xs text-zinc-400">
            <span className="font-medium">Punycode (Wire ASCII)</span>
            <button
              onClick={() => handleCopy(homograph.punycodeAscii, 'puny')}
              className="text-zinc-500 hover:text-zinc-300 transition-colors"
              title="Copy Punycode ASCII"
            >
              {copiedKey === 'puny' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            </button>
          </div>
          <div className="mt-1.5 font-mono text-sm font-semibold text-zinc-100 break-all select-all">
            {homograph.punycodeAscii}
          </div>
          <div className="mt-1 text-[11px] text-zinc-500">
            DNS query string transmitted over wire
          </div>
        </div>

        {/* Card 2: Rendered Unicode Domain */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3">
          <div className="flex items-center justify-between text-xs text-zinc-400">
            <span className="font-medium">Rendered Unicode</span>
            <button
              onClick={() => handleCopy(homograph.unicodeString, 'unicode')}
              className="text-zinc-500 hover:text-zinc-300 transition-colors"
              title="Copy Rendered Unicode"
            >
              {copiedKey === 'unicode' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            </button>
          </div>
          <div className="mt-1.5 font-mono text-sm font-semibold text-rose-300 break-all select-all">
            {homograph.unicodeString}
          </div>
          <div className="mt-1 text-[11px] text-zinc-500">
            Visual glyph appearance in unsuspecting browsers
          </div>
        </div>

        {/* Card 3: Target Brand / Normalized */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3">
          <div className="flex items-center justify-between text-xs text-zinc-400">
            <span className="font-medium">Normalized Latin Target</span>
            {homograph.impersonatedBrand && (
              <button
                onClick={() => handleCopy(`${homograph.impersonatedBrand}.com`, 'target')}
                className="text-zinc-500 hover:text-zinc-300 transition-colors"
                title="Copy Target Domain"
              >
                {copiedKey === 'target' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
              </button>
            )}
          </div>
          <div className="mt-1.5 font-mono text-sm font-semibold text-emerald-400 break-all">
            {homograph.impersonatedBrand ? `${homograph.impersonatedBrand}.com` : apexDomain}
          </div>
          <div className="mt-1 text-[11px] text-zinc-500">
            Legitimate organization being mimicked
          </div>
        </div>
      </div>

      {/* Confusable Characters Breakdown Table */}
      {homograph.confusableChars.length > 0 && (
        <div className="mt-4">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 mb-2">
            Dissected Lookalike Characters ({homograph.confusableChars.length})
          </h4>
          <div className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-900/40">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-zinc-800 text-[11px] text-zinc-400">
                  <th className="py-2 px-3">Position</th>
                  <th className="py-2 px-3">Adversary Glyph</th>
                  <th className="py-2 px-3">Unicode Code Point</th>
                  <th className="py-2 px-3">Script Origin</th>
                  <th className="py-2 px-3">Intended Latin Target</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60">
                {homograph.confusableChars.map((char, index) => (
                  <tr key={index} className="hover:bg-zinc-800/30 transition-colors">
                    <td className="py-2 px-3 text-zinc-500">Index {char.position}</td>
                    <td className="py-2 px-3 font-bold text-base text-rose-400">{char.char}</td>
                    <td className="py-2 px-3">
                      <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-[11px] text-zinc-300">
                        {char.codePoint}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-zinc-300">{char.script}</td>
                    <td className="py-2 px-3">
                      <div className="flex items-center gap-1.5 font-bold text-emerald-400">
                        <span>{char.lookalikeLatin}</span>
                        <span className="text-[10px] text-zinc-500 font-normal">(Latin script)</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
