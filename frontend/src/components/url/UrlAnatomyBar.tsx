import React, { useState } from 'react';
import { UrlAnatomy, defangUrl, refangUrl } from '../../lib/url/url-dissector';
import {
  Copy,
  Check,
  ShieldAlert,
  Terminal,
  ExternalLink,
  Lock,
  Globe,
  Server,
  Code,
  Key,
  Activity,
  AlertTriangle,
  FolderTree,
} from 'lucide-react';
import { useLocker } from '@/lib/locker';

interface UrlAnatomyBarProps {
  anatomy: UrlAnatomy;
  onSelectComponent?: (part: string, value: string) => void;
}

export const UrlAnatomyBar: React.FC<UrlAnatomyBarProps> = ({ anatomy, onSelectComponent }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isDefanged, setIsDefanged] = useState(false);
  const { add: addLockerItem } = useLocker();

  const handleCopy = (text: string, key: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const displayedUrl = isDefanged ? defangUrl(anatomy.normalizedUrl) : anatomy.normalizedUrl;

  const handleStashDomain = () => {
    if (anatomy.apexDomain) {
      addLockerItem({
        value: anatomy.apexDomain,
        type: 'domain',
        source: '/url',
        note: `URL Analysis of ${anatomy.host}`,
      });
    }
  };

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-5 shadow-2xl backdrop-blur">
      {/* Top Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800/80 pb-3.5">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500/10 text-indigo-400 ring-1 ring-indigo-500/30">
            <Globe className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold tracking-wide text-zinc-100 uppercase">
                URL Anatomy & Structural Breakdown
              </h3>
              <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] font-mono text-zinc-400">
                RFC 3986
              </span>
            </div>
            <p className="text-xs text-zinc-400">
              Dissected into protocol, authority, hierarchical path, query, and entropy components
            </p>
          </div>
        </div>

        {/* Action Toolbar */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsDefanged(!isDefanged)}
            className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-all ${
              isDefanged
                ? 'bg-amber-500/20 text-amber-300 ring-1 ring-amber-500/40'
                : 'bg-zinc-900 text-zinc-300 hover:bg-zinc-800'
            }`}
            title="Toggle defanging for safe sharing without accidental clicks"
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            {isDefanged ? 'Defanged (hxxp)' : 'Defang'}
          </button>

          <a
            href={`/utils?input=${encodeURIComponent(anatomy.normalizedUrl)}`}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 rounded-md bg-zinc-900 px-2.5 py-1 text-xs font-medium text-zinc-300 hover:bg-zinc-800 transition-colors"
            title="Open in CyberChef Utilities"
          >
            <Terminal className="h-3.5 w-3.5 text-indigo-400" />
            CyberChef
          </a>

          <button
            onClick={handleStashDomain}
            className="flex items-center gap-1.5 rounded-md bg-zinc-900 px-2.5 py-1 text-xs font-medium text-emerald-400 hover:bg-zinc-800 transition-colors"
            title="Stash apex domain to IOC Locker"
          >
            <Lock className="h-3.5 w-3.5" />
            Stash Domain
          </button>

          <button
            onClick={(e) => handleCopy(displayedUrl, 'full', e)}
            className="flex items-center gap-1.5 rounded-md bg-zinc-900 px-2.5 py-1 text-xs font-medium text-zinc-300 hover:bg-zinc-800 transition-colors"
          >
            {copiedKey === 'full' ? (
              <>
                <Check className="h-3.5 w-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" />
                Copy URL
              </>
            )}
          </button>
        </div>
      </div>

      {/* Visual Anatomy Block Grid */}
      <div className="mt-4 flex flex-wrap items-center gap-1.5 rounded-lg border border-zinc-800/80 bg-zinc-900/60 p-2.5 font-mono text-xs overflow-x-auto">
        {/* Scheme */}
        <div
          onClick={() => onSelectComponent?.('scheme', anatomy.scheme)}
          className="group relative flex cursor-pointer items-center gap-1 rounded bg-indigo-500/15 px-2 py-1 text-indigo-300 ring-1 ring-indigo-500/30 hover:bg-indigo-500/25 transition-all"
          title="Click to inspect scheme"
        >
          <span className="text-[10px] text-indigo-400/70 select-none">SCHEME:</span>
          <span className="font-bold">{anatomy.scheme}://</span>
          <button
            onClick={(e) => handleCopy(anatomy.scheme, 'scheme', e)}
            className="opacity-0 group-hover:opacity-100 hover:text-white transition-opacity ml-1"
          >
            {copiedKey === 'scheme' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
          </button>
        </div>

        {/* Userinfo (Credentials) if present */}
        {(anatomy.username || anatomy.password) && (
          <div
            onClick={() => onSelectComponent?.('credentials', `${anatomy.username}:${anatomy.password || ''}`)}
            className="group relative flex cursor-pointer items-center gap-1 rounded bg-rose-500/20 px-2 py-1 text-rose-300 ring-1 ring-rose-500/50 hover:bg-rose-500/30 transition-all"
            title="Warning: Userinfo / Credentials embedded in URL"
          >
            <Key className="h-3 w-3 text-rose-400" />
            <span className="text-[10px] text-rose-400/80 select-none">USERINFO:</span>
            <span className="font-bold font-mono">
              {anatomy.username}:{anatomy.password ? '***' : ''}@
            </span>
            <button
              onClick={(e) => handleCopy(`${anatomy.username}:${anatomy.password || ''}`, 'userinfo', e)}
              className="opacity-0 group-hover:opacity-100 hover:text-white transition-opacity ml-1"
            >
              {copiedKey === 'userinfo' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            </button>
          </div>
        )}

        {/* Subdomain */}
        {anatomy.subdomain && (
          <div
            onClick={() => onSelectComponent?.('subdomain', anatomy.subdomain)}
            className="group relative flex cursor-pointer items-center gap-1 rounded bg-purple-500/15 px-2 py-1 text-purple-300 ring-1 ring-purple-500/30 hover:bg-purple-500/25 transition-all"
            title="Subdomain hierarchy"
          >
            <span className="text-[10px] text-purple-400/70 select-none">SUB:</span>
            <span className="font-medium">{anatomy.subdomain}.</span>
            <button
              onClick={(e) => handleCopy(anatomy.subdomain, 'subdomain', e)}
              className="opacity-0 group-hover:opacity-100 hover:text-white transition-opacity ml-1"
            >
              {copiedKey === 'subdomain' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            </button>
          </div>
        )}

        {/* Apex Domain */}
        <div
          onClick={() => onSelectComponent?.('apexDomain', anatomy.apexDomain)}
          className="group relative flex cursor-pointer items-center gap-1 rounded bg-emerald-500/15 px-2.5 py-1 text-emerald-300 ring-1 ring-emerald-500/40 hover:bg-emerald-500/25 transition-all font-semibold"
          title="Apex / Registrable Domain"
        >
          <Server className="h-3 w-3 text-emerald-400" />
          <span className="text-[10px] text-emerald-400/70 select-none">APEX:</span>
          <span>{anatomy.apexDomain}</span>
          <button
            onClick={(e) => handleCopy(anatomy.apexDomain, 'apex', e)}
            className="opacity-0 group-hover:opacity-100 hover:text-white transition-opacity ml-1"
          >
            {copiedKey === 'apex' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
          </button>
        </div>

        {/* Port */}
        {anatomy.port && (
          <div
            onClick={() => onSelectComponent?.('port', String(anatomy.port))}
            className={`group relative flex cursor-pointer items-center gap-1 rounded px-2 py-1 ring-1 transition-all ${
              anatomy.portCategory === 'c2_suspicious'
                ? 'bg-red-500/20 text-red-300 ring-red-500/50'
                : 'bg-zinc-800 text-zinc-300 ring-zinc-700'
            }`}
            title={`Port ${anatomy.port} (${anatomy.portCategory})`}
          >
            <span className="text-[10px] opacity-70 select-none">PORT:</span>
            <span className="font-bold">:{anatomy.port}</span>
            <button
              onClick={(e) => handleCopy(String(anatomy.port), 'port', e)}
              className="opacity-0 group-hover:opacity-100 hover:text-white transition-opacity ml-1"
            >
              {copiedKey === 'port' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            </button>
          </div>
        )}

        {/* Path */}
        {anatomy.path && anatomy.path !== '/' && (
          <div
            onClick={() => onSelectComponent?.('path', anatomy.path)}
            className="group relative flex cursor-pointer items-center gap-1 rounded bg-sky-500/15 px-2.5 py-1 text-sky-300 ring-1 ring-sky-500/30 hover:bg-sky-500/25 transition-all"
            title="URL Path"
          >
            <FolderTree className="h-3 w-3 text-sky-400" />
            <span className="text-[10px] text-sky-400/70 select-none">PATH:</span>
            <span>{anatomy.path}</span>
            <button
              onClick={(e) => handleCopy(anatomy.path, 'path', e)}
              className="opacity-0 group-hover:opacity-100 hover:text-white transition-opacity ml-1"
            >
              {copiedKey === 'path' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            </button>
          </div>
        )}

        {/* Query */}
        {anatomy.query && (
          <div
            onClick={() => onSelectComponent?.('query', anatomy.query)}
            className="group relative flex cursor-pointer items-center gap-1 rounded bg-amber-500/15 px-2.5 py-1 text-amber-300 ring-1 ring-amber-500/30 hover:bg-amber-500/25 transition-all"
            title="Query Parameters"
          >
            <Code className="h-3 w-3 text-amber-400" />
            <span className="text-[10px] text-amber-400/70 select-none">QUERY:</span>
            <span>?{anatomy.query.length > 35 ? `${anatomy.query.slice(0, 35)}...` : anatomy.query}</span>
            <button
              onClick={(e) => handleCopy(anatomy.query, 'query', e)}
              className="opacity-0 group-hover:opacity-100 hover:text-white transition-opacity ml-1"
            >
              {copiedKey === 'query' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            </button>
          </div>
        )}

        {/* Fragment */}
        {anatomy.fragment && (
          <div
            onClick={() => onSelectComponent?.('fragment', anatomy.fragment)}
            className="group relative flex cursor-pointer items-center gap-1 rounded bg-zinc-800 px-2 py-1 text-zinc-300 ring-1 ring-zinc-700"
          >
            <span className="text-[10px] text-zinc-500 select-none">HASH:</span>
            <span>#{anatomy.fragment}</span>
          </div>
        )}
      </div>

      {/* Security Telemetry & Entropy Badges */}
      <div className="mt-3.5 grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 p-2.5">
          <div className="flex items-center justify-between text-zinc-400">
            <span className="text-[11px] font-medium">Shannon Entropy</span>
            <Activity className={`h-3.5 w-3.5 ${anatomy.entropy.fullUrl > 4.5 ? 'text-amber-400' : 'text-zinc-500'}`} />
          </div>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className="text-base font-bold font-mono text-zinc-100">{anatomy.entropy.fullUrl}</span>
            <span className="text-[10px] text-zinc-400">bits/char</span>
          </div>
          <div className="mt-0.5 text-[10px] text-zinc-500">
            Path: {anatomy.entropy.path} | Query: {anatomy.entropy.query}
          </div>
        </div>

        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 p-2.5">
          <div className="flex items-center justify-between text-zinc-400">
            <span className="text-[11px] font-medium">Risk Score</span>
            <ShieldAlert className={`h-3.5 w-3.5 ${anatomy.riskScore >= 60 ? 'text-rose-400' : anatomy.riskScore >= 30 ? 'text-amber-400' : 'text-emerald-400'}`} />
          </div>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className={`text-base font-bold font-mono ${
              anatomy.riskScore >= 60 ? 'text-rose-400' : anatomy.riskScore >= 30 ? 'text-amber-400' : 'text-emerald-400'
            }`}>
              {anatomy.riskScore}/100
            </span>
            <span className="text-[10px] uppercase tracking-wider font-semibold text-zinc-400">
              {anatomy.verdict.replace('_', ' ')}
            </span>
          </div>
          <div className="mt-0.5 text-[10px] text-zinc-500">
            {anatomy.signals.length} heuristic signal(s)
          </div>
        </div>

        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 p-2.5">
          <div className="flex items-center justify-between text-zinc-400">
            <span className="text-[11px] font-medium">Port Class</span>
            <Server className="h-3.5 w-3.5 text-zinc-500" />
          </div>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className="text-base font-bold font-mono text-zinc-100">
              {anatomy.port ? `Port ${anatomy.port}` : anatomy.scheme.toUpperCase()}
            </span>
          </div>
          <div className="mt-0.5 text-[10px] text-zinc-500 capitalize">
            {anatomy.portCategory.replace('_', ' ')}
          </div>
        </div>

        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 p-2.5">
          <div className="flex items-center justify-between text-zinc-400">
            <span className="text-[11px] font-medium">Domain Script</span>
            <Globe className="h-3.5 w-3.5 text-zinc-500" />
          </div>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className={`text-base font-bold font-mono ${anatomy.homograph.isMixedScript ? 'text-rose-400' : 'text-zinc-100'}`}>
              {anatomy.homograph.isMixedScript ? 'Mixed Script' : anatomy.homograph.isPunycode ? 'IDN Punycode' : 'Latin'}
            </span>
          </div>
          <div className="mt-0.5 text-[10px] text-zinc-500">
            {anatomy.homograph.confusableChars.length} confusable glyph(s)
          </div>
        </div>
      </div>
    </div>
  );
};
