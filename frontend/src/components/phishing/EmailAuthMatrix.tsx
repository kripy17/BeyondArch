import React from 'react';
import { AuthQuadCheck } from '../../lib/phishing/email-header-parser';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Lock,
  Key,
  FileCheck,
  Link,
} from 'lucide-react';

interface EmailAuthMatrixProps {
  auth: AuthQuadCheck;
  fromDomain: string;
}

export const EmailAuthMatrix: React.FC<EmailAuthMatrixProps> = ({ auth, fromDomain }) => {
  const isDmarcPass = auth.dmarc.aligned && auth.dmarc.result === 'pass';

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-5 shadow-2xl backdrop-blur">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div
            className={`flex h-8 w-8 items-center justify-center rounded-lg ring-1 ${
              isDmarcPass
                ? 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30'
                : 'bg-rose-500/10 text-rose-400 ring-rose-500/30'
            }`}
          >
            {isDmarcPass ? <ShieldCheck className="h-4 w-4" /> : <ShieldAlert className="h-4 w-4" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold tracking-wide text-zinc-100 uppercase">
                Email Authentication Quad-Check Matrix
              </h3>
              <span
                className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                  isDmarcPass
                    ? 'bg-emerald-500/20 text-emerald-300 ring-1 ring-emerald-500/30'
                    : 'bg-rose-500/20 text-rose-300 ring-1 ring-rose-500/30'
                }`}
              >
                {isDmarcPass ? 'DMARC Aligned' : 'DMARC Alignment Failed'}
              </span>
            </div>
            <p className="text-xs text-zinc-400">
              Evaluates SPF, DKIM, DMARC, and ARC cryptographic alignment against From domain ({fromDomain || 'N/A'})
            </p>
          </div>
        </div>
      </div>

      {/* DMARC Summary Banner */}
      <div
        className={`mt-4 flex items-start gap-3 rounded-lg border p-3.5 ${
          isDmarcPass
            ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
            : 'border-rose-500/30 bg-rose-500/10 text-rose-200'
        }`}
      >
        {isDmarcPass ? (
          <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-400 mt-0.5" />
        ) : (
          <XCircle className="h-5 w-5 shrink-0 text-rose-400 mt-0.5" />
        )}
        <div className="text-xs">
          <div className="font-semibold text-sm">
            {isDmarcPass
              ? 'DMARC Passed & Aligned: High Sender Confidence'
              : 'DMARC Verification Failed: Domain Spoofing or Unauthorized Relay'}
          </div>
          <div className="mt-0.5 opacity-90 leading-relaxed">
            {isDmarcPass ? (
              <span>
                The sender address aligns with verified SPF/DKIM records for <span className="font-bold">{fromDomain}</span>.
              </span>
            ) : (
              <span>
                Even if third-party SPF or DKIM passed for a mailing vendor, the domain in the From header (
                <span className="font-bold underline">{fromDomain}</span>) failed alignment.
                {auth.dmarc.policy && (
                  <span className="ml-1 font-semibold text-rose-300">
                    Domain policy specifies p={auth.dmarc.policy.toUpperCase()}.
                  </span>
                )}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* 4 Quadrant Grid: SPF, DKIM, DMARC, ARC */}
      <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Quadrant 1: SPF */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3.5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-zinc-300">
                <Lock className="h-3.5 w-3.5 text-indigo-400" />
                SPF (Sender Policy)
              </div>
              <span
                className={`rounded px-1.5 py-0.5 text-[10px] font-mono font-bold uppercase ring-1 ${
                  auth.spf.result === 'pass'
                    ? 'bg-emerald-500/20 text-emerald-300 ring-emerald-500/30'
                    : auth.spf.result === 'fail' || auth.spf.result === 'softfail'
                    ? 'bg-rose-500/20 text-rose-300 ring-rose-500/30'
                    : 'bg-zinc-800 text-zinc-400 ring-zinc-700'
                }`}
              >
                {auth.spf.result}
              </span>
            </div>

            <div className="mt-2.5 space-y-1.5 text-xs font-mono">
              <div className="flex items-center justify-between text-zinc-400">
                <span>SPF Domain:</span>
                <span className="text-zinc-200 font-semibold truncate max-w-[130px]" title={auth.spf.domain}>
                  {auth.spf.domain || 'N/A'}
                </span>
              </div>
              <div className="flex items-center justify-between text-zinc-400">
                <span>From Alignment:</span>
                <span className={auth.spf.aligned ? 'text-emerald-400 font-semibold' : 'text-rose-400 font-semibold'}>
                  {auth.spf.aligned ? 'ALIGNED' : 'MISALIGNED'}
                </span>
              </div>
            </div>
          </div>
          <div className="mt-3 pt-2 border-t border-zinc-800/60 text-[11px] text-zinc-500">
            Validates sending server IP against DNS TXT record
          </div>
        </div>

        {/* Quadrant 2: DKIM */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3.5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-zinc-300">
                <Key className="h-3.5 w-3.5 text-purple-400" />
                DKIM (Digital Signature)
              </div>
              <span
                className={`rounded px-1.5 py-0.5 text-[10px] font-mono font-bold uppercase ring-1 ${
                  auth.dkim.result === 'pass'
                    ? 'bg-emerald-500/20 text-emerald-300 ring-emerald-500/30'
                    : auth.dkim.result === 'fail'
                    ? 'bg-rose-500/20 text-rose-300 ring-rose-500/30'
                    : 'bg-zinc-800 text-zinc-400 ring-zinc-700'
                }`}
              >
                {auth.dkim.result}
              </span>
            </div>

            <div className="mt-2.5 space-y-1.5 text-xs font-mono">
              <div className="flex items-center justify-between text-zinc-400">
                <span>Signing d=:</span>
                <span className="text-zinc-200 font-semibold truncate max-w-[130px]" title={auth.dkim.domain}>
                  {auth.dkim.domain || 'N/A'}
                </span>
              </div>
              <div className="flex items-center justify-between text-zinc-400">
                <span>Selector s=:</span>
                <span className="text-zinc-300 truncate max-w-[130px]" title={auth.dkim.selector}>
                  {auth.dkim.selector || 'N/A'}
                </span>
              </div>
              <div className="flex items-center justify-between text-zinc-400">
                <span>From Alignment:</span>
                <span className={auth.dkim.aligned ? 'text-emerald-400 font-semibold' : 'text-rose-400 font-semibold'}>
                  {auth.dkim.aligned ? 'ALIGNED' : 'MISALIGNED'}
                </span>
              </div>
            </div>
          </div>
          <div className="mt-3 pt-2 border-t border-zinc-800/60 text-[11px] text-zinc-500">
            Cryptographic signature guaranteeing message integrity
          </div>
        </div>

        {/* Quadrant 3: DMARC */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3.5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-zinc-300">
                <ShieldCheck className="h-3.5 w-3.5 text-sky-400" />
                DMARC Enforcement
              </div>
              <span
                className={`rounded px-1.5 py-0.5 text-[10px] font-mono font-bold uppercase ring-1 ${
                  auth.dmarc.result === 'pass'
                    ? 'bg-emerald-500/20 text-emerald-300 ring-emerald-500/30'
                    : 'bg-rose-500/20 text-rose-300 ring-rose-500/30'
                }`}
              >
                {auth.dmarc.result}
              </span>
            </div>

            <div className="mt-2.5 space-y-1.5 text-xs font-mono">
              <div className="flex items-center justify-between text-zinc-400">
                <span>Policy (p=):</span>
                <span className="text-zinc-200 uppercase font-bold">
                  {auth.dmarc.policy || 'none'}
                </span>
              </div>
              <div className="flex items-center justify-between text-zinc-400">
                <span>SPF Aligned:</span>
                <span className={auth.dmarc.spfAligned ? 'text-emerald-400 font-semibold' : 'text-rose-400 font-semibold'}>
                  {auth.dmarc.spfAligned ? 'YES' : 'NO'}
                </span>
              </div>
              <div className="flex items-center justify-between text-zinc-400">
                <span>DKIM Aligned:</span>
                <span className={auth.dmarc.dkimAligned ? 'text-emerald-400 font-semibold' : 'text-rose-400 font-semibold'}>
                  {auth.dmarc.dkimAligned ? 'YES' : 'NO'}
                </span>
              </div>
            </div>
          </div>
          <div className="mt-3 pt-2 border-t border-zinc-800/60 text-[11px] text-zinc-500">
            Enforces policy when SPF and DKIM fail alignment
          </div>
        </div>

        {/* Quadrant 4: ARC */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3.5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-zinc-300">
                <FileCheck className="h-3.5 w-3.5 text-amber-400" />
                ARC (Forwarding Chain)
              </div>
              <span
                className={`rounded px-1.5 py-0.5 text-[10px] font-mono font-bold uppercase ring-1 ${
                  auth.arc.present
                    ? 'bg-amber-500/20 text-amber-300 ring-amber-500/30'
                    : 'bg-zinc-800 text-zinc-400 ring-zinc-700'
                }`}
              >
                {auth.arc.present ? 'Present' : 'None'}
              </span>
            </div>

            <div className="mt-2.5 space-y-1.5 text-xs font-mono">
              <div className="flex items-center justify-between text-zinc-400">
                <span>ARC Chain:</span>
                <span className="text-zinc-200">
                  {auth.arc.present ? `${auth.arc.sealCount} Seal(s)` : 'Direct Delivery'}
                </span>
              </div>
              <div className="flex items-center justify-between text-zinc-400">
                <span>Forward Status:</span>
                <span className="text-zinc-300 uppercase">
                  {auth.arc.status}
                </span>
              </div>
            </div>
          </div>
          <div className="mt-3 pt-2 border-t border-zinc-800/60 text-[11px] text-zinc-500">
            Authenticated Received Chain preserves results through mailing lists
          </div>
        </div>
      </div>
    </div>
  );
};
