import { useState, useRef, useEffect } from "react";
import { useLocation } from "@tanstack/react-router";
import { useLocker, type LockerItem } from "@/lib/locker";
import { copyText } from "@/lib/copy";
import { X, PackageOpen, Copy, NotebookPen, ChevronUp, Network, PenLine, StickyNote } from "lucide-react";
import { toast } from "sonner";
import { InvestigationGraphPanel } from "@/components/investigation/InvestigationGraph";
import { sendToCase } from "@/lib/handoff";

const TYPE_COLORS: Record<string, string> = {
  ipv4: "text-[var(--ansi-blue)]", ipv6: "text-[var(--ansi-blue)]",
  domain: "text-[var(--ansi-cyan)]", url: "text-[var(--ansi-green)]",
  sha256: "text-[var(--ansi-magenta)]", sha1: "text-[var(--ansi-magenta)]", md5: "text-[var(--ansi-magenta)]",
  email: "text-[var(--ansi-yellow)]",
  file: "text-[var(--ansi-cyan)]",
};

export function IocLockerTrigger({ onClick, count }: { onClick: () => void; count: number }) {
  const [showMenu, setShowMenu] = useState(false);
  const [showGraph, setShowGraph] = useState(false);
  const [showScratchpad, setShowScratchpad] = useState(false);
  const [showAttach, setShowAttach] = useState(false);

  return (
    <>
      <div className="fixed bottom-6 right-6 z-40 flex flex-col items-end gap-2">
        {showMenu && (
          <>
            <div className="fixed inset-0 z-40" onClick={() => setShowMenu(false)} />
            <div className="z-50 flex flex-col gap-1 rounded-lg border border-border bg-card p-1.5 elevation-raised">
              <button
                onClick={() => { setShowMenu(false); onClick(); }}
                className="flex items-center gap-2 rounded-md px-3 py-2 text-left text-mono ba-text-2xs text-fg-dim hover:bg-primary/5"
              >
                <PackageOpen className="h-4 w-4 text-primary" />
                <span>IOC Locker</span>
                {count > 0 && (
                  <span className="ml-auto rounded-full bg-destructive px-1.5 py-0.5 text-mono ba-text-3xs font-bold text-destructive-foreground">
                    {count > 99 ? "99+" : count}
                  </span>
                )}
              </button>
              <button
                onClick={() => { setShowMenu(false); setShowGraph(true); }}
                className="flex items-center gap-2 rounded-md px-3 py-2 text-left text-mono ba-text-2xs text-fg-dim hover:bg-primary/5"
              >
                <Network className="h-4 w-4 text-primary" />
                <span>Investigation Graph</span>
              </button>
              <button
                onClick={() => { setShowMenu(false); setShowScratchpad(true); }}
                className="flex items-center gap-2 rounded-md px-3 py-2 text-left text-mono ba-text-2xs text-fg-dim hover:bg-primary/5"
              >
                <PenLine className="h-4 w-4 text-primary" />
                <span>Scratchpad</span>
              </button>
              <button
                onClick={() => { setShowMenu(false); setShowAttach(true); }}
                className="flex items-center gap-2 rounded-md px-3 py-2 text-left text-mono ba-text-2xs text-fg-dim hover:bg-primary/5"
              >
                <StickyNote className="h-4 w-4 text-primary" />
                <span>Attach to Case</span>
              </button>
            </div>
          </>
        )}

        <button
          onClick={() => setShowMenu((v) => !v)}
          className="flex h-12 w-12 items-center justify-center rounded-full border border-primary/40 bg-primary/15 text-primary shadow-glow transition-all hover:-translate-y-0.5 hover:bg-primary/25"
          aria-label="Quick actions"
        >
          {showMenu ? <ChevronUp className="h-5 w-5" /> : <PackageOpen className="h-5 w-5" />}
          {!showMenu && count > 0 && (
            <span className="absolute -right-1 -top-1 flex h-5 w-5 items-center justify-center rounded-full bg-destructive text-mono ba-text-3xs font-bold text-destructive-foreground">
              {count > 99 ? "99+" : count}
            </span>
          )}
        </button>
      </div>

      <InvestigationGraphPanel open={showGraph} onClose={() => setShowGraph(false)} />
      <ScratchpadPanel open={showScratchpad} onClose={() => setShowScratchpad(false)} />
      <AttachPanel open={showAttach} onClose={() => setShowAttach(false)} />
    </>
  );
}

export function ScratchpadPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [text, setText] = useState("");
  const textRef = useRef(text);
  textRef.current = text;
  const drawerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    try { const v = localStorage.getItem("ba.scratchpad"); if (v) setText(v); } catch {}
  }, []);

  useEffect(() => {
    const timer = setInterval(() => {
      try { localStorage.setItem("ba.scratchpad", textRef.current); } catch {}
    }, 3000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (open) {
      const el = drawerRef.current?.querySelector<HTMLElement>("textarea,input") ?? drawerRef.current?.querySelector<HTMLElement>("button");
      el?.focus();
    }
  }, [open]);

  return (
    <>
      {open && <div className="fixed inset-0 z-50 bg-black/30 backdrop-blur-sm" onClick={onClose} />}
      <div
        ref={drawerRef}
        inert={!open}
        aria-hidden={!open}
        className={
          "fixed bottom-0 right-0 top-0 z-50 flex w-full max-w-xl flex-col border-l border-border bg-background/95 backdrop-blur transition-transform duration-300 " +
          (open ? "translate-x-0" : "translate-x-full")
        }
      >
        <header className="flex items-center gap-2 border-b border-divider-strong px-3 py-2">
          <span className="grid h-6 w-6 place-items-center rounded border border-primary/40 bg-primary/10 text-primary">
            <PenLine className="h-3.5 w-3.5" />
          </span>
          <span className="text-mono ba-text-3xs text-foreground">Scratchpad</span>
          <span className="text-mono ba-text-3xs text-muted-foreground">auto-saves</span>
          <div className="ml-auto flex items-center gap-1">
            <button onClick={onClose} aria-label="Close scratchpad" title="Close" className="grid h-5 w-5 place-items-center rounded border border-border text-muted-foreground hover:text-foreground"><X className="h-3 w-3" /></button>
          </div>
        </header>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Escape") onClose(); }}
          placeholder="Quick notes, observations, pending points…"
          aria-label="Scratchpad notes"
          className="flex-1 resize-none bg-surface-0 p-3 font-mono ba-text-sm text-foreground outline-none placeholder:text-fg-dim"
        />
        <footer className="flex items-center justify-between border-t border-border px-3 py-2 text-mono ba-text-3xs text-muted-foreground">
          <span>{text.length} chars</span>
          <button onClick={onClose} className="rounded border border-border px-2 py-0.5 hover:border-primary/40 hover:text-primary transition-colors duration-150">
            close
          </button>
        </footer>
      </div>
    </>
  );
}

export function AttachPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [text, setText] = useState("");
  const location = useLocation();
  const drawerRef = useRef<HTMLDivElement>(null);

  const activeId = (() => { try { return localStorage.getItem("ba.cases.active") || ""; } catch { return ""; } })();
  const hasActive = activeId.length > 0;

  useEffect(() => {
    if (open) {
      const el = drawerRef.current?.querySelector<HTMLElement>("textarea,input") ?? drawerRef.current?.querySelector<HTMLElement>("button");
      el?.focus();
    }
  }, [open]);

  const doAttach = () => {
    if (!text.trim() || !hasActive) return;
    sendToCase({ body: text.trim(), source: location.pathname, kind: "evidence" });
    setText("");
    toast("Attached to case");
    onClose();
  };

  return (
    <>
      {open && <div className="fixed inset-0 z-50 bg-black/30 backdrop-blur-sm" onClick={onClose} />}
      <div
        ref={drawerRef}
        inert={!open}
        aria-hidden={!open}
        className={
          "fixed bottom-0 right-0 top-0 z-50 flex w-full max-w-md flex-col border-l border-border bg-background/95 backdrop-blur transition-transform duration-300 " +
          (open ? "translate-x-0" : "translate-x-full")
        }
      >
        <header className="flex items-center gap-2 border-b border-divider-strong px-3 py-2">
          <span className="grid h-6 w-6 place-items-center rounded border border-primary/40 bg-primary/10 text-primary">
            <StickyNote className="h-3.5 w-3.5" />
          </span>
          <span className="text-mono ba-text-3xs text-foreground">Attach to Case</span>
          <span className="text-mono ba-text-3xs text-muted-foreground">{hasActive ? `case ${activeId}` : "no active case"}</span>
          <div className="ml-auto flex items-center gap-1">
            <button onClick={onClose} aria-label="Close attach panel" title="Close" className="grid h-5 w-5 place-items-center rounded border border-border text-muted-foreground hover:text-foreground"><X className="h-3 w-3" /></button>
          </div>
        </header>
        <div className="flex-1 overflow-y-auto p-3">
          {!hasActive ? (
            <div className="flex flex-col items-center gap-2 px-4 py-16 text-mono ba-text-2xs text-muted-foreground">
              <StickyNote className="h-8 w-8 opacity-40" />
              <p>No active case.</p>
              <p className="ba-text-2xs">Open a case first, then attach evidence from this workspace.</p>
            </div>
          ) : (
            <>
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { e.preventDefault(); doAttach(); } if (e.key === "Escape") onClose(); }}
                placeholder="Evidence text…"
                aria-label="Evidence text to attach"
                rows={8}
                className="w-full resize-y rounded border border-border bg-surface-0 p-2 text-mono ba-text-2xs text-foreground outline-none focus:border-primary/50"
              />
              <div className="mt-1.5 flex items-center justify-between">
                <span className="text-mono ba-text-3xs text-fg-dim">Evidence note</span>
                <button onClick={doAttach} disabled={!text.trim()} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-mono ba-text-2xs text-primary hover:bg-primary/20 disabled:opacity-40 transition-colors duration-150">
                  <StickyNote className="h-3 w-3" /> attach
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
}

export function IocLockerPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { items, remove, clear } = useLocker();

  return (
    <>
      {open && (
        <div className="fixed inset-0 z-50 bg-black/30 backdrop-blur-sm" onClick={onClose} />
      )}
      <div
        inert={!open}
        aria-hidden={!open}
        className={
          "fixed bottom-0 right-0 top-0 z-50 flex w-full max-w-md flex-col border-l border-border bg-background/95 backdrop-blur transition-transform duration-300 " +
          (open ? "translate-x-0" : "translate-x-full")
        }
      >
        <header className="flex items-center gap-2 border-b border-divider-strong px-4 py-3">
          <span className="grid h-7 w-7 place-items-center rounded-md border border-primary/40 bg-primary/10 text-primary">
            <PackageOpen className="h-4 w-4" />
          </span>
          <h2 className="text-mono ba-text-xs text-foreground">IOC Locker</h2>
          <span className="text-mono ba-text-2xs text-muted-foreground">{items.length} items</span>
          <div className="ml-auto flex items-center gap-1">
            {items.length > 0 && (
              <button
                onClick={() => { clear(); toast("Locker cleared"); }}
                className="rounded border border-divider-strong px-2 py-1 text-mono ba-text-2xs text-muted-foreground transition-colors duration-150 hover:border-destructive/50 hover:text-destructive"
              >
                clear all
              </button>
            )}
            <button onClick={onClose} aria-label="Close IOC locker" title="Close" className="grid h-7 w-7 place-items-center rounded-md border border-border text-muted-foreground hover:text-foreground transition-colors duration-150">
              <X className="h-4 w-4" />
            </button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto">
          {items.length === 0 ? (
            <div className="flex flex-col items-center gap-2 px-4 py-16 text-mono ba-text-2xs text-muted-foreground">
              <PackageOpen className="h-8 w-8 opacity-40" />
              <p>No IOCs collected yet.</p>
              <p className="ba-text-2xs">Use the locker from any workspace.</p>
            </div>
          ) : (
            <div className="divide-y divide-border/50">
              {items.map((item) => (
                <LockerRow key={item.id} item={item} onRemove={remove} />
              ))}
            </div>
          )}
        </div>

        {items.length > 0 && (
          <footer className="border-t border-divider-strong px-4 py-2">
            <div className="flex items-center gap-2 text-mono ba-text-2xs text-muted-foreground">
              <span>{items.filter((i) => i.type === "ipv4" || i.type === "domain").length} network</span>
              <span className="text-border/60">·</span>
              <span>{items.filter((i) => i.type === "sha256" || i.type === "sha1" || i.type === "md5").length} hashes</span>
              <span className="text-border/60">·</span>
              <span>{items.filter((i) => i.type === "url").length} urls</span>
            </div>
          </footer>
        )}
      </div>
    </>
  );
}

function LockerRow({ item, onRemove }: { item: LockerItem; onRemove: (id: string) => void }) {
  const { updateNote } = useLocker();
  const [editingNote, setEditingNote] = useState(false);
  const [noteDraft, setNoteDraft] = useState(item.note ?? "");
  const ts = new Date(item.ts).toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });

  return (
    <div className="group px-4 py-2.5 transition-colors duration-150 hover:bg-surface-1">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className={"text-mono ba-text-3xs" + (TYPE_COLORS[item.type] ?? "text-muted-foreground")}>
              {item.type}
            </span>
            <span className="text-mono ba-text-3xs text-fg-dim">{ts}</span>
          </div>
          <code className="mt-0.5 block truncate ba-text-xs text-foreground">{item.value}</code>
          <span className="text-mono ba-text-3xs text-muted-foreground">from {item.source}</span>
        </div>
        <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
          <button
            onClick={() => { copyText(item.value); toast("Copied"); }}
            className="grid h-6 w-6 place-items-center rounded border border-border text-muted-foreground hover:text-foreground"
            aria-label="Copy"
          >
            <Copy className="h-3 w-3" />
          </button>
          <button
            onClick={() => onRemove(item.id)}
            className="grid h-6 w-6 place-items-center rounded border border-border text-muted-foreground hover:text-destructive"
            aria-label="Remove"
          >
            <X className="h-3 w-3" />
          </button>
        </div>
      </div>

      {(item.note || editingNote) && (
        <div className="mt-1.5 flex items-start gap-1">
          <NotebookPen className="mt-0.5 h-3 w-3 shrink-0 text-fg-dim" />
          {editingNote ? (
            <div className="flex flex-1 items-center gap-1">
              <input
                value={noteDraft}
                onChange={(e) => setNoteDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") { updateNote(item.id, noteDraft); setEditingNote(false); }
                  if (e.key === "Escape") { setNoteDraft(item.note ?? ""); setEditingNote(false); }
                }}
                onBlur={() => { updateNote(item.id, noteDraft); setEditingNote(false); }}
                className="min-w-0 flex-1 rounded border border-divider-strong bg-surface-0 px-1.5 py-0.5 text-mono ba-text-2xs text-foreground outline-none"
                placeholder="Add a note…"
                aria-label="Add a note to this IOC"
                autoFocus
              />
            </div>
          ) : (
            <button onClick={() => { setEditingNote(true); }} className="flex-1 text-left ba-text-2xs text-muted-foreground/80 hover:text-foreground">
              {item.note}
            </button>
          )}
        </div>
      )}

      {!item.note && !editingNote && (
        <button
          onClick={() => { setEditingNote(true); setNoteDraft(item.note ?? ""); }}
          className="mt-1 text-mono ba-text-3xs text-muted-foreground hover:text-fg-dim"
        >
          + add note
        </button>
      )}
    </div>
  );
}
