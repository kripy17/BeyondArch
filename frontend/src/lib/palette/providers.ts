import {
  LayoutDashboard, ListChecks, MailWarning, Link2, File, Paperclip,
  ScrollText, Globe,
  FileText, Clock, Bug, ShieldCheck, Target, FlaskConical,
  Activity, Wand2, Wrench, Code2, Search, Bookmark,
  BookOpen, Settings,
  Plus, PackageOpen, Palette,
  Database, SearchIcon, Notebook,
  FolderOpen, ShieldAlert, Play, Trash2, CircleSlash,
  type LucideIcon,
} from "lucide-react";
import { notify } from "@/lib/notify";
import { GROUPS, findItem } from "@/lib/workspaces";
import { setActiveCaseId } from "@/data/case";
import type { SearchItem } from "@/lib/search-index";
import type { PaletteProvider, CommandResult, PaletteContext } from "./types";
import { detectObservable, observableLabel } from "./intent";
import { loadRecentCommands } from "./recent";
import { createMacroFromRecent, deleteMacro, macroId, loadMacros, MACRO_STEPS_LIMIT, type MacroStep } from "./macros";

const ITEM_ICONS: Record<string, LucideIcon> = {
  "/": LayoutDashboard,
  "/triage": ListChecks, "/phishing": MailWarning, "/url": Link2,
  "/file": File, "/attachment": Paperclip, "/logs": ScrollText,
  "/pcap": Globe,
  "/case": FileText, "/activity": Clock, "/timeline": Clock,
  "/intel": Bug, "/detection": ShieldCheck, "/mitre": Target,
  "/sigma-tester": FlaskConical, "/siem": Activity,
  "/parser": Wand2, "/chef": Wrench,
  "/diff": Code2, "/regex-playground": Search, "/snippets": Bookmark,
  "/guide": BookOpen, "/validation": FlaskConical,
  "/settings": Settings,
};

const INVEST_ICONS: Record<string, LucideIcon> = {
  case: FolderOpen, finding: ShieldAlert, ioc: Database, event: Activity,
  report: FileText, detection: ShieldCheck, mitre: Target, entity: Bug, alert: Activity,
};

const INVEST_LABELS: Record<string, string> = {
  case: "Case", finding: "Finding", ioc: "IOC", event: "Event",
  report: "Report", detection: "Detection", mitre: "MITRE", entity: "Entity", alert: "Alert",
};

export const LOCKER_OPEN_EVENT = "ba:locker-open";

function navResult(id: string, title: string, subtitle: string, icon: LucideIcon, url: string, go: (url: string) => void, score = 80): CommandResult {
  return { id, title, subtitle, icon, category: "Navigate", keywords: [title, subtitle], score, run: () => go(url) };
}

export function navigationProvider(go: (url: string) => void): PaletteProvider {
  return {
    id: "navigation",
    priority: 100,
    getResults(input: string): CommandResult[] {
      const q = input.toLowerCase().trim();
      const items = GROUPS.flatMap((g) =>
        g.items
          .filter((it) => it.group !== "System")
          .map((it) =>
            navResult(`nav-${it.url}`, it.title, it.desc, ITEM_ICONS[it.url] ?? it.icon, it.url, go)
          )
      );
      if (!q) return items;
      return items.filter((r) => `${r.title} ${r.subtitle}`.toLowerCase().includes(q));
    },
  };
}

type Go = (url: string) => void;

function intelAction(id: string, title: string, input: string, icon: LucideIcon, subtitle: string, go: Go): CommandResult {
  return {
    id, title, subtitle, icon, category: "Intel",
    keywords: [input, "intel", "lookup"], score: 105,
    run: () => go(`/intel?q=${encodeURIComponent(input)}`),
  };
}

export function searchProvider(go: (url: string) => void): PaletteProvider {
  return {
    id: "search",
    priority: 90,
    getResults(input: string, _ctx: PaletteContext): CommandResult[] {
      if (!input.trim()) return [];

      const kind = detectObservable(input);
      const results: CommandResult[] = [];
      const baseScore = 95;

      if (kind === "cve") {
        results.push(intelAction("cve-intel", `Search Intel for ${input}`, input, Bug, "CVE lookup", go));
        results.push({ id: "cve-mitre", title: "View MITRE coverage", subtitle: "Related techniques", icon: Target, category: "Intel", keywords: [input, "cve", "mitre"], score: baseScore, run: () => go("/mitre") });
      } else if (kind === "mitre") {
        results.push(intelAction("mitre-open", `Open MITRE ${input}`, input, Target, "Technique details", go));
        results.push({ id: "mitre-detection", title: "Search detection rules", subtitle: "Find related Sigma/YARA", icon: ShieldCheck, category: "Detection", keywords: [input, "detection", "sigma", "yara"], score: baseScore - 5, run: () => go("/detection") });
      } else if (kind === "ipv4" || kind === "ipv6") {
        results.push(intelAction("ip-intel", `Search Intel for ${input}`, input, Bug, "Reputation lookup", go));
        results.push({ id: "ip-analyze", title: "Launch URL analysis", subtitle: "Redirects, lists, reputation", icon: Link2, category: "Intake", keywords: [input, "analyze", "url"], score: baseScore, run: () => go("/url") });
      } else if (kind === "domain" || kind === "url") {
        results.push(intelAction("dom-intel", `Search Intel for ${input}`, input, Bug, "Reputation lookup", go));
        results.push({ id: "dom-url", title: "Open URL analyzer", subtitle: "Full analysis", icon: Link2, category: "Intake", keywords: [input, "url", "analyze"], score: baseScore, run: () => go("/url") });
      } else if (kind && kind.startsWith("hash-")) {
        results.push(intelAction("hash-intel", `Search Intel for ${input}`, input, Bug, `${observableLabel(kind)} lookup`, go));
        results.push({ id: "hash-file", title: "Open file analysis", subtitle: "Hashes, strings, markers", icon: File, category: "Intake", keywords: [input, "hash", "file"], score: baseScore, run: () => go("/file") });
      } else if (kind === "email") {
        results.push(intelAction("email-intel", `Search Intel for ${input}`, input, Bug, "Reputation lookup", go));
        results.push({ id: "email-phishing", title: "Open phishing analyzer", subtitle: "Auth, headers, body verdict", icon: MailWarning, category: "Intake", keywords: [input, "email", "phishing"], score: baseScore, run: () => go("/phishing") });
      } else if (kind === "win-event-id") {
        results.push({ id: "evt-search", title: `Search SIEM for Event ${input}`, subtitle: "Windows event log search", icon: Activity, category: "Search", keywords: [input, "event", "siem", "windows"], score: baseScore, run: () => go("/siem") });
      }

      if (results.length > 0) {
        results.unshift({
          id: "observable-detected",
          title: `Detected: ${observableLabel(kind!)}`,
          subtitle: input,
          icon: SearchIcon,
          category: "Search",
          keywords: [input],
          score: baseScore + 20,
          run: () => {},
        });
      }

      return results;
    },
  };
}

export function investigationProvider(go: (url: string) => void, searchResults: SearchItem[] = []): PaletteProvider {
  return {
    id: "investigation",
    priority: 80,
    getResults(input: string, ctx: PaletteContext): CommandResult[] {
      const results: CommandResult[] = [];
      const q = input.toLowerCase().trim();

      const caseActions: CommandResult[] = [];
      if (ctx.activeCase) {
        caseActions.push(
          {
            id: "act-case-header", title: ctx.activeCase.title, subtitle: "Active investigation",
            icon: Notebook, category: "Investigation", keywords: ["active", "case", ctx.activeCase.title],
            score: 100, run: () => go("/case"),
          },
          { id: "act-case-timeline", title: "Open timeline", subtitle: "Case event log", icon: Clock, category: "Investigation", keywords: ["timeline", "case"], score: 85, run: () => go("/case?tab=timeline") },
          { id: "act-case-notebook", title: "Open notebook", subtitle: "Case notes & findings", icon: Notebook, category: "Investigation", keywords: ["notebook", "case"], score: 80, run: () => go("/case?tab=notebook") },
          { id: "act-case-intel", title: "Run intel search", subtitle: "Enrich context", icon: Bug, category: "Investigation", keywords: ["intel", "enrich", "case"], score: 75, run: () => go("/intel") },
          { id: "act-case-report", title: "Generate report", subtitle: "Markdown handoff brief", icon: FileText, category: "Investigation", keywords: ["report", "export", "case"], score: 70, run: () => go("/case?tab=reports") },
        );
      }
      const caseKws = caseActions.flatMap((a) => a.keywords);
      if (!q || caseKws.some((k) => k.includes(q)) || q.startsWith("case") || q.startsWith("investigat")) {
        results.push(...caseActions);
      }

      if (!q || "investigation cases new".includes(q)) {
        results.push({ id: "new-investigation", title: "New investigation", subtitle: "Create a fresh case file", icon: Plus, category: "Create", keywords: ["new", "case", "investigation"], score: q ? 60 : 80, run: () => go("/case") });
      }

      if (q && searchResults.length > 0) {
        const grouped = new Map<string, SearchItem[]>();
        for (const r of searchResults) {
          if (r.type === "page" || r.type === "note" || r.type === "artifact") continue;
          if (!grouped.has(r.type)) grouped.set(r.type, []);
          if (grouped.get(r.type)!.length < 5) grouped.get(r.type)!.push(r);
        }
        const order = ["case", "finding", "ioc", "event", "report", "detection", "mitre", "entity", "alert"];
        for (const type of order) {
          const items = grouped.get(type);
          if (!items) continue;
          const Icon = INVEST_ICONS[type] ?? Database;
          for (const item of items) {
            results.push({
              id: `search-${item.id}`,
              title: type === "ioc" ? item.label : item.label,
              subtitle: `${INVEST_LABELS[type]} — ${item.caseTitle}`,
              icon: Icon,
              category: "Search",
              keywords: [item.label, item.description, item.tags, type, item.caseTitle],
              score: 85 - order.indexOf(type) * 5,
              run: () => {
                if (item.url) { go(item.url); return; }
                if (item.caseId) setActiveCaseId(item.caseId);
                go("/case");
              },
            });
          }
        }
      }

      if (ctx.recentPaths.length > 0 && !q) {
        for (const url of ctx.recentPaths.slice(0, 5)) {
          const item = findItem(url);
          if (item) {
            results.push({ id: `recent-${url}`, title: item.title, subtitle: `Recent — ${item.group}`, icon: ITEM_ICONS[url] ?? item.icon, category: "Recent", keywords: [item.title, item.group], score: 50 - ctx.recentPaths.indexOf(url) * 5, run: () => go(url) });
          }
        }
      }

      return results;
    },
  };
}

export function intakeProvider(go: (url: string) => void): PaletteProvider {
  const actions: { id: string; title: string; icon: LucideIcon; url: string; keywords: string[] }[] = [
    { id: "intake-url", title: "Analyze URL", icon: Link2, url: "/url", keywords: ["analyze", "url", "link"] },
    { id: "intake-email", title: "Analyze email", icon: MailWarning, url: "/phishing", keywords: ["analyze", "email", "phishing"] },
    { id: "intake-file", title: "Analyze file", icon: File, url: "/file", keywords: ["analyze", "file", "hash"] },
    { id: "intake-attachment", title: "Dissect attachment", icon: Paperclip, url: "/attachment", keywords: ["analyze", "attachment", "email"] },
    { id: "intake-logs", title: "Import logs", icon: ScrollText, url: "/logs", keywords: ["import", "logs", "parse"] },
    { id: "intake-pcap", title: "Analyze PCAP", icon: Globe, url: "/pcap", keywords: ["analyze", "pcap", "packet"] },
    { id: "intake-triage", title: "Open triage", icon: ListChecks, url: "/triage", keywords: ["triage", "review", "events"] },
  ];
  return {
    id: "intake",
    priority: 70,
    getResults(input: string): CommandResult[] {
      const q = input.toLowerCase().trim();
      if (q && !actions.some((a) => a.keywords.some((k) => k.includes(q)))) return [];
      const results: CommandResult[] = [];

      for (const a of actions) {
        if (!q || a.keywords.some((k) => k.includes(q))) {
          results.push({ id: a.id, title: a.title, subtitle: "Quick intake action", icon: a.icon, category: "Intake", keywords: a.keywords, score: 70, run: () => go(a.url) });
        }
      }

      return results;
    },
  };
}

export function actionProvider(
  go: (url: string) => void,
  ctxFn: () => PaletteContext,
  cycleTheme: () => void,
  copyFirstIoc: () => void,
): PaletteProvider {
  const actions: { id: string; title: string; icon: LucideIcon; category: CommandResult["category"]; keywords: string[]; score: () => number; run: () => void }[] = [
    {
      id: "act-locker", title: "View IOC locker", icon: PackageOpen, category: "Actions", keywords: ["locker", "ioc"],
      score: () => ctxFn().lockerCount > 0 ? 75 : 45,
      run: () => { window.dispatchEvent(new CustomEvent(LOCKER_OPEN_EVENT)); },
    },
    {
      id: "act-copy", title: "Copy active IOC", icon: Database, category: "Actions", keywords: ["copy", "ioc", "clipboard"],
      score: () => ctxFn().lockerCount > 0 ? 60 : 30,
      run: copyFirstIoc,
    },
    {
      id: "act-detection", title: "Create detection rule", icon: ShieldCheck, category: "Actions", keywords: ["detection", "rule", "sigma", "yara"],
      score: () => 65,
      run: () => go("/detection"),
    },
    {
      id: "act-theme", title: "Cycle theme", icon: Palette, category: "Actions", keywords: ["theme", "cycle"],
      score: () => 40,
      run: cycleTheme,
    },
  ];
  return {
    id: "actions",
    priority: 60,
    getResults(input: string): CommandResult[] {
      const q = input.toLowerCase().trim();
      if (q && !actions.some((a) => a.keywords.some((k) => k.includes(q)))) return [];
      return actions
        .filter((a) => !q || a.keywords.some((k) => k.includes(q)))
        .map((a) => ({
          id: a.id, title: a.title, icon: a.icon, category: a.category, keywords: a.keywords,
          score: a.score(), run: a.run,
          subtitle: a.id === "act-locker" ? `${ctxFn().lockerCount} items loaded` : a.id === "act-copy" ? "First item in locker" : undefined,
        }));
    },
  };
}

export function detectionProvider(go: (url: string) => void): PaletteProvider {
  const actions: { id: string; title: string; icon: LucideIcon; url: string; keywords: string[] }[] = [
    { id: "det-workspace", title: "Detection workspace", icon: ShieldCheck, url: "/detection", keywords: ["detection", "sigma", "yara"] },
    { id: "det-mitre", title: "MITRE ATT&CK", icon: Target, url: "/mitre", keywords: ["mitre", "att&ck", "coverage"] },
    { id: "det-sigma-tester", title: "Sigma tester", icon: FlaskConical, url: "/sigma-tester", keywords: ["sigma", "test", "events"] },
  ];
  return {
    id: "detection",
    priority: 65,
    getResults(input: string): CommandResult[] {
      const q = input.toLowerCase().trim();
      if (q && !actions.some((a) => a.keywords.some((k) => k.includes(q)))) return [];
      const results: CommandResult[] = [];
      for (const a of actions) {
        if (!q || a.keywords.some((k) => k.includes(q))) {
          results.push({ id: a.id, title: a.title, subtitle: "Detection workspace", icon: a.icon, category: "Detection", keywords: a.keywords, score: a.id === "det-sigma-tester" ? 55 : a.id === "det-mitre" ? 65 : 70, run: () => go(a.url) });
        }
      }
      return results;
    },
  };
}

/** Analyst experience v1: recently invoked palette commands, pinned above results. */
export function recentCommandProvider(go: (url: string) => void): PaletteProvider {
  return {
    id: "recent-commands",
    priority: 95,
    getResults(input: string): CommandResult[] {
      if (input.trim()) return [];
      return loadRecentCommands()
        .filter((c) => c.title)
        .map((c) => ({
          id: `recent-${c.id}`,
          title: c.title,
          subtitle: "recent",
          icon: Clock,
          category: "Recent",
          keywords: [c.title],
          score: 90,
          run: () => go(c.title.startsWith("/") ? c.title : `/${c.title.toLowerCase().replace(/\s+/g, "-")}`),
        }));
    },
  };
}

/**
 * Analyst experience v1 macros: run saved command sequences, create a macro
 * from the recent-command ledger ("macro <name>"), or delete one.
 * Step resolution is delegated to `resolve` so replays execute current
 * provider behavior; unresolved steps are reported honestly, never skipped
 * silently.
 */
export function macrosProvider(
  resolve: (id: string) => CommandResult | null,
): PaletteProvider {
  const runMacro = (name: string, steps: MacroStep[]) => {
    let ran = 0;
    let missing = 0;
    for (const step of steps) {
      const cmd = resolve(step.id);
      if (cmd) { cmd.run(); ran++; }
      else missing++;
    }
    if (missing > 0) notify.warning(`Macro "${name}" — ${ran}/${steps.length} steps ran`, { description: `${missing} step(s) unavailable in this session` });
    else notify.success(`Ran macro "${name}"`, { description: `${ran} step${ran === 1 ? "" : "s"}` });
  };

  return {
    id: "macros",
    priority: 92,
    getResults(input: string): CommandResult[] {
      const q = input.toLowerCase().trim();
      const macros = loadMacros();
      const results: CommandResult[] = [];

      // Create offer: "macro <name>" saves the last commands as a macro.
      const nameMatch = q.startsWith("macro ") ? input.trim().slice(6).trim() : "";
      if (nameMatch) {
        const recents = loadRecentCommands().slice(0, MACRO_STEPS_LIMIT);
        results.push({
          id: "macro-create",
          title: `Save macro "${nameMatch}"`,
          subtitle: recents.length > 0 ? `${recents.length} recent command${recents.length === 1 ? "" : "s"}` : "nothing recorded yet",
          icon: recents.length > 0 ? Plus : CircleSlash,
          category: "Macros",
          keywords: ["macro", "save", "record", nameMatch],
          score: 110,
          run: () => {
            const m = createMacroFromRecent(nameMatch, recents);
            if (m) notify.success(`Macro "${m.name}" saved`, { description: `${m.steps.length} steps — type its name to replay` });
            else notify.error(`Could not save macro "${nameMatch}"`, { description: "Run some palette commands first" });
          },
        });
      }

      const matching = macros.filter((m) => !q || m.name.toLowerCase().includes(q) || (nameMatch && m.id === macroId(nameMatch)));
      for (const m of matching) {
        results.push({
          id: `mac-run-${m.id}`,
          title: `Run macro · ${m.name}`,
          subtitle: `${m.steps.length} step${m.steps.length === 1 ? "" : "s"} — ${m.steps.map((s) => s.title).join(" → ")}`,
          icon: Play,
          category: "Macros",
          keywords: ["macro", "run", m.name, ...m.steps.map((s) => s.title)],
          score: q ? 100 : 88,
          run: () => runMacro(m.name, m.steps),
        });
        results.push({
          id: `mac-del-${m.id}`,
          title: `Delete macro "${m.name}"`,
          subtitle: `${m.steps.length} steps`,
          icon: Trash2,
          category: "Macros",
          keywords: ["macro", "delete", "remove", m.name],
          score: 40,
          run: () => { deleteMacro(m.id); notify.info(`Macro "${m.name}" deleted`); },
        });
      }

      return results;
    },
  };
}
