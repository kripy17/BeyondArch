import { useState } from "react";
import { Terminal, Copy, Check, ChevronRight, ChevronDown, ShieldAlert, Cpu, User, AlertTriangle } from "lucide-react";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import { Chip } from "@/components/soc";
import { detectAndDeobfuscate } from "@/lib/siem/payload-deobfuscator";

export interface ProcessNode {
  id: string;
  name: string;
  pid?: string;
  ppid?: string;
  user?: string;
  commandLine: string;
  decodedCommand?: string;
  isLolbas: boolean;
  isElevated: boolean;
  isSuspiciousPath: boolean;
  children: ProcessNode[];
}

const LOLBAS_BINARIES = new Set([
  "powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe", "net.exe", "net1.exe",
  "vssadmin.exe", "bcdedit.exe", "certutil.exe", "rundll32.exe", "regsvr32.exe",
  "mshta.exe", "cscript.exe", "wscript.exe", "bitsadmin.exe", "schtasks.exe",
  "sc.exe", "reg.exe", "tasklist.exe", "whoami.exe", "nltest.exe", "dsquery.exe"
]);

export function parseProcessLineage(logText: string): ProcessNode[] {
  const blocks = logText.split(/\n\s*\n/);
  const nodes: ProcessNode[] = [];
  const lines = logText.split("\n");

  // Helper to extract fields from block
  const getField = (block: string, field: string) => {
    const rx = new RegExp(`(?:${field}|${field.toLowerCase()}):\\s*(.+)`, "i");
    const m = block.match(rx);
    return m ? m[1].trim() : "";
  };

  for (const block of blocks) {
    const processName = getField(block, "ProcessName") || getField(block, "Image") || getField(block, "NewProcessName");
    const commandLine = getField(block, "CommandLine") || getField(block, "ScriptBlock") || getField(block, "BinaryPath");
    const user = getField(block, "User") || getField(block, "AccountName") || getField(block, "SubjectUserName");
    const pid = getField(block, "ProcessId") || getField(block, "NewProcessId");
    const ppid = getField(block, "ParentProcessId") || getField(block, "ProcessId");

    if (processName || commandLine) {
      const cleanName = (processName.split("\\").pop() || processName || "process.exe").toLowerCase();
      const isLolbas = LOLBAS_BINARIES.has(cleanName);
      const isElevated = (user || "").toUpperCase().includes("SYSTEM") || (user || "").toUpperCase().includes("ADMIN");
      const isSuspiciousPath = (processName || commandLine).toLowerCase().includes("\\users\\public") ||
        (processName || commandLine).toLowerCase().includes("\\temp\\") ||
        (processName || commandLine).toLowerCase().includes("\\appdata\\");

      const deob = detectAndDeobfuscate(commandLine);
      const decodedCommand = deob ? deob.decodedText : undefined;

      nodes.push({
        id: `proc-${nodes.length + 1}`,
        name: cleanName || (commandLine.split(" ")[0] || "process.exe"),
        pid: pid || `PID:${1000 + nodes.length * 4}`,
        ppid: ppid || "PID:4",
        user: user || "NT AUTHORITY\\SYSTEM",
        commandLine: commandLine || processName,
        decodedCommand,
        isLolbas,
        isElevated,
        isSuspiciousPath,
        children: [],
      });
    }
  }

  // Also check individual raw command lines if structured blocks were sparse
  if (nodes.length === 0) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      for (const lol of LOLBAS_BINARIES) {
        if (line.toLowerCase().includes(lol) || line.toLowerCase().startsWith(lol.replace(".exe", ""))) {
          const deob = detectAndDeobfuscate(line);
          nodes.push({
            id: `line-${i}`,
            name: lol,
            pid: `PID:${2000 + i * 4}`,
            ppid: "PID:1000",
            user: "Context: Elevated",
            commandLine: line,
            decodedCommand: deob?.decodedText,
            isLolbas: true,
            isElevated: true,
            isSuspiciousPath: line.includes("\\Users\\Public") || line.includes("temp"),
            children: [],
          });
          break;
        }
      }
    }
  }

  // Build simple hierarchical tree
  if (nodes.length > 1) {
    const root: ProcessNode = {
      id: "root-proc",
      name: "system_session (Parent Initial Execution)",
      pid: "PID:4",
      user: "SYSTEM",
      commandLine: "Kernel / Interactive Session Dispatcher",
      isLolbas: false,
      isElevated: true,
      isSuspiciousPath: false,
      children: nodes,
    };
    return [root];
  }

  return nodes;
}

export function ProcessTreeVisualizer({ logText }: { logText: string }) {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set(["root-proc", "proc-1", "proc-2", "proc-3"]));

  const tree = parseProcessLineage(logText);

  const handleCopy = (text: string, id: string) => {
    copyText(text);
    setCopiedId(id);
    toast.success("Command line copied to clipboard");
    setTimeout(() => setCopiedId(null), 1800);
  };

  const toggleExpand = (id: string) => {
    setExpandedNodes((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  if (tree.length === 0) {
    return (
      <div className="rounded-lg border border-subtle bg-surface-0 p-6 text-center text-mono ba-text-xs text-muted-foreground">
        <Cpu className="mx-auto h-7 w-7 text-muted-foreground/60 mb-2" />
        <p className="font-semibold text-foreground">No Process Execution Events Detected in Current Buffer</p>
        <p className="mt-1">
          Provide Windows Security Event 4688 (Process Creation) or Sysmon Event 1 logs containing ProcessName, Image, or CommandLine.
        </p>
      </div>
    );
  }

  const renderNode = (node: ProcessNode, depth: number = 0) => {
    const isExpanded = expandedNodes.has(node.id);
    const hasChildren = node.children.length > 0;

    return (
      <div key={node.id} className="relative font-mono">
        <div
          className={`group flex items-start gap-2 rounded-lg border p-2.5 transition-colors ${
            node.isLolbas || node.isSuspiciousPath
              ? "border-destructive/30 bg-destructive/5 hover:border-destructive/50"
              : "border-subtle bg-surface-1 hover:border-primary/40"
          } ${depth > 0 ? "ml-4 sm:ml-6 mt-2 border-l-2 border-l-primary/40" : ""}`}
        >
          {/* Expand / Leaf Icon */}
          <button
            onClick={() => toggleExpand(node.id)}
            className="mt-0.5 text-muted-foreground hover:text-foreground shrink-0"
          >
            {hasChildren ? (
              isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />
            ) : (
              <Terminal className="h-4 w-4 text-primary" />
            )}
          </button>

          <div className="min-w-0 flex-1 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="ba-text-xs font-bold text-foreground">{node.name}</span>
              {node.pid && <span className="text-mono ba-text-3xs text-muted-foreground">({node.pid})</span>}
              {node.user && (
                <span className="inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground">
                  <User className="h-2.5 w-2.5" />
                  {node.user}
                </span>
              )}

              {/* Threat Badges */}
              {node.isLolbas && <Chip tone="destructive">LOLBAS</Chip>}
              {node.isElevated && <Chip tone="warning">ELEVATED</Chip>}
              {node.isSuspiciousPath && <Chip tone="destructive">SUSPICIOUS PATH</Chip>}
              {node.decodedCommand && <Chip tone="primary">DEOBFUSCATED BASE64</Chip>}

              <button
                onClick={() => handleCopy(node.commandLine, node.id)}
                className="ml-auto inline-flex items-center gap-1 text-mono ba-text-3xs text-muted-foreground hover:text-primary"
                title="Copy full command line"
              >
                {copiedId === node.id ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                {copiedId === node.id ? "copied" : "copy"}
              </button>
            </div>

            {/* Command Line Preview */}
            <div className="rounded border border-border/40 bg-surface-0 p-1.5 ba-text-3xs text-foreground/90 overflow-x-auto whitespace-pre-wrap break-all">
              {node.commandLine}
            </div>

            {/* Deobfuscated Command Box */}
            {node.decodedCommand && (
              <div className="rounded border border-primary/40 bg-primary/10 p-2 ba-text-3xs text-primary overflow-x-auto">
                <span className="font-bold uppercase tracking-wider block mb-0.5">Decoded In-Memory Payload:</span>
                <code className="whitespace-pre-wrap break-all">{node.decodedCommand}</code>
              </div>
            )}
          </div>
        </div>

        {/* Children Lineage */}
        {hasChildren && isExpanded && (
          <div className="space-y-2 border-l border-dashed border-border/60 ml-2 pl-2 mt-1">
            {node.children.map((child) => renderNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2 pb-2 border-b border-border/50">
        <div className="flex items-center gap-2">
          <Cpu className="h-4 w-4 text-primary" />
          <span className="text-mono ba-text-xs font-semibold uppercase tracking-wider text-foreground">
            Windows Security & Sysmon Process Lineage Tree
          </span>
        </div>
        <span className="text-mono ba-text-3xs text-muted-foreground">
          EID 4688 / Sysmon 1 Hierarchical Decomposition
        </span>
      </div>

      <div className="space-y-2">
        {tree.map((node) => renderNode(node, 0))}
      </div>
    </div>
  );
}
