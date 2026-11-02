import { useState } from "react";
import {
  Activity,
  Globe,
  Lock,
  Key,
  FileCode,
  Network,
  ExternalLink,
  Database,
  Copy,
  AlertTriangle,
  FileText,
  Binary,
} from "lucide-react";
import {
  type ZeekConn,
  type ZeekDns,
  type ZeekHttp,
  type ZeekSsl,
  type CredentialFinding,
  type ExtractedFile,
  connStateLabel,
  connStateTone,
} from "@/lib/pcap/zeek-models";
import { Chip } from "@/components/soc";
import { useLocker } from "@/lib/locker";
import { useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";

interface ZeekLogViewerProps {
  conns: ZeekConn[];
  dns: ZeekDns[];
  http: ZeekHttp[];
  ssl: ZeekSsl[];
  credentials: CredentialFinding[];
  extractedFiles: ExtractedFile[];
  onFollowStream: (conn: ZeekConn) => void;
}

export function ZeekLogViewer({
  conns,
  dns,
  http,
  ssl,
  credentials,
  extractedFiles,
  onFollowStream,
}: ZeekLogViewerProps) {
  const [activeLog, setActiveLog] = useState<"conn" | "dns" | "http" | "ssl" | "creds" | "files">("conn");
  const locker = useLocker();
  const navigate = useNavigate();

  const handleStash = (type: "ipv4" | "domain" | "sha256" | "text", value: string, note?: string) => {
    locker.add({
      type,
      value,
      source: "/pcap",
      note: note || "PCAP network observable",
    });
    toast.success(`Stashed ${value} to Evidence Locker`);
  };

  const handlePivotIntel = (val: string) => {
    navigate({ to: "/intel", search: { q: val } });
  };

  return (
    <div className="space-y-3 rounded-lg border border-border bg-card/40 p-3">
      {/* Log Tab Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-2">
        <div className="flex flex-wrap items-center gap-1">
          <button
            type="button"
            onClick={() => setActiveLog("conn")}
            className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 font-mono text-2xs transition ${
              activeLog === "conn"
                ? "border border-primary/50 bg-primary/15 text-primary font-medium"
                : "text-muted-foreground hover:bg-surface-1 hover:text-foreground"
            }`}
          >
            <Network className="h-3 w-3" />
            <span>conn.log</span>
            <span className="rounded bg-surface-2 px-1 text-3xs">{conns.length}</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveLog("dns")}
            className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 font-mono text-2xs transition ${
              activeLog === "dns"
                ? "border border-primary/50 bg-primary/15 text-primary font-medium"
                : "text-muted-foreground hover:bg-surface-1 hover:text-foreground"
            }`}
          >
            <Globe className="h-3 w-3" />
            <span>dns.log</span>
            <span className="rounded bg-surface-2 px-1 text-3xs">{dns.length}</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveLog("http")}
            className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 font-mono text-2xs transition ${
              activeLog === "http"
                ? "border border-primary/50 bg-primary/15 text-primary font-medium"
                : "text-muted-foreground hover:bg-surface-1 hover:text-foreground"
            }`}
          >
            <Activity className="h-3 w-3" />
            <span>http.log</span>
            <span className="rounded bg-surface-2 px-1 text-3xs">{http.length}</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveLog("ssl")}
            className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 font-mono text-2xs transition ${
              activeLog === "ssl"
                ? "border border-primary/50 bg-primary/15 text-primary font-medium"
                : "text-muted-foreground hover:bg-surface-1 hover:text-foreground"
            }`}
          >
            <Lock className="h-3 w-3" />
            <span>ssl.log</span>
            <span className="rounded bg-surface-2 px-1 text-3xs">{ssl.length}</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveLog("creds")}
            className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 font-mono text-2xs transition ${
              activeLog === "creds"
                ? "border border-destructive/50 bg-destructive/15 text-destructive font-medium"
                : credentials.length > 0
                ? "text-destructive hover:bg-destructive/10"
                : "text-muted-foreground hover:bg-surface-1 hover:text-foreground"
            }`}
          >
            <Key className="h-3 w-3" />
            <span>Credentials</span>
            <span className={`rounded px-1 text-3xs ${credentials.length > 0 ? "bg-destructive/20 text-destructive font-bold" : "bg-surface-2"}`}>
              {credentials.length}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveLog("files")}
            className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 font-mono text-2xs transition ${
              activeLog === "files"
                ? "border border-warning/50 bg-warning/15 text-warning font-medium"
                : extractedFiles.length > 0
                ? "text-warning hover:bg-warning/10"
                : "text-muted-foreground hover:bg-surface-1 hover:text-foreground"
            }`}
          >
            <FileCode className="h-3 w-3" />
            <span>Extracted Files</span>
            <span className={`rounded px-1 text-3xs ${extractedFiles.length > 0 ? "bg-warning/20 text-warning font-bold" : "bg-surface-2"}`}>
              {extractedFiles.length}
            </span>
          </button>
        </div>

        <div className="font-mono text-3xs text-muted-foreground">
          Zeek NSM Protocol Streams · Click row to pivot
        </div>
      </div>

      {/* 1. Connection Log Table */}
      {activeLog === "conn" && (
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-2xs border-collapse">
            <thead>
              <tr className="border-b border-border/60 text-muted-foreground bg-surface-1/50">
                <th className="p-2">UID</th>
                <th className="p-2">PROTO</th>
                <th className="p-2">SERVICE</th>
                <th className="p-2">ORIGINATOR (SRC)</th>
                <th className="p-2">RESPONDER (DST)</th>
                <th className="p-2">STATE</th>
                <th className="p-2 text-right">PKTS</th>
                <th className="p-2 text-right">BYTES</th>
                <th className="p-2 text-center">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {conns.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-4 text-center text-muted-foreground">
                    No connection flows recorded
                  </td>
                </tr>
              ) : (
                conns.map((c, idx) => (
                  <tr key={c.uid || idx} className="hover:bg-surface-1/80 transition">
                    <td className="p-2 text-muted-foreground">{c.uid}</td>
                    <td className="p-2 uppercase font-semibold text-foreground">{c.proto}</td>
                    <td className="p-2">
                      <span className="rounded bg-surface-2 px-1.5 py-0.5 uppercase text-3xs text-primary font-medium">
                        {c.service}
                      </span>
                    </td>
                    <td className="p-2 text-foreground font-mono">
                      {c.orig_h}:{c.orig_p}
                    </td>
                    <td className="p-2 text-foreground font-mono">
                      {c.resp_h}:{c.resp_p}
                    </td>
                    <td className="p-2">
                      <Chip tone={connStateTone(c.conn_state)}>
                        {c.conn_state} ({connStateLabel(c.conn_state).split(" ")[0]})
                      </Chip>
                    </td>
                    <td className="p-2 text-right text-muted-foreground">{c.packets}</td>
                    <td className="p-2 text-right text-muted-foreground font-mono">{c.orig_bytes} B</td>
                    <td className="p-2 text-center">
                      <div className="inline-flex items-center gap-1">
                        <button
                          type="button"
                          onClick={() => onFollowStream(c)}
                          className="rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-3xs text-primary hover:bg-primary/20 transition"
                          title="Follow TCP Stream dialogue"
                        >
                          Stream
                        </button>
                        <button
                          type="button"
                          onClick={() => handleStash("ipv4", c.resp_h)}
                          className="rounded p-1 text-muted-foreground hover:text-primary transition"
                          title="Stash destination IP to Evidence Locker"
                        >
                          <Database className="h-3 w-3" />
                        </button>
                        <button
                          type="button"
                          onClick={() => handlePivotIntel(c.resp_h)}
                          className="rounded p-1 text-muted-foreground hover:text-primary transition"
                          title="Pivot IP into Threat Intel"
                        >
                          <ExternalLink className="h-3 w-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* 2. DNS Log Table */}
      {activeLog === "dns" && (
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-2xs border-collapse">
            <thead>
              <tr className="border-b border-border/60 text-muted-foreground bg-surface-1/50">
                <th className="p-2">QUERY</th>
                <th className="p-2">TYPE</th>
                <th className="p-2">ENTROPY</th>
                <th className="p-2">STATUS</th>
                <th className="p-2 text-center">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {dns.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-4 text-center text-muted-foreground">
                    No DNS queries recorded
                  </td>
                </tr>
              ) : (
                dns.map((d, idx) => (
                  <tr key={idx} className="hover:bg-surface-1/80 transition">
                    <td className="p-2 text-foreground font-mono max-w-md truncate">
                      {d.query}
                    </td>
                    <td className="p-2">
                      <span className="rounded bg-surface-2 px-1.5 py-0.5 text-3xs text-primary font-medium">
                        {d.qtype}
                      </span>
                    </td>
                    <td className="p-2 font-mono text-muted-foreground">
                      {typeof d.entropy === "number" ? d.entropy.toFixed(2) : "—"}
                    </td>
                    <td className="p-2">
                      {d.is_tunneling ? (
                        <Chip tone="destructive">Tunneling Alert</Chip>
                      ) : (
                        <Chip tone="success">Normal</Chip>
                      )}
                    </td>
                    <td className="p-2 text-center">
                      <div className="inline-flex items-center gap-1">
                        <button
                          type="button"
                          onClick={() => handleStash("domain", d.query)}
                          className="rounded p-1 text-muted-foreground hover:text-primary transition"
                          title="Stash domain to Evidence Locker"
                        >
                          <Database className="h-3 w-3" />
                        </button>
                        <button
                          type="button"
                          onClick={() => handlePivotIntel(d.query)}
                          className="rounded p-1 text-muted-foreground hover:text-primary transition"
                          title="Pivot domain into Threat Intel"
                        >
                          <ExternalLink className="h-3 w-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* 3. HTTP Log Table */}
      {activeLog === "http" && (
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-2xs border-collapse">
            <thead>
              <tr className="border-b border-border/60 text-muted-foreground bg-surface-1/50">
                <th className="p-2">METHOD</th>
                <th className="p-2">HOST</th>
                <th className="p-2">URI PATH</th>
                <th className="p-2">USER-AGENT</th>
                <th className="p-2 text-center">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {http.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-4 text-center text-muted-foreground">
                    No HTTP sessions recorded
                  </td>
                </tr>
              ) : (
                http.map((h, idx) => (
                  <tr key={idx} className="hover:bg-surface-1/80 transition">
                    <td className="p-2">
                      <Chip tone={h.method === "POST" ? "warning" : "info"}>{h.method}</Chip>
                    </td>
                    <td className="p-2 font-mono text-foreground font-medium">{h.host || "—"}</td>
                    <td className="p-2 font-mono text-fg-dim max-w-xs truncate">{h.path}</td>
                    <td className="p-2 font-mono text-muted-foreground max-w-xs truncate">
                      {h.user_agent ? (
                        <span className={h.suspicious_ua ? "text-destructive font-semibold" : ""}>
                          {h.user_agent}
                          {h.suspicious_ua && " ⚠️"}
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="p-2 text-center">
                      <div className="inline-flex items-center gap-1">
                        {h.host && (
                          <>
                            <button
                              type="button"
                              onClick={() => handleStash("domain", h.host)}
                              className="rounded p-1 text-muted-foreground hover:text-primary transition"
                              title="Stash host to Evidence Locker"
                            >
                              <Database className="h-3 w-3" />
                            </button>
                            <button
                              type="button"
                              onClick={() => handlePivotIntel(h.host)}
                              className="rounded p-1 text-muted-foreground hover:text-primary transition"
                              title="Pivot into Threat Intel"
                            >
                              <ExternalLink className="h-3 w-3" />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* 4. SSL / TLS Log Table */}
      {activeLog === "ssl" && (
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-2xs border-collapse">
            <thead>
              <tr className="border-b border-border/60 text-muted-foreground bg-surface-1/50">
                <th className="p-2">SERVER NAME (SNI)</th>
                <th className="p-2">VERSION</th>
                <th className="p-2">JA3 FINGERPRINT</th>
                <th className="p-2">ENDPOINTS</th>
                <th className="p-2 text-center">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {ssl.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-4 text-center text-muted-foreground">
                    No TLS / SSL handshakes recorded
                  </td>
                </tr>
              ) : (
                ssl.map((s, idx) => (
                  <tr key={idx} className="hover:bg-surface-1/80 transition">
                    <td className="p-2 font-mono text-foreground font-semibold">{s.server_name}</td>
                    <td className="p-2">
                      <Chip tone={s.is_deprecated ? "destructive" : "success"}>
                        {s.version} {s.is_deprecated && " (Deprecated)"}
                      </Chip>
                    </td>
                    <td className="p-2 font-mono text-muted-foreground">{s.ja3}</td>
                    <td className="p-2 font-mono text-muted-foreground">
                      {s.src} → {s.dst}
                    </td>
                    <td className="p-2 text-center">
                      <div className="inline-flex items-center gap-1">
                        {s.server_name && s.server_name !== "—" && (
                          <button
                            type="button"
                            onClick={() => handleStash("domain", s.server_name)}
                            className="rounded p-1 text-muted-foreground hover:text-primary transition"
                            title="Stash SNI domain to Evidence Locker"
                          >
                            <Database className="h-3 w-3" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* 5. Harvested Credentials Table */}
      {activeLog === "creds" && (
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-2xs border-collapse">
            <thead>
              <tr className="border-b border-border/60 text-muted-foreground bg-surface-1/50">
                <th className="p-2">PROTOCOL</th>
                <th className="p-2">FLOW</th>
                <th className="p-2">USERNAME</th>
                <th className="p-2">PASSWORD (MASKED)</th>
                <th className="p-2">RAW EVIDENCE</th>
                <th className="p-2 text-center">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {credentials.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-4 text-center text-muted-foreground">
                    No plaintext credentials detected in traffic
                  </td>
                </tr>
              ) : (
                credentials.map((cr, idx) => (
                  <tr key={idx} className="bg-destructive/5 hover:bg-destructive/10 transition">
                    <td className="p-2">
                      <Chip tone="destructive">{cr.protocol}</Chip>
                    </td>
                    <td className="p-2 font-mono text-foreground">
                      {cr.src} → {cr.dst}
                    </td>
                    <td className="p-2 font-mono font-bold text-destructive">{cr.username}</td>
                    <td className="p-2 font-mono text-foreground">{cr.password_masked}</td>
                    <td className="p-2 font-mono text-muted-foreground max-w-xs truncate">{cr.raw}</td>
                    <td className="p-2 text-center">
                      <button
                        type="button"
                        onClick={() => handleStash("text", `Credential: ${cr.username}:${cr.password_masked} (${cr.protocol})`)}
                        className="rounded border border-destructive/40 bg-destructive/10 px-2 py-0.5 text-3xs text-destructive hover:bg-destructive/20 transition"
                        title="Stash exposed credentials to Evidence Locker"
                      >
                        Stash Creds
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* 6. Extracted Files Table */}
      {activeLog === "files" && (
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-2xs border-collapse">
            <thead>
              <tr className="border-b border-border/60 text-muted-foreground bg-surface-1/50">
                <th className="p-2">FILENAME / TYPE</th>
                <th className="p-2">SIZE</th>
                <th className="p-2">SHA-256 HASH</th>
                <th className="p-2">FLOW</th>
                <th className="p-2 text-center">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {extractedFiles.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-4 text-center text-muted-foreground">
                    No transferred file artifacts detected in traffic
                  </td>
                </tr>
              ) : (
                extractedFiles.map((f, idx) => (
                  <tr key={idx} className="hover:bg-surface-1/80 transition">
                    <td className="p-2">
                      <div className="font-mono text-foreground font-semibold">{f.filename}</div>
                      <div className="text-3xs text-muted-foreground">{f.type_desc}</div>
                    </td>
                    <td className="p-2 font-mono text-muted-foreground">{f.size_bytes} B</td>
                    <td className="p-2 font-mono text-foreground max-w-xs truncate">{f.sha256}</td>
                    <td className="p-2 font-mono text-muted-foreground">
                      {f.src} → {f.dst}
                    </td>
                    <td className="p-2 text-center">
                      <button
                        type="button"
                        onClick={() => handleStash("sha256", f.sha256, `Extracted file: ${f.filename}`)}
                        className="rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-3xs text-primary hover:bg-primary/20 transition"
                        title="Stash payload SHA-256 to Evidence Locker"
                      >
                        Stash Hash
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
