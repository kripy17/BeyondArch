export interface ZeekConn {
  uid: string;
  ts: number;
  duration: number;
  orig_h: string;
  orig_p: string;
  resp_h: string;
  resp_p: string;
  proto: string;
  service: string;
  orig_bytes: number;
  resp_bytes: number;
  conn_state: string;
  packets: number;
}

export interface ZeekDns {
  ts: number;
  query: string;
  qtype: string;
  rcode: string;
  answers: string[];
  entropy?: number;
  is_tunneling?: boolean;
  reasons?: string[];
}

export interface ZeekHttp {
  src: string;
  dst: string;
  method: string;
  host: string;
  path: string;
  user_agent: string;
  suspicious_ua?: boolean;
  status_code?: number;
}

export interface ZeekSsl {
  src: string;
  dst: string;
  server_name: string;
  version: string;
  is_deprecated: boolean;
  ja3: string;
}

export interface CredentialFinding {
  protocol: string;
  src: string;
  dst: string;
  username: string;
  password_masked: string;
  raw: string;
}

export interface ExtractedFile {
  filename: string;
  mime_type: string;
  type_desc: string;
  sha256: string;
  size_bytes: number;
  src: string;
  dst: string;
}

export function connStateLabel(state: string): string {
  switch (state) {
    case "SF":
      return "Normal (SYN-ACK-FIN)";
    case "S0":
      return "Attempted (No reply)";
    case "REJ":
      return "Rejected (RST)";
    case "RSTO":
      return "Reset by origin";
    case "RSTR":
      return "Reset by responder";
    default:
      return state || "Other";
  }
}

export function connStateTone(state: string): "success" | "warning" | "destructive" | "default" {
  switch (state) {
    case "SF":
      return "success";
    case "S0":
      return "warning";
    case "REJ":
    case "RSTO":
    case "RSTR":
      return "destructive";
    default:
      return "default";
  }
}

export function extractZeekFromText(rawText: string): {
  conns: ZeekConn[];
  dns: ZeekDns[];
  http: ZeekHttp[];
  creds: CredentialFinding[];
} {
  const lines = rawText.split("\n").map((l) => l.trim()).filter(Boolean);
  const conns: ZeekConn[] = [];
  const dns: ZeekDns[] = [];
  const http: ZeekHttp[] = [];
  const creds: CredentialFinding[] = [];

  const connMap = new Map<string, ZeekConn>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Check for IP packet: e.g. 10:15:01.123456 IP 10.0.0.5.51234 > 93.184.216.34.80: Flags [P.], seq ...
    const ipMatch = line.match(/(?:IP|IP6)\s+([0-9a-f.:]+)\.(\d+)\s+>\s+([0-9a-f.:]+)\.(\d+):\s*(.*)/i);
    if (ipMatch) {
      const [, src, sport, dst, dport, rest] = ipMatch;
      const key = `${src}:${sport}->${dst}:${dport}`;

      let service = "other";
      if (dport === "80" || dport === "8080" || sport === "80") service = "http";
      else if (dport === "443" || sport === "443") service = "ssl";
      else if (dport === "53" || sport === "53") service = "dns";
      else if (dport === "22" || sport === "22") service = "ssh";
      else if (dport === "21" || sport === "21") service = "ftp";

      let state = "SF";
      if (rest.includes("Flags [S]")) state = "S0";
      if (rest.includes("Flags [R]")) state = "REJ";

      if (!connMap.has(key)) {
        connMap.set(key, {
          uid: `C${i + 1}`,
          ts: Date.now() / 1000 - (lines.length - i),
          duration: 0.1,
          orig_h: src,
          orig_p: sport,
          resp_h: dst,
          resp_p: dport,
          proto: "tcp",
          service,
          orig_bytes: line.length,
          resp_bytes: 0,
          conn_state: state,
          packets: 1,
        });
      } else {
        const c = connMap.get(key)!;
        c.packets++;
        c.orig_bytes += line.length;
        if (state !== "SF") c.conn_state = state;
      }
    }

    // Check for DNS: e.g. "A? evil.darkc2.com." or "query: example.com"
    const dnsMatch = line.match(/(?:A\?|AAAA\?|TXT\?|query[:\s]+)\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
    if (dnsMatch) {
      const q = dnsMatch[1].toLowerCase();
      const isTunneling = q.length > 50 || q.split(".").length > 4;
      dns.push({
        ts: Date.now() / 1000,
        query: q,
        qtype: line.includes("AAAA?") ? "AAAA" : line.includes("TXT?") ? "TXT" : "A",
        rcode: "NOERROR",
        answers: [],
        entropy: isTunneling ? 4.1 : 2.5,
        is_tunneling: isTunneling,
        reasons: isTunneling ? ["High label count or query length"] : [],
      });
    }

    // Check for HTTP: e.g. "GET /index.html HTTP/1.1", "Host: evil.com"
    const httpMatch = line.match(/(GET|POST|PUT|DELETE)\s+([^\s]+)\s+HTTP/i);
    if (httpMatch) {
      const [, method, path] = httpMatch;
      http.push({
        src: "10.0.0.5",
        dst: "external",
        method: method.toUpperCase(),
        host: "target.corp",
        path,
        user_agent: "Mozilla/5.0",
      });
    }

    // Check for Basic Auth
    const authMatch = line.match(/Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i);
    if (authMatch) {
      try {
        const decoded = atob(authMatch[1]);
        if (decoded.includes(":")) {
          const [username, password] = decoded.split(":");
          creds.push({
            protocol: "HTTP Basic",
            src: "10.0.0.5",
            dst: "target.corp",
            username,
            password_masked: password.length > 2 ? password[0] + "*".repeat(password.length - 2) + password.slice(-1) : "***",
            raw: authMatch[0],
          });
        }
      } catch {
        // ignore decode errors
      }
    }
  }

  return {
    conns: Array.from(connMap.values()),
    dns,
    http,
    creds,
  };
}
