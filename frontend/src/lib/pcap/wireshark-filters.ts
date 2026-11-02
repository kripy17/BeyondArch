export interface FilterPreset {
  id: string;
  name: string;
  category: "dns" | "http" | "tls" | "scanning" | "c2";
  filter: string;
  description: string;
}

export const WIRESHARK_PRESETS: FilterPreset[] = [
  {
    id: "dns_tunneling",
    name: "DNS Tunneling / Large Queries",
    category: "dns",
    filter: "dns.flags.response == 0 && frame.len > 100",
    description: "Filters un-replied DNS queries exceeding normal length, typical of DNS data exfiltration.",
  },
  {
    id: "plaintext_creds",
    name: "Plaintext Credentials",
    category: "http",
    filter: 'http.authorization || http.request.uri contains "password" || tcp.port == 21',
    description: "Detects HTTP Basic Auth headers, credential URI parameters, or FTP authentication.",
  },
  {
    id: "suspicious_ua",
    name: "Suspicious User-Agents",
    category: "http",
    filter: 'http.user_agent matches "(?i)(curl|powershell|python|mimikatz|certutil)"',
    description: "Matches command-line or offensive tool user agents communicating over HTTP.",
  },
  {
    id: "tls_no_sni",
    name: "TLS Handshake Without SNI",
    category: "tls",
    filter: "tls.handshake.type == 1 && !tls.handshake.extension.type == 0",
    description: "TLS ClientHello packets connecting directly by IP without Server Name Indication.",
  },
  {
    id: "syn_scan",
    name: "SYN Port Scan / Half-Open",
    category: "scanning",
    filter: "tcp.flags.syn == 1 && tcp.flags.ack == 0",
    description: "Isolates SYN packets initiating new handshakes, common in network reconnaissance.",
  },
  {
    id: "c2_ports",
    name: "C2 / Non-Standard Ports",
    category: "c2",
    filter: "tcp.port in {4444, 1337, 8443, 9001}",
    description: "Filters traffic destined to typical reverse shell or Metasploit/Cobalt Strike listener ports.",
  },
];

export interface FilterCriteria {
  ip?: string;
  port?: string;
  proto?: string;
  host?: string;
  search?: string;
}

export function buildWiresharkFilter(criteria: FilterCriteria): string {
  const parts: string[] = [];

  if (criteria.ip) {
    parts.push(`ip.addr == ${criteria.ip}`);
  }
  if (criteria.port) {
    parts.push(`tcp.port == ${criteria.port} || udp.port == ${criteria.port}`);
  }
  if (criteria.proto) {
    parts.push(criteria.proto.toLowerCase());
  }
  if (criteria.host) {
    parts.push(`http.host == "${criteria.host}" || tls.handshake.extensions_server_name == "${criteria.host}"`);
  }
  if (criteria.search) {
    parts.push(`frame contains "${criteria.search}"`);
  }

  return parts.join(" && ") || "frame";
}

export function buildTsharkCommand(filter: string, pcapFile = "capture.pcap"): string {
  const cleanFilter = filter.trim() || "frame";
  return `tshark -r "${pcapFile}" -Y '${cleanFilter}' -T fields -e frame.number -e _ws.col.Time -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info`;
}
