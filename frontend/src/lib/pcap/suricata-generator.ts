export interface SuricataRuleParams {
  action?: "alert" | "drop" | "pass";
  proto?: "tcp" | "udp" | "http" | "dns" | "tls" | "ip";
  src?: string;
  sport?: string;
  dst?: string;
  dport?: string;
  msg: string;
  content?: string;
  httpUri?: string;
  httpUserAgent?: string;
  dnsQuery?: string;
  classtype?: string;
  sid?: number;
  rev?: number;
}

export function generateSuricataRule(params: SuricataRuleParams): string {
  const action = params.action || "alert";
  const proto = params.proto || "tcp";
  const src = params.src || "$HOME_NET";
  const sport = params.sport || "any";
  const dst = params.dst || "$EXTERNAL_NET";
  const dport = params.dport || "any";
  const sid = params.sid || 2026001;
  const rev = params.rev || 1;
  const classtype = params.classtype || "trojan-activity";

  const options: string[] = [
    `msg:"BeyondLabs PCAP Detection - ${params.msg.replace(/"/g, "'")}"`,
  ];

  if (params.content) {
    options.push(`content:"${params.content.replace(/"/g, '\\"')}"`);
  }
  if (params.httpUri) {
    options.push(`content:"${params.httpUri.replace(/"/g, '\\"')}"; http_uri`);
  }
  if (params.httpUserAgent) {
    options.push(`content:"${params.httpUserAgent.replace(/"/g, '\\"')}"; http_user_agent`);
  }
  if (params.dnsQuery) {
    options.push(`dns.query; content:"${params.dnsQuery.replace(/"/g, '\\"')}"; nocase`);
  }

  options.push(`classtype:${classtype}`);
  options.push(`sid:${sid}`);
  options.push(`rev:${rev}`);

  return `${action} ${proto} ${src} ${sport} -> ${dst} ${dport} (${options.join("; ")};)`;
}

export function generateRulesetFromPcap(findings: Array<{ title: string; reason?: string; detail?: string }>, beaconingPairs: Array<{ src: string; dst: string; packets: number }>, dnsQueries: string[], httpRequests: Array<{ method?: string; path?: string; user_agent?: string; host?: string }>): string {
  const rules: string[] = [
    "# ==========================================================================",
    "# BeyondLabs Incident Response - Synthesized Suricata IDS Signatures",
    `# Generated: ${new Date().toISOString()}`,
    "# ==========================================================================",
    "",
  ];

  let sid = 2026101;

  // 1. Beaconing pairs
  for (const pair of beaconingPairs.slice(0, 3)) {
    rules.push(
      generateSuricataRule({
        proto: "tcp",
        dst: pair.dst,
        msg: `Potential C2 Beaconing to ${pair.dst} (${pair.packets} pkts)`,
        classtype: "trojan-activity",
        sid: sid++,
      })
    );
  }

  // 2. High entropy or tunneling domains
  const suspiciousDns = dnsQueries.filter((q) => q.length > 40 || q.split(".").length > 4).slice(0, 3);
  for (const domain of suspiciousDns) {
    rules.push(
      generateSuricataRule({
        proto: "dns",
        dport: "53",
        msg: `Suspicious DNS Query / Tunneling to ${domain.slice(0, 25)}`,
        dnsQuery: domain.slice(0, 20),
        classtype: "bad-unknown",
        sid: sid++,
      })
    );
  }

  // 3. HTTP suspicious requests
  for (const req of httpRequests.slice(0, 3)) {
    if (req.user_agent && /curl|python|powershell|mimikatz|certutil/i.test(req.user_agent)) {
      rules.push(
        generateSuricataRule({
          proto: "http",
          dport: "80,8080",
          msg: `Offensive Tool User-Agent (${req.user_agent.slice(0, 30)})`,
          httpUserAgent: req.user_agent,
          classtype: "suspicious-traffic",
          sid: sid++,
        })
      );
    }
  }

  if (rules.length === 4) {
    // Fallback default rule if no specific indicators triggered
    rules.push(
      generateSuricataRule({
        proto: "tcp",
        msg: "Generic Suspicious External Outbound Connection",
        classtype: "misc-activity",
        sid: sid++,
      })
    );
  }

  return rules.join("\n");
}
