import { describe, it, expect } from "vitest";
import { connStateLabel, connStateTone, extractZeekFromText } from "../pcap/zeek-models";
import { buildWiresharkFilter, buildTsharkCommand, WIRESHARK_PRESETS } from "../pcap/wireshark-filters";
import { generateSuricataRule, generateRulesetFromPcap } from "../pcap/suricata-generator";

describe("Zeek Protocol Models & State Handlers", () => {
  it("formats connection states accurately", () => {
    expect(connStateLabel("SF")).toBe("Normal (SYN-ACK-FIN)");
    expect(connStateLabel("S0")).toBe("Attempted (No reply)");
    expect(connStateLabel("REJ")).toBe("Rejected (RST)");
    expect(connStateTone("SF")).toBe("success");
    expect(connStateTone("S0")).toBe("warning");
    expect(connStateTone("REJ")).toBe("destructive");
  });

  it("extracts Zeek connections and DNS from raw tcpdump text", () => {
    const sample = `
10:15:01.000000 IP 192.168.1.50.49152 > 10.0.0.1.53: 12345+ A? evil.darkc2.com. (32)
10:15:01.050000 IP 192.168.1.50.55432 > 45.33.32.156.80: Flags [S], seq 100
10:15:01.060000 IP 192.168.1.50.55432 > 45.33.32.156.80: Flags [P.], seq 101:200, ack 1
GET /beacon HTTP/1.1
Host: evil.darkc2.com
Authorization: Basic YWRtaW46UGFzc3dvcmQxMjM=
    `;

    const extracted = extractZeekFromText(sample);
    expect(extracted.conns.length).toBeGreaterThan(0);
    expect(extracted.dns.length).toBe(1);
    expect(extracted.dns[0].query).toBe("evil.darkc2.com");
    expect(extracted.creds.length).toBe(1);
    expect(extracted.creds[0].username).toBe("admin");
    expect(extracted.creds[0].password_masked).not.toBe("Password123");
  });
});

describe("Wireshark Filters & TShark Builder", () => {
  it("builds multi-criteria Wireshark display filters", () => {
    const filter = buildWiresharkFilter({
      ip: "10.0.0.5",
      port: "443",
      proto: "TCP",
      host: "evil.com",
    });

    expect(filter).toContain("ip.addr == 10.0.0.5");
    expect(filter).toContain("tcp.port == 443");
    expect(filter).toContain("tcp");
    expect(filter).toContain('http.host == "evil.com"');
  });

  it("builds standard TShark CLI commands", () => {
    const cmd = buildTsharkCommand("http.request.method == 'POST'", "incident.pcap");
    expect(cmd).toContain("tshark -r \"incident.pcap\"");
    expect(cmd).toContain("-Y 'http.request.method == 'POST''");
  });

  it("contains essential SOC preset filters", () => {
    const presetIds = WIRESHARK_PRESETS.map((p) => p.id);
    expect(presetIds).toContain("dns_tunneling");
    expect(presetIds).toContain("plaintext_creds");
    expect(presetIds).toContain("syn_scan");
    expect(presetIds).toContain("c2_ports");
  });
});

describe("Suricata IDS Generator", () => {
  it("generates valid individual Suricata rules", () => {
    const rule = generateSuricataRule({
      proto: "tcp",
      dst: "45.33.32.156",
      dport: "8080",
      msg: "C2 Cobalt Strike Beacon",
      content: "POST",
      httpUri: "/submit.php",
      sid: 2026999,
    });

    expect(rule).toMatch(/^alert tcp \$HOME_NET any -> 45\.33\.32\.156 8080/);
    expect(rule).toContain('msg:"BeyondLabs PCAP Detection - C2 Cobalt Strike Beacon";');
    expect(rule).toContain('content:"POST";');
    expect(rule).toContain('content:"/submit.php"; http_uri;');
    expect(rule).toContain("sid:2026999;");
  });

  it("synthesizes complete rulesets from PCAP telemetry", () => {
    const ruleset = generateRulesetFromPcap(
      [{ title: "Suspicious Flow" }],
      [{ src: "192.168.1.5", dst: "5.188.62.18", packets: 65 }],
      ["aW5maWx0cmF0aW9u.tunnel.corp.net"],
      [{ user_agent: "curl/7.81.0" }]
    );

    expect(ruleset).toContain("# BeyondLabs Incident Response - Synthesized Suricata IDS Signatures");
    expect(ruleset).toContain("5.188.62.18");
    expect(ruleset).toContain("curl/7.81.0");
  });
});
