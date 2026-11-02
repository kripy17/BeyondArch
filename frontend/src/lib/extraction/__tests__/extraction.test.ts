import { describe, expect, it } from "vitest";
import { classifyIoc, normalizeDomain, normalizeEmail, normalizeHash, normalizeIp, normalizeUrl, observationId, makeObservation, extractObservations, observationsFromIocs, extractCommandLines, EVTX_ADAPTER, CSV_ADAPTER, ZEEK_ADAPTER, SURICATA_ADAPTER, TEXT_ADAPTER, normalizeObservations } from "@/lib/extraction";
import { PCAP_ADAPTER, NGINX_ADAPTER } from "@/lib/extraction/adapters";
import { INVESTIGATION_OBJECTS_V1, type ObservationKind } from "@/types/objects";

const OBSERVATION_KINDS = new Set<ObservationKind>([
  "url", "url-part", "domain", "ip", "hash", "email", "header", "string",
  "macro", "import", "registry-key", "process", "command", "user-agent",
  "ja3", "certificate", "dns", "asn", "mutex", "unknown",
]);

const SYSTEM_CLOCK = "2026-08-07T10:00:00.000Z";

describe("normalize", () => {
  it("refangs and validates IPs", () => {
    expect(normalizeIp("198[.]51[.]100[.]23")).toBe("198.51.100.23");
    expect(normalizeIp("999.1.1.1")).toBeNull();
    expect(normalizeIp("not-an-ip")).toBeNull();
  });

  it("canonicalizes domains", () => {
    expect(normalizeDomain("evil-example[.]com")).toBe("evil-example.com");
    expect(normalizeDomain("EXAMPLE.COM.")).toBe("example.com");
    expect(normalizeDomain("localhost")).toBeNull();
    expect(normalizeDomain("bad_domain")).toBeNull();
  });

  it("canonicalizes emails", () => {
    expect(normalizeEmail("Analyst@Corp[.]Local")).toBe("analyst@corp.local");
    expect(normalizeEmail("no-at-sign")).toBeNull();
  });

  it("classifies hashes by length", () => {
    expect(normalizeHash("44d88612fea8a8f36de82e1278abb02f")).toEqual({ type: "md5", value: "44d88612fea8a8f36de82e1278abb02f" });
    expect(normalizeHash("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")).toEqual({ type: "sha256", value: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2" });
    expect(normalizeHash("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")).toBeNull();
  });

  it("refangs URLs and normalizes scheme/host", () => {
    expect(normalizeUrl("hxxps[:]//Login.Example[.]Com/Reset")).toBe("https://login.example.com/Reset");
    expect(normalizeUrl("ftp://example.com")).toBeNull();
  });

  it("classifies IOCs", () => {
    expect(classifyIoc("198[.]51[.]100[.]23")).toBe("ipv4");
    expect(classifyIoc("2001:db8::1")).toBe("ipv6");
    expect(classifyIoc("evil[.]com")).toBe("domain");
    expect(classifyIoc("a@b[.]com")).toBe("email");
    expect(classifyIoc("44d88612fea8a8f36de82e1278abb02f")).toBe("md5");
    expect(classifyIoc("hxxps[:]//evil[.]com/x")).toBe("url");
    expect(classifyIoc("CVE-2024-1234")).toBe("unknown");
  });
});

describe("observations", () => {
  it("assigns deterministic ids from kind+canonical value", () => {
    const a = makeObservation({ kind: "ip", value: "8.8.8.8", source: "t" });
    const b = makeObservation({ kind: "ip", value: "8.8.8.8", source: "different-source" });
    expect(a.id).toBe(b.id);
    expect(a.id).toBe(observationId("ip", "8.8.8.8"));
    expect(makeObservation({ kind: "domain", value: "8.8.8.8", source: "t" }).id).not.toBe(a.id);
  });

  it("emits schema-versioned, immutable-shape objects", () => {
    const o = makeObservation({ kind: "ip", value: "8.8.8.8", source: "t", ts: SYSTEM_CLOCK });
    expect(o.schemaVersion).toBe(INVESTIGATION_OBJECTS_V1);
    expect(o.ts).toBe(SYSTEM_CLOCK);
    expect(o.meta).toEqual({});
  });

  it("extracts facts only — never intent", () => {
    const { observations } = extractObservations("hxxps[:]//checkout[.]example[.]com/reset?id=1 from 198.51.100.23", "t", SYSTEM_CLOCK);
    for (const o of observations) {
      expect(OBSERVATION_KINDS.has(o.kind)).toBe(true);
      const blob = JSON.stringify({ meta: o.meta, source: o.source });
      expect(blob).not.toMatch(/malicious|suspicious|phishing|intent/i);
    }
  });

  it("decomposes URLs into host domain/ip sub-observations", () => {
    const { observations } = extractObservations("visit http://198.51.100.23/payload.ps1", "t", SYSTEM_CLOCK);
    const kinds = observations.map((o) => o.kind).sort();
    expect(kinds).toContain("url");
    expect(kinds).toContain("ip");
    expect(kinds).not.toContain("domain");
    const url = observations.find((o) => o.kind === "url");
    expect(url?.meta.host).toBe("198.51.100.23");
    expect(url?.meta.scheme).toBe("http");
    expect(url?.meta.path).toBe("/payload.ps1");
  });

  it("dedups re-assertions by canonical id", () => {
    const { observations } = extractObservations("a@b.com and a@b[.]com", "t", SYSTEM_CLOCK);
    expect(observations.filter((o) => o.kind === "email")).toHaveLength(1);
  });

  it("bridges legacy parser IOC maps without losing hash type", () => {
    const obs = observationsFromIocs(
      { SHA256: ["a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"], CVE: ["CVE-2024-12345"], URL: ["hxxps[:]//evil[.]com"] },
      "t",
      "case-1",
      SYSTEM_CLOCK,
    );
    const hash = obs.find((o) => o.kind === "hash");
    expect(hash?.meta.hashType).toBe("sha256");
    const url = obs.find((o) => o.kind === "url");
    expect(url?.value).toBe("https://evil.com/");
    const cve = obs.find((o) => o.value.includes("CVE-2024-12345"));
    expect(cve?.meta.iocType).toBe("cve");
    expect(cve?.meta.context).toBe("case-1");
  });
});

describe("adapters — one canonical vocabulary (ANALYSIS_ENGINE §4b)", () => {
  const EVTX = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><Computer>DC01.corp.local</Computer></System>
<EventData>
<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name="CommandLine">powershell.exe -nop -w hidden -enc SQBFAFgA</Data>
<Data Name="User">CORP\\analyst</Data>
<Data Name="SourceIp">198.51.100.23</Data>
<Data Name="Hashes">MD5=44d88612fea8a8f36de82e1278abb02f,SHA256=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2</Data>
</EventData></Event>`;

  const CSV = "type,value,source,note\nipv4,198.51.100.23,alerts.csv,scan source\ndomain,evil-example[.]com,threatintel,targeted\nsha256,a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2,vxhub,stealer";

  const ZEEK = `#separator \\x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto
#types	time	string	string	port	string	port	enum
1501501007.123456	CiFdP63fiUqBpbDZll	10.2.3.4	2273	185.94.188.22	443	tcp
1501501015.902113	CHhAvVWN1dTqn45ik	192.168.10.53	51034	195.54.175.121	8888	tcp`;

  const SURICATA = '{"timestamp":"2026-04-25T10:12:00Z","event_type":"alert","src_ip":"198.51.100.23","dest_ip":"10.0.0.5","alert":{"signature":"ET WEB_SERVER Possible SQL Injection"}}';

  const TCPDUMP = `12:34:56.789012 IP 192.168.1.100.443 > 10.0.0.2.52341: Flags [P.], seq 1:1460, ack 1, win 8192
12:34:57.501234 IP 192.168.1.100.49153 > 8.8.8.8.53: 1234+ A? evil-payload.ru
12:34:57.501334 IP 8.8.8.8.53 > 192.168.1.100.49153: 1234 NXDomain 0/1/0 (95)`;

  const TSHARK = `1   0.000000 192.168.1.100 → 203.0.113.55 HTTP GET /index.html
7   0.200000 192.168.1.100 → 8.8.8.8 DNS Standard query A google.com
5   0.100000 192.168.1.100 → 185.220.101.44 TLSv1.2 Client Hello (SNI=evil-payload.ru)`;

  it("detects the right adapter per format", () => {
    expect(EVTX_ADAPTER.detect(EVTX)).toBe(true);
    expect(CSV_ADAPTER.detect(CSV)).toBe(true);
    expect(ZEEK_ADAPTER.detect(ZEEK)).toBe(true);
    expect(SURICATA_ADAPTER.detect(SURICATA)).toBe(true);
    expect(PCAP_ADAPTER.detect(TCPDUMP)).toBe(true);
    expect(PCAP_ADAPTER.detect(TSHARK)).toBe(true);
    expect(TEXT_ADAPTER.detect("anything")).toBe(true);
  });

  it("reaches the same vocabulary across EVTX / CSV / Zeek / Suricata / PCAP", () => {
    const kindsOf = (raw: string) => normalizeObservations(raw, { source: "acceptance", ts: SYSTEM_CLOCK }).observations.map((o) => o.kind);
    const evtx = kindsOf(EVTX);
    const csv = kindsOf(CSV);
    const zeek = kindsOf(ZEEK);
    const suricata = kindsOf(SURICATA);
    const pcap = kindsOf(TCPDUMP + "\n" + TSHARK);
    for (const kinds of [evtx, csv, zeek, suricata, pcap]) {
      for (const kind of kinds) expect(OBSERVATION_KINDS.has(kind)).toBe(true);
    }
    expect(evtx).toContain("ip");
    expect(evtx).toContain("hash");
    expect(evtx).toContain("domain");
    expect(evtx).toContain("process");
    expect(evtx).toContain("command");
    expect(csv).toContain("ip");
    expect(csv).toContain("hash");
    expect(csv).toContain("domain");
    expect(zeek).toContain("ip");
    expect(suricata).toContain("ip");
    expect(pcap).toContain("ip");
    expect(pcap).toContain("domain");
  });

  it("assigns identical ids to the same canonical value across formats", () => {
    const evtx = normalizeObservations(EVTX, { source: "a", ts: SYSTEM_CLOCK }).observations;
    const csv = normalizeObservations(CSV, { source: "b", ts: SYSTEM_CLOCK }).observations;
    const sharedHash = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
    const inEvtx = evtx.find((o) => o.value === sharedHash);
    const inCsv = csv.find((o) => o.value === sharedHash);
    expect(inEvtx).toBeDefined();
    expect(inCsv).toBeDefined();
    expect(inEvtx?.id).toBe(inCsv?.id);
  });

  it("emits structural facts from EVTX fields", () => {
    const obs = EVTX_ADAPTER.extract(EVTX, "test", SYSTEM_CLOCK);
    const process = obs.find((o) => o.kind === "process");
    expect(process?.value).toContain("powershell.exe");
    const command = obs.find((o) => o.kind === "command");
    expect(command?.value).toContain("-enc");
    const user = obs.find((o) => o.meta.attr === "user");
    expect(user?.value).toContain("CORP");
  });

  it("maps CSV rows through the type column", () => {
    const obs = CSV_ADAPTER.extract(CSV, "test", SYSTEM_CLOCK);
    const ip = obs.find((o) => o.kind === "ip");
    expect(ip?.value).toBe("198.51.100.23");
    expect(ip?.meta.source).toBe("alerts.csv");
    const hash = obs.find((o) => o.kind === "hash");
    expect(hash?.meta.hashType).toBe("sha256");
  });

  it("emits conn-state facts from Zeek conn_state column", () => {
    const ZEEK_STATES = `#path	conn
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	conn_state
#types	time	string	string	port	string	port	enum	enum
1501501022.330123	C2E1j9tG44Flnm4sha	192.168.10.9	49502	85.209.159.98	80	tcp	RSTR
1501501027.884210	CLJtMq2hK7Q1Tb3mzr	10.2.3.4	44321	45.155.205.233	8080	tcp	REJ`;
    const obs = ZEEK_ADAPTER.extract(ZEEK_STATES, "test", SYSTEM_CLOCK);
    const states = obs.filter((o) => o.meta.attr === "zeek-conn-state");
    expect(states.length).toBe(2);
    expect(states[0].meta.state).toBe("RSTR");
    expect(states[0].meta.src).toBe("192.168.10.9");
    expect(states[0].meta.dst).toBe("85.209.159.98");
    expect(states[1].meta.state).toBe("REJ");
    expect(obs.filter((o) => o.kind === "ip").length).toBe(4);
  });

  it("parses Nginx combined log into http-request facts", () => {
    const NGINX = '198.51.100.23 - - [25/Apr/2026:10:12:00 +0000] "GET /wp-login.php HTTP/2.0" 401 512 "-" "curl/7.88.1"';
    expect(NGINX_ADAPTER.detect(NGINX)).toBe(true);
    const obs = NGINX_ADAPTER.extract(NGINX, "test", SYSTEM_CLOCK);
    const req = obs.find((o) => o.meta.attr === "http-request");
    expect(req?.meta.method).toBe("GET");
    expect(req?.meta.path).toBe("/wp-login.php");
    expect(req?.meta.status).toBe("401");
    expect(req?.meta.client).toBe("198.51.100.23");
    const ip = obs.find((o) => o.kind === "ip");
    expect(ip?.value).toBe("198.51.100.23");
  });
});

describe("extractObservations counts", () => {
  it("reports kind counts for consumers", () => {
    const { counts } = extractObservations("8.8.8.8 8.8.8.8 a@b.com", "t", SYSTEM_CLOCK);
    expect(counts.ip).toBe(1);
    expect(counts.email).toBe(1);
  });
});

describe("extractCommandLines", () => {
  it("captures powershell invocation lines as command observations", () => {
    const obs = extractCommandLines("powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA", "t", SYSTEM_CLOCK);
    expect(obs).toHaveLength(1);
    expect(obs[0].kind).toBe("command");
    expect(obs[0].value).toContain("-EncodedCommand");
    expect(obs[0].meta.process).toBe("powershell");
  });

  it("normalizes Command Line: prefixes from log events", () => {
    const obs = extractCommandLines("Event ID: 4688\nCommand Line: cmd.exe /c start powershell", "t", SYSTEM_CLOCK);
    expect(obs).toHaveLength(1);
    expect(obs[0].value.startsWith("cmd.exe /c start powershell")).toBe(true);
  });

  it("ignores non-command text and email bodies", () => {
    const obs = extractCommandLines("Subject: Password reset required\nPlease verify at hxxps[:]//login.example[.]com/reset", "t", SYSTEM_CLOCK);
    expect(obs).toHaveLength(0);
  });

  it("deterministic ids across re-extraction", () => {
    const text = "powershell.exe -enc SQBFAFgA";
    const a = extractCommandLines(text, "t", SYSTEM_CLOCK);
    const b = extractCommandLines(text, "t", SYSTEM_CLOCK);
    expect(a[0].id).toBe(b[0].id);
  });
});
