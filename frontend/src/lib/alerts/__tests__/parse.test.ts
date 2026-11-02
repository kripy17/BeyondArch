import { describe, expect, it } from "vitest";
import { parseAlert, detectAlertFormat, iocObservations, observationKinds } from "@/lib/alerts/parse";

const CANONICAL = JSON.stringify({
  schema: "beyondlabs.alert.v1",
  title: "Malicious payload download",
  severity: "high",
  summary: "PowerShell cradle contacting staging host",
  observed_at: "2026-08-14T09:30:00.000Z",
  rule_ref: "sigma-encoded-download",
  observables: ["hxxps[:]//evil[.]example[.]xyz/x", "victim@corp.xyz", "198.51.100.73"],
});

const SIGMA = `title: Suspicious PowerShell Encoded Command
id: 7f2a4b3c-0000-0000-0000-000000000001
status: test
level: high
description: Detects encoded PowerShell invocations
tags:
  - attack.t1059.001
detection:
  selection:
    CommandLine|contains: '-enc'
  condition: selection
`;

const SURICATA = JSON.stringify({
  timestamp: "2026-08-14T09:31:00.000Z",
  event_type: "alert",
  src_ip: "203.0.113.9",
  dest_ip: "198.51.100.20",
  alert: { signature: "ET MALWARE Possible Cobalt Strike", severity: 1 },
});

const SYSMON = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/><EventID>3</EventID><TimeCreated SystemTime="2026-08-14T09:32:00.000Z"/></System>
<EventData><Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c powershell -enc SQBFAFgA</Data><Data Name="DestinationIp">203.0.113.9</Data></EventData>
</Event>`;

describe("parseAlert — format detection", () => {
  it("detects beyondlabs canonical, sigma, suricata, sysmon; rejects others", () => {
    expect(detectAlertFormat(CANONICAL)).toBe("beyondlabs");
    expect(detectAlertFormat(SIGMA)).toBe("sigma");
    expect(detectAlertFormat(SURICATA)).toBe("suricata");
    expect(detectAlertFormat(SYSMON)).toBe("sysmon");
    expect(detectAlertFormat("just some plain text with no alert grammar")).toBeNull();
  });
});

describe("parseAlert — beyondlabs canonical", () => {
  it("parses title/severity/summary/rule_ref and scans observables into canonical observations", () => {
    const a = parseAlert(CANONICAL)!;
    expect(a).not.toBeNull();
    expect(a.format).toBe("beyondlabs");
    expect(a.title).toBe("Malicious payload download");
    expect(a.severity).toBe("high");
    expect(a.observedAt).toBe("2026-08-14T09:30:00.000Z");
    expect(a.ruleName).toBe("sigma-encoded-download");
    const kinds = observationKinds(a.observations);
    expect(kinds).toContain("url");
    expect(kinds).toContain("email");
    expect(kinds).toContain("ip");
    expect(a.observations.some((o) => o.value === "198.51.100.73")).toBe(true);
    expect(a.observations.some((o) => o.value === "victim@corp.xyz")).toBe(true);
  });

  it("does not synthesize observations from schema metadata", () => {
    const a = parseAlert(CANONICAL)!;
    expect(a.observations.some((o) => o.value.includes("beyondlabs"))).toBe(false);
    expect(a.observations.some((o) => o.value.includes("alert.v1"))).toBe(false);
  });

  it("falls back to medium for unknown severity and tolerates missing fields", () => {
    const a = parseAlert(JSON.stringify({ schema: "beyondlabs.alert.v1", title: "Minimal alert" }))!;
    expect(a.severity).toBe("medium");
    expect(a.summary).toBe("");
    expect(a.ruleName).toBeUndefined();
  });

  it("handles defanged observables via refang", () => {
    const a = parseAlert(JSON.stringify({
      schema: "beyondlabs.alert.v1",
      title: "Defanged",
      observables: ["hxxp[:]//bad[.]example[.]com/"],
    }))!;
    expect(a.observations.some((o) => o.kind === "url" && o.value === "http://bad.example.com/")).toBe(true);
  });
});

describe("parseAlert — sigma-style detection output", () => {
  it("maps level to severity and carries the rule title as ruleName", () => {
    const a = parseAlert(SIGMA)!;
    expect(a.format).toBe("sigma");
    expect(a.title).toBe("Suspicious PowerShell Encoded Command");
    expect(a.severity).toBe("high");
    expect(a.ruleName).toBe("Suspicious PowerShell Encoded Command");
    expect(a.summary).toContain("encoded PowerShell");
  });

  it("maps informational to low severity", () => {
    const a = parseAlert(SIGMA.replace("level: high", "level: informational"))!;
    expect(a.severity).toBe("low");
  });

  it("requires the detection block", () => {
    expect(parseAlert("title: No detection block here\nlevel: high")).toBeNull();
  });
});

describe("parseAlert — suricata EVE alert", () => {
  it("extracts src/dest ips with roles and maps severity 1 → critical", () => {
    const a = parseAlert(SURICATA)!;
    expect(a.format).toBe("suricata");
    expect(a.title).toBe("ET MALWARE Possible Cobalt Strike");
    expect(a.severity).toBe("critical");
    expect(a.observedAt).toBe("2026-08-14T09:31:00.000Z");
    const ips = a.observations.filter((o) => o.kind === "ip");
    expect(ips).toHaveLength(2);
    expect(ips.find((o) => o.value === "203.0.113.9")?.meta.role).toBe("src");
    expect(ips.find((o) => o.value === "198.51.100.20")?.meta.role).toBe("dst");
  });

  it("maps severity 4 → low and defaults missing severity to medium", () => {
    const low = parseAlert(JSON.stringify({ event_type: "alert", alert: { signature: "Low signal", severity: 4 } }))!;
    expect(low.severity).toBe("low");
    const none = parseAlert(JSON.stringify({ event_type: "alert", alert: { signature: "No sev" } }))!;
    expect(none.severity).toBe("medium");
  });

  it("rejects non-alert EVE events", () => {
    expect(parseAlert(JSON.stringify({ event_type: "flow", src_ip: "203.0.113.9" }))).toBeNull();
  });
});

describe("parseAlert — sysmon-derived alert", () => {
  it("extracts the command line as a command observation and maps EventID 3 → high", () => {
    const a = parseAlert(SYSMON)!;
    expect(a.format).toBe("sysmon");
    expect(a.severity).toBe("high");
    expect(a.title).toContain("EventID 3");
    const cmds = a.observations.filter((o) => o.kind === "command");
    expect(cmds.length).toBeGreaterThan(0);
    expect(cmds[0]!.value).toContain("powershell -enc");
  });

  it("maps EventID 22 (dns query) to low severity", () => {
    const dns = SYSMON.replace("<EventID>3</EventID>", "<EventID>22</EventID>").replace(
      '<Data Name="CommandLine">cmd.exe /c powershell -enc SQBFAFgA</Data>',
      '<Data Name="QueryName">update.evil.xyz</Data>',
    );
    const a = parseAlert(dns)!;
    expect(a.severity).toBe("low");
    expect(a.title).toContain("EventID 22");
  });

  it("requires the Sysmon provider", () => {
    const other = SYSMON.replace("Microsoft-Windows-Sysmon", "Microsoft-Windows-Security-Auditing");
    expect(parseAlert(other)).toBeNull();
  });
});

describe("iocObservations", () => {
  it("keeps classic IOC kinds only — commands and strings stay out of the IOC table", () => {
    const a = parseAlert(SYSMON)!;
    const iocs = iocObservations(a.observations);
    expect(iocs.every((o) => ["ip", "domain", "url", "email", "hash"].includes(o.kind))).toBe(true);
    expect(iocs.some((o) => o.kind === "command")).toBe(false);
  });
});
