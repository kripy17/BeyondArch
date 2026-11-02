import { describe, it, expect, beforeEach } from "vitest";
import {
  detectQueryDialect,
  inferMitreTechnique,
  extractDetectionTokens,
  generateNoiseFilters,
  tuneQueryToSigma,
  evaluateSigmaHealth,
  promoteRuleToDetectionLab,
  LS_PENDING_RULE_ID,
} from "../detection/sigma-tuning-engine";

const store = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => {
    store.set(k, v);
  },
  removeItem: (k: string) => {
    store.delete(k);
  },
  clear: () => {
    store.clear();
  },
  key: (i: number) => [...store.keys()][i] ?? null,
  get length() {
    return store.size;
  },
};

describe("Sigma Rule Auto-Tuning Engine", () => {
  beforeEach(() => {
    store.clear();
  });

  describe("Query Dialect Detection", () => {
    it("identifies Splunk SPL queries", () => {
      const q = 'index=windows sourcetype="WinEventLog:Security" EventCode=4688 | stats count by user';
      expect(detectQueryDialect(q)).toBe("splunk");
    });

    it("identifies Microsoft Sentinel KQL queries", () => {
      const q = 'DeviceProcessEvents | where FileName =~ "powershell.exe" | project Timestamp, DeviceName';
      expect(detectQueryDialect(q)).toBe("sentinel");
    });

    it("identifies Elastic EQL queries", () => {
      const q = 'process where event.type == "start" and process.name == "certutil.exe"';
      expect(detectQueryDialect(q)).toBe("elastic");
    });

    it("identifies Suricata IDS signatures", () => {
      const q = 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Test rule"; sid:10001;)';
      expect(detectQueryDialect(q)).toBe("suricata");
    });

    it("falls back to generic for plain text searches", () => {
      expect(detectQueryDialect("malicious activity payload.exe")).toBe("generic");
    });
  });

  describe("MITRE Technique Inference", () => {
    it("maps Kerberoasting queries to T1558.003", () => {
      const res = inferMitreTechnique("EventCode=4769 Ticket_Encryption_Type=0x17");
      expect(res).not.toBeNull();
      expect(res?.techniqueId).toBe("T1558.003");
      expect(res?.tactic).toBe("Credential Access");
    });

    it("maps PsExec named pipe execution to T1569.002", () => {
      const res = inferMitreTechnique('ServiceName="PSEXESVC" admin$');
      expect(res).not.toBeNull();
      expect(res?.techniqueId).toBe("T1569.002");
      expect(res?.tactic).toBe("Execution");
    });

    it("maps volume shadow copy deletion to T1490", () => {
      const res = inferMitreTechnique("vssadmin delete shadows /all /quiet");
      expect(res).not.toBeNull();
      expect(res?.techniqueId).toBe("T1490");
      expect(res?.defaultLevel).toBe("critical");
    });

    it("respects explicitly specified MITRE technique override", () => {
      const res = inferMitreTechnique("arbitrary query", "T1059.001");
      expect(res?.techniqueId).toBe("T1059.001");
      expect(res?.techniqueName).toContain("PowerShell");
    });
  });

  describe("Token & Selection Extraction", () => {
    it("extracts EventCode and process name from SPL", () => {
      const spl = 'index=windows EventCode=4688 NewProcessName="C:\\\\Windows\\\\System32\\\\cmd.exe"';
      const { selection, logsource } = extractDetectionTokens(spl, "splunk");

      expect(selection.EventID).toBe(4688);
      expect(selection["Image|endswith"]).toContain("cmd.exe");
      expect(logsource.category).toBe("process_creation");
    });

    it("extracts FileName and CommandLine from KQL", () => {
      const kql = 'DeviceProcessEvents | where FileName =~ "certutil.exe" | where ProcessCommandLine has "-urlcache"';
      const { selection, logsource } = extractDetectionTokens(kql, "sentinel");

      expect(selection["Image|endswith"]).toBe("\\certutil.exe");
      expect(selection["CommandLine|contains"]).toBe("-urlcache");
      expect(logsource.category).toBe("process_creation");
    });
  });

  describe("Noise Suppression Filters", () => {
    it("generates updater and parent process exclusion filters for process_creation", () => {
      const filters = generateNoiseFilters({ category: "process_creation" }, {});
      expect(filters.length).toBeGreaterThanOrEqual(2);

      const updaterFilter = filters.find((f) => f.id === "filter-updater");
      expect(updaterFilter).toBeDefined();
      expect(updaterFilter?.enabled).toBe(true);

      const userFilter = filters.find((f) => f.id === "filter-system-user");
      expect(userFilter).toBeDefined();
    });

    it("generates machine account filter for security Kerberos events", () => {
      const filters = generateNoiseFilters({ service: "security" }, { EventID: 4769 });
      const machineFilter = filters.find((f) => f.id === "filter-machine-accounts");
      expect(machineFilter).toBeDefined();
      expect(machineFilter?.value).toBe("$");
    });
  });

  describe("Autonomous Query-to-Sigma Tuning Engine", () => {
    it("tunes a raw Splunk query into a complete Sigma YAML rule", () => {
      const spl = 'index=windows sourcetype="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17" Service_Name!="*$"';
      const tuned = tuneQueryToSigma(spl);

      expect(tuned.id).toBeTruthy();
      expect(tuned.status).toBe("test");
      expect(tuned.techniqueId).toBe("T1558.003");
      expect(tuned.yaml).toContain("title:");
      expect(tuned.yaml).toContain("id:");
      expect(tuned.yaml).toContain("detection:");
      expect(tuned.yaml).toContain("filter_noise:");
      expect(tuned.yaml).toContain("condition: selection and not filter_noise");
      expect(tuned.yaml).toContain("falsepositives:");
      expect(tuned.healthScore).toBeGreaterThanOrEqual(80);
      expect(tuned.noiseRisk).toMatch(/minimal|low|moderate/);
    });

    it("tunes a Sentinel KQL query with high fidelity and proper tagging", () => {
      const kql = 'DeviceProcessEvents | where FileName =~ "powershell.exe" | where ProcessCommandLine has "-EncodedCommand"';
      const tuned = tuneQueryToSigma(kql);

      expect(tuned.techniqueId).toBe("T1059.001");
      expect(tuned.tags).toContain("attack.execution");
      expect(tuned.tags).toContain("attack.t1059.001");
      expect(tuned.yaml).toContain("filter_noise:");
      expect(tuned.healthScore).toBeGreaterThanOrEqual(85);
    });
  });

  describe("Sigma Quality & Health Evaluation", () => {
    it("penalizes missing sections and rewards noise suppression", () => {
      const poorYaml = `
title: Minimal Rule
detection:
  selection:
    CommandLine: powershell.exe
  condition: selection
`;
      const poorHealth = evaluateSigmaHealth(poorYaml);
      expect(poorHealth.healthScore).toBeLessThan(70);

      const goodYaml = `
title: High Quality Rule
id: 12345678-1234-1234-1234-123456789abc
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
  filter_noise:
    User: 'NT AUTHORITY\\SYSTEM'
  condition: selection and not filter_noise
falsepositives:
  - Administrative maintenance
level: high
tags:
  - attack.execution
  - attack.t1059.001
`;
      const goodHealth = evaluateSigmaHealth(goodYaml);
      expect(goodHealth.healthScore).toBeGreaterThanOrEqual(90);
      expect(goodHealth.noiseRisk).toBe("minimal");
      expect(goodHealth.fpEstimatedPct).toBeLessThan(3.0);
    });
  });

  describe("Detection Sandbox Promotion", () => {
    it("promotes tuned rule directly into Detection Library and stores pendingRuleId", () => {
      const spl = 'index=windows EventCode=7045 ServiceName="PSEXESVC"';
      const tuned = tuneQueryToSigma(spl);

      const saved = promoteRuleToDetectionLab(tuned);
      expect(saved.id).toBe(tuned.id);
      expect(saved.name).toBe(tuned.title);
      expect(saved.format).toBe("sigma");
      expect(saved.state).toBe("draft");

      // Verify localStorage was updated
      expect(store.get(LS_PENDING_RULE_ID)).toBe(tuned.id);
      const rawLibrary = store.get("ba.detection.rules.v2");
      expect(rawLibrary).toBeTruthy();
      expect(rawLibrary).toContain(tuned.id);
    });
  });
});
