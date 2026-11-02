import { describe, expect, it } from "vitest";
import {
  parseQuery,
  toSplunkSPL,
  toElasticKQL,
  toSigmaRule,
  toVelociraptorVQL,
  translateAll,
} from "@/lib/siem/query-translator";

describe("siem query-translator", () => {
  it("parses tokens, key-value fields, and pipe commands", () => {
    const parsed = parseQuery('user:admin "mimikatz" failed | stats count by src | head 10');
    expect(parsed.fieldFilters).toEqual([{ field: "user", value: "admin" }]);
    expect(parsed.terms).toContain("mimikatz");
    expect(parsed.terms).toContain("failed");
    expect(parsed.pipeCommands).toEqual(["stats count by src", "head 10"]);
  });

  it("translates to Splunk SPL with time ranges, chips, and pipes", () => {
    const spl = toSplunkSPL("svc_db", [{ field: "src", value: "45.33.32.156" }], "15m");
    expect(spl).toContain("earliest=-15m");
    expect(spl).toContain('src_ip="45.33.32.156"');
    expect(spl).toContain("(*svc_db*)");
    expect(spl).toContain("| stats count by src_ip");
  });

  it("translates OR queries to Splunk and Elastic KQL", () => {
    const spl = toSplunkSPL("mimikatz | beacon");
    expect(spl).toContain("(*mimikatz* OR *beacon*)");

    const kql = toElasticKQL("mimikatz | beacon");
    expect(kql).toContain("(*mimikatz* or *beacon*)");
  });

  it("translates filter chips and field queries to Elastic KQL", () => {
    const kql = toElasticKQL("user:root", [{ field: "src", value: "10.0.0.1" }]);
    expect(kql).toContain('source.ip: "10.0.0.1"');
    expect(kql).toContain('user.name: "root"');
  });

  it("generates a valid Sigma YAML detection rule", () => {
    const sigma = toSigmaRule(
      "powershell -enc",
      [{ field: "user", value: "svc_admin" }],
      "Suspicious PowerShell Invocations",
      ["T1059.001", "T1078"]
    );
    expect(sigma).toContain("title: Suspicious PowerShell Invocations");
    expect(sigma).toContain("attack.t1059.001");
    expect(sigma).toContain("attack.t1078");
    expect(sigma).toContain('user.name: "svc_admin"');
    expect(sigma).toContain("- \"powershell\"");
    expect(sigma).toContain("- \"-enc\"");
    expect(sigma).toContain("condition: selection");
  });

  it("generates a Velociraptor VQL hunt query", () => {
    const vql = toVelociraptorVQL("mimikatz", [{ field: "user", value: "Administrator" }]);
    expect(vql).toContain("Artifact.Windows.EventLogs.EvtxHunter");
    expect(vql).toContain('TargetUserName =~ "Administrator"');
    expect(vql).toContain('Message =~ "mimikatz"');
  });

  it("translates all formats in translateAll", () => {
    const result = translateAll("test", [{ field: "src", value: "192.168.1.1" }]);
    expect(result.splunkSpl).toBeDefined();
    expect(result.elasticKql).toBeDefined();
    expect(result.sigmaYaml).toBeDefined();
    expect(result.velociraptorVql).toBeDefined();
  });
});
