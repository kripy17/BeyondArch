import { describe, it, expect } from "vitest";
import {
  exportNavigatorLayerJson,
  importNavigatorLayerJson,
  getTechniqueEnrichment,
  PRESET_LAYERS,
} from "../detection/navigator-layer-engine";
import {
  runClientSimulation,
  ENTERPRISE_TELEMETRY_SUITE,
} from "../detection/detection-simulator";

describe("MITRE ATT&CK Navigator Layer Engine", () => {
  it("exports valid Navigator Layer v4.5 standard JSON", () => {
    const coverageMap = {
      "T1059.001": "full" as const,
      "T1566.001": "partial" as const,
      "T1003.001": "none" as const,
    };
    const notes = {
      "T1059.001": "Covered by deployed PowerShell Sigma rule",
    };

    const jsonStr = exportNavigatorLayerJson(coverageMap, notes);
    expect(jsonStr).toBeDefined();

    const layer = JSON.parse(jsonStr);
    expect(layer.versions.navigator).toBe("4.5");
    expect(layer.domain).toBe("enterprise-attack");
    expect(layer.gradient.colors).toHaveLength(3);
    expect(Array.isArray(layer.techniques)).toBe(true);

    const psTech = layer.techniques.find((t: any) => t.techniqueID === "T1059.001");
    expect(psTech).toBeDefined();
    expect(psTech.score).toBe(100);
    expect(psTech.color).toBe("#22c55e");
    expect(psTech.comment).toContain("PowerShell Sigma rule");
  });

  it("imports and parses Navigator Layer JSON", () => {
    const mockLayer = {
      name: "Threat Actor Layer",
      domain: "enterprise-attack",
      versions: { attack: "15", navigator: "4.5", layer: "4.5" },
      techniques: [
        { techniqueID: "T1059.001", score: 100, comment: "Full rule coverage" },
        { techniqueID: "T1110", score: 50, comment: "Work in progress" },
        { techniqueID: "T1078", score: 0 },
      ],
    };

    const result = importNavigatorLayerJson(JSON.stringify(mockLayer));
    expect(result.success).toBe(true);
    expect(result.name).toBe("Threat Actor Layer");
    expect(result.stats.full).toBe(1);
    expect(result.stats.partial).toBe(1);
    expect(result.stats.none).toBe(1);
    expect(result.coverageMap["T1059.001"]).toBe("full");
    expect(result.coverageMap["T1110"]).toBe("partial");
    expect(result.coverageMap["T1078"]).toBe("none");
  });

  it("handles malformed JSON gracefully", () => {
    const res = importNavigatorLayerJson("invalid json content");
    expect(res.success).toBe(false);
    expect(res.error).toBeDefined();
  });

  it("provides enriched metadata and Atomic Red Team test snippets", () => {
    const tech = getTechniqueEnrichment("T1059.001");
    expect(tech.platforms).toContain("Windows");
    expect(tech.dataSources.some((ds) => ds.includes("Process"))).toBe(true);
    expect(tech.atomicTest.command).toContain("powershell.exe");
    expect(tech.detectionGuidance).toBeDefined();
  });

  it("has predefined presets for threat modeling", () => {
    expect(PRESET_LAYERS.length).toBeGreaterThanOrEqual(3);
    const rw = PRESET_LAYERS.find((p) => p.id === "ransomware");
    expect(rw).toBeDefined();
    expect(rw?.techniqueIds).toContain("T1486");
  });
});

describe("Detection Telemetry Simulation Engine", () => {
  it("correctly simulates Sigma rule execution against telemetry suite", () => {
    const sigmaRule = `title: Suspicious PowerShell EncodedCommand
detection:
  selection:
    - powershell.exe
    - -EncodedCommand
  condition: selection`;

    const report = runClientSimulation(sigmaRule, "sigma", ENTERPRISE_TELEMETRY_SUITE);
    expect(report.totalScenarios).toBe(ENTERPRISE_TELEMETRY_SUITE.length);
    expect(report.truePositives).toBeGreaterThanOrEqual(1);

    const hitScen = report.results.find((r) => r.id === "scen-ps-encoded");
    expect(hitScen).toBeDefined();
    expect(hitScen?.hit).toBe(true);
    expect(hitScen?.verdict).toBe("tp");

    const benignScen = report.results.find((r) => r.id === "scen-ps-admin-backup");
    expect(benignScen).toBeDefined();
    expect(benignScen?.hit).toBe(false);
    expect(benignScen?.verdict).toBe("tn");
  });

  it("generates tuning suggestions when false positive occurs", () => {
    const broadRule = `title: Detect Any PowerShell Execution
detection:
  selection:
    - powershell.exe
  condition: selection`;

    const report = runClientSimulation(broadRule, "sigma", ENTERPRISE_TELEMETRY_SUITE);
    expect(report.falsePositives).toBeGreaterThanOrEqual(1);
    expect(report.tuningSuggestions.length).toBeGreaterThanOrEqual(1);
    expect(report.tuningSuggestions[0].filterSnippet).toContain("filter:");
  });
});
