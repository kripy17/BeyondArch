import { describe, it, expect } from "vitest";
import {
  parseAndEvaluateSigma,
  parseAndEvaluateYara,
  compileSigmaToQueries,
  lintDetectionRule,
  DETECTION_PRESETS,
} from "../detection-sandbox";

describe("Detection Sandbox Engine", () => {
  describe("Sigma Rule Evaluation", () => {
    it("evaluates genuine Sigma selection and condition logic against multi-event logs", () => {
      const preset = DETECTION_PRESETS[0]; // PowerShell AMSI Bypass
      const result = parseAndEvaluateSigma(preset.rule, preset.sampleEvents);

      expect(result.matched).toBe(true);
      expect(result.totalEvents).toBe(3);
      // Event 1 has both bypass flag and WebClient download cradle -> matched!
      expect(result.eventMatches[0].matched).toBe(true);
      expect(result.eventMatches[0].matchedTokens).toContain("System.Net.WebClient");
      expect(result.eventMatches[0].matchedTokens).toContain("-ExecutionPolicy Bypass");

      // Event 2 is cmd.exe maintenance -> should NOT match!
      expect(result.eventMatches[1].matched).toBe(false);

      // Event 3 has bypass but no download cradle -> condition 'selection_flags and selection_cradle' fails!
      expect(result.eventMatches[2].matched).toBe(false);
      expect(result.matchCount).toBe(1);
    });

    it("evaluates Pass-the-Hash Logon Type 9 rule", () => {
      const pthPreset = DETECTION_PRESETS[1];
      const result = parseAndEvaluateSigma(pthPreset.rule, pthPreset.sampleEvents);

      expect(result.totalEvents).toBe(2);
      expect(result.eventMatches[0].matched).toBe(true);
      expect(result.eventMatches[1].matched).toBe(false);
      expect(result.matchCount).toBe(1);
    });

    it("evaluates Process Hollowing svchost anomalous parent rule", () => {
      const hollowingPreset = DETECTION_PRESETS[2];
      const result = parseAndEvaluateSigma(hollowingPreset.rule, hollowingPreset.sampleEvents);

      expect(result.totalEvents).toBe(2);
      // Event 1 has explorer.exe parent -> matched
      expect(result.eventMatches[0].matched).toBe(true);
      // Event 2 has services.exe parent -> normal/false
      expect(result.eventMatches[1].matched).toBe(false);
    });
  });

  describe("Sigma Transpiler", () => {
    it("transpiles Sigma YAML into Splunk, Sentinel KQL, Elastic EQL, and QRadar AQL", () => {
      const rule = DETECTION_PRESETS[0].rule;
      const transpiled = compileSigmaToQueries(rule);

      // Splunk
      expect(transpiled.splunk).toContain("index=*");
      expect(transpiled.splunk).toContain("EventID=\"4688\"");
      expect(transpiled.splunk).toContain("CommandLine=\"*-ExecutionPolicy Bypass*\"");

      // Sentinel KQL
      expect(transpiled.sentinel).toContain("SecurityEvent | where");
      expect(transpiled.sentinel).toContain("EventID == \"4688\"");
      expect(transpiled.sentinel).toContain("CommandLine has \"System.Net.WebClient\"");

      // Elastic EQL
      expect(transpiled.elastic).toContain("process where");
      expect(transpiled.elastic).toContain("process.command_line : \"*-ExecutionPolicy Bypass*\"");

      // QRadar AQL
      expect(transpiled.qradar).toContain("SELECT * FROM events WHERE");
      expect(transpiled.qradar).toContain("\"EventID\" = '4688'");
    });
  });

  describe("Sigma HQ Linter", () => {
    it("reports zero errors on valid Sigma presets", () => {
      const errors = lintDetectionRule(DETECTION_PRESETS[0].rule, "sigma").filter((i) => i.severity === "error");
      expect(errors.length).toBe(0);
    });

    it("detects missing logsource and missing condition", () => {
      const malformedRule = `title: Malformed Rule
detection:
  selection:
    CommandLine: powershell`;
      const issues = lintDetectionRule(malformedRule, "sigma");
      const errorMessages = issues.filter((i) => i.severity === "error").map((i) => i.message);

      expect(errorMessages.some((m) => m.includes("logsource"))).toBe(true);
      expect(errorMessages.some((m) => m.includes("condition"))).toBe(true);
    });
  });

  describe("YARA Rule Evaluation", () => {
    it("scans and matches in-memory payload strings with condition logic", () => {
      const yaraPreset = DETECTION_PRESETS[3]; // Cobalt strike
      const result = parseAndEvaluateYara(yaraPreset.rule, yaraPreset.sampleEvents);

      expect(result.matched).toBe(true);
      expect(result.matchCount).toBe(1);
      expect(result.eventMatches[0].matchedTokens).toContain("ReflectiveLoader");
      expect(result.eventMatches[0].matchedTokens).toContain("\\\\.\\pipe\\msagent_");
    });
  });
});
