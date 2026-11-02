import { describe, it, expect } from "vitest";
import { parseAlert, detectAlertFormat } from "../parse";
import { ALERT_SAMPLES } from "@/data/alert-samples";

describe("Enterprise Alert Parsers", () => {
  it("detects and parses CrowdStrike Falcon detection format", () => {
    const sample = ALERT_SAMPLES.find((s) => s.format === "crowdstrike");
    expect(sample).toBeDefined();
    expect(detectAlertFormat(sample!.text)).toBe("crowdstrike");

    const parsed = parseAlert(sample!.text);
    expect(parsed).not.toBeNull();
    expect(parsed!.format).toBe("crowdstrike");
    expect(parsed!.severity).toBe("critical");
    expect(parsed!.title).toContain("Command and Scripting Interpreter");
    expect(parsed!.summary).toContain("CORP-FIN-WS01");

    // Check observations
    const commands = parsed!.observations.filter((o) => o.kind === "command");
    expect(commands.length).toBeGreaterThan(0);
    const hashes = parsed!.observations.filter((o) => o.kind === "hash");
    expect(hashes.some((h) => h.value === "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")).toBe(true);
  });

  it("detects and parses Microsoft Defender 365 format", () => {
    const sample = ALERT_SAMPLES.find((s) => s.format === "defender");
    expect(sample).toBeDefined();
    expect(detectAlertFormat(sample!.text)).toBe("defender");

    const parsed = parseAlert(sample!.text);
    expect(parsed).not.toBeNull();
    expect(parsed!.format).toBe("defender");
    expect(parsed!.severity).toBe("high");
    expect(parsed!.title).toContain("Initial Access & Credential Harvesting");

    // Check observations from evidence array
    const ips = parsed!.observations.filter((o) => o.kind === "ip");
    expect(ips.some((i) => i.value === "194.26.29.112")).toBe(true);
    const urls = parsed!.observations.filter((o) => o.kind === "url");
    expect(urls.some((u) => u.value.includes("microsoftonline-verify.xyz"))).toBe(true);
  });

  it("detects and parses AWS GuardDuty finding format", () => {
    const sample = ALERT_SAMPLES.find((s) => s.format === "guardduty");
    expect(sample).toBeDefined();
    expect(detectAlertFormat(sample!.text)).toBe("guardduty");

    const parsed = parseAlert(sample!.text);
    expect(parsed).not.toBeNull();
    expect(parsed!.format).toBe("guardduty");
    expect(parsed!.severity).toBe("high");
    expect(parsed!.title).toContain("IAM credentials obtained via instance metadata");

    const ips = parsed!.observations.filter((o) => o.kind === "ip");
    expect(ips.some((i) => i.value === "45.33.32.156")).toBe(true);
  });

  it("detects and parses Elastic ECS detection format", () => {
    const sample = ALERT_SAMPLES.find((s) => s.format === "elastic");
    expect(sample).toBeDefined();
    expect(detectAlertFormat(sample!.text)).toBe("elastic");

    const parsed = parseAlert(sample!.text);
    expect(parsed).not.toBeNull();
    expect(parsed!.format).toBe("elastic");
    expect(parsed!.severity).toBe("high");
    expect(parsed!.title).toContain("Unusual Remote File Download");

    const ips = parsed!.observations.filter((o) => o.kind === "ip");
    expect(ips.some((i) => i.value === "91.108.240.11")).toBe(true);
  });
});
