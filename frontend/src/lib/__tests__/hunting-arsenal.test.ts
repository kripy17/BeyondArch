import { describe, it, expect, beforeEach } from "vitest";
import {
  HUNTING_PRESETS,
  interpolateQuery,
  calculateArsenalTelemetry,
  createCustomSnippet,
  loadHuntingSnippets,
  saveCustomSnippets,
  type HuntingSnippet,
} from "../hunting-arsenal";

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

describe("Threat Hunting Arsenal", () => {
  beforeEach(() => {
    store.clear();
  });

  describe("Preset Catalog", () => {
    it("provides enterprise presets across all 5 key categories", () => {
      expect(HUNTING_PRESETS.length).toBeGreaterThanOrEqual(20);
      const categories = new Set(HUNTING_PRESETS.map((p) => p.category));
      expect(categories.has("splunk")).toBe(true);
      expect(categories.has("sentinel")).toBe(true);
      expect(categories.has("elastic")).toBe(true);
      expect(categories.has("suricata")).toBe(true);
      expect(categories.has("checklists")).toBe(true);
    });

    it("ensures each preset has non-empty query template and descriptive title", () => {
      for (const p of HUNTING_PRESETS) {
        expect(p.id).toBeTruthy();
        expect(p.title).toBeTruthy();
        expect(p.queryTemplate.trim().length).toBeGreaterThan(10);
      }
    });
  });

  describe("Variable Interpolation Engine", () => {
    it("substitutes target parameters into query template", () => {
      const template = "index=dns src_ip={{TARGET_IP}} dest_port={{PORT}}";
      const interpolated = interpolateQuery(template, {
        TARGET_IP: "198.51.100.45",
        PORT: "53",
      });

      expect(interpolated).toBe("index=dns src_ip=198.51.100.45 dest_port=53");
    });

    it("leaves unfilled variable placeholders when no value is supplied", () => {
      const template = "DeviceProcessEvents | where RemoteIP == '{{TARGET_IP}}' and User == '{{USERNAME}}'";
      const interpolated = interpolateQuery(template, {
        TARGET_IP: "203.0.113.88",
      });

      expect(interpolated).toBe("DeviceProcessEvents | where RemoteIP == '203.0.113.88' and User == '{{USERNAME}}'");
    });
  });

  describe("calculateArsenalTelemetry", () => {
    it("computes accurate counts across categories", () => {
      const telemetry = calculateArsenalTelemetry(HUNTING_PRESETS);
      expect(telemetry.total).toBe(HUNTING_PRESETS.length);
      expect(telemetry.splunkCount).toBeGreaterThan(0);
      expect(telemetry.sentinelCount).toBeGreaterThan(0);
      expect(telemetry.elasticCount).toBeGreaterThan(0);
      expect(telemetry.suricataCount).toBeGreaterThan(0);
      expect(telemetry.checklistsCount).toBeGreaterThan(0);
    });
  });

  describe("Custom Snippet Management", () => {
    it("creates custom snippet and extracts {{KEY}} variables automatically", () => {
      const snippet = createCustomSnippet({
        title: "Custom Lateral Kerberos Query",
        category: "splunk",
        description: "Searches for anomalous Kerberos ticket grants",
        queryTemplate: "index=security src={{SRC_IP}} user={{TARGET_USER}}",
        tags: ["custom", "kerberos"],
        mitreTechnique: "T1558",
      });

      expect(snippet.id).toMatch(/^snip-/);
      expect(snippet.isCustom).toBe(true);
      expect(snippet.variables).toContain("SRC_IP");
      expect(snippet.variables).toContain("TARGET_USER");
    });

    it("persists and retrieves custom snippets in localStorage", () => {
      const customSnippet: HuntingSnippet = {
        id: "snip-custom-1",
        title: "My Custom Sentinel Query",
        category: "sentinel",
        description: "Testing custom persistence",
        queryTemplate: "SigninLogs | where IPAddress == '{{IP}}'",
        variables: ["IP"],
        tags: ["custom"],
        isCustom: true,
      };

      saveCustomSnippets([customSnippet]);
      const loaded = loadHuntingSnippets();
      const found = loaded.find((s) => s.id === "snip-custom-1");
      expect(found).toBeDefined();
      expect(found?.title).toBe("My Custom Sentinel Query");
    });
  });
});
