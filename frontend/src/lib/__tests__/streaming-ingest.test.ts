import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  streamingIngestClient,
  isAudioMuted,
  setAudioMuted,
  isStreamingActive,
  setStreamingActive,
  type StreamingAlert,
} from "../alerts/streaming-ingest";

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

describe("Real-Time Streaming Alert Ingestion Pipeline", () => {
  beforeEach(() => {
    store.clear();
  });

  describe("Stream State & Audio Preferences", () => {
    it("manages audio mute state persistently", () => {
      expect(isAudioMuted()).toBe(false);
      setAudioMuted(true);
      expect(isAudioMuted()).toBe(true);
      expect(store.get("ba.streaming.muted")).toBe("true");
      setAudioMuted(false);
      expect(isAudioMuted()).toBe(false);
    });

    it("manages streaming active toggle persistently", () => {
      expect(isStreamingActive()).toBe(true);
      setStreamingActive(false);
      expect(isStreamingActive()).toBe(false);
      expect(store.get("ba.streaming.active")).toBe("false");
      setStreamingActive(true);
      expect(isStreamingActive()).toBe(true);
    });
  });

  describe("Subscription & Burst Simulation", () => {
    it("subscribes listener and receives incoming simulated burst alerts", async () => {
      const received: StreamingAlert[] = [];
      const unsubscribe = streamingIngestClient.subscribe((alert) => {
        received.push(alert);
      });

      // Mock fetch failure so it exercises the robust local fallback generator
      const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("Offline"));

      const generated = await streamingIngestClient.triggerSimulationBurst("apt29", 3);

      expect(generated.length).toBe(3);
      expect(received.length).toBeGreaterThanOrEqual(3);

      const first = generated[0];
      expect(first.id).toBeTruthy();
      expect(first.title).toBeTruthy();
      expect(first.severity).toBeDefined();
      expect(first.technique).toBeTruthy();
      expect(first.simulated).toBe(true);

      unsubscribe();
      fetchSpy.mockRestore();
    });

    it("generates realistic Volt Typhoon SCADA and LOLBin telemetry", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("Offline"));

      const generated = await streamingIngestClient.triggerSimulationBurst("volt_typhoon", 2);
      expect(generated.length).toBe(2);

      const titles = generated.map((g) => g.title);
      expect(titles.some((t) => t.includes("LOLBin") || t.includes("SharpHound"))).toBe(true);

      fetchSpy.mockRestore();
    });

    it("generates ransomware shadow copy and data staging indicators", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("Offline"));

      const generated = await streamingIngestClient.triggerSimulationBurst("ransomware", 3);
      expect(generated.length).toBe(3);

      const techniques = generated.map((g) => g.technique);
      expect(techniques).toContain("T1490");

      fetchSpy.mockRestore();
    });
  });
});
