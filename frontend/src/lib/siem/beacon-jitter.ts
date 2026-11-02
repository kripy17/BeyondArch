import type { SiemEvent } from "@/data/siem";

export interface BeaconJitterResult {
  destination: string;
  count: number;
  meanIntervalSec: number;
  stdDevSec: number;
  jitterPct: number;
  isBeacon: boolean;
  confidence: "high" | "medium" | "low";
  deltas: number[];
}

/**
 * Computes inter-arrival time deltas, mean period, standard deviation,
 * and jitter percentage for network events grouped by destination.
 * Jitter % = (stdDev / meanInterval) * 100
 * Low jitter (<= 25%) indicates automated C2 beaconing cadence (Cobalt Strike, Mythic, Sliver).
 */
export function computeBeaconJitter(events: SiemEvent[]): Record<string, BeaconJitterResult> {
  const destTimestamps = new Map<string, number[]>();

  for (const e of events) {
    let dest = e.dst && e.dst !== "—" && e.dst !== "-" ? e.dst : "";
    if (!dest && e.sig) {
      const m = e.sig.match(/(?:outbound to|connect to|destination:)\s*(\d{1,3}(?:\.\d{1,3}){3})/i);
      if (m) dest = m[1];
    }
    if (!dest || dest === e.src) continue;

    // Determine timestamp in seconds
    let epochSec: number | null = null;
    if (e.ts && e.ts.includes(":")) {
      const parts = e.ts.split(":");
      if (parts.length >= 2) {
        const hh = parseInt(parts[0], 10) || 0;
        const mm = parseInt(parts[1], 10) || 0;
        const ss = parseInt(parts[2] || "0", 10) || 0;
        epochSec = hh * 3600 + mm * 60 + ss;
      }
    }
    if (epochSec === null && typeof e.min === "number") {
      epochSec = e.min * 60;
    }

    if (epochSec !== null) {
      if (!destTimestamps.has(dest)) destTimestamps.set(dest, []);
      destTimestamps.get(dest)!.push(epochSec);
    }
  }

  const results: Record<string, BeaconJitterResult> = {};

  for (const [dest, epochs] of destTimestamps.entries()) {
    if (epochs.length < 4) continue;

    const sorted = [...epochs].sort((a, b) => a - b);
    const deltas: number[] = [];
    for (let i = 0; i < sorted.length - 1; i++) {
      const diff = sorted[i + 1] - sorted[i];
      if (diff > 0) deltas.push(diff);
    }

    if (deltas.length >= 3) {
      const mean = deltas.reduce((acc, v) => acc + v, 0) / deltas.length;
      if (mean >= 5) {
        const variance = deltas.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / deltas.length;
        const stdDev = Math.sqrt(variance);
        const jitterPct = (stdDev / mean) * 100;
        const isBeacon = jitterPct <= 25.0;

        results[dest] = {
          destination: dest,
          count: epochs.length,
          meanIntervalSec: Math.round(mean * 10) / 10,
          stdDevSec: Math.round(stdDev * 10) / 10,
          jitterPct: Math.round(jitterPct * 10) / 10,
          isBeacon,
          confidence: jitterPct <= 15.0 ? "high" : jitterPct <= 25.0 ? "medium" : "low",
          deltas,
        };
      }
    }
  }

  return results;
}
