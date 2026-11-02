import type { Severity } from "@/lib/severity";
import { LOG_SEVERITY_FLOOR } from "./log-rules";

/**
 * PCAP detection rule data (migrated from the retired legacy pcap analyzer).
 * PCAP findings arrive pre-scored from the capture parser or the backend; the
 * Analysis Engine turns each into a per-observation finding via
 * pcap-detection observations (meta.attr === "pcap-detection"). The severity
 * band floors drive observation weighting (weighting.ts) exactly like the
 * log-event band.
 */

/** PCAP-detection observation weight floor per severity band. */
export const PCAP_SEVERITY_FLOOR: Record<Severity, number> = LOG_SEVERITY_FLOOR;

export interface PcapRule {
  severity: Severity;
  minScore: number;
}