import type { Severity } from "@/lib/severity";
import { LOG_SEVERITY_FLOOR } from "./log-rules";

/**
 * Zeek conn.log connection-state rule table (signal generator data).
 * Zeek records a measured `conn_state` for each connection (a fact); the
 * Analysis Engine converts anomalous states into findings via
 * zeek-conn-state observations (meta.attr === "zeek-conn-state"). SF
 * (normal establishment and termination) is deliberately absent — it is not
 * a signal. Pure data — single source of truth for state → severity/mitre.
 */

/** Zeek-conn-state observation weight floor per severity band (weighting.ts). */
export const ZEEK_SEVERITY_FLOOR: Record<Severity, number> = LOG_SEVERITY_FLOOR;

export interface ZeekStateRule {
  /** Zeek conn_state value (S0, REJ, RSTR, OTH, …). */
  state: string;
  title: string;
  reason: string;
  action: string;
  severity: Severity;
  mitre: { id: string; name: string };
}

export const ZEEK_STATE_RULES: ZeekStateRule[] = [
  {
    state: "REJ",
    severity: "medium",
    title: "Connection attempt rejected",
    reason: "A connection attempt received an RST — the service is closed or refusing. Consistent with port/service scanning.",
    action: "Correlate the source IP across the timeframe; check for repeated REJ patterns against multiple ports.",
    mitre: { id: "T1046", name: "Network Service Discovery" },
  },
  {
    state: "S0",
    severity: "medium",
    title: "Connection attempt with no reply",
    reason: "A SYN was sent but no SYN-ACK returned — the endpoint is unreachable or filtering. Common during host discovery.",
    action: "Verify the target was reachable during the window; correlate with S0 attempts from the same source.",
    mitre: { id: "T1046", name: "Network Service Discovery" },
  },
  {
    state: "RSTOS0",
    severity: "medium",
    title: "SYN followed by RST",
    reason: "The originator sent a SYN then immediately aborted with an RST — a scanning fingerprint.",
    action: "Check for additional RSTOS0 and OTH states from the same source IP.",
    mitre: { id: "T1046", name: "Network Service Discovery" },
  },
  {
    state: "RSTRH",
    severity: "medium",
    title: "SYN-ACK followed by RST",
    reason: "The responder sent SYN-ACK then immediately reset — an asymmetric handshake typical of fingerprinting.",
    action: "Correlate the responder's RSTRH pattern with other incomplete handshakes.",
    mitre: { id: "T1046", name: "Network Service Discovery" },
  },
  {
    state: "OTH",
    severity: "medium",
    title: "Mid-stream connection (no SYN observed)",
    reason: "Traffic appeared with no SYN handshake — may indicate session hijacking, evasion, or traffic injection.",
    action: "Inspect the flows surrounding the mid-stream connection for payload anomalies.",
    mitre: { id: "T1046", name: "Network Service Discovery" },
  },
  {
    state: "SH",
    severity: "medium",
    title: "SYN followed by FIN",
    reason: "The originator sent a SYN then a FIN with no SYN-ACK — an incomplete-handshake scan signature.",
    action: "Review the source for broader scanning behavior across the observation window.",
    mitre: { id: "T1046", name: "Network Service Discovery" },
  },
  {
    state: "S1",
    severity: "low",
    title: "Connection established but not terminated",
    reason: "A connection was established but never cleanly closed — a long-lived or abandoned session.",
    action: "Check session duration and bytes transferred for beaconing or persistence patterns.",
    mitre: { id: "T1071", name: "Application Layer Protocol" },
  },
  {
    state: "S2",
    severity: "low",
    title: "Established with unacknowledged close",
    reason: "The originator attempted to close but the responder never replied — a half-closed connection.",
    action: "Verify the responder's health and whether the session lingered beyond expected.",
    mitre: { id: "T1046", name: "Network Service Discovery" },
  },
  {
    state: "S3",
    severity: "low",
    title: "Established with unacknowledged close (responder)",
    reason: "The responder attempted to close but the originator never replied — a half-closed connection.",
    action: "Verify the originator's state and whether the session lingered beyond expected.",
    mitre: { id: "T1046", name: "Network Service Discovery" },
  },
  {
    state: "RSTO",
    severity: "low",
    title: "Established connection aborted by originator",
    reason: "An established connection was reset by the originator — may indicate a disrupted session.",
    action: "Correlate with other aborted connections from the same host for a pattern.",
    mitre: { id: "T1046", name: "Network Service Discovery" },
  },
  {
    state: "RSTR",
    severity: "low",
    title: "Established connection aborted by responder",
    reason: "An established connection was reset by the responder — the remote service terminated abruptly.",
    action: "Review the target service state and the flows preceding the reset.",
    mitre: { id: "T1046", name: "Network Service Discovery" },
  },
  {
    state: "SHR",
    severity: "low",
    title: "SYN-ACK followed by FIN",
    reason: "The responder sent SYN-ACK then a FIN with no SYN from the originator — an incomplete handshake.",
    action: "Review surrounding flows for a broader scan pattern.",
    mitre: { id: "T1046", name: "Network Service Discovery" },
  },
  {
    state: "TST",
    severity: "low",
    title: "Timed out mid-handshake",
    reason: "The connection timed out while in an established or partial state.",
    action: "Check endpoint availability during the window.",
    mitre: { id: "T1046", name: "Network Service Discovery" },
  },
  {
    state: "TFA",
    severity: "low",
    title: "Timed out with no activity",
    reason: "The connection timed out without any observed traffic.",
    action: "Check endpoint availability during the window.",
    mitre: { id: "T1046", name: "Network Service Discovery" },
  },
];
