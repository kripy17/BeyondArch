import type { Severity } from "@/lib/severity";
import { LOG_SEVERITY_FLOOR } from "./log-rules";

/**
 * HTTP request rule table (signal generator data) for Nginx/combined access
 * logs. Extraction records measured facts (status code, request path, method,
 * client IP) as http-request observations (meta.attr === "http-request"); the
 * Analysis Engine converts error codes and probe paths into findings here.
 * Pure data — single source of truth for status/path → severity/mitre.
 */

/** HTTP-request observation weight floor per severity band (weighting.ts). */
export const WEB_SEVERITY_FLOOR: Record<Severity, number> = LOG_SEVERITY_FLOOR;

export interface WebStatusRule {
  /** Exact status code ("404") or a band prefix ("5xx"). */
  status: string;
  title: string;
  reason: string;
  action: string;
  severity: Severity;
  mitre: { id: string; name: string };
}

export interface WebProbeRule {
  /** Case-insensitive regex matched against the lowercased request path. */
  path: RegExp;
  title: string;
  reason: string;
  action: string;
  severity: Severity;
  mitre: { id: string; name: string };
}

/** HTTP error-code bands — measured status → signal. */
export const WEB_STATUS_RULES: WebStatusRule[] = [
  {
    status: "5xx",
    severity: "medium",
    title: "Server error response",
    reason: "The server returned a 5xx error — may indicate an application fault or exploitation attempt.",
    action: "Correlate with the requesting client; review application logs for the failing request.",
    mitre: { id: "T1499", name: "Endpoint Denial of Service" },
  },
  {
    status: "404",
    severity: "low",
    title: "Resource not found",
    reason: "A request targeted a resource that does not exist — frequent 404s suggest path scanning.",
    action: "Check for a burst of 404s from the same client against common admin or config paths.",
    mitre: { id: "T1595", name: "Active Scanning" },
  },
  {
    status: "403",
    severity: "medium",
    title: "Forbidden request",
    reason: "The server refused a request — repeated 403s indicate access probing against restricted resources.",
    action: "Identify the client and the targeted path; check WAF or ACL logs for the same source.",
    mitre: { id: "T1595", name: "Active Scanning" },
  },
  {
    status: "401",
    severity: "medium",
    title: "Unauthorized request",
    reason: "Authentication was required and failed — repeated 401s suggest credential or endpoint probing.",
    action: "Correlate source IP and path; check for brute-force patterns against auth endpoints.",
    mitre: { id: "T1595", name: "Active Scanning" },
  },
];

/** Known probing paths — a request matching any of these is a strong signal. */
export const WEB_PROBE_RULES: WebProbeRule[] = [
  {
    path: /\/\.env\b|\.env\.example|\.env\.local/,
    severity: "high",
    title: "Environment file probe",
    reason: "A request targeted an environment file containing credentials and configuration secrets.",
    action: "Confirm the file is not served; rotate any credentials exposed by the endpoint.",
    mitre: { id: "T1190", name: "Exploit Public-Facing Application" },
  },
  {
    path: /\/\.git\b|\/\.git\/|\.git\/config|\.git\/HEAD/,
    severity: "high",
    title: "Git repository probe",
    reason: "A request targeted .git metadata — source disclosure or repository extraction attempt.",
    action: "Verify .git is not web-accessible; review for exposed repository content.",
    mitre: { id: "T1190", name: "Exploit Public-Facing Application" },
  },
  {
    path: /(^|\/)(wp-login(\.php)?|wp-admin|wp-content|wordpress)(\/|$)/,
    severity: "high",
    title: "WordPress admin probing",
    reason: "A request targeted WordPress admin or login surfaces — brute force or plugin-exploit preparation.",
    action: "Check for credential-stuffing volume against wp-login; review auth logs.",
    mitre: { id: "T1190", name: "Exploit Public-Facing Application" },
  },
  {
    path: /(^|\/)(phpmyadmin|pma|mysql-admin|adminer)(\/|$)/,
    severity: "high",
    title: "Database administration surface probe",
    reason: "A request targeted a database administration interface — unauthorized access attempt.",
    action: "Verify the interface is not internet-reachable; review auth attempts.",
    mitre: { id: "T1190", name: "Exploit Public-Facing Application" },
  },
  {
    path: /(^|\/)(\.ssh|\.aws|\.azure|\.google)(\/|$)|credentials|secret|apikey|api[-_]?key/,
    severity: "high",
    title: "Credential or secret probe",
    reason: "A request targeted a credential, API-key, or secret-bearing path — secret hunting.",
    action: "Confirm sensitive files are not served; rotate exposed credentials.",
    mitre: { id: "T1190", name: "Exploit Public-Facing Application" },
  },
  {
    path: /(^|\/)(actuator|console|jmx-console|manager|admin|administrator|login)(\/|$)/,
    severity: "medium",
    title: "Administrative surface probing",
    reason: "A request targeted an administrative or management interface — access probing.",
    action: "Verify admin surfaces are access-controlled; review auth failures from the client.",
    mitre: { id: "T1595", name: "Active Scanning" },
  },
  {
    path: /(^|\/)(config|configuration|settings|backup|bak|dump|db|sql|export)(\.|\/|$)/,
    severity: "medium",
    title: "Configuration or backup file probe",
    reason: "A request targeted a configuration, backup, or database dump path — data-exposure hunting.",
    action: "Confirm backup/config artifacts are not web-accessible; review file permissions.",
    mitre: { id: "T1595", name: "Active Scanning" },
  },
  {
    path: /(^|\/)(shell|c99|r57|webshell|\.jsp$|\.php\?.*(cmd|exec)|cgi-bin)(\/|$)/,
    severity: "high",
    title: "Web shell or command execution probe",
    reason: "A request targeted a web shell, CGI script, or command-execution endpoint — remote code execution attempt.",
    action: "Inspect the response; review the client for further exploitation attempts.",
    mitre: { id: "T1505.003", name: "Server Software Component: Web Shell" },
  },
  {
    path: /(^|\/)(\.\.\/|%2e%2e|\/\/etc\/passwd|\.\\.\\)/,
    severity: "critical",
    title: "Path traversal attempt",
    reason: "A request contained path-traversal sequences — arbitrary file read attempt.",
    action: "Verify input validation on the affected route; check response for leaked file content.",
    mitre: { id: "T1190", name: "Exploit Public-Facing Application" },
  },
];

/** Resolve the strongest probe rule for a request path (or undefined). */
export function matchWebProbe(path: string): WebProbeRule | undefined {
  const lower = path.toLowerCase();
  return WEB_PROBE_RULES.find((r) => r.path.test(lower));
}

/** Resolve the status rule for a status code (or undefined). */
export function matchWebStatus(status: string): WebStatusRule | undefined {
  const band = `${status.slice(0, 1)}xx`;
  const s = status.trim();
  return WEB_STATUS_RULES.find((r) => r.status === s) ?? WEB_STATUS_RULES.find((r) => r.status === band);
}
