import type { LookupTool, LookupResult, LookupResultField } from "./types";

/* ── User-Agent Decoder ─────────────────────────────────── */

const UA_RE = /^(?:Mozilla|curl|Wget|python-requests|Go-http-client|Nuclei|masscan|PostmanRuntime|axios|Microsoft Office)/i;

function parseUa(ua: string): LookupResultField[] {
  const fields: LookupResultField[] = [];

  fields.push({ label: "Raw", value: ua });

  if (/Chrome\/\d+/i.test(ua)) {
    fields.push({ label: "Browser", value: "Chrome" });
    const m = ua.match(/Chrome\/(\d+)/);
    if (m) fields.push({ label: "Version", value: m[1] });
  } else if (/Firefox\/\d+/i.test(ua)) {
    fields.push({ label: "Browser", value: "Firefox" });
    const m = ua.match(/Firefox\/(\d+)/);
    if (m) fields.push({ label: "Version", value: m[1] });
  } else if (/Safari\//i.test(ua) && !/Chrome/i.test(ua)) {
    fields.push({ label: "Browser", value: "Safari" });
  } else if (/Edg/i.test(ua)) {
    fields.push({ label: "Browser", value: "Edge" });
  } else if (/curl\//i.test(ua)) {
    fields.push({ label: "Tool", value: "curl" });
    const m = ua.match(/curl\/([\d.]+)/);
    if (m) fields.push({ label: "Version", value: m[1] });
  } else if (/Wget\//i.test(ua)) {
    fields.push({ label: "Tool", value: "Wget" });
  } else if (/python-requests/i.test(ua)) {
    fields.push({ label: "Library", value: "Python Requests" });
  } else if (/Go-http-client/i.test(ua)) {
    fields.push({ label: "Library", value: "Go HTTP Client" });
  } else if (/Nuclei/i.test(ua)) {
    fields.push({ label: "Tool", value: "Nuclei Scanner" });
  } else if (/masscan/i.test(ua)) {
    fields.push({ label: "Tool", value: "masscan" });
  } else if (/PostmanRuntime/i.test(ua)) {
    fields.push({ label: "Tool", value: "Postman" });
  } else if (/axios/i.test(ua)) {
    fields.push({ label: "Library", value: "Axios" });
  } else if (/Microsoft Office/i.test(ua)) {
    fields.push({ label: "Application", value: "Microsoft Office" });
  }

  if (/Windows NT 10/i.test(ua)) fields.push({ label: "OS", value: "Windows 10" });
  else if (/Windows NT 6\.1/i.test(ua)) fields.push({ label: "OS", value: "Windows 7" });
  else if (/Mac OS X/i.test(ua)) fields.push({ label: "OS", value: "macOS" });
  else if (/Linux/i.test(ua) && !/Android/i.test(ua)) fields.push({ label: "OS", value: "Linux" });
  else if (/Android/i.test(ua)) fields.push({ label: "OS", value: "Android" });
  else if (/iPhone|iOS/i.test(ua)) fields.push({ label: "OS", value: "iOS" });

  if (/Mobile/i.test(ua)) fields.push({ label: "Device", value: "Mobile" });
  if (/Googlebot/i.test(ua)) fields.push({ label: "Bot", value: "Googlebot" });
  if (/Bingbot/i.test(ua)) fields.push({ label: "Bot", value: "Bingbot" });
  if (/AhrefsBot/i.test(ua)) fields.push({ label: "Bot", value: "AhrefsBot" });
  if (/SemrushBot/i.test(ua)) fields.push({ label: "Bot", value: "SemrushBot" });

  if (fields.length <= 1) {
    fields.push({ label: "Type", value: "Unknown / Custom" });
  }

  return fields;
}

export const uaDecoder: LookupTool = {
  id: "ua-decoder",
  label: "User-Agent Decoder",
  icon: "Monitor",
  description: "Parse user-agent strings to identify browser, OS, device, or bot",
  detect: (input) => UA_RE.test(input.trim()),
  execute: (input) => {
    const fields = parseUa(input.trim());
    return {
      toolId: "ua-decoder",
      input: input.trim(),
      parsed: fields,
      done: true,
    };
  },
};

export const LOOKUP_TOOLS: LookupTool[] = [uaDecoder];

export function executeLookups(input: string): LookupResult[] {
  const results: LookupResult[] = [];
  for (const tool of LOOKUP_TOOLS) {
    if (tool.detect(input)) {
      results.push(tool.execute(input));
    }
  }
  return results;
}
