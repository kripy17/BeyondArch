import { describe, expect, it, beforeEach, vi } from "vitest";
import {
  extractObservables,
  scoreObservable,
  promoteObservablesToCase,
  exportObservablesCsv,
  exportObservablesJson,
  exportObservablesMarkdown,
  exportObservablesDefangedList,
  MODERN_PATTERNS,
} from "@/lib/parser-engine";
import {
  decodePowerShell,
  decodeBase64,
  decodeUrl,
  decodeHex,
  decodeRot13,
  reverseText,
  detectObfuscation,
} from "@/lib/deobfuscator";
import { loadCases, saveCases, type Case } from "@/data/case";

function stubStorage() {
  const store = new Map<string, string>();
  const storageMock = {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => store.set(key, String(value)),
    removeItem: (key: string) => store.delete(key),
    clear: () => store.clear(),
  };
  vi.stubGlobal("localStorage", storageMock);
  if (typeof window !== "undefined") {
    Object.defineProperty(window, "localStorage", { value: storageMock, writable: true });
  }
}

describe("Modern DFIR Patterns & Extraction", () => {
  it("extracts Bitcoin, Monero, and Ethereum crypto addresses", () => {
    const text = `
      Pay ransom to BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
      Segwit BTC: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
      Monero wallet: 44AFFq5AxYBfmGWymQAQ88f8a1vK81kEwQvT87sQ7C4YqQ7Zq8xR4Q4V9W9mZ9dY1x7y7x8w7v7u6t5s4r3q2p1
      ETH address: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
    `;
    const obs = extractObservables(text);
    const crypto = obs.filter((o) => o.type === "Crypto");
    expect(crypto.length).toBeGreaterThanOrEqual(4);
    expect(crypto.some((c) => c.value.startsWith("1A1z"))).toBe(true);
    expect(crypto.some((c) => c.value.startsWith("bc1"))).toBe(true);
    expect(crypto.some((c) => c.value.startsWith("44AF"))).toBe(true);
    expect(crypto.some((c) => c.value.startsWith("0x742d"))).toBe(true);
  });

  it("extracts Windows registry keys and UNC network paths", () => {
    const text = `
      Persistence: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware_loader
      User run: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\payload
      Network share: \\\\192.168.1.50\\finance_share\\ransom_docs
    `;
    const obs = extractObservables(text);
    const reg = obs.filter((o) => o.type === "Registry");
    const unc = obs.filter((o) => o.type === "UNC");
    expect(reg.length).toBe(2);
    expect(unc.length).toBe(1);
    expect(reg.some((r) => r.tags.includes("Persistence Autostart Key"))).toBe(true);
  });

  it("extracts AWS ARNs, JWT tokens, and CIDRs", () => {
    const text = `
      IAM: arn:aws:iam::123456789012:user/compromised-analyst
      Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4B1sWq
      Subnet: 10.200.0.0/16
    `;
    const obs = extractObservables(text);
    expect(obs.some((o) => o.type === "AWS-ARN")).toBe(true);
    expect(obs.some((o) => o.type === "JWT")).toBe(true);
    expect(obs.some((o) => o.type === "CIDR")).toBe(true);
  });
});

describe("Threat Scoring & Risk Heuristics Matrix", () => {
  it("scores phishing URL with suspicious TLD, direct IP, and phishing path higher", () => {
    const badUrl = scoreObservable("URL", "http://185.220.101.5:8080/account/login-verify.php?target=admin");
    expect(badUrl.score).toBeGreaterThanOrEqual(70);
    expect(["high", "critical"]).toContain(badUrl.severity);
    expect(badUrl.tags).toContain("Direct IP Host");
    expect(badUrl.tags).toContain("Non-standard Port (:8080)");

    const cleanUrl = scoreObservable("URL", "https://google.com/search?q=test");
    expect(cleanUrl.score).toBeLessThan(badUrl.score);
  });

  it("scores private RFC1918 IPs low risk, but public IPs as notable", () => {
    const privateIp = scoreObservable("IPv4", "192.168.1.1");
    expect(privateIp.score).toBe(10);
    expect(privateIp.tags).toContain("RFC1918 Private Subnet");

    const publicIp = scoreObservable("IPv4", "185.220.101.5");
    expect(publicIp.score).toBe(45);
    expect(publicIp.tags).toContain("Public Internet Address");
  });

  it("assigns critical risk to exposed secrets and active JWTs", () => {
    const secret = scoreObservable("Secret", "AKIAIOSFODNN7EXAMPLE");
    expect(secret.score).toBeGreaterThanOrEqual(80);
    expect(secret.severity).toBe("critical");

    const jwt = scoreObservable("JWT", "eyJhbGciOi...");
    expect(jwt.score).toBeGreaterThanOrEqual(80);
    expect(jwt.severity).toBe("critical");
  });
});

describe("De-obfuscator Engine", () => {
  it("decodes PowerShell UTF-16LE EncodedCommand correctly", () => {
    // UTF-16LE Base64 for "IEX"
    // 'I' = 0x49 0x00, 'E' = 0x45 0x00, 'X' = 0x58 0x00 -> SQBFAFgA
    const decoded = decodePowerShell("SQBFAFgA");
    expect(decoded).toBe("IEX");
  });

  it("decodes standard Base64 UTF-8", () => {
    // Base64 for "malicious_payload_url"
    const b64 = btoa("malicious_payload_url");
    const decoded = decodeBase64(b64);
    expect(decoded).toBe("malicious_payload_url");
  });

  it("decodes URL percent-encoding and Hex sequences", () => {
    expect(decodeUrl("https%3A%2F%2Fevil.com%2Fpath%20with%20spaces")).toBe("https://evil.com/path with spaces");
    expect(decodeHex("\\x63\\x6d\\x64\\x2e\\x65\\x78\\x65")).toBe("cmd.exe");
    expect(decodeHex("0x63, 0x6d, 0x64")).toBe("cmd");
  });

  it("decodes ROT13 and reverses text", () => {
    expect(decodeRot13("cbjrefuryy")).toBe("powershell");
    expect(reverseText("exe.llehsrewop")).toBe("powershell.exe");
  });

  it("detects obfuscated PowerShell commands automatically", () => {
    const cmd = "powershell.exe -NoP -w hidden -EncodedCommand SQBFAFgA";
    const detected = detectObfuscation(cmd);
    expect(detected.length).toBeGreaterThanOrEqual(1);
    expect(detected[0].type).toBe("powershell");
    expect(detected[0].decoded).toBe("IEX");
  });
});

describe("Bulk Case Promotion & Export Suite", () => {
  beforeEach(() => {
    stubStorage();
  });

  it("promotes observables to active case with deduplication", () => {
    const mockCase: Case = {
      id: "CASE-DFIR-01",
      title: "Active Threat Case",
      tags: ["investigation"],
      createdAt: new Date().toISOString(),
      state: "active",
      entries: [],
      iocs: [
        {
          id: "ioc-existing",
          value: "198.51.100.23",
          type: "ipv4",
          context: "pre-existing",
          source: "/alerts",
          severity: "high",
        },
      ],
    };
    saveCases([mockCase]);

    const observables = extractObservables(`
      C2 IP: 198.51.100.23
      New Malicious IP: 185.94.188.22
      Malicious Domain: evil-phish[.]com
    `);

    const result = promoteObservablesToCase("CASE-DFIR-01", observables);
    expect(result.added).toBe(2); // 198.51.100.23 deduplicated!

    const updated = loadCases().find((c) => c.id === "CASE-DFIR-01");
    expect(updated?.iocs?.length).toBe(3);
    expect(updated?.entries.length).toBe(1);
    expect(updated?.entries[0].kind).toBe("ioc");
  });

  it("exports observables to standard CSV, JSON, Markdown, and defanged text", () => {
    const observables = extractObservables("evil[.]com 198.51.100.44");
    const csv = exportObservablesCsv(observables);
    expect(csv).toContain("type,value,defanged,severity,score,tags");
    expect(csv).toContain("Domain");

    const json = exportObservablesJson(observables);
    const parsed = JSON.parse(json);
    expect(parsed.total).toBe(observables.length);
    expect(parsed.observables.length).toBe(observables.length);

    const md = exportObservablesMarkdown(observables);
    expect(md).toContain("| Type | Indicator (Defanged) |");

    const defanged = exportObservablesDefangedList(observables);
    expect(defanged).toContain("[.]");
  });
});
