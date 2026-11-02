import { describe, expect, it } from "vitest";
import { parseAuthResults, extractAttachmentFilenames } from "@/data/phishing";

describe("parseAuthResults", () => {
  it("reports zero headers when no Authentication-Results present", () => {
    const r = parseAuthResults("From: a@b.c\nSubject: x\n\nbody");
    expect(r.headerCount).toBe(0);
    expect(r.spf).toBe("none");
    expect(r.conflict.spf).toBe(false);
  });

  it("parses a single header without conflict", () => {
    const r = parseAuthResults([
      "Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=evil.com; dkim=none; dmarc=fail",
      "",
      "body",
    ].join("\n"));
    expect(r.headerCount).toBe(1);
    expect(r.spf).toBe("fail");
    expect(r.dkim).toBe("fail");
    expect(r.dmarc).toBe("fail");
    expect(r.conflict.spf).toBe(false);
  });

  it("handles folded (multi-line) headers", () => {
    const r = parseAuthResults([
      "Authentication-Results: mx.example.org;",
      "\tspf=pass smtp.mailfrom=ok.com;",
      "\tdkim=pass; dmarc=pass",
      "",
      "body",
    ].join("\n"));
    expect(r.headerCount).toBe(1);
    expect(r.spf).toBe("pass");
    expect(r.dmarc).toBe("pass");
  });

  it("takes verdicts from the topmost header when several exist", () => {
    const r = parseAuthResults([
      "Authentication-Results: mx2.last.org; spf=pass; dkim=pass; dmarc=pass",
      "Authentication-Results: mx1.first.org; spf=fail; dkim=fail; dmarc=fail",
      "",
      "body",
    ].join("\n"));
    expect(r.headerCount).toBe(2);
    expect(r.spf).toBe("pass");
    expect(r.dmarc).toBe("pass");
  });

  it("flags conflicting verdicts across headers per family", () => {
    const r = parseAuthResults([
      "Authentication-Results: mx2.last.org; spf=pass; dkim=pass; dmarc=pass",
      "Authentication-Results: mx1.first.org; spf=fail; dkim=fail; dmarc=pass",
      "",
      "body",
    ].join("\n"));
    expect(r.conflict.spf).toBe(true);
    expect(r.conflict.dkim).toBe(true);
    expect(r.conflict.dmarc).toBe(false);
  });

  it("maps neutral/temperror/permerror to softfail", () => {
    const r = parseAuthResults("Authentication-Results: mx.x; spf=neutral; dkim=temperror; dmarc=permerror");
    expect(r.spf).toBe("softfail");
    expect(r.dkim).toBe("softfail");
    expect(r.dmarc).toBe("softfail");
  });
});

describe("extractAttachmentFilenames", () => {
  it("extracts quoted and unquoted filenames", () => {
    const out = extractAttachmentFilenames([
      'Content-Disposition: attachment; filename="invoice.pdf"',
      "Content-Disposition: attachment; filename=payload.scr",
    ].join("\n"));
    expect(out).toEqual(["invoice.pdf", "payload.scr"]);
  });

  it("decodes RFC 2231 extended filenames", () => {
    const out = extractAttachmentFilenames("Content-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.docm");
    expect(out).toEqual(["résumé.docm"]);
  });

  it("deduplicates and ignores empty values", () => {
    const out = extractAttachmentFilenames([
      'Content-Disposition: attachment; filename="a.zip"',
      'Content-Disposition: attachment; filename="a.zip"',
      "Content-Disposition: attachment; filename=",
    ].join("\n"));
    expect(out).toEqual(["a.zip"]);
  });

  it("returns empty when no attachments", () => {
    expect(extractAttachmentFilenames("Content-Type: text/plain")).toEqual([]);
  });
});
