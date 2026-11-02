import { describe, expect, it } from "vitest";
import { isAuthParamToken } from "@/lib/ioc-patterns";

describe("isAuthParamToken", () => {
  it("flags email-auth parameter names that mimic domains", () => {
    for (const v of ["smtp.mailfrom", "smtp.helo", "header.from", "header.d", "envelope-from", "SMTP.MAILFROM"]) {
      expect(isAuthParamToken(v)).toBe(true);
    }
  });

  it("keeps real domains, hosts, and auth values", () => {
    for (const v of ["evil.com", "mail.example-login.com", "mx.example.org", "example-login.com", "none", "fail", "pass"]) {
      expect(isAuthParamToken(v)).toBe(false);
    }
  });
});
