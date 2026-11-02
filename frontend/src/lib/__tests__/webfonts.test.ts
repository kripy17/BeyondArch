import { describe, expect, it } from "vitest";
import { ensureWebFont, fontStylesheetHref, isEagerFont } from "../webfonts";

describe("webfonts", () => {
  it("eager-loads only the two defaults and unknown families", () => {
    expect(isEagerFont("Inter")).toBe(true);
    expect(isEagerFont("JetBrains Mono")).toBe(true);
    expect(isEagerFont("Fira Code")).toBe(false);
    expect(isEagerFont("Space Mono")).toBe(false);
    expect(isEagerFont("Comic Sans MS")).toBe(true);
  });

  it("builds deterministic stylesheet hrefs with correct weight sets", () => {
    expect(fontStylesheetHref("Fira Code")).toBe(
      "https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&display=swap",
    );
    expect(fontStylesheetHref("Space Mono")).toBe(
      "https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap",
    );
  });

  it("never injects anything outside a document", () => {
    expect(() => ensureWebFont("Sora")).not.toThrow();
  });
});
