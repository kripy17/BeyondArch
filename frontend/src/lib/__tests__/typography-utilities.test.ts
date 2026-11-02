/// <reference types="node" />
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// vitest always runs with cwd = frontend/, matching package.json's test script
const ROOT = process.cwd();

function walk(dir: string, ext: RegExp): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full, ext));
    else if (ext.test(entry.name)) out.push(full);
  }
  return out;
}

function definedUtilities(): Set<string> {
  const css = readFileSync(join(ROOT, "src", "styles.css"), "utf8");
  return new Set([...css.matchAll(/@utility\s+(ba-text-[a-z0-9]+)/g)].map((m) => m[1]));
}

describe("ba-text typography utilities", () => {
  it("defines the full micro-type scale", () => {
    const defined = definedUtilities();
    for (const size of ["3xs", "2xs", "xs", "sm", "base", "lg", "xl"]) {
      expect(defined, `missing @utility ba-text-${size}`).toContain(`ba-text-${size}`);
    }
  });

  it("has a definition for every ba-text-* class referenced in source", () => {
    const defined = definedUtilities();
    const files = walk(join(ROOT, "src"), /\.(tsx|ts)$/);
    expect(files.length).toBeGreaterThan(50);

    const used = new Map<string, number>();
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(/ba-text-[a-z0-9]+/g)) {
        used.set(match[0], (used.get(match[0]) ?? 0) + 1);
      }
    }
    expect(used.size).toBeGreaterThan(0);
    for (const [name] of used) {
      expect(defined, `${name} used but not defined in styles.css`).toContain(name);
    }
  });
});
