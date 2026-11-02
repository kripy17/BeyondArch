import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  addAttachmentFiles,
  attachmentsUsedBytes,
  caseAttachmentCount,
  decodeAttachment,
  entryAttachments,
  hasAttachmentPayload,
  LS_ATTACHMENTS,
  MAX_FILE_BYTES,
  MAX_TOTAL_BYTES,
  removeAttachmentPayloads,
} from "@/lib/attachments";
import { buildExportBundle } from "@/lib/export-bundle";
import type { Case, Entry } from "@/data/case";
import type { NotebookHypothesis } from "@/data/notebook";

function stubStorage(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
    clear: () => void map.clear(),
  });
}

function mkFile(name: string, bytes: Uint8Array, type = "text/plain"): File {
  const buf = new ArrayBuffer(bytes.length);
  new Uint8Array(buf).set(bytes);
  return new File([buf], name, { type });
}

const PNG_MAGIC = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

beforeEach(() => {
  stubStorage();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("attachments store", () => {
  it("round-trips file content through base64 payloads", async () => {
    const { added, errors } = await addAttachmentFiles([mkFile("shot.png", PNG_MAGIC, "image/png")]);
    expect(errors).toEqual([]);
    expect(added).toHaveLength(1);
    const [att] = added;
    expect(att.name).toBe("shot.png");
    expect(att.mime).toBe("image/png");
    expect(att.size).toBe(PNG_MAGIC.length);
    expect(hasAttachmentPayload(att.id)).toBe(true);
    expect([...decodeAttachment(att.id)!]).toEqual([...PNG_MAGIC]);
    expect(attachmentsUsedBytes()).toBeGreaterThan(0);
  });

  it("assigns deterministic ids — same content+name dedupes to one payload", async () => {
    const [a] = (await addAttachmentFiles([mkFile("note.txt", new TextEncoder().encode("hello"))])).added;
    const before = JSON.stringify(localStorage.getItem(LS_ATTACHMENTS));
    const [b] = (await addAttachmentFiles([mkFile("note.txt", new TextEncoder().encode("hello"))])).added;
    expect(b.id).toBe(a.id);
    expect(JSON.stringify(localStorage.getItem(LS_ATTACHMENTS))).toBe(before);
    // different name → different id even for identical bytes
    const [c] = (await addAttachmentFiles([mkFile("other.txt", new TextEncoder().encode("hello"))])).added;
    expect(c.id).not.toBe(a.id);
  });

  it("rejects oversized files with honest errors", async () => {
    const big = new Uint8Array(MAX_FILE_BYTES + 1);
    const { added, errors } = await addAttachmentFiles([mkFile("huge.bin", big)]);
    expect(added).toEqual([]);
    expect(errors[0]).toMatch(/exceeds the .* per-file cap/);
    expect(attachmentsUsedBytes()).toBe(0);
  });

  it("enforces the total local-storage budget", async () => {
    // Seed the store near capacity directly (bypassing the per-file cap).
    const targetUsed = MAX_TOTAL_BYTES - 100;
    const b64Len = Math.ceil((targetUsed * 4) / 3);
    localStorage.setItem(
      LS_ATTACHMENTS,
      JSON.stringify({ "att-seeded": { mime: "application/octet-stream", b64: "A".repeat(b64Len) } }),
    );
    expect(attachmentsUsedBytes()).toBeGreaterThanOrEqual(targetUsed);
    const { added, errors } = await addAttachmentFiles([mkFile("c.bin", new Uint8Array(1024))]);
    expect(added).toEqual([]);
    expect(errors[0]).toMatch(/budget exhausted/);
  });

  it("removes payloads only when no entry references them anymore", async () => {
    const [att] = (await addAttachmentFiles([mkFile("gone.bin", PNG_MAGIC)])).added;
    const casesJson = JSON.stringify({
      entries: [{ id: "e1", attachments: [{ ...att }] }],
    });
    localStorage.setItem("ba.cases.v2", casesJson);
    removeAttachmentPayloads([att.id]);
    expect(hasAttachmentPayload(att.id)).toBe(true); // still referenced by a case
    localStorage.setItem("ba.cases.v2", JSON.stringify({ entries: [] }));
    removeAttachmentPayloads([att.id]);
    expect(hasAttachmentPayload(att.id)).toBe(false);
  });

  it("entry/case helpers treat missing attachment lists as empty", () => {
    const e = { id: "e1", ts: "", kind: "note" as const, body: "plain" };
    expect(entryAttachments(e as Entry)).toEqual([]);
    const c = { entries: [e, { ...e, id: "e2", attachments: [{ id: "att-x", name: "n", mime: "text/plain", size: 3, addedAt: "" }] }] } as unknown as Case;
    expect(caseAttachmentCount(c)).toBe(1);
  });
});

describe("export bundle integration", () => {
  it("packs entry attachment payloads into attachments/ and fingerprints them", async () => {
    const bytes = PNG_MAGIC;
    const [att] = (await addAttachmentFiles([mkFile("screen shot.png", bytes, "image/png")])).added;
    const c = {
      id: "c1",
      title: "T",
      tags: [],
      state: "active",
      createdAt: "2026-08-01T00:00:00.000Z",
      entries: [
        { id: "e-9", ts: "2026-08-01T00:00:01.000Z", kind: "note", body: "see shot", attachments: [att] },
        { id: "e-lost", ts: "2026-08-01T00:00:02.000Z", kind: "note", body: "lost payload", attachments: [{ ...att, id: "att-deadbeef-deadbeef", name: "lost.png" }] },
      ],
    } as unknown as Case;
    const { blob, manifest, fileCount } = buildExportBundle({ case: c, reportType: "executive", hypotheses: [] as NotebookHypothesis[], generatedAt: "2026-08-25T10:00:00.000Z" });
    expect(fileCount).toBe(6); // case + md + html + attachment + missing-payload note + manifest
    const text = await blob.text();
    expect(text).toContain("attachments/e-9-screen_shot.png");
    expect(text).toContain("missing payload");
    expect(manifest.some((l) => l.startsWith("attachments/e-9-screen_shot.png"))).toBe(true);
  });
});
