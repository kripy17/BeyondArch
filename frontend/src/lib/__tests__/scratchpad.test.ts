import { describe, expect, it, beforeEach } from "vitest";
import { addScratchNote, deleteScratchNote, loadScratchNotes } from "@/lib/scratchpad";

const store = new Map<string, string>();
(globalThis as Record<string, unknown>).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => { store.set(k, v); },
  removeItem: (k: string) => { store.delete(k); },
  clear: () => { store.clear(); },
  key: (i: number) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
};

describe("scratch notes", () => {
  beforeEach(() => {
    localStorage.removeItem("ba.scratch.v1");
  });

  it("adds newest first and ignores blank text", () => {
    expect(loadScratchNotes()).toEqual([]);
    expect(addScratchNote("   ")).toEqual([]);
    addScratchNote("first");
    const notes = addScratchNote("second");
    expect(notes.map((n) => n.text)).toEqual(["second", "first"]);
    expect(loadScratchNotes().length).toBe(2);
  });

  it("deletes by id and survives malformed storage", () => {
    const [note] = addScratchNote("keep me");
    expect(deleteScratchNote(note.id).length).toBe(0);
    localStorage.setItem("ba.scratch.v1", "{not-json");
    expect(loadScratchNotes()).toEqual([]);
    localStorage.setItem("ba.scratch.v1", JSON.stringify([{ id: 1, ts: "x" }, { id: "ok", ts: "t", text: "fine" }, "junk"]));
    const notes = loadScratchNotes();
    expect(notes.length).toBe(1);
    expect(notes[0].text).toBe("fine");
  });
});
