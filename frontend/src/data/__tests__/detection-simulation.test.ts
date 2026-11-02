import { describe, expect, it } from "vitest";
import { runCorpus, corpusDigest, SIM_CORPUS, type Format } from "../detection";

const FORMATS: Format[] = ["sigma", "yara", "kql"];

describe("runCorpus", () => {
  FORMATS.forEach(fmt => {
    describe(fmt, () => {
      it("runs one sample per corpus entry", () => {
        const run = runCorpus(fmt);
        expect(run.fmt).toBe(fmt);
        expect(run.samples).toHaveLength(SIM_CORPUS[fmt].length);
      });

      it("produces one of each verdict (tp/tn/fp/fn)", () => {
        const run = runCorpus(fmt);
        const verdicts = run.samples.map(s => s.verdict).sort();
        expect(verdicts).toEqual(["fn", "fp", "tn", "tp"]);
      });

      it("summarizes matches, misses, and false positives deterministically", () => {
        const run = runCorpus(fmt);
        expect(run.summary.matches).toBe(1);
        expect(run.summary.misses).toBe(1);
        expect(run.summary.falsePositives).toBe(1);
        expect(run.summary.coverage).toBeCloseTo(0.5);
        expect(run.summary.precision).toBeCloseTo(0.5);
      });

      it("is stable across runs", () => {
        expect(runCorpus(fmt)).toEqual(runCorpus(fmt));
      });
    });
  });

  it("marks expected match + matcher hit as tp", () => {
    expect(runCorpus("sigma").samples.find(s => s.id === "found")!.verdict).toBe("tp");
  });

  it("marks benign traffic carrying rule keywords as fp", () => {
    expect(runCorpus("sigma").samples.find(s => s.id === "benign-keyword")!.hit).toBe(true);
    expect(runCorpus("sigma").samples.find(s => s.id === "benign-keyword")!.verdict).toBe("fp");
  });

  it("marks partial-keyword events as fn", () => {
    expect(runCorpus("yara").samples.find(s => s.id === "partial")!.verdict).toBe("fn");
  });
});

describe("corpusDigest", () => {
  it("is stable for identical runs", () => {
    expect(corpusDigest(runCorpus("sigma"))).toBe(corpusDigest(runCorpus("sigma")));
  });

  it("differs between formats", () => {
    expect(corpusDigest(runCorpus("sigma"))).not.toBe(corpusDigest(runCorpus("kql")));
  });

  it("encodes per-sample verdicts", () => {
    const d = corpusDigest(runCorpus("sigma"));
    expect(d).toContain("found:tp");
    expect(d).toContain("benign-keyword:fp");
    expect(d).toContain("partial:fn");
    expect(d).toContain("benign:tn");
  });
});