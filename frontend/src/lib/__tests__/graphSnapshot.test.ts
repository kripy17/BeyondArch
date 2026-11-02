import { describe, expect, it } from "vitest";
import { graphSnapshotBody, type GraphSnapshotInput } from "@/lib/graph/snapshot";

const base: GraphSnapshotInput = {
  mode: "relationship",
  hopLimit: 2,
  sourceFilter: "all",
  minConfidence: null,
  kindFilter: null,
  relationFilter: null,
  focus: null,
  nodeCount: 12,
  edgeCount: 8,
};

describe("graphSnapshotBody", () => {
  it("renders counts with correct pluralization and control defaults", () => {
    const body = graphSnapshotBody(base);
    expect(body).toContain("Graph snapshot (relationship view)");
    expect(body).toContain("visible: 12 nodes, 8 edges");
    expect(body).toContain("hops: 2 · source: all · min confidence: any");
    expect(body).toContain("kinds: mode default");
    expect(body).toContain("relations: mode default");
    expect(body).not.toContain("focus:");
    expect(body).toMatch(/not an image, not an analysis claim/);
  });

  it("singularizes single node/edge", () => {
    expect(graphSnapshotBody({ ...base, nodeCount: 1, edgeCount: 1 })).toContain("visible: 1 node, 1 edge");
  });

  it("includes filters, focus, and sorted kind/relation lists when set", () => {
    const body = graphSnapshotBody({
      ...base,
      hopLimit: null,
      sourceFilter: "triage-escalation",
      minConfidence: 0.5,
      kindFilter: ["alert", "ioc"],
      relationFilter: ["enriched-by", "created"],
      focus: "ioc:x1",
    });
    expect(body).toContain("hops: all");
    expect(body).toContain("source: triage-escalation");
    expect(body).toContain("min confidence: 0.5");
    expect(body).toContain("kinds: alert, ioc");
    expect(body).toContain("relations: created, enriched-by");
    expect(body).toContain("focus: ioc:x1");
  });

  it("handles empty explicit filter lists as mode default", () => {
    const body = graphSnapshotBody({ ...base, kindFilter: [], relationFilter: [] });
    expect(body).toContain("kinds: mode default");
    expect(body).toContain("relations: mode default");
  });
});
