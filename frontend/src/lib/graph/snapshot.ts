/**
 * Graph snapshot → notebook (ROADMAP-v4 V4.2): turns the investigation
 * graph's current filter state into a deterministic text body the analyst
 * can file as a case entry. Honest by design: it records exactly which
 * filters were active and what was visible — it is a filter-state record,
 * not an image and not an analysis claim.
 */

export interface GraphSnapshotInput {
  mode: string;
  hopLimit: number | null;
  sourceFilter: string;
  minConfidence: number | null;
  /** null = no explicit kind filter (mode default layers shown) */
  kindFilter: string[] | null;
  /** null = no explicit relation filter */
  relationFilter: string[] | null;
  /** "kind:id" of the focused/selected node, or null */
  focus: string | null;
  nodeCount: number;
  edgeCount: number;
}

export function graphSnapshotBody(s: GraphSnapshotInput): string {
  const lines: string[] = [];
  lines.push(`Graph snapshot (${s.mode} view)`);
  lines.push(`visible: ${s.nodeCount} node${s.nodeCount === 1 ? "" : "s"}, ${s.edgeCount} edge${s.edgeCount === 1 ? "" : "s"}`);
  const controls: string[] = [
    `hops: ${s.hopLimit ?? "all"}`,
    `source: ${s.sourceFilter}`,
    `min confidence: ${s.minConfidence ?? "any"}`,
  ];
  lines.push(controls.join(" · "));
  lines.push(`kinds: ${s.kindFilter && s.kindFilter.length ? [...s.kindFilter].sort().join(", ") : "mode default"}`);
  lines.push(`relations: ${s.relationFilter && s.relationFilter.length ? [...s.relationFilter].sort().join(", ") : "mode default"}`);
  if (s.focus) lines.push(`focus: ${s.focus}`);
  lines.push("Filter-state record captured from the investigation graph — not an image, not an analysis claim.");
  return lines.join("\n");
}
