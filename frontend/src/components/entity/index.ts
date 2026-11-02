/*
 * ── Living Inventory ─────────────────────────────────────
 * Track which pages use each primitive. Update on migration.
 *
 *                           Intel   Case    Report  DevShow  Dash
 * EntityHeader               ✓       ✓       ✓       ✓       ✓
 * KnowledgeBar               ✓       ☐       ☐       ✓       ☐
 * ActionDock                 ✓       ☐       ☐       ✓       ☐
 * EntitySection              ✓       ✓       ✓       ✓       ✓
 * EntityMetadata             ✓       ☐       ☐       ✓       ☐
 * ObservableList             ✓       ☐       ☐       ✓       ☐
 * RelationshipCard           ✓       ☐       ☐       ✓       ☐
 * MetricGrid                 ☐       ✓       ✓       ✓       ☐
 * FindingCard                ☐       ✓       ✓       ✓       ☐
 */

export { EntityTypeBadge, EntityTypeIcon, ConfidenceBadge, ScoreBadge } from "./EntityBadge";
export { EntityHeader, HeaderAction, headerActionClass } from "./EntityHeader";
export { KnowledgeBar } from "./KnowledgeBar";
export { EntityMetadata } from "./EntityMetadata";
export { ObservableList } from "./ObservableList";
export { RelationshipCard, RelationshipList } from "./RelationshipCard";
export { ActionDock } from "./ActionDock";
export { EntitySection, EntitySectionRow } from "./EntitySection";
export { MetricGrid, MetricCard } from "./MetricGrid";
export { FindingCard } from "./FindingCard";
export { ProvenanceTrace } from "./ProvenanceTrace";
