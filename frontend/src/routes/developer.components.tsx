import { createFileRoute } from "@tanstack/react-router";
import { PageShell } from "@/components/PageShell";
import {
  EntityTypeBadge, EntityTypeIcon, ConfidenceBadge, ScoreBadge,
  EntityHeader,
  KnowledgeBar,
  EntityMetadata,
  ObservableList,
  RelationshipList,
  ActionDock,
  EntitySection, EntitySectionRow,
  MetricGrid, MetricCard,
  FindingCard,
} from "@/components/entity";
import type { IntelEntity, Observable, Relationship } from "@/data/intel";
import { useState } from "react";
import { Boxes, Code, FileText } from "lucide-react";

export const Route = createFileRoute("/developer/components")({ component: ComponentShowcase });

const SAMPLE_ENTITY: IntelEntity = {
  id: "CVE-2026-1234",
  type: "vulnerability",
  score: 82,
  confidence: "high",
  title: "CVE-2026-1234: Authentication bypass in WidgetCorp API Gateway",
  summary: "An authentication bypass vulnerability in WidgetCorp API Gateway v3.2–3.5 allows unauthenticated remote attackers to access admin endpoints via crafted session tokens.",
  tags: ["widgetcorp", "api-gateway", "auth-bypass", "CVE-2026"],
  cvss: 9.1,
  epss: 0.83,
  kev: true,
  exploits: { metasploit: true, nuclei: true, exploitDb: true },
  vendor: "WidgetCorp",
  published: "2026-07-21",
  affected: "API Gateway v3.2–3.5",
  observables: [
    { id: "obs-1", type: "ipv4", value: "198.51.100.42", context: "C2 callback", source: "/intel", timestamp: "2026-07-28T10:00:00Z" },
    { id: "obs-2", type: "sha256", value: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b", context: "dropper hash", source: "/intel", timestamp: "2026-07-28T10:00:00Z" },
    { id: "obs-3", type: "domain", value: "evil-c2.example.com", context: "C2 domain", source: "/intel", timestamp: "2026-07-28T10:00:00Z" },
    { id: "obs-4", type: "url", value: "https://evil-c2.example.com/beacon", context: "full beacon URL", source: "/intel", timestamp: "2026-07-28T10:00:00Z" },
  ],
};

const SAMPLE_OBSERVABLES: Observable[] = SAMPLE_ENTITY.observables;

const SAMPLE_RELATIONSHIPS: Relationship[] = [
  { sourceId: SAMPLE_ENTITY.id, targetId: "ACTOR-001", targetType: "threat-actor", relationshipType: "uses-tool", confidence: "medium", source: "/intel", reason: "CVE observed in campaigns by ACTOR-001" },
  { sourceId: SAMPLE_ENTITY.id, targetId: "MAL-001", targetType: "malware", relationshipType: "implements", confidence: "high", source: "/intel", reason: "CVE exploited by MAL-001 dropper" },
];

function ComponentShowcase() {
  const [findingCreated, setFindingCreated] = useState(false);
  const [iocsAttached, setIocsAttached] = useState(false);
  const [activeCase] = useState({ id: "CASE-001", title: "WidgetCorp breach investigation" });

  const Section = ({ title, desc, children }: { title: string; desc?: string; children: React.ReactNode }) => (
    <div className="rounded-md border border-subtle bg-surface-1">
      <header className="flex items-center gap-2 border-b border-subtle px-4 py-2.5">
        <Boxes className="h-3.5 w-3.5 text-muted-foreground" />
        <h3 className="font-mono ba-text-2xs text-foreground">{title}</h3>
        {desc && <span className="font-mono ba-text-3xs text-muted-foreground">· {desc}</span>}
      </header>
      <div className="space-y-4 p-4">{children}</div>
    </div>
  );

  const ImportBlock = ({ path }: { path: string }) => (
    <div className="flex items-center gap-2 font-mono ba-text-2xs text-fg-dim">
      <Code className="h-3 w-3" />
      <code className="rounded border border-subtle bg-surface-2 px-1.5 py-0.5">import {'{ … }'} from &quot;{path}&quot;</code>
    </div>
  );

  return (
    <PageShell
      eyebrow="dev / components"
      title="Component Showcase"
      description="Living inventory of entity primitives — every component with import path, props, and a live example."
      crumbs={[{ label: "Dev", href: "/developer" }, { label: "Components" }]}
      jumps={[
        { label: "Badges", to: "#badges" },
        { label: "EntityHeader", to: "#entity-header" },
        { label: "KnowledgeBar", to: "#knowledge-bar" },
        { label: "Section", to: "#entity-section" },
        { label: "Metadata", to: "#entity-metadata" },
        { label: "Observables", to: "#observable-list" },
        { label: "Relationships", to: "#relationship-card" },
        { label: "Metrics", to: "#metric-grid" },
        { label: "Findings", to: "#finding-card" },
        { label: "ActionDock", to: "#action-dock" },
      ]}
    >
      {/* ── Badges ── */}
      <div id="badges">
        <Section title="Badges" desc="EntityBadge.tsx — type, confidence, and score indicators">
          <ImportBlock path="@/components/entity" />
          <div className="space-y-3">
            <div>
              <span className="font-mono ba-text-3xs text-fg-dim">EntityTypeBadge</span>
              <div className="mt-1 flex flex-wrap gap-2">
                <EntityTypeBadge type="vulnerability" />
                <EntityTypeBadge type="threat-actor" />
                <EntityTypeBadge type="malware" />
                <EntityTypeBadge type="file-hash" />
                <EntityTypeBadge type="tls-fingerprint" />
              </div>
            </div>
            <div>
              <span className="font-mono ba-text-3xs text-fg-dim">EntityTypeIcon (standalone)</span>
              <div className="mt-1 flex gap-3">
                <EntityTypeIcon type="vulnerability" />
                <EntityTypeIcon type="threat-actor" />
                <EntityTypeIcon type="malware" />
              </div>
            </div>
            <div>
              <span className="font-mono ba-text-3xs text-fg-dim">ConfidenceBadge</span>
              <div className="mt-1 flex flex-wrap gap-2">
                <ConfidenceBadge confidence="high" />
                <ConfidenceBadge confidence="medium" />
                <ConfidenceBadge confidence="low" />
                <ConfidenceBadge confidence="unknown" />
              </div>
            </div>
            <div>
              <span className="font-mono ba-text-3xs text-fg-dim">ScoreBadge</span>
              <div className="mt-1 flex flex-wrap gap-2">
                <ScoreBadge score={95} />
                <ScoreBadge score={72} />
                <ScoreBadge score={41} />
              </div>
            </div>
          </div>
        </Section>
      </div>

      {/* ── EntityHeader: intel variant ── */}
      <div id="entity-header">
        <Section title="EntityHeader" desc="EntityHeader.tsx — sticky header with discriminated union">
          <ImportBlock path="@/components/entity" />
          <div className="space-y-4">
            <div>
              <span className="font-mono ba-text-3xs text-fg-dim">variant=&quot;intel&quot; — Intel entity detail header</span>
              <p className="mb-2 font-mono ba-text-2xs text-fg-dim">Props: entity, onBack, onExport?, onAddToLocker?</p>
              <div className="relative overflow-hidden rounded-md border border-subtle">
                <style>{`.dev-header-demo [class*="sticky"] { position: relative !important; }`}</style>
                <div className="dev-header-demo">
                  <EntityHeader
                    variant="intel"
                    entity={SAMPLE_ENTITY}
                    onBack={() => {}}
                    onExport={() => {}}
                    onAddToLocker={() => {}}
                  />
                </div>
              </div>
            </div>
            <div>
              <span className="font-mono ba-text-3xs text-fg-dim">variant=&quot;case&quot; — Case header</span>
              <p className="mb-2 font-mono ba-text-2xs text-fg-dim">Props: title, onBack?, tags?, actions?, children?</p>
              <div className="relative overflow-hidden rounded-md border border-subtle">
                <div className="dev-header-demo">
                  <EntityHeader
                    variant="case"
                    title="WidgetCorp breach investigation"
                    onBack={() => {}}
                    tags={["phishing", "C2", "data-exfil"]}
                    actions={<span className="rounded border border-warning/40 bg-warning/10 px-2 py-0.5 font-mono ba-text-3xs text-warning">active</span>}
                  >
                    <div className="mt-2 font-mono ba-text-2xs text-muted-foreground">Created: 2026-07-28 · ID: CASE-001 · Age: 1 day</div>
                  </EntityHeader>
                </div>
              </div>
            </div>
          </div>
        </Section>
      </div>

      {/* ── KnowledgeBar ── */}
      <div id="knowledge-bar">
        <Section title="KnowledgeBar" desc="KnowledgeBar.tsx — 4-stat summary grid (observables / relationships / MITRE / case)">
          <ImportBlock path="@/components/entity" />
          <p className="mb-2 font-mono ba-text-2xs text-fg-dim">Props: entity, relationshipCount, activeCase?, observables?, mitre?</p>
          <KnowledgeBar
            entity={SAMPLE_ENTITY}
            relationshipCount={SAMPLE_RELATIONSHIPS.length}
            activeCase={activeCase}
            observables={SAMPLE_ENTITY.observables.length}
            mitre={3}
          />
        </Section>
      </div>

      {/* ── EntitySection ── */}
      <div id="entity-section">
        <Section title="EntitySection" desc="EntitySection.tsx — titled section wrapper with optional icon and metadata">
          <ImportBlock path="@/components/entity" />
          <p className="mb-2 font-mono ba-text-2xs text-fg-dim">Props: title?, icon?, meta?, children, className?</p>
          <div className="space-y-3">
            <EntitySection title="Investigation Overview" icon={FileText} meta="4 findings">
              <p className="font-mono ba-text-xs text-fg-dim">EntitySection provides a consistent container for any domain content block.</p>
            </EntitySection>
            <EntitySection title="Without Icon">
              <EntitySectionRow label="Status" value="Open" />
              <EntitySectionRow label="Priority" value="High" />
              <EntitySectionRow label="Assignee" value="analyst-01" />
            </EntitySection>
          </div>
        </Section>
      </div>

      {/* ── EntityMetadata ── */}
      <div id="entity-metadata">
        <Section title="EntityMetadata" desc="EntityMetadata.tsx — grouped key-value fields auto-categorized into Identity / Threat sections">
          <ImportBlock path="@/components/entity" />
          <p className="mb-2 font-mono ba-text-2xs text-fg-dim">Props: fields: {'{ label: string; value: string }[]'}, entityType</p>
          <EntityMetadata
            entityType="vulnerability"
            fields={[
              { label: "Type", value: "CVE" },
              { label: "Score", value: "82 / 100" },
              { label: "Confidence", value: "High" },
              { label: "Tags", value: "widgetcorp, auth-bypass" },
              { label: "Published", value: "2026-07-28" },
              { label: "CVSS Vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
              { label: "Affected Versions", value: "WidgetCorp API Gateway v3.2–3.5" },
            ]}
          />
        </Section>
      </div>

      {/* ── ObservableList ── */}
      <div id="observable-list">
        <Section title="ObservableList" desc="ObservableList.tsx — type-iconed rows with copy + locker actions">
          <ImportBlock path="@/components/entity" />
          <p className="mb-2 font-mono ba-text-2xs text-fg-dim">Props: observables: Observable[]</p>
          <ObservableList observables={SAMPLE_OBSERVABLES} />
        </Section>
      </div>

      {/* ── RelationshipCard / List ── */}
      <div id="relationship-card">
        <Section title="RelationshipCard / RelationshipList" desc="RelationshipCard.tsx — clickable relationship row with chip">
          <ImportBlock path="@/components/entity" />
          <p className="mb-2 font-mono ba-text-2xs text-fg-dim">Props: relationship, onNavigate? (targetId) ={'>'} void</p>
          <RelationshipList relationships={SAMPLE_RELATIONSHIPS} onNavigate={() => {}} />
        </Section>
      </div>

      {/* ── MetricGrid ── */}
      <div id="metric-grid">
        <Section title="MetricGrid / MetricCard" desc="MetricGrid.tsx — 2- or 4-column metric cards with tone support">
          <ImportBlock path="@/components/entity" />
          <p className="mb-2 font-mono ba-text-2xs text-fg-dim">Props: metrics: {'{ label, value, tone? }[]'}, MetricCard also accepts children + onClick</p>
          <MetricGrid
            metrics={[
              { label: "Findings", value: "12", tone: "primary" },
              { label: "IOCs", value: "47", tone: "destructive" },
              { label: "Events", value: "89", tone: "info" },
              { label: "Total", value: "148" },
            ]}
          />
          <div className="mt-2">
            <span className="font-mono ba-text-3xs text-fg-dim">MetricCard with children (custom content)</span>
            <div className="mt-1 grid grid-cols-2 gap-2 sm:grid-cols-3">
              <MetricCard label="Detections">
                <div className="mt-0.5 font-mono text-sm font-bold tabular-nums text-warning">3 active</div>
              </MetricCard>
              <MetricCard label="Coverage" onClick={() => {}}>
                <div className="mt-0.5 font-mono text-sm font-bold tabular-nums text-success">94%</div>
              </MetricCard>
            </div>
          </div>
        </Section>
      </div>

      {/* ── FindingCard ── */}
      <div id="finding-card">
        <Section title="FindingCard" desc="FindingCard.tsx — severity-toned finding card with related IOC chips">
          <ImportBlock path="@/components/entity" />
          <p className="mb-2 font-mono ba-text-2xs text-fg-dim">Props: finding: Finding, relatedIocs?: IOC[], onFilterSource?, filterActive?</p>
          <div className="space-y-2">
            <FindingCard
              finding={{
                id: "F-001",
                title: "Outbound C2 beacon detected",
                severity: "critical",
                detail: "Process 'svchost.exe' (PID 4821) established persistent HTTPS beacon to 198.51.100.42 every 60s over the last 4 hours.",
                source: "SIEM",
                technique: "T1071",
              }}
              relatedIocs={[
                { type: "ipv4", value: "198.51.100.42", source: "SIEM", context: "C2 beacon destination", severity: "critical" },
                { type: "domain", value: "evil-c2.example.com", source: "DNS", context: "C2 infrastructure", severity: "high" },
              ]}
              onFilterSource={() => {}}
              filterActive={false}
            />
            <FindingCard
              finding={{
                id: "F-002",
                title: "Phishing link clicked by 3 users",
                severity: "high",
                detail: "URL 'https://phishy.example.com/login' was accessed by 3 users within 5 minutes of email delivery.",
                source: "Email Gateway",
                technique: "T1566",
              }}
            />
            <FindingCard
              finding={{
                id: "F-003",
                title: "Unusual outbound data transfer",
                severity: "medium",
                detail: "15GB uploaded to unknown IP over 2 hours via non-standard port 8443.",
                source: "Network",
              }}
            />
          </div>
        </Section>
      </div>

      {/* ── ActionDock ── */}
      <div id="action-dock">
        <Section title="ActionDock" desc="ActionDock.tsx — locker, export, case actions (create finding, attach IOCs)">
          <ImportBlock path="@/components/entity" />
          <p className="mb-2 font-mono ba-text-2xs text-fg-dim">Props: activeCase?, findingCreated, iocsAttached, observableCount, onCreateFinding, onAttachIocs, onAddToLocker, onExport</p>
          <div className="flex items-center gap-3 mb-3">
            <label className="flex items-center gap-2 font-mono ba-text-2xs text-fg-dim">
              <input type="checkbox" checked={findingCreated} onChange={() => setFindingCreated(!findingCreated)} />
              findingCreated
            </label>
            <label className="flex items-center gap-2 font-mono ba-text-2xs text-fg-dim">
              <input type="checkbox" checked={iocsAttached} onChange={() => setIocsAttached(!iocsAttached)} />
              iocsAttached
            </label>
          </div>
          <ActionDock
            activeCase={activeCase}
            findingCreated={findingCreated}
            iocsAttached={iocsAttached}
            observableCount={4}
            onCreateFinding={() => setFindingCreated(true)}
            onAttachIocs={() => setIocsAttached(true)}
            onAddToLocker={() => {}}
            onExport={() => {}}
          />
        </Section>
      </div>

      {/* ── Summary ── */}
      <Section title="Primitive Inventory" desc="Design System v1.0 — frozen. See frontend/docs/DESIGN_SYSTEM.md for the full contract.">
        <table className="w-full font-mono ba-text-2xs">
          <thead>
            <tr className="border-b border-subtle ba-text-3xs text-fg-dim">
              <th className="pb-2 pr-4 text-left">Component</th>
              <th className="pb-2 pr-4 text-left">File</th>
              <th className="pb-2 pr-4 text-left">Pages</th>
              <th className="pb-2 text-left">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/30">
            {[
              ["EntityTypeBadge, EntityTypeIcon, ConfidenceBadge, ScoreBadge", "EntityBadge.tsx", "Intel", "Stable"],
              ["EntityHeader (variant=intel | case)", "EntityHeader.tsx", "Intel, Case, Report", "Stable"],
              ["KnowledgeBar", "KnowledgeBar.tsx", "Intel", "Stable"],
              ["EntityMetadata", "EntityMetadata.tsx", "Intel", "Stable"],
              ["ObservableList", "ObservableList.tsx", "Intel", "Stable"],
              ["RelationshipCard, RelationshipList", "RelationshipCard.tsx", "Intel", "Stable"],
              ["ActionDock", "ActionDock.tsx", "Intel", "Stable"],
              ["EntitySection, EntitySectionRow", "EntitySection.tsx", "Intel, Case, Report", "Stable"],
              ["MetricGrid, MetricCard", "MetricGrid.tsx", "Case, Report", "Stable"],
              ["FindingCard", "FindingCard.tsx", "Case, Report", "Stable"],
            ].map(([comp, file, pages, status]) => (
              <tr key={comp} className="text-fg-dim">
                <td className="py-2 pr-4">{comp}</td>
                <td className="py-2 pr-4 text-muted-foreground">{file}</td>
                <td className="py-2 pr-4 text-muted-foreground">{pages}</td>
                <td className="py-2 text-success">{status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
    </PageShell>
  );
}
