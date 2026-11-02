import type { IntelEntityType } from "@/data/intel";

interface MetaField {
  label: string;
  value: string;
}

interface MetaSection {
  title: string;
  fields: MetaField[];
}

export function EntityMetadata({
  fields,
  entityType,
}: {
  fields: MetaField[];
  entityType: IntelEntityType;
}) {
  const sections = groupFields(fields, entityType);

  return (
    <div className="space-y-4">
      {sections.map((section) => (
        <div key={section.title}>
          <h4 className="mb-2 font-mono ba-text-2xs text-fg-dim">
            {section.title}
          </h4>
          <div className="grid grid-cols-1 gap-x-6 gap-y-1.5 sm:grid-cols-2">
            {section.fields.map((f) => (
              <div key={f.label} className="flex items-baseline gap-2">
                <span className="shrink-0 font-mono ba-text-2xs text-fg-dim">
                  {f.label}
                </span>
                <span className="truncate font-mono ba-text-xs text-foreground">{f.value}</span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function groupFields(fields: MetaField[], entityType: IntelEntityType): MetaSection[] {
  const identityFields = ["type", "score", "confidence", "tags", "last seen", "first seen"];
  const identity = fields.filter((f) => identityFields.includes(f.label.toLowerCase()));
  const remaining = fields.filter((f) => !identityFields.includes(f.label.toLowerCase()));

  const sections: MetaSection[] = [];
  if (identity.length > 0) sections.push({ title: "Identity", fields: identity });

  const threatLabel = entityType === "vulnerability" ? "Vulnerability" : "Threat Intelligence";
  if (remaining.length > 0) sections.push({ title: threatLabel, fields: remaining });

  return sections;
}
