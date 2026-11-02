import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { ArrowLeft, Database, ExternalLink } from "lucide-react";
import { notify } from "@/lib/notify";
import type { IntelEntity } from "@/data/intel";
import { EntityTypeBadge, ConfidenceBadge, ScoreBadge } from "./EntityBadge";

/* Standardized header action button — every page uses the same
 * size, border, type scale, and hover language. Ordering contract:
 * Primary action(s) → Export → Share/Copy → More. */

export const headerActionClass =
  "inline-flex items-center gap-1 rounded border border-subtle px-2 py-1 font-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:border-primary/40 hover:text-primary";

export function HeaderAction({
  icon,
  children,
  onClick,
  disabled,
  tone = "default",
  title,
  className,
}: {
  icon?: ReactNode;
  children?: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  tone?: "default" | "primary" | "danger";
  title?: string;
  className?: string;
}) {
  const tones = {
    default: "",
    primary: "border-primary/40 bg-primary/10 text-primary hover:bg-primary/20",
    danger: "hover:border-destructive/50 hover:text-destructive",
  };
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={
        headerActionClass +
        " " +
        tones[tone] +
        " disabled:pointer-events-none disabled:opacity-40" +
        (className ? " " + className : "")
      }
    >
      {icon}
      {children}
    </button>
  );
}

type Common = {
  onBack?: () => void;
  backLabel?: string;
};

type IntelVariant = Common & {
  variant: "intel";
  entity: IntelEntity;
  onExport?: () => void;
  onAddToLocker?: () => void;
  actions?: ReactNode;
};

type CaseVariant = Common & {
  variant: "case";
  /** Optional — omit when PageShell already renders the page title. */
  title?: string;
  tags?: string[];
  actions?: ReactNode;
  children?: ReactNode;
};

/* Shared sticky shell: one offset (below the top bar), one blur, one
 * border language, one compact transition (~150ms, compress not collapse). */
export function EntityHeader(props: IntelVariant | CaseVariant) {
  const shellRef = useRef<HTMLDivElement>(null);
  const [compact, setCompact] = useState(false);
  const [barH, setBarH] = useState<number>(48);

  useEffect(() => {
    let raf = 0;
    const measure = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        const el = shellRef.current;
        if (!el) return;
        const header = document.querySelector("header");
        const h = header ? header.getBoundingClientRect().height : 0;
        setBarH((prev) => (prev === h ? prev : h));
        setCompact(el.getBoundingClientRect().top <= h);
        document.documentElement.style.setProperty("--ba-header-h", `${el.getBoundingClientRect().height}px`);
      });
    };
    measure();
    window.addEventListener("scroll", measure, { passive: true });
    window.addEventListener("resize", measure);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("scroll", measure);
      window.removeEventListener("resize", measure);
    };
  }, []);

  useEffect(() => {
    const t = setTimeout(() => {
      if (shellRef.current) {
        document.documentElement.style.setProperty("--ba-header-h", `${shellRef.current.getBoundingClientRect().height}px`);
      }
    }, 170);
    return () => clearTimeout(t);
  }, [compact]);

  const isIntel = "entity" in props;
  const title = isIntel ? props.entity.title : props.title;
  const backLabel = props.backLabel ?? "back";

  const backRow = props.onBack && (
    <div
      className={
        "grid transition-[grid-template-rows,opacity] duration-150 ease-out " +
        (compact ? "grid-rows-[0fr] opacity-0" : "grid-rows-[1fr] opacity-100")
      }
    >
      <div className="min-h-0 overflow-hidden">
        <button
          onClick={props.onBack}
          className="mb-2 inline-flex items-center gap-1 rounded px-1 py-0.5 font-mono ba-text-2xs text-fg-dim transition-colors duration-150 hover:text-foreground"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          {backLabel}
        </button>
      </div>
    </div>
  );

  return (
    <div
      ref={shellRef}
      style={{ top: `${barH}px` }}
      className={
        "sticky z-20 -mx-4 -mt-4 border-t-2 border-primary border-b border-subtle bg-surface-2/90 backdrop-blur-md transition-[padding] duration-150 ease-out " +
        (compact ? "px-4 pt-2 pb-2" : "px-4 pt-4 pb-3")
      }
    >
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          {backRow}
          <div className="flex items-center gap-2">
            {isIntel && <EntityTypeBadge type={props.entity.type} />}
            {title && <h2 className="truncate font-mono text-lg font-bold text-foreground">{title}</h2>}
          </div>
          {!isIntel && props.children}
          {isIntel && (
            <>
              <p className="mt-1 line-clamp-2 font-mono ba-text-xs leading-relaxed text-fg-dim">
                {props.entity.summary}
              </p>
              {props.entity.tags.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {props.entity.tags.map((tag) => (
                    <span
                      key={tag}
                      className="rounded border border-subtle bg-surface-1 px-1.5 py-px font-mono ba-text-3xs text-fg-dim"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              )}
            </>
          )}
          {!isIntel && props.tags && props.tags.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {props.tags.map((tag) => (
                <span
                  key={tag}
                  className="rounded border border-subtle bg-surface-1 px-1.5 py-px font-mono ba-text-3xs text-fg-dim"
                >
                  {tag}
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="flex shrink-0 flex-col items-end gap-2">
          {isIntel ? (
            <>
              <div className="flex items-center gap-1">
                {props.onAddToLocker && (
                  <HeaderAction
                    tone="primary"
                    icon={<Database className="h-3 w-3" />}
                    onClick={() => {
                      props.onAddToLocker!();
                      notify.success("Added to locker");
                    }}
                  >
                    locker
                  </HeaderAction>
                )}
                {props.onExport && (
                  <HeaderAction icon={<ExternalLink className="h-3 w-3" />} onClick={props.onExport}>
                    export
                  </HeaderAction>
                )}
                {props.actions}
              </div>
              <div className="flex items-center gap-2">
                <ScoreBadge score={props.entity.score} />
                <ConfidenceBadge confidence={props.entity.confidence} />
              </div>
            </>
          ) : (
            props.actions
          )}
        </div>
      </div>
    </div>
  );
}
