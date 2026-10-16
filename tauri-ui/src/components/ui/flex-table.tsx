// Access v5 table: a grey header strip, flex columns (each cell takes a `flex`
// weight, like the design's `cols: [['Heure', 0.5], ['Membre', 3.4], …]`),
// 56 px rows with dashed dividers, an empty line, an optional footer.
// ARIA table roles, no <table> — the rows are flex so long text truncates.
import * as React from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Tone } from "./tone";
import { Avatar, Chip, ToneIcon } from "./chip";

export interface FlexColumn {
  label: React.ReactNode;
  flex: number;
  align?: "left" | "right" | "center";
}

const JUSTIFY = { left: "justify-start text-left", right: "justify-end text-right", center: "justify-center text-center" } as const;

export function FlexTable({ label, columns, children, empty, footer, className }: {
  label: string; columns: FlexColumn[]; children?: React.ReactNode;
  /** Shown instead of rows when `children` is empty. */
  empty?: React.ReactNode; footer?: React.ReactNode; className?: string;
}) {
  const hasRows = React.Children.toArray(children).length > 0;
  return (
    <div role="table" aria-label={label} className={cn("mt-3.5", className)}>
      <div role="row" className="flex h-10 items-center bg-muted px-[18px] text-[12.5px] font-semibold text-muted-foreground">
        {columns.map((c, i) => (
          <span
            key={i}
            role="columnheader"
            className={cn("min-w-0 whitespace-nowrap pr-2.5", JUSTIFY[c.align ?? "left"])}
            style={{ flex: c.flex }}
          >
            {c.label}
          </span>
        ))}
      </div>
      {hasRows ? children : empty != null && (
        <div className="px-[18px] py-7 text-center text-[13.5px] text-muted-foreground">{empty}</div>
      )}
      {footer && <div className="flex items-center gap-2.5 px-[18px] py-2.5 text-[13px] text-muted-foreground">{footer}</div>}
    </div>
  );
}

export function FlexRow({ selected, className, minHeight = 56, style, ...props }: React.HTMLAttributes<HTMLDivElement> & {
  selected?: boolean; minHeight?: number;
}) {
  return (
    <div
      role="row"
      className={cn("flex items-center border-b border-dashed border-grey/20 px-[18px]", selected && "bg-primary/6", className)}
      style={{ minHeight, ...style }}
      {...props}
    />
  );
}

export function FlexCell({ flex, align = "left", className, style, ...props }: React.HTMLAttributes<HTMLDivElement> & {
  flex: number; align?: "left" | "right" | "center";
}) {
  return (
    <div
      role="cell"
      className={cn("flex min-w-0 items-center gap-2 py-2 pr-2.5", JUSTIFY[align], className)}
      style={{ flex, ...style }}
      {...props}
    />
  );
}

/** Title + optional sub line, truncating. `flags` = small chips after the title. */
export function CellText({ title, sub, mono, subMono, strong, titleClassName, subClassName, flags }: {
  title: React.ReactNode; sub?: React.ReactNode; mono?: boolean; subMono?: boolean; strong?: boolean;
  titleClassName?: string; subClassName?: string; flags?: { label: string; tone: Tone }[];
}) {
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-1.5">
        <span className={cn("truncate text-[13.5px] text-foreground", strong ? "font-semibold" : "font-normal", mono && "font-mono", titleClassName)}>
          {title}
        </span>
        {flags?.map((f) => <Chip key={f.label} tone={f.tone} size="sm">{f.label}</Chip>)}
      </div>
      {sub != null && sub !== "" && (
        <div className={cn("truncate text-[12px] text-muted-foreground", subMono && "font-mono", subClassName)}>{sub}</div>
      )}
    </div>
  );
}

/** Person cell: initials avatar + name + sub. */
export function PersonCell({ name, initials, sub, tone = "grey", subClassName }: {
  name: React.ReactNode; initials: string; sub?: React.ReactNode; tone?: Tone; subClassName?: string;
}) {
  return (
    <>
      <Avatar initials={initials} tone={tone} />
      <CellText title={name} sub={sub} strong subClassName={subClassName} />
    </>
  );
}

/** Icon cell: round icon tile + title + sub (system rows, unresolved credentials). */
export function IconCell({ icon, title, sub, tone = "grey", subClassName }: {
  icon: LucideIcon; title: React.ReactNode; sub?: React.ReactNode; tone?: Tone; subClassName?: string;
}) {
  return (
    <>
      <ToneIcon icon={icon} tone={tone} size={34} />
      <CellText title={title} sub={sub} strong subClassName={subClassName} />
    </>
  );
}
