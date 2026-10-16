// Access v5 card ("block") grammar — radius 16, the dashboard's two-layer
// shadow, a 16/18 px header with title + sub + controls, dashed row dividers.
//   <PageGrid>           12-column content grid, 18 px gap (spans: col-span-8 / col-span-4 …)
//   <Panel>              the card
//   <PanelHeader>        title, sub, right-side controls (search, segmented, buttons)
//   <PanelList>/<ListRow> the icon-tile list used for rails ("État du poste")
//   <Note>               soft-tinted explanatory note
import * as React from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { INK, type Tone } from "./tone";
import { ToneIcon } from "./chip";

export function PageGrid({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("grid grid-cols-12 items-start gap-[18px]", className)} {...props} />;
}

export function Panel({ className, ...props }: React.HTMLAttributes<HTMLElement>) {
  return (
    <section
      className={cn("min-w-0 overflow-hidden rounded-2xl bg-card text-card-foreground shadow-[var(--shadow-card)]", className)}
      {...props}
    />
  );
}

export function PanelHeader({ title, sub, children, className }: {
  title?: React.ReactNode; sub?: React.ReactNode; children?: React.ReactNode; className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-center gap-2.5 px-[18px] pt-4", className)}>
      <div className="min-w-[160px] flex-1">
        {title != null && <h2 className="m-0 text-[16px] font-bold leading-snug">{title}</h2>}
        {sub != null && <div className="mt-0.5 text-[13px] text-muted-foreground">{sub}</div>}
      </div>
      {children}
    </div>
  );
}

/** Dashed divider (rgba(145,158,171,.2)). */
export function DashedRule({ className }: { className?: string }) {
  return <div className={cn("border-t border-dashed border-grey/20", className)} />;
}

export function PanelList({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("px-[18px] pb-3.5 pt-2.5", className)} {...props} />;
}

export interface ListRowProps {
  icon?: LucideIcon;
  tone?: Tone;
  title: React.ReactNode;
  sub?: React.ReactNode;
  /** Tone of the title / sub text (default ink / muted). */
  titleTone?: Tone;
  subTone?: Tone;
  /** Right-aligned bold value ("3 / 4"). */
  value?: React.ReactNode;
  valueTone?: Tone;
  valueMono?: boolean;
  /** Right-aligned chip or any trailing node. */
  trailing?: React.ReactNode;
  /** Buttons under the text, indented to the text column. */
  actions?: React.ReactNode;
  /** Progress bar under the text (0–100). */
  bar?: number;
  barTone?: Tone;
  /** Let title/sub wrap instead of truncating. */
  wrap?: boolean;
  mono?: boolean;
  /** Selected row (blue tint + ring). */
  selected?: boolean;
  className?: string;
}

const BAR: Record<Tone, string> = {
  primary: "bg-primary", success: "bg-success", warning: "bg-warning",
  error: "bg-error", info: "bg-info", grey: "bg-grey",
};

export function ListRow({
  icon, tone = "grey", title, sub, titleTone, subTone, value, valueTone, valueMono,
  trailing, actions, bar, barTone = "primary", wrap, mono, selected, className,
}: ListRowProps) {
  const clip = wrap ? "whitespace-normal" : "truncate";
  return (
    <div
      className={cn(
        "-mx-2.5 rounded-xl p-2.5",
        selected && "bg-primary/8 outline outline-1 outline-primary/32",
        className,
      )}
    >
      <div className="flex items-center gap-3">
        {icon && <ToneIcon icon={icon} tone={tone} />}
        <div className="min-w-0 flex-1">
          <div className={cn("text-[13.5px] font-semibold", clip, titleTone ? INK[titleTone] : "text-foreground", mono && "font-mono")}>
            {title}
          </div>
          {sub != null && sub !== "" && (
            <div className={cn("text-[12.5px] leading-[1.45]", clip, subTone ? INK[subTone] : "text-muted-foreground")}>
              {sub}
            </div>
          )}
        </div>
        {value != null && value !== "" && (
          <span className={cn("whitespace-nowrap text-[13.5px] font-bold", valueTone ? INK[valueTone] : "text-foreground", valueMono && "font-mono")}>
            {value}
          </span>
        )}
        {trailing}
      </div>
      {bar != null && (
        <div className={cn("mb-0.5 mt-2.5 h-1.5 rounded-full bg-muted", icon && "ml-[50px]")}>
          <div className={cn("h-1.5 rounded-full transition-[width] duration-300", BAR[barTone])} style={{ width: `${Math.max(0, Math.min(100, bar))}%` }} />
        </div>
      )}
      {actions && <div className={cn("mt-2 flex flex-wrap gap-1.5", icon && "ml-[50px]")}>{actions}</div>}
    </div>
  );
}

export function Note({ tone = "info", className, children }: { tone?: Tone; className?: string; children: React.ReactNode }) {
  const soft: Record<Tone, string> = {
    primary: "bg-primary/16 text-primary-ink", success: "bg-success/16 text-success-ink",
    warning: "bg-warning/16 text-warning-ink", error: "bg-error/16 text-error-ink",
    info: "bg-info/16 text-info-ink", grey: "bg-muted text-foreground",
  };
  return <div className={cn("rounded-lg px-3 py-2.5 text-[13px] leading-normal", soft[tone], className)}>{children}</div>;
}
