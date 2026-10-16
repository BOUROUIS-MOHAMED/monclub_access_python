// Access v5 soft chip: 16 % tint + dark text, radius 6. `size="sm"` is the
// 20 px flag chip used next to a name in a table cell.
import * as React from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { DOT, SOFT, SOLID, type Tone } from "./tone";

export interface ChipProps extends React.HTMLAttributes<HTMLSpanElement> {
  tone?: Tone;
  size?: "sm" | "md";
  /** Filled instead of soft (e.g. the hero "Autorisé"). */
  solid?: boolean;
  /** Small status dot before the label. */
  dot?: boolean;
  icon?: LucideIcon;
}

export function Chip({ tone = "grey", size = "md", solid, dot, icon: Icon, className, children, ...props }: ChipProps) {
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap font-bold",
        size === "sm" ? "h-5 rounded-[5px] px-1.5 text-[11px]" : "h-6 rounded-md px-2 text-[12px]",
        solid ? SOLID[tone] : SOFT[tone],
        className,
      )}
      {...props}
    >
      {dot && <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", DOT[tone])} />}
      {Icon && <Icon className="h-3.5 w-3.5 shrink-0" />}
      {children}
    </span>
  );
}

/** Rounded-square icon tile on a soft tint (list rows, KPI cards). */
export function ToneIcon({ icon: Icon, tone = "grey", size = 38, className }: {
  icon: LucideIcon; tone?: Tone; size?: 34 | 38 | 44; className?: string;
}) {
  const box = size === 44 ? "h-11 w-11 rounded-xl" : size === 38 ? "h-[38px] w-[38px] rounded-[10px]" : "h-[34px] w-[34px] rounded-full";
  const ico = size === 44 ? "h-[22px] w-[22px]" : size === 38 ? "h-[19px] w-[19px]" : "h-[17px] w-[17px]";
  return (
    <span className={cn("grid shrink-0 place-items-center", box, SOFT[tone], className)}>
      <Icon className={ico} />
    </span>
  );
}

/** Round initials avatar on a soft tint. */
export function Avatar({ initials, tone = "grey", size = 34, className }: {
  initials: string; tone?: Tone; size?: 32 | 34 | 56 | 76; className?: string;
}) {
  const box = {
    32: "h-8 w-8 text-[13px] font-extrabold",
    34: "h-[34px] w-[34px] text-[12.5px] font-bold",
    56: "h-14 w-14 font-num text-[21px] font-extrabold",
    76: "h-[76px] w-[76px] font-num text-[28px] font-extrabold",
  }[size];
  return (
    <span className={cn("grid shrink-0 place-items-center rounded-full", box, SOFT[tone], className)}>
      {initials}
    </span>
  );
}
