// Access v5 button. Kinds follow the design's `btn()` helper:
//   outline (white, grey border) · primary (blue) · dark (ink) · danger (red
//   outline) · warn (amber soft) · ghost. Sizes: lg 36 px (header, dialogs),
//   md 32 px (card headers), sm 30 px (rows), xs 28 px.
// A separate component on purpose: the shadcn `Button` is shared with the TV
// build and must keep its look.
import * as React from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export type ActionKind = "outline" | "primary" | "dark" | "danger" | "warn" | "ghost";
export type ActionSize = "lg" | "md" | "sm" | "xs";

const KIND: Record<ActionKind, string> = {
  outline: "border border-grey/32 bg-card text-foreground hover:bg-muted",
  primary: "border border-transparent bg-primary text-primary-foreground hover:bg-primary/90",
  dark: "border border-transparent bg-foreground text-background hover:bg-foreground/85",
  danger: "border border-error/48 bg-card text-error-ink hover:bg-error/8",
  warn: "border border-warning/48 bg-warning/16 text-warning-ink hover:bg-warning/24",
  ghost: "border border-transparent bg-transparent text-foreground hover:bg-muted",
};

const SIZE: Record<ActionSize, string> = {
  lg: "h-9 px-3 text-[14px] [&_svg]:h-[17px] [&_svg]:w-[17px]",
  md: "h-8 px-3 text-[13px] [&_svg]:h-[15px] [&_svg]:w-[15px]",
  sm: "h-[30px] px-3 text-[12.5px] [&_svg]:h-[14px] [&_svg]:w-[14px]",
  xs: "h-7 px-2.5 text-[12.5px] [&_svg]:h-[14px] [&_svg]:w-[14px]",
};

export interface ActionButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  kind?: ActionKind;
  size?: ActionSize;
  icon?: LucideIcon;
  /** Icon only: the label goes to aria-label/title instead. */
  iconOnly?: boolean;
  /** Spin the icon (e.g. a running sync). */
  spin?: boolean;
}

export const ActionButton = React.forwardRef<HTMLButtonElement, ActionButtonProps>(
  ({ kind = "outline", size = "lg", icon: Icon, iconOnly, spin, className, children, type, ...props }, ref) => (
    <button
      ref={ref}
      type={type ?? "button"}
      className={cn(
        "inline-flex shrink-0 cursor-pointer items-center justify-center gap-[7px] whitespace-nowrap rounded-lg font-bold transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50 disabled:pointer-events-none disabled:opacity-50",
        "[&_svg]:shrink-0",
        KIND[kind],
        SIZE[size],
        iconOnly && "px-2",
        className,
      )}
      {...props}
    >
      {Icon && <Icon className={cn(spin && "animate-spin")} aria-hidden="true" />}
      {iconOnly ? <span className="sr-only">{children}</span> : children}
    </button>
  ),
);
ActionButton.displayName = "ActionButton";
