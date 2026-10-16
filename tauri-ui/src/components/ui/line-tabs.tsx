// Access v5 underline tabs (page tabs and dialog tabs): 2 px ink rule under the
// active tab, optional icon and count badge (ink when active, soft tone else).
// Controlled, renders only the tab strip — the caller renders the panel.
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { SOFT, type Tone } from "./tone";

export interface LineTabItem<T extends string> {
  value: T;
  label: string;
  icon?: LucideIcon;
  count?: number | string;
  countTone?: Tone;
}

export function LineTabs<T extends string>({ items, value, onChange, size = "page", className }: {
  items: LineTabItem<T>[]; value: T; onChange: (v: T) => void;
  /** "page" = 42 px / 14 px / 24 px gap; "dialog" = 40 px / 13.5 px / 20 px gap. */
  size?: "page" | "dialog"; className?: string;
}) {
  return (
    <div
      role="tablist"
      className={cn(
        "flex shadow-[inset_0_-2px_0_rgba(145,158,171,0.12)]",
        size === "page" ? "gap-6" : "gap-5",
        className,
      )}
    >
      {items.map((it) => {
        const on = it.value === value;
        const Icon = it.icon;
        return (
          <button
            key={it.value}
            type="button"
            role="tab"
            aria-selected={on}
            tabIndex={on ? 0 : -1}
            onClick={() => onChange(it.value)}
            onKeyDown={(e) => {
              if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
              const i = items.findIndex((x) => x.value === value);
              const next = items[(i + (e.key === "ArrowRight" ? 1 : items.length - 1)) % items.length];
              onChange(next.value);
              const sibling = e.key === "ArrowRight" ? e.currentTarget.nextElementSibling : e.currentTarget.previousElementSibling;
              (sibling as HTMLElement | null)?.focus();
            }}
            className={cn(
              "inline-flex cursor-pointer items-center gap-2 whitespace-nowrap border-b-2 bg-transparent p-0 transition-colors",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50",
              size === "page" ? "h-[42px] text-[14px]" : "h-10 text-[13.5px]",
              on ? "border-foreground font-bold text-foreground" : "border-transparent font-medium text-muted-foreground hover:text-foreground",
            )}
          >
            {Icon && <Icon className="h-[18px] w-[18px]" />}
            {it.label}
            {it.count != null && it.count !== "" && (
              <span
                className={cn(
                  "inline-flex h-[22px] items-center rounded-md px-[7px] text-[12px] font-bold",
                  on ? "bg-foreground text-background" : it.countTone ? SOFT[it.countTone] : "bg-muted text-muted-foreground",
                )}
              >
                {it.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
