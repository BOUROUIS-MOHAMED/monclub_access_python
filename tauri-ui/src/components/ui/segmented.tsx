// Access v5 segmented control (grey track, white selected pill, optional count).
import { cn } from "@/lib/utils";

export interface SegmentItem<T extends string> {
  value: T;
  label: string;
  count?: number | string;
}

export function Segmented<T extends string>({ items, value, onChange, ariaLabel, className }: {
  items: SegmentItem<T>[]; value: T; onChange: (v: T) => void; ariaLabel: string; className?: string;
}) {
  return (
    <div role="group" aria-label={ariaLabel} className={cn("inline-flex gap-0.5 rounded-lg bg-muted p-[3px]", className)}>
      {items.map((it) => {
        const on = it.value === value;
        return (
          <button
            key={it.value}
            type="button"
            aria-pressed={on}
            onClick={() => onChange(it.value)}
            className={cn(
              "inline-flex h-7 cursor-pointer items-center gap-[5px] whitespace-nowrap rounded-md px-2.5 text-[13px] transition-colors",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50",
              on ? "bg-card font-bold text-foreground shadow-[0_1px_2px_rgba(145,158,171,0.24)]" : "font-medium text-muted-foreground hover:text-foreground",
            )}
          >
            {it.label}
            {it.count != null && it.count !== "" && <span className="text-muted-foreground">{it.count}</span>}
          </button>
        );
      })}
    </div>
  );
}
