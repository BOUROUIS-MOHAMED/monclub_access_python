// Access v5 KPI card: soft icon tile, grey label, Barlow value, one sub line.
import * as React from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { INK, type Tone } from "./tone";
import { ToneIcon } from "./chip";

export function KpiRow({ cols, className, ...props }: React.HTMLAttributes<HTMLDivElement> & { cols: 2 | 3 | 4 | 5 }) {
  const grid = { 2: "grid-cols-2", 3: "grid-cols-3", 4: "grid-cols-4", 5: "grid-cols-5" }[cols];
  return <div className={cn("grid gap-[18px]", grid, className)} {...props} />;
}

export function KpiCard({ label, value, sub, icon, tone = "grey", subTone, className }: {
  label: React.ReactNode; value: React.ReactNode; sub?: React.ReactNode;
  icon: LucideIcon; tone?: Tone; subTone?: Tone; className?: string;
}) {
  return (
    <div className={cn("flex min-w-0 items-center gap-3.5 rounded-2xl bg-card px-[18px] py-4 shadow-[var(--shadow-card)]", className)}>
      <ToneIcon icon={icon} tone={tone} size={44} />
      <div className="min-w-0">
        <div className="truncate text-[13px] text-muted-foreground">{label}</div>
        <div className="truncate font-num text-[24px] font-bold leading-[1.2] text-foreground">{value}</div>
        {sub != null && sub !== "" && (
          <div className={cn("truncate text-[12px]", subTone ? INK[subTone] : "text-muted-foreground")}>{sub}</div>
        )}
      </div>
    </div>
  );
}
