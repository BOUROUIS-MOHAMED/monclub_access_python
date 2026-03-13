import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const variantMap: Record<string, { className: string; dot: string }> = {
  online:  { className: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/30", dot: "bg-emerald-500" },
  syncing: { className: "bg-sky-500/15 text-sky-700 dark:text-sky-400 border-sky-500/30", dot: "bg-sky-500 animate-pulse" },
  offline: { className: "bg-zinc-500/15 text-zinc-600 dark:text-zinc-400 border-zinc-500/30", dot: "bg-zinc-400" },
  error:   { className: "bg-red-500/15 text-red-700 dark:text-red-400 border-red-500/30", dot: "bg-red-500" },
  idle:    { className: "bg-zinc-500/15 text-zinc-500 dark:text-zinc-400 border-zinc-500/30", dot: "bg-zinc-400" },
};

interface StatusChipProps { variant: string; label: string; className?: string }

export default function StatusChip({ variant, label, className }: StatusChipProps) {
  const v = variantMap[variant] ?? variantMap.idle;
  return (
    <Badge variant="outline" className={cn("gap-1.5 font-medium", v.className, className)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", v.dot)} />
      {label}
    </Badge>
  );
}

