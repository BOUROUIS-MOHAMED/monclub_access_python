// Access v5 header filter: a select that looks like an outline ActionButton
// (« Statut : tous ▾ »). Used in the page header next to « Recharger ».
import type { LucideIcon } from "lucide-react";
import { Filter } from "lucide-react";
import { Select, SelectContent, SelectItem, SelectTrigger } from "@/components/ui/select";
import { cn } from "@/lib/utils";

export function FilterSelect<T extends string>({ label, value, options, onChange, icon: Icon = Filter, className }: {
  /** « Statut » → the trigger reads « Statut : Réussi ». */
  label: string;
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
  icon?: LucideIcon;
  className?: string;
}) {
  const current = options.find((o) => o.value === value)?.label ?? value;
  return (
    <Select value={value} onValueChange={(v) => onChange(v as T)}>
      <SelectTrigger
        aria-label={label}
        className={cn(
          "h-9 w-auto gap-[7px] rounded-lg border-grey/32 bg-card px-3 text-[14px] font-bold text-foreground shadow-none hover:bg-muted",
          className,
        )}
      >
        <Icon className="h-[17px] w-[17px] shrink-0" aria-hidden="true" />
        <span className="whitespace-nowrap">{label} : {current}</span>
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
      </SelectContent>
    </Select>
  );
}
