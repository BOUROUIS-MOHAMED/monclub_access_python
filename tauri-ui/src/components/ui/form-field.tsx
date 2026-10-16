// Access v5 dialog form field (the design's `R.field`): a 46 px outlined box,
// the label sitting on its top border, the control inside without its own
// border. Two per row inside <FieldGrid>; `full` spans the row.
//   <FieldGrid>
//     <FieldSection>Identité</FieldSection>
//     <FormField label="Prénom"><FieldInput value… onChange… /></FormField>
//     <FormField label="Abonnement" full><Select>…<FieldSelectTrigger/>…</Select></FormField>
//   </FieldGrid>
import * as React from "react";
import { Input } from "@/components/ui/input";
import { SelectTrigger } from "@/components/ui/select";
import { cn } from "@/lib/utils";

export function FieldGrid({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("grid grid-cols-2 gap-x-3.5", className)} {...props} />;
}

export function FieldSection({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("col-span-full pb-0.5 pt-4 text-[12px] font-bold uppercase tracking-[0.04em] text-muted-foreground first:pt-1", className)}>
      {children}
    </div>
  );
}

export function FormField({ label, full, addon, className, children }: {
  label: React.ReactNode; full?: boolean;
  /** Small button inside the box on the right (« Scanner »). */
  addon?: React.ReactNode;
  className?: string; children: React.ReactNode;
}) {
  // A <label>: names the control inside it and focuses it on a click in the box.
  return (
    <label
      className={cn(
        "relative mt-3 flex h-[46px] items-center gap-2 rounded-lg border border-grey/32 px-3 transition-colors focus-within:border-primary",
        full && "col-span-full",
        className,
      )}
    >
      <span className="pointer-events-none absolute -top-[9px] left-[9px] bg-card px-1 text-[12px] font-semibold leading-[18px] text-muted-foreground">
        {label}
      </span>
      <div className="min-w-0 flex-1">{children}</div>
      {addon}
    </label>
  );
}

/** Borderless input for inside a FormField. */
export const FieldInput = React.forwardRef<HTMLInputElement, React.ComponentProps<"input">>(
  ({ className, ...props }, ref) => (
    <Input
      ref={ref}
      className={cn("h-8 rounded-none border-0 bg-transparent px-0 text-[13.5px] shadow-none focus-visible:ring-0", className)}
      {...props}
    />
  ),
);
FieldInput.displayName = "FieldInput";

/** Borderless select trigger for inside a FormField. */
export const FieldSelectTrigger = React.forwardRef<
  React.ComponentRef<typeof SelectTrigger>,
  React.ComponentPropsWithoutRef<typeof SelectTrigger>
>(({ className, ...props }, ref) => (
  <SelectTrigger
    ref={ref}
    className={cn("h-8 rounded-none border-0 bg-transparent px-0 text-[13.5px] shadow-none focus:ring-0", className)}
    {...props}
  />
));
FieldSelectTrigger.displayName = "FieldSelectTrigger";
