// Access v5 dialog frame (the design's modal): title 18/700 + muted sub, an
// optional tab strip, a scrolling body, a dashed footer with the actions.
//   <DialogFrame open onOpenChange title sub width tabs={<LineTabs size="dialog" …/>} footer={…}>
//     body
//   </DialogFrame>
//   <DialogSection>  small grey section title inside the body ("Blocage de ré-entrée")
//   <DialogRow>      label + hint on the left, controls on the right, dashed divider
// Built on the shadcn Dialog (which the TV build also uses) through className
// overrides only, so the TV look is untouched.
import * as React from "react";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import { INK, type Tone } from "./tone";

export function DialogFrame({
  open, onOpenChange, title, sub, width = 480, tabs, footer, children, bodyClassName,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: React.ReactNode;
  sub?: React.ReactNode;
  width?: number;
  tabs?: React.ReactNode;
  footer?: React.ReactNode;
  children?: React.ReactNode;
  bodyClassName?: string;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="flex max-h-[88vh] flex-col gap-0 overflow-hidden rounded-2xl border-0 bg-card p-0 text-card-foreground shadow-[var(--shadow-dialog)] sm:rounded-2xl"
        style={{ maxWidth: width }}
      >
        <div className="flex-none px-[22px] pb-1.5 pr-12 pt-[18px]">
          <DialogTitle className="m-0 text-[18px] font-bold leading-snug tracking-normal">{title}</DialogTitle>
          {sub != null && sub !== "" ? (
            <DialogDescription className="mt-0.5 text-[13.5px] text-muted-foreground">{sub}</DialogDescription>
          ) : (
            <DialogDescription className="sr-only">{typeof title === "string" ? title : ""}</DialogDescription>
          )}
        </div>
        {tabs && <div className="flex-none px-[22px] pt-1">{tabs}</div>}
        <div className={cn("min-h-0 flex-1 overflow-y-auto px-[22px] pb-1.5 pt-3", bodyClassName)}>{children}</div>
        {footer && (
          <div className="mt-2 flex flex-none flex-wrap items-center justify-end gap-2.5 border-t border-dashed border-grey/20 px-[22px] pb-[18px] pt-3.5">
            {footer}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

export function DialogSection({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("pb-1 pt-3.5 text-[12px] font-bold uppercase tracking-[0.04em] text-muted-foreground first:pt-0", className)}>
      {children}
    </div>
  );
}

export function DialogRow({ label, hint, labelTone, mono, children, className }: {
  label: React.ReactNode; hint?: React.ReactNode; labelTone?: Tone; mono?: boolean;
  children?: React.ReactNode; className?: string;
}) {
  return (
    <div className={cn("flex min-h-[48px] flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-dashed border-grey/20 py-2.5", className)}>
      <div className="min-w-[160px] flex-1">
        <div className={cn("text-[13.5px] font-semibold", labelTone ? INK[labelTone] : "text-foreground", mono && "font-mono font-medium")}>
          {label}
        </div>
        {hint != null && hint !== "" && <div className="mt-0.5 text-[12.5px] text-muted-foreground">{hint}</div>}
      </div>
      {children != null && <div className="flex flex-wrap items-center justify-end gap-1.5">{children}</div>}
    </div>
  );
}
