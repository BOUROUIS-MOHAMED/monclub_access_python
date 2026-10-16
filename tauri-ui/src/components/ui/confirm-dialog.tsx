// Access v5 confirmation dialog: title 18/700, muted sub, optional body (a
// <Note>, fields…), dashed footer with "Annuler" + the confirm button.
// The confirm button does NOT close the dialog by itself: `onConfirm` decides
// (some callers close first, the tray quit keeps it open while the app stops).
import * as React from "react";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { cn } from "@/lib/utils";
import { ActionButton, type ActionKind } from "./action-button";

export function ConfirmDialog({
  open, onOpenChange, title, description, children, confirmLabel, confirmKind = "danger",
  onConfirm, cancelLabel = "Annuler", confirmDisabled, width = 460,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: React.ReactNode;
  description?: React.ReactNode;
  children?: React.ReactNode;
  confirmLabel: React.ReactNode;
  confirmKind?: ActionKind;
  onConfirm: () => void;
  cancelLabel?: React.ReactNode;
  confirmDisabled?: boolean;
  width?: number;
}) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent
        className="gap-0 overflow-hidden rounded-2xl border-0 bg-card p-0 text-card-foreground shadow-[var(--shadow-dialog)]"
        style={{ maxWidth: width }}
      >
        <div className="px-[22px] pb-1.5 pt-[18px]">
          <AlertDialogTitle className="m-0 text-[18px] font-bold leading-snug">{title}</AlertDialogTitle>
          {description != null && (
            <AlertDialogDescription className="mt-0.5 text-[13.5px] text-muted-foreground">
              {description}
            </AlertDialogDescription>
          )}
        </div>
        {children != null && <div className="px-[22px] pb-1.5 pt-2">{children}</div>}
        <div className={cn("mt-2 flex justify-end gap-2.5 border-t border-dashed border-grey/20 px-[22px] pb-[18px] pt-3.5")}>
          <AlertDialogCancel asChild>
            <ActionButton kind="outline" className="px-4">{cancelLabel}</ActionButton>
          </AlertDialogCancel>
          <ActionButton kind={confirmKind} className="px-4" onClick={onConfirm} disabled={confirmDisabled}>
            {confirmLabel}
          </ActionButton>
        </div>
      </AlertDialogContent>
    </AlertDialog>
  );
}
