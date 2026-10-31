import { useEffect, useState } from "react";
import { CircleCheck, X } from "lucide-react";

type StaffToast = { title: string; message?: string };
export function showStaffToast(title: string, message?: string) {
  window.dispatchEvent(new CustomEvent<StaffToast>("staff-toast", { detail: { title, message } }));
}

export default function Toast() {
  const [toast, setToast] = useState<StaffToast | null>(null);
  useEffect(() => {
    const receive = (event: Event) => setToast((event as CustomEvent<StaffToast>).detail);
    window.addEventListener("staff-toast", receive);
    return () => window.removeEventListener("staff-toast", receive);
  }, []);
  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 5000);
    return () => window.clearTimeout(timer);
  }, [toast]);
  if (!toast) return null;
  return (
    <div role="status" className="fixed bottom-6 right-6 z-[100] flex max-w-[calc(100vw-3rem)] items-start gap-3 rounded-xl border border-grey/20 bg-card p-4 text-card-foreground shadow-[var(--shadow-dialog)] sm:w-[410px]">
      <CircleCheck className="mt-0.5 h-5 w-5 shrink-0 text-success-ink" />
      <div className="min-w-0 flex-1 text-[13px]"><div className="font-bold">{toast.title}</div>{toast.message && <div className="mt-1 text-muted-foreground">{toast.message}</div>}</div>
      <button type="button" aria-label="Fermer la notification" onClick={() => setToast(null)} className="rounded p-1 focus-visible:ring-2 focus-visible:ring-primary"><X className="h-4 w-4" /></button>
    </div>
  );
}
