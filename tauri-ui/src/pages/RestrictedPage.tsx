// Accès restreint — Access v3, screen 09b. Shown when the session or the club
// contract has lapsed. The refonte replaces the bullet list of reasons with one
// explained card per reason, and leaves a single action.
//
// The reason strings come from the backend as-is (app/ui/app.py
// `_restriction_reasons`) and are ALREADY full French sentences — e.g. "Votre
// session a expirée (dernière connexion il y a N jours). Veuillez vous
// reconnecter." So they are rendered verbatim; only the icon is derived, by
// looking for "session" / "contrat" in the text. Nothing is reworded, because
// rewording a reason we did not author risks changing what it actually says.

import { useApp } from "@/context/AppContext";
import { Button } from "@/components/ui/button";
import { TOPO_BACKGROUND_IMAGE } from "@/lib/topo";
import { ShieldX, LogIn, Clock, FileText, LifeBuoy } from "lucide-react";

function iconForReason(reason: string) {
  const r = reason.toLowerCase();
  if (r.includes("session") || r.includes("connexion") || r.includes("login")) return Clock;
  if (r.includes("contrat") || r.includes("contract")) return FileText;
  return ShieldX;
}

export default function RestrictedPage() {
  const { status, logout } = useApp();
  const reasons = status?.session?.reasons ?? [];

  return (
    <div className="relative flex h-screen items-center justify-center overflow-hidden bg-background p-4">
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.06] dark:opacity-[0.09] dark:invert"
        style={{ backgroundImage: TOPO_BACKGROUND_IMAGE, backgroundSize: "cover", backgroundPosition: "center" }}
      />

      <div className="relative w-[452px] rounded-3xl bg-card px-9 pb-[30px] pt-[34px] shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="mb-4 flex h-[60px] w-[60px] items-center justify-center rounded-3xl bg-primary/[0.09] text-primary">
            <ShieldX className="h-[30px] w-[30px]" />
          </div>
          <h2 className="mb-[9px] font-display text-[26px] font-extrabold leading-[1.1] tracking-[-0.025em] text-foreground">
            Accès suspendu
          </h2>
          <p className="max-w-[330px] text-[13.5px] leading-[1.6] text-muted-foreground">
            {reasons.length > 0
              ? "Le poste ne peut pas être utilisé pour le moment. Voici pourquoi :"
              : "Le poste ne peut pas être utilisé pour le moment."}
          </p>
        </div>

        {reasons.length > 0 && (
          <div className="mb-6 flex flex-col gap-2.5">
            {reasons.map((reason, i) => {
              const Icon = iconForReason(reason);
              return (
                <div
                  key={i}
                  className="flex items-start gap-[13px] rounded-[18px] border border-primary/20 bg-primary/[0.05] px-4 py-3.5"
                >
                  <span className="flex h-[34px] w-[34px] shrink-0 items-center justify-center rounded-[18px] bg-primary/[0.09] text-primary">
                    <Icon className="h-[18px] w-[18px]" />
                  </span>
                  <p className="min-w-0 flex-1 text-[12.5px] leading-[1.5] text-foreground">{reason}</p>
                </div>
              );
            })}
          </div>
        )}

        <Button
          onClick={logout}
          className="h-11 w-full justify-center gap-2 rounded-full text-[13.5px] font-bold shadow-[0_8px_20px_rgba(226,32,63,0.22)]"
        >
          <LogIn className="h-[17px] w-[17px]" />Se reconnecter
        </Button>

        <div className="mt-5 flex items-center justify-center gap-2">
          <LifeBuoy className="h-[15px] w-[15px] text-muted-foreground" />
          <span className="text-[11.5px] text-muted-foreground">
            Les portes continuent de fonctionner en mode hors ligne
          </span>
        </div>
      </div>
    </div>
  );
}
