// P3b-2 (owner decision 3): after an enrolment, "Enregistré" and then each turnstile with the
// PC that puts the finger on it. No PC route reports a driver's push per turnstile, so a
// turnstile another PC drives stays "en attente du PC pilote" — never shown as done.
import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";

import { realtime, type EnrollTurnstile } from "@/api/realtime";

export default function EnrollTurnstileStatus() {
  const [rows, setRows] = useState<EnrollTurnstile[] | null>(null);
  const [role, setRole] = useState<string>("");

  useEffect(() => {
    let alive = true;
    realtime.enrollTurnstiles()
      .then((r) => { if (alive) { setRows(r.turnstiles || []); setRole(r.role); } })
      .catch(() => { if (alive) setRows([]); });
    return () => { alive = false; };
  }, []);

  if (rows === null) {
    return <div className="flex items-center gap-2 text-xs text-muted-foreground"><Loader2 className="h-3 w-3 animate-spin" />Tourniquets…</div>;
  }
  if (!rows.length) return null;
  return (
    <div className="rounded-md border p-2 text-xs">
      <div className="mb-1 font-semibold">Enregistré sur le serveur. Transmission aux tourniquets :</div>
      <ul className="space-y-0.5">
        {rows.map((t) => (
          <li key={t.gymDeviceId} className="flex justify-between gap-2">
            <span>{t.name || `Tourniquet ${t.gymDeviceId}`}</span>
            <span className="text-muted-foreground">
              {t.status === "THIS_PC"
                ? "envoyé par ce PC"
                : `en attente du PC pilote${t.driverPcName ? ` (${t.driverPcName})` : ""}`}
            </span>
          </li>
        ))}
      </ul>
      {role === "READER" && (
        <div className="mt-1 text-muted-foreground">
          Chaque PC pilote l'envoie aux tourniquets où l'abonnement donne accès, à sa prochaine synchronisation.
        </div>
      )}
    </div>
  );
}
