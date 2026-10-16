// P3b-2 (owner decision 3): after an enrolment, "Enregistré" and then each turnstile with the
// PC that puts the finger on it. No PC route reports a driver's push per turnstile, so a
// turnstile another PC drives stays "en attente du PC pilote" — never shown as done.
import { useEffect, useState } from "react";
import { Loader2, Router } from "lucide-react";

import { realtime, type EnrollTurnstile } from "@/api/realtime";
import { Chip } from "@/components/ui/chip";
import { ListRow, Panel, PanelHeader, PanelList } from "@/components/ui/panel";

export default function EnrollTurnstileStatus({ className }: { className?: string }) {
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
    return (
      <div className="flex items-center gap-2 text-[12.5px] text-muted-foreground">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />Tourniquets…
      </div>
    );
  }
  if (!rows.length) return null;
  return (
    <Panel className={className}>
      <PanelHeader
        title="Transmission aux tourniquets"
        sub={role === "READER"
          ? "Enregistré sur le serveur. Chaque PC pilote l'envoie aux tourniquets où l'abonnement donne accès, à sa prochaine synchronisation."
          : "Enregistré sur le serveur. Transmission aux tourniquets :"}
      />
      <PanelList>
        {rows.map((t) => {
          const mine = t.status === "THIS_PC";
          return (
            <ListRow
              key={t.gymDeviceId}
              icon={Router}
              tone={mine ? "success" : "warning"}
              title={t.name || `Tourniquet ${t.gymDeviceId}`}
              trailing={(
                <Chip tone={mine ? "success" : "warning"}>
                  {mine ? "envoyé par ce PC" : `en attente du PC pilote${t.driverPcName ? ` (${t.driverPcName})` : ""}`}
                </Chip>
              )}
            />
          );
        })}
      </PanelList>
    </Panel>
  );
}
