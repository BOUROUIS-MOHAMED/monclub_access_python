import { AlertTriangle, MonitorCog } from "lucide-react";

import { Button } from "@/components/ui/button";
import { usePcIdentity } from "@/context/PcIdentityContext";

export default function PcIdentityBanner() {
  const { requiresSetup, status, openSetup } = usePcIdentity();
  if (!requiresSetup) return null;

  const interrupted = status?.state === "revoked"
    || status?.state === "invalid_credentials"
    || status?.state === "invalid_token";

  return (
    <div className="flex shrink-0 items-center gap-3 border-b border-amber-500/20 bg-amber-500/[0.08] px-6 py-2.5">
      <AlertTriangle className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
      <p className="min-w-0 flex-1 text-[12px] leading-5 text-amber-900 dark:text-amber-200">
        <span className="font-bold">
          {interrupted ? "L’identité de ce PC doit être renouvelée." : "Ce PC n’est pas encore enregistré."}
        </span>{" "}
        La télémétrie est suspendue, mais le contrôle d’accès et les portes restent opérationnels.
      </p>
      <Button variant="outline" size="sm" onClick={openSetup} className="h-8 shrink-0 gap-1.5 rounded-full bg-card">
        <MonitorCog className="h-3.5 w-3.5" />
        Configurer
      </Button>
    </div>
  );
}
