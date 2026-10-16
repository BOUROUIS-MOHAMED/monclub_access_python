import { AlertTriangle } from "lucide-react";

import { ActionButton } from "@/components/ui/action-button";
import { usePcIdentity } from "@/context/PcIdentityContext";

export default function PcIdentityBanner() {
  const { requiresSetup, status, openSetup } = usePcIdentity();
  if (!requiresSetup) return null;

  const interrupted = status?.state === "revoked"
    || status?.state === "invalid_credentials"
    || status?.state === "invalid_token";

  return (
    <div
      role="status"
      className="mx-6 mt-3 flex shrink-0 items-center gap-3 rounded-[10px] bg-warning/16 px-3.5 py-2.5 text-[13.5px] text-warning-ink"
    >
      <AlertTriangle className="h-5 w-5 shrink-0" />
      <p className="m-0 min-w-0 flex-1 leading-normal">
        <strong className="font-bold">
          {interrupted ? "L’identité de ce PC doit être renouvelée." : "Ce PC n’est pas encore enregistré."}
        </strong>{" "}
        La télémétrie est suspendue, mais le contrôle d’accès et les portes restent opérationnels.
      </p>
      <ActionButton kind="warn" size="sm" onClick={openSetup} className="bg-card hover:bg-card/80">
        Configurer
      </ActionButton>
    </div>
  );
}
