import { useState } from "react";
import { post } from "@/api/client";
import type { StaffBlock } from "@/api/types";
import { StaffActionButton, staffError } from "@/components/StaffChip";

export default function OfflineFingerprintDisable({ staff, activeMembershipId, fingerprintId }: {
  staff?: StaffBlock; activeMembershipId: number; fingerprintId?: number | null;
}) {
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");
  if (!staff?.enabled || !staff.offline?.active || !(activeMembershipId > 0) || !fingerprintId) return null;
  const disable = async () => {
    if (busy || saved) return;
    setBusy(true); setError("");
    try {
      await post(`/members/${activeMembershipId}/fingerprints/${fingerprintId}/disable-here`, {});
      setSaved(true);
    } catch (e) { setError(staffError(e)); }
    finally { setBusy(false); }
  };
  return <div className="text-right">
    <StaffActionButton staff={staff} permission="ACTIVE_MEMBERSHIP_FINGERPRINTS" permissionLabel="Empreintes"
      kind="outline" size="xs" disabled={busy || saved} onClick={() => void disable()}>
      {saved ? "Désactivée sur le tourniquet · en attente de validation" : busy ? "Enregistrement…" : "Désactiver ici"}
    </StaffActionButton>
    {error && <p role="alert" className="mt-1 max-w-[280px] text-[12px] text-error-ink">{error}</p>}
  </div>;
}
