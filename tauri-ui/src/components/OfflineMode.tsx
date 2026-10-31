import { useEffect, useRef, useState } from "react";
import { LockKeyhole, WifiOff } from "lucide-react";
import { ApiError, post } from "@/api/client";
import type { StaffBlock } from "@/api/types";
import { ActionButton } from "@/components/ui/action-button";
import { DialogFrame } from "@/components/ui/dialog-frame";
import { Note } from "@/components/ui/panel";
import { Avatar } from "@/components/ui/chip";
import { initialsOf } from "@/components/ui/tone";
import { showStaffToast } from "@/components/Toast";
import { staffError } from "@/components/StaffChip";
import { Switch } from "@/components/ui/switch";
import { useApp } from "@/context/AppContext";

function openOfflineDialog(name: string) {
  window.dispatchEvent(new CustomEvent("offline-dialog", { detail: name }));
}

export function OfflineBanner({ staff }: { staff?: StaffBlock }) {
  const off = staff?.offline;
  if (!staff?.enabled || !off) return null;
  const pendingError = off.pending.lastError === "UNKNOWN_AGENT" ? "La personne choisie n'est plus autorisée. Vérifiez dans le tableau de bord."
    : off.pending.lastError === "UNKNOWN_PC" ? "Ce poste doit être enregistré dans le tableau de bord."
    : off.pending.lastError;
  if (!off.active) return pendingError ? <div role="status" className="border-b border-warning/24 bg-warning/16 px-6 py-3 text-[13px] text-warning-ink"><strong>{off.pending.count} modification(s) attendent leur envoi pour validation.</strong><div className="mt-1">{pendingError}</div></div> : null;
  const reader = off.role !== "DRIVER" && off.role !== "ALL_TURNSTILES";
  return <div className="flex flex-wrap items-center gap-3 border-b border-warning/24 bg-warning/16 px-6 py-3 text-[13px] text-warning-ink" role="status">
    <WifiOff className="h-5 w-5 shrink-0" />
    <div className="min-w-[240px] flex-1">
      <div className="font-bold">{reader ? `Hors ligne – utilisez le PC pilote (${off.driverName || "nom indisponible"}) pour les modifications` : "Hors ligne – vos modifications seront validées dans le tableau de bord."}</div>
      <div className="mt-0.5 text-[12.5px]">{reader ? "La recherche de membres reste disponible sur ce poste." : "La porte, les empreintes et les cartes continuent de fonctionner avec les données déjà sur le tourniquet."}</div>
      {off.pending.count > 0 && <div className="mt-1 text-[12px]">{off.pending.count} modification(s) à envoyer pour validation.</div>}
      {pendingError && <div className="mt-1 text-[12px] text-error-ink">{pendingError}</div>}
    </div>
    {!reader && <div className="flex flex-wrap items-center gap-2.5">
      {off.unlocked && <span>Porte {Math.max(0, off.limits.door.max - off.limits.door.used)}/{off.limits.door.max} · Argent {Math.max(0, off.limits.money.max - off.limits.money.used)}/{off.limits.money.max} restantes</span>}
      <ActionButton size="sm" kind="ghost" onClick={() => openOfflineDialog("rules")}>Règles</ActionButton>
      {!off.unlocked && <ActionButton size="sm" kind="dark" icon={LockKeyhole} onClick={() => openOfflineDialog("unlock")}>Déverrouiller</ActionButton>}
    </div>}
  </div>;
}

export default function OfflineControls({ staff }: { staff?: StaffBlock }) {
  const { refreshStatus } = useApp();
  const off = staff?.offline;
  const [modal, setModal] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [limit, setLimit] = useState<{ category?: string; used?: number; max?: number }>({});
  const previousPeriod = useRef<string | null>(null);
  const lastUpload = useRef<string | null | undefined>(undefined);
  const reader = off?.role !== "DRIVER" && off?.role !== "ALL_TURNSTILES";
  useEffect(() => {
    const receive = (event: Event) => { setModal((event as CustomEvent<string>).detail); setError(""); setCode(""); };
    const reached = (event: Event) => { setLimit((event as CustomEvent).detail || {}); setModal("limit"); };
    window.addEventListener("offline-dialog", receive);
    window.addEventListener("offline-limit", reached);
    return () => { window.removeEventListener("offline-dialog", receive); window.removeEventListener("offline-limit", reached); };
  }, []);
  useEffect(() => {
    if (staff?.enabled && off?.active && off.since !== previousPeriod.current) {
      previousPeriod.current = off.since;
      setModal(reader ? null : "rules"); setCode(""); setError("");
    }
    if (!staff?.enabled || !off?.active) { previousPeriod.current = null; setModal(null); setCode(""); setError(""); }
  }, [staff?.enabled, off?.active, off?.since, reader]);
  useEffect(() => {
    const upload = off?.lastUpload;
    if (!staff?.enabled || !off) return;
    if (lastUpload.current === undefined) { lastUpload.current = upload?.at ?? null; return; }
    if (upload && upload.at !== lastUpload.current) {
      lastUpload.current = upload.at;
      showStaffToast(`Connexion rétablie – ${upload.count} modifications envoyées pour validation`, "Elles attendent une décision dans le tableau de bord.");
    }
  }, [staff?.enabled, off]);
  if (!staff?.enabled || !off) return null;
  const control = async (action: string, body?: unknown) => {
    if (busy) return;
    setBusy(true); setError("");
    try {
      await post(`/offline/${action}`, body);
      await refreshStatus();
      if (action === "unlock") setModal("act-as");
      if (action === "act-as") setModal(null);
      if (action === "lock") setModal("unlock");
    } catch (e) {
      if (e instanceof ApiError && e.code === "WRONG") setError(`Code incorrect – ${e.payload?.remaining} essais restants`);
      else if (e instanceof ApiError && e.code === "LOCKED") setError("Trop d'essais – réessayez dans 5 min");
      else if (e instanceof ApiError && e.code === "NO_CODE") setError("Aucun code défini. Demandez à l'administrateur de le définir dans le tableau de bord.");
      else setError(staffError(e));
      if (action === "manual") setModal("error");
      await refreshStatus();
    } finally { setBusy(false); if (action === "unlock") setCode(""); }
  };
  const locked = off.lock.lockedSeconds > 0;
  const readyToChoose = off.unlocked;
  return <>
    {!reader && <label className="inline-flex shrink-0 cursor-pointer items-center gap-2 rounded-lg bg-grey/12 px-2.5 py-2 text-[12.5px] font-semibold text-muted-foreground">
      <WifiOff className="h-4 w-4" />
      <span className="hidden lg:inline">Mode hors ligne</span>
      <Switch aria-label="Mode hors ligne" className="data-[state=checked]:bg-warning" checked={off.manual} disabled={busy} onCheckedChange={(on) => void control("manual", { on })} />
    </label>}
    {off.active && <div className="inline-flex max-w-[360px] shrink-0 items-center gap-2 rounded-lg bg-warning/16 px-2.5 py-2 text-[12.5px] font-bold text-warning-ink">
      <button type="button" disabled={reader || busy} onClick={() => { setError(""); setCode(""); setModal(readyToChoose ? "act-as" : "unlock"); }} className="truncate rounded focus-visible:ring-2 focus-visible:ring-primary">
        {reader ? "Hors ligne · lecteur" : off.actAs ? `Hors ligne · Agir en tant que ${off.actAs.name}` : "Hors ligne · verrouillé"}
      </button>
      {off.actAs && <button type="button" disabled={busy} onClick={() => void control("lock")} className="rounded text-[12px] font-semibold underline focus-visible:ring-2 focus-visible:ring-primary">Changer</button>}
    </div>}
    <DialogFrame open={modal !== null} onOpenChange={(open) => { if (!open && !busy) { setModal(null); setCode(""); setError(""); } }} width={modal === "rules" ? 680 : modal === "act-as" ? 600 : 480}
      title={modal === "unlock" ? "Déverrouiller le mode hors ligne" : modal === "act-as" ? "Agir en tant que" : modal === "limit" ? "Limite atteinte pour aujourd'hui" : modal === "error" ? "Mode hors ligne" : "Vous êtes hors ligne"}
      sub={modal === "unlock" ? "Entrez le code hors ligne à 6 chiffres défini dans le tableau de bord." : modal === "act-as" ? "Les modifications porteront le nom de la personne choisie, avec ses permissions." : undefined} lockOutside
      footer={modal === "rules" || modal === "limit" || modal === "error" ? <ActionButton kind="dark" onClick={() => setModal(null)}>J'ai compris</ActionButton> : <><ActionButton disabled={busy} onClick={() => { setModal(null); setCode(""); setError(""); }}>Annuler</ActionButton>{modal === "unlock" && off.codeSet && !locked && <ActionButton kind="dark" disabled={busy || code.length !== 6} onClick={() => void control("unlock", { code })}>Déverrouiller</ActionButton>}</>}>
      {modal === "unlock" && (!off.codeSet ? <Note tone="warning">Le mode hors ligne a besoin d'un code défini par l'administrateur dans le tableau de bord. La porte continue de fonctionner.</Note> : <>
        <div className="relative my-4 rounded-lg focus-within:ring-2 focus-within:ring-primary">
          <div className="flex justify-center gap-2" aria-hidden="true">{Array.from({ length: 6 }, (_, i) => <span key={i} className="grid h-14 w-11 place-items-center rounded-lg border border-grey/32 bg-muted/40 font-mono text-2xl">{code[i] || ""}</span>)}</div>
          <input autoFocus type="text" inputMode="numeric" pattern="[0-9]{6}" autoComplete="off" aria-label="Code hors ligne à six chiffres" maxLength={6} value={code} disabled={busy || locked}
            onChange={(e) => { setCode(e.target.value.replace(/\D/g, "").slice(0, 6)); setError(""); }} onKeyDown={(e) => { if (e.key === "Enter" && code.length === 6 && !busy && !locked) void control("unlock", { code }); }}
            className="absolute inset-0 h-full w-full cursor-text rounded-lg opacity-[0.01] focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary" />
        </div>
        {locked && <Note tone="grey">Trop d'essais – réessayez dans {Math.ceil(off.lock.lockedSeconds / 60)} min.</Note>}
      </>)}
      {modal === "act-as" && <div className="grid grid-cols-2 gap-2.5 pb-3 sm:grid-cols-5">{staff.allowedAgents.map((person) => <button type="button" key={person.id} disabled={busy || !readyToChoose} onClick={() => void control("act-as", { agentId: person.id })}
        className="flex w-full flex-col items-center gap-2 rounded-xl border border-grey/24 px-2 py-3.5 text-center hover:border-primary focus-visible:ring-2 focus-visible:ring-primary disabled:opacity-50">
        <Avatar initials={initialsOf(person.name)} tone={person.adminAgent ? "error" : "primary"} size={56} className="h-[46px] w-[46px] text-[16px]" /><span><span className="block text-[14px] font-bold">{person.name}</span><span className="text-[12px] text-muted-foreground">{person.adminAgent ? "Admin" : "Agent"}</span></span>
      </button>)}{!staff.allowedAgents.length && <Note tone="warning">Aucun membre du personnel autorisé dans la copie locale.</Note>}</div>}
      {modal === "rules" && <div className="space-y-4 pb-3 text-[13px]">
        <Note tone="warning"><strong>En attente de validation</strong><div className="mt-2 grid grid-cols-2 gap-2">{["Nouveaux membres", "Renouvellements", "Paiements", "Gel", "Suppression", "Modification des dates", "Empreintes", "Cartes"].map((label) => <span key={label}>{label}</span>)}</div></Note>
        <p>Un membre vendu hors ligne aura accès après validation dans le tableau de bord.</p>
        {(["door", "money"] as const).map((key) => { const lim = off.limits[key]; return <div key={key}><div className="mb-2 flex justify-between"><span>{key === "door" ? "Modifications de porte" : "Opérations d'argent"}</span><strong>{Math.max(0, lim.max - lim.used)} sur {lim.max} restantes</strong></div><progress aria-label={key === "door" ? "Porte restantes" : "Argent restantes"} className="h-2 w-full accent-warning" max={Math.max(1, lim.max)} value={Math.max(0, lim.max - lim.used)} /></div>; })}
        <Note tone="grey">La porte s'ouvre toujours, même à la limite.</Note>
      </div>}
      {modal === "limit" && <div className="space-y-3 pb-3 text-[13px]"><Note tone="warning">{limit.category === "DOOR" ? "Porte" : "Argent"} : {limit.used ?? limit.max ?? "—"}/{limit.max ?? "—"} opérations utilisées aujourd'hui. Utilisez le tableau de bord pour continuer.</Note><p>La porte s'ouvre toujours, même à la limite.</p></div>}
      {error && <div role="alert"><Note tone="error" className="mb-3">{error}</Note></div>}
    </DialogFrame>
  </>;
}
