import { useEffect, useState } from "react";
import { post } from "@/api/client";
import type { StaffBlock, StaffMember } from "@/api/types";
import { ActionButton } from "@/components/ui/action-button";
import { DialogFrame } from "@/components/ui/dialog-frame";
import { FieldGrid, FieldInput, FormField } from "@/components/ui/form-field";
import { Note } from "@/components/ui/panel";
import { staffError, staffPermissionHint, staffResultUnknown } from "@/components/StaffChip";
import { StaffPaymentFields, staffDate, staffEmptyPayment, staffMoney, staffPaymentPayload, staffPaymentValid, staffToday } from "@/components/PayRestDialog";
import { showStaffToast } from "@/components/Toast";
import { cn } from "@/lib/utils";

export type StaffPlan = { id: number | string; title?: string; price?: number | string };
type StaffRenewalKind = "QUEUED" | "START_TODAY" | "AFTER_EXPIRY";
type StaffDebtTerm = { termId: number; seq: number; planTitle: string; rest: number; dueDate: string | null; suggestedDueDate: string | null };
type StaffRenewalQuote = {
  allowedKinds: StaffRenewalKind[]; renewalKind: StaffRenewalKind;
  currentEffectiveEnd: string | null; startDate: string; endDate: string; logicalStartDate: string; newEffectiveEnd: string;
  forfeitedDays: number; outstanding: { amount: number; dueDate: string | null } | null;
  defaultDueDate: string | null; dueDateMin: string | null; dueDateMax: string | null;
  termsAuthoritative: boolean; startInsideCurrentPeriod: boolean; daysWithoutAccess: number | null;
  doorCoverageLoss: { turnstiles: { id: number; name: string }[]; gyms: { id: number; name: string }[] };
  debt: { keepAvailable: boolean; terms: StaffDebtTerm[] };
};
const STAFF_KINDS: { value: StaffRenewalKind; label: string }[] = [
  { value: "QUEUED", label: "À la suite" }, { value: "START_TODAY", label: "Commence aujourd'hui" }, { value: "AFTER_EXPIRY", label: "Après expiration" },
];
const STAFF_PREVIEW = { QUEUED: "À la suite de l'abonnement actuel", START_TODAY: "Commence aujourd'hui", AFTER_EXPIRY: "Après expiration" };
function staffShiftDay(date: string, days: number) {
  const parsed = new Date(`${date.slice(0, 10)}T12:00:00`);
  parsed.setDate(parsed.getDate() + days);
  return `${parsed.getFullYear()}-${String(parsed.getMonth() + 1).padStart(2, "0")}-${String(parsed.getDate()).padStart(2, "0")}`;
}

type RenewDialogProps = {
  member: StaffMember; plans: StaffPlan[]; staff?: StaffBlock; gymDate?: string | null;
  onClose: () => void; onSuccess: () => void;
};

export default function RenewDialog(props: RenewDialogProps) {
  return props.staff?.enabled && props.staff.offline?.active ? <OfflineRenewDialog {...props} /> : <OnlineRenewDialog {...props} />;
}

function OfflineRenewDialog({ member, plans, staff, onClose, onSuccess }: RenewDialogProps) {
  const initial = plans.find((p) => String(p.id) === String(member.membershipId)) || plans[0];
  const [planId, setPlanId] = useState(String(initial?.id || ""));
  const [price, setPrice] = useState(String(initial?.price ?? ""));
  const [paid, setPaid] = useState(String(initial?.price ?? ""));
  const [payment, setPayment] = useState(staffEmptyPayment);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [requestId] = useState(() => crypto.randomUUID());
  const hint = staffPermissionHint(staff, "ACTIVE_MEMBERSHIP_RENEWAL", "Renouveler");
  const limit = staff?.offline?.limits.money;
  const amount = Number(paid), cost = Number(price);
  const valid = !hint && !!planId && price !== "" && paid !== "" && Number.isFinite(amount) && Number.isFinite(cost)
    && amount >= 0 && cost >= amount && (amount === 0 || staffPaymentValid(payment));
  const submit = async () => {
    if (!valid || busy) return;
    setBusy(true); setError("");
    try {
      await post("/members/renew", { activeMembershipId: Number(member.activeMembershipId), membership_id: Number(planId),
        price: cost, payedPrice: amount, ...staffPaymentPayload(payment), clientRequestId: requestId });
      showStaffToast("Renouvellement enregistré pour validation", `${member.fullName} · ${staffMoney(amount)} DT · dates calculées à la validation`);
      onSuccess(); onClose();
    } catch (e) { setError(staffError(e)); } finally { setBusy(false); }
  };
  return <DialogFrame open onOpenChange={(open) => { if (!open && !busy) onClose(); }} title="Renouveler · hors ligne" sub={member.fullName} width={590} lockOutside
    footer={<><span className="mr-auto text-[12.5px] text-muted-foreground">Argent : {limit ? Math.max(0, limit.max - limit.used) : 0} sur {limit?.max ?? 0} restantes</span><ActionButton disabled={busy} onClick={onClose}>Annuler</ActionButton><ActionButton kind="primary" disabled={!valid || busy} onClick={() => void submit()}>{busy ? "Enregistrement…" : `Enregistrer pour validation · ${staffMoney(amount || 0)} DT`}</ActionButton></>}>
    <fieldset disabled={busy} className="min-w-0 space-y-3 pb-3">
      <legend className="sr-only">Renouvellement hors ligne</legend>
      <div className="grid gap-2 sm:grid-cols-3" role="radiogroup" aria-label="Abonnement">{plans.map((plan) => <button key={plan.id} type="button" role="radio" aria-checked={String(plan.id) === planId}
        className={cn("rounded-[10px] border p-3 text-left text-[13px] focus-visible:ring-2 focus-visible:ring-primary", String(plan.id) === planId ? "border-primary bg-primary/8" : "border-grey/32")}
        onClick={() => { setPlanId(String(plan.id)); setPrice(String(plan.price ?? "")); setPaid(String(plan.price ?? "")); }}><div className="font-bold">{plan.title || `Abonnement ${plan.id}`}</div><div className="mt-1 text-muted-foreground">{plan.price == null ? "Prix à renseigner" : `${staffMoney(Number(plan.price))} DT`}</div></button>)}</div>
      {!plans.length && <Note tone="warning">Aucun abonnement disponible dans la copie locale.</Note>}
      <FieldGrid><FormField label="Prix (DT)"><FieldInput type="number" min="0" step="0.001" value={price} onChange={(e) => setPrice(e.target.value)} /></FormField><FormField label="Payé maintenant (DT)"><FieldInput type="number" min="0" step="0.001" max={price} value={paid} onChange={(e) => setPaid(e.target.value)} /></FormField><StaffPaymentFields value={payment} onChange={setPayment} disabled={busy} /></FieldGrid>
      <Note tone="warning">Hors ligne : les dates seront calculées à la validation dans le tableau de bord.</Note>
      <p className="text-[13px] text-muted-foreground">Ces questions seront posées à la personne qui valide : la dette, et l'accès entre deux périodes.</p>
      {(hint || error) && <Note tone="error">{hint || error}</Note>}
    </fieldset>
  </DialogFrame>;
}

function OnlineRenewDialog({ member, plans, staff, gymDate, onClose, onSuccess }: RenewDialogProps) {
  const today = gymDate || staffToday();
  const initialPlan = plans.find((p) => String(p.id) === String(member.membershipId)) || plans[0];
  const [planId, setPlanId] = useState(String(initialPlan?.id || ""));
  const [price, setPrice] = useState(String(initialPlan?.price ?? ""));
  const [paid, setPaid] = useState(String(initialPlan?.price ?? ""));
  const [payment, setPayment] = useState(staffEmptyPayment);
  const [kind, setKind] = useState<StaffRenewalKind | null>(null);
  const [startDate, setStartDate] = useState(today);
  const [dueDate, setDueDate] = useState("");
  const [debtChoice, setDebtChoice] = useState<"KEEP" | "FORGIVE" | null>(null);
  const [keptDates, setKeptDates] = useState<Record<string, string>>({});
  const [ackDoorLoss, setAckDoorLoss] = useState(false);
  const [ackStartInside, setAckStartInside] = useState(false);
  const [answer, setAnswer] = useState<{ key: string; quote: StaffRenewalQuote } | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [resultUnknown, setResultUnknown] = useState(false);
  const [error, setError] = useState("");
  const [requestId] = useState(() => crypto.randomUUID());
  const requestKey = JSON.stringify([member.activeMembershipId, planId, kind, kind === "AFTER_EXPIRY" ? startDate : null, refresh]);
  const quote = answer?.key === requestKey ? answer.quote : null;
  const hint = staff?.enabled ? staffPermissionHint(staff, "ACTIVE_MEMBERSHIP_RENEWAL", "Renouveler") : "La connexion du personnel est désactivée.";
  const forgiveHint = staffPermissionHint(staff, "ACTIVE_MEMBERSHIP_DEBT_FORGIVE", "Effacer une dette");

  useEffect(() => {
    if (!planId) return;
    let active = true;
    setError(""); setAckDoorLoss(false); setAckStartInside(false); setDebtChoice(null); setKeptDates({});
    post<StaffRenewalQuote>("/members/renew/quote", {
      activeMembershipId: Number(member.activeMembershipId), membership_id: Number(planId),
      ...(kind ? { renewalKind: kind } : {}), ...(kind === "AFTER_EXPIRY" ? { startDate } : {}),
    }, 60_000).then((data) => {
      if (!active) return;
      setAnswer({ key: requestKey, quote: data });
      setDueDate(data.defaultDueDate || "");
    }).catch((e) => { if (active) setError(staffError(e)); });
    return () => { active = false; };
  }, [requestKey, member.activeMembershipId, planId, kind, startDate]);

  const terms = quote?.termsAuthoritative && quote.debt?.keepAvailable ? quote.debt.terms || [] : [];
  const owed = terms.length ? Math.round(terms.reduce((sum, term) => sum + Number(term.rest), 0) * 1000) / 1000 : Number(quote?.outstanding?.amount || 0);
  const needsDate = (term: StaffDebtTerm) => !term.dueDate || term.dueDate < today;
  const keptDate = (term: StaffDebtTerm) => keptDates[String(term.termId)] ?? term.suggestedDueDate ?? "";
  const invalidDebt = owed > 0 && (!debtChoice || (debtChoice === "FORGIVE" && !!forgiveHint) || (debtChoice === "KEEP" && (!quote?.debt?.keepAvailable || terms.some((t) => needsDate(t) && (!keptDate(t) || keptDate(t) < today)))));
  const lostDoors = [...(quote?.doorCoverageLoss?.turnstiles || []), ...(quote?.doorCoverageLoss?.gyms || [])];
  const gapStart = quote?.startInsideCurrentPeriod ? today : quote?.currentEffectiveEnd ? staffShiftDay(quote.currentEffectiveEnd, 1) : today;
  const gapEnd = quote ? staffShiftDay(quote.logicalStartDate, -1) : "";
  const hasGap = !!quote && quote.renewalKind === "AFTER_EXPIRY" && gapStart <= gapEnd;
  const needsDoorAck = lostDoors.length > 0 || hasGap;
  const numericPrice = Number(price), numericPaid = Number(paid);
  const valid = !resultUnknown && !!quote && !hint && price !== "" && paid !== "" && Number.isFinite(numericPrice) && Number.isFinite(numericPaid)
    && numericPrice >= 0 && numericPaid >= 0 && numericPaid <= numericPrice && !invalidDebt
    && (!needsDoorAck || ackDoorLoss) && (!quote.startInsideCurrentPeriod || ackStartInside)
    && (numericPaid === 0 || staffPaymentValid(payment)) && (numericPaid >= numericPrice || !!dueDate);
  const submit = async () => {
    if (!valid || !quote || busy) return;
    setBusy(true); setError("");
    const plan = plans.find((p) => String(p.id) === planId);
    try {
      const result = await post<{ effectiveEndDate?: string; endDate?: string; keptAmount?: number; forgivenAmount?: number }>("/members/renew", {
        activeMembershipId: Number(member.activeMembershipId), membership_id: Number(planId),
        renewalKind: quote.renewalKind, ...(quote.renewalKind === "AFTER_EXPIRY" ? { startDate } : {}),
        price: numericPrice, payedPrice: numericPaid, quotedPlanPrice: plan?.price == null ? undefined : Number(plan.price),
        ...staffPaymentPayload(payment), paymentStatus: "COMPLETED", remainingPaymentDueDate: numericPaid < numericPrice ? dueDate : null,
        ...(owed > 0 ? { debtResolution: debtChoice } : {}),
        ...(terms.length ? { debtTermIds: terms.map((t) => t.termId), debtTotalSeen: owed } : {}),
        ...(debtChoice === "KEEP" ? { keptDueDates: Object.fromEntries(terms.filter(needsDate).map((t) => [String(t.termId), keptDate(t)])) } : {}),
        acknowledgeDoorLoss: ackDoorLoss, acknowledgeStartInsidePeriod: ackStartInside, clientRequestId: requestId,
      }, 60_000);
      const debtNote = Number(result.keptAmount) > 0 ? ` · dette de ${staffMoney(Number(result.keptAmount))} DT gardée` : Number(result.forgivenAmount) > 0 ? ` · dette de ${staffMoney(Number(result.forgivenAmount))} DT effacée` : "";
      showStaffToast(`${member.fullName} renouvelé(e) jusqu'au ${staffDate(result.effectiveEndDate || result.endDate || quote.newEffectiveEnd)}`,
        `Fait par ${staff?.agent?.name || ""} · ${staffMoney(numericPaid)} DT encaissés${debtNote}`);
      onSuccess(); onClose();
    } catch (e) { setError(staffError(e)); setResultUnknown(staffResultUnknown(e)); } finally { setBusy(false); }
  };

  return <DialogFrame open onOpenChange={(open) => { if (!open && !busy) onClose(); }} title="Renouveler" sub={member.fullName} width={590} lockOutside
    footer={<><span className="mr-auto text-[12.5px] text-muted-foreground">Fait par {staff?.agent?.name}</span><ActionButton disabled={busy} onClick={onClose}>Annuler</ActionButton><ActionButton kind="primary" disabled={!valid || busy} onClick={() => void submit()}>{busy ? "Renouvellement…" : `Renouveler · ${staffMoney(numericPrice || 0)} DT`}</ActionButton></>}>
    <fieldset disabled={busy} className="min-w-0 space-y-3">
      <legend className="sr-only">Abonnement et paiement</legend>
      <div className="grid gap-2 sm:grid-cols-3" role="radiogroup" aria-label="Abonnement">
        {plans.map((plan) => <button type="button" role="radio" aria-checked={String(plan.id) === planId} key={plan.id}
          className={cn("rounded-[10px] border p-3 text-left text-[13px] focus-visible:ring-2 focus-visible:ring-primary", String(plan.id) === planId ? "border-primary bg-primary/8" : "border-grey/32")}
          onClick={() => { setPlanId(String(plan.id)); setPrice(String(plan.price ?? "")); setPaid(String(plan.price ?? "")); }}>
          <div className="font-bold">{plan.title || `Abonnement ${plan.id}`}</div><div className="mt-1 text-muted-foreground">{plan.price == null ? "Prix à renseigner" : `${staffMoney(Number(plan.price))} DT`}</div>
        </button>)}
      </div>
      {!plans.length && <Note tone="warning">Aucun abonnement disponible. Synchronisez le catalogue.</Note>}
      <FieldGrid>
        <FormField label="Prix (DT)"><FieldInput type="number" min="0" step="0.001" value={price} onChange={(e) => setPrice(e.target.value)} /></FormField>
        <FormField label="Payé maintenant (DT)"><FieldInput type="number" min="0" max={price} step="0.001" value={paid} onChange={(e) => setPaid(e.target.value)} /></FormField>
        <StaffPaymentFields value={payment} onChange={setPayment} disabled={busy} />
        {numericPaid < numericPrice && <FormField label="Échéance du reste" full><FieldInput type="date" value={dueDate} min={quote?.dueDateMin || undefined} max={quote?.dueDateMax || undefined} onChange={(e) => setDueDate(e.target.value)} /></FormField>}
      </FieldGrid>
      <div className="flex flex-wrap gap-1 rounded-lg bg-muted p-1" aria-label="Début du renouvellement">
        {STAFF_KINDS.map((item) => <ActionButton key={item.value} size="xs" kind={(kind || quote?.renewalKind) === item.value ? "dark" : "ghost"} disabled={!quote || !quote.allowedKinds.includes(item.value)} onClick={() => setKind(item.value)}>{item.label}</ActionButton>)}
      </div>
      {kind === "AFTER_EXPIRY" && <FieldGrid><FormField label="Date de début souhaitée" full><FieldInput type="date" value={startDate} onChange={(e) => setStartDate(e.target.value)} /></FormField></FieldGrid>}
      {quote ? <Note tone="primary"><div className="font-semibold">{STAFF_PREVIEW[quote.renewalKind]} : du {staffDate(quote.logicalStartDate)} au {staffDate(quote.newEffectiveEnd)}</div>{quote.forfeitedDays > 0 && <div className="mt-1">{quote.forfeitedDays} jour(s) de l'abonnement actuel ne seront pas conservés.</div>}</Note> : !error && plans.length > 0 ? <div role="status" className="text-[13px] text-muted-foreground">Calcul des dates…</div> : null}
      {owed > 0 && <fieldset className="space-y-2 rounded-xl border border-grey/24 p-3">
        <legend className="px-1 text-[13px] font-bold">Dette de {staffMoney(owed)} DT sur l'abonnement actuel</legend>
        {(["KEEP", "FORGIVE"] as const).map((choice) => {
          const disabled = choice === "KEEP" ? !quote?.debt?.keepAvailable : !!forgiveHint;
          return <label key={choice} className={cn("flex cursor-pointer items-start gap-2.5 rounded-lg border p-3 text-[13px]", debtChoice === choice ? "border-primary bg-primary/8" : "border-grey/32", disabled && "cursor-not-allowed opacity-50")}>
            <input type="radio" className="mt-0.5 accent-primary" name="staff-debt" checked={debtChoice === choice} disabled={disabled} onChange={() => setDebtChoice(choice)} />
            <span><span className="font-semibold">{choice === "KEEP" ? "Garder la dette (avec une échéance)" : "Effacer la dette"}</span><span className="mt-0.5 block text-muted-foreground">{choice === "KEEP" ? (disabled ? "Indisponible pour cet abonnement" : "Les sommes restent dues à leurs échéances") : disabled ? "Nécessite : Effacer une dette" : "Cette somme ne sera plus demandée"}</span></span>
          </label>;
        })}
        {debtChoice === "KEEP" && terms.map((term) => <div key={term.termId} className="text-[12.5px] text-muted-foreground">
          Vente {term.seq} · {term.planTitle} · {staffMoney(Number(term.rest))} DT
          {needsDate(term) ? <FormField label="Échéance de la dette"><FieldInput type="date" min={today} value={keptDate(term)} onChange={(e) => setKeptDates((prev) => ({ ...prev, [term.termId]: e.target.value }))} /></FormField> : ` · échéance le ${staffDate(term.dueDate)}`}
        </div>)}
        {!debtChoice && <p className="text-[12.5px] text-warning-ink">Choisissez quoi faire de la dette pour continuer.</p>}
      </fieldset>}
      {needsDoorAck && <label className="flex cursor-pointer items-start gap-2.5 rounded-lg bg-warning/16 p-3 text-[13px] text-warning-ink"><input type="checkbox" className="mt-0.5 accent-primary" checked={ackDoorLoss} onChange={(e) => setAckDoorLoss(e.target.checked)} /><span>{hasGap ? `Je confirme : ${member.fullName} n'aura pas accès du ${staffDate(gapStart)} au ${staffDate(gapEnd)}.` : "Je confirme la perte d'accès aux portes suivantes."}{lostDoors.length > 0 && <span className="mt-1 block">Accès retirés : {lostDoors.map((door) => door.name).join(", ")}</span>}</span></label>}
      {quote?.startInsideCurrentPeriod && <label className="flex cursor-pointer items-start gap-2.5 rounded-lg bg-warning/16 p-3 text-[13px] text-warning-ink"><input type="checkbox" className="mt-0.5 accent-primary" checked={ackStartInside} onChange={(e) => setAckStartInside(e.target.checked)} /><span>Je confirme : l'abonnement en cours se termine aujourd'hui. Le membre attendra le début du nouvel abonnement.</span></label>}
    </fieldset>
    {(hint || error) && <Note tone="error" className="mt-3">{hint || error}</Note>}
    {resultUnknown && <Note tone="warning" className="mt-3">Le résultat du renouvellement est inconnu. Vérifiez l'abonnement et le paiement dans le tableau de bord avant toute nouvelle tentative.</Note>}
    {error && <ActionButton size="sm" className="mt-2" disabled={busy} onClick={() => setRefresh((n) => n + 1)}>Actualiser le devis</ActionButton>}
  </DialogFrame>;
}
