import { useEffect, useState } from "react";
import { post } from "@/api/client";
import type { StaffBlock, StaffMember } from "@/api/types";
import { ActionButton } from "@/components/ui/action-button";
import { DialogFrame } from "@/components/ui/dialog-frame";
import { FieldGrid, FieldInput, FieldSelectTrigger, FormField } from "@/components/ui/form-field";
import { Select, SelectContent, SelectItem, SelectValue } from "@/components/ui/select";
import { Note } from "@/components/ui/panel";
import { staffError, staffPermissionHint, staffResultUnknown } from "@/components/StaffChip";
import { showStaffToast } from "@/components/Toast";

export const staffMoney = (amount: number) => new Intl.NumberFormat("fr-TN", { maximumFractionDigits: 3 }).format(amount);
const staffRemaining = (price: number, paid: number) => Math.max(0, Math.round(Number(price) * 1000) - Math.round(Number(paid) * 1000)) / 1000;
export const staffDate = (date?: string | null) => date?.slice(0, 10).split("-").reverse().join("/") || "—";
export const staffToday = () => {
  const date = new Date();
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
};

export type StaffPayment = { method: string; chequeNumber: string; chequeEnd: string; bankName: string; reference: string };
export const staffEmptyPayment = (): StaffPayment => ({ method: "CASH", chequeNumber: "", chequeEnd: "", bankName: "", reference: "" });
export function staffPaymentPayload(payment: StaffPayment) {
  return {
    paymentMethod: payment.method,
    cheque: payment.method === "CHEQUE" ? { chequeNumber: payment.chequeNumber, endDate: `${payment.chequeEnd}T00:00:00`, bankName: payment.bankName } : null,
    bankTransfer: payment.method === "BANK_TRANSFER" ? { type: "VIREMENT", bankName: payment.bankName, transferReference: payment.reference } : null,
  };
}
export function staffPaymentValid(payment: StaffPayment) {
  return payment.method !== "CHEQUE" || (!!payment.chequeNumber.trim() && !!payment.chequeEnd);
}
export function StaffPaymentFields({ value, onChange, disabled }: { value: StaffPayment; onChange: (payment: StaffPayment) => void; disabled?: boolean }) {
  const set = (patch: Partial<StaffPayment>) => onChange({ ...value, ...patch });
  return <>
    <FormField label="Mode de paiement" full><Select disabled={disabled} value={value.method} onValueChange={(method) => set({ method })}>
      <FieldSelectTrigger><SelectValue /></FieldSelectTrigger><SelectContent>
        {[["CASH", "Espèces"], ["TPE", "Carte bancaire"], ["BANK_TRANSFER", "Virement"], ["CHEQUE", "Chèque"], ["BALANCE", "Solde du membre"]].map(([id, label]) => <SelectItem key={id} value={id}>{label}</SelectItem>)}
      </SelectContent></Select></FormField>
    {value.method === "CHEQUE" && <>
      <FormField label="N° de chèque"><FieldInput disabled={disabled} value={value.chequeNumber} onChange={(e) => set({ chequeNumber: e.target.value })} /></FormField>
      <FormField label="Échéance du chèque"><FieldInput disabled={disabled} type="date" value={value.chequeEnd} onChange={(e) => set({ chequeEnd: e.target.value })} /></FormField>
    </>}
    {["CHEQUE", "BANK_TRANSFER"].includes(value.method) && <FormField label="Banque (facultatif)" full><FieldInput disabled={disabled} value={value.bankName} onChange={(e) => set({ bankName: e.target.value })} /></FormField>}
    {value.method === "BANK_TRANSFER" && <FormField label="Référence du virement (facultatif)" full><FieldInput disabled={disabled} value={value.reference} onChange={(e) => set({ reference: e.target.value })} /></FormField>}
  </>;
}

type StaffPaymentDetails = {
  membership: { price: number; payedPrice: number; outstandingTotal?: number; remainingPaymentDueDate?: string | null };
  terms: { authoritative: boolean; terms: { termId: number; seq: number; planTitle: string; price: number; payedPrice: number; remainingPaymentDueDate?: string | null; debtState: string }[] };
};

export default function PayRestDialog({ member, staff, onClose, onSuccess }: {
  member: StaffMember; staff?: StaffBlock; onClose: () => void; onSuccess: () => void;
}) {
  const [details, setDetails] = useState<StaffPaymentDetails | null>(null);
  const [termId, setTermId] = useState<number | null>(null);
  const [amount, setAmount] = useState("");
  const [dueDate, setDueDate] = useState("");
  const [payment, setPayment] = useState(staffEmptyPayment);
  const [busy, setBusy] = useState(false);
  const [resultUnknown, setResultUnknown] = useState(false);
  const [error, setError] = useState("");
  const [requestId] = useState(() => crypto.randomUUID());
  const hint = staff?.enabled ? staffPermissionHint(staff, "ACTIVE_MEMBERSHIP_PAY_REMAINING", "Payer le reste") : "La connexion du personnel est désactivée.";
  useEffect(() => {
    let active = true;
    post<StaffPaymentDetails>("/members/pay-rest/details", { activeMembershipId: Number(member.activeMembershipId) }, 60_000)
      .then((data) => {
        if (!active) return;
        setDetails(data);
        const terms = data.terms.authoritative ? data.terms.terms.filter((t) => !["FORGIVEN", "VOID"].includes(t.debtState) && Number(t.price) > Number(t.payedPrice)).sort((a, b) => a.seq - b.seq) : [];
        const first = terms[0];
        setTermId(first?.termId ?? null);
        setAmount(String(first ? staffRemaining(first.price, first.payedPrice) : staffRemaining(data.membership.price, data.membership.payedPrice)));
        setDueDate(first?.remainingPaymentDueDate || data.membership.remainingPaymentDueDate || "");
      }).catch((e) => { if (active) setError(staffError(e)); });
    return () => { active = false; };
  }, [member.activeMembershipId]);
  const terms = details?.terms.authoritative ? details.terms.terms.filter((t) => !["FORGIVEN", "VOID"].includes(t.debtState) && Number(t.price) > Number(t.payedPrice)).sort((a, b) => a.seq - b.seq) : [];
  const term = terms.find((t) => t.termId === termId);
  const remaining = details ? (details.terms.authoritative ? (term ? staffRemaining(term.price, term.payedPrice) : 0) : staffRemaining(details.membership.price, details.membership.payedPrice)) : null;
  const numericAmount = Number(amount);
  const valid = !resultUnknown && !hint && remaining !== null && amount !== "" && Number.isFinite(numericAmount) && numericAmount > 0 && numericAmount <= remaining && numericAmount === Math.round(numericAmount * 1000) / 1000 && staffPaymentValid(payment);
  const submit = async () => {
    if (!valid || busy) return;
    setBusy(true); setError("");
    try {
      await post("/members/pay-rest", { activeMembershipId: Number(member.activeMembershipId), amount: numericAmount,
        ...staffPaymentPayload(payment), remainingPaymentDueDate: dueDate || null, termId,
        clientRequestId: requestId }, 60_000);
      showStaffToast(`${staffMoney(numericAmount)} DT encaissés pour ${member.fullName}`, `Fait par ${staff?.agent?.name || ""}`);
      onSuccess(); onClose();
    } catch (e) { setError(staffError(e)); setResultUnknown(staffResultUnknown(e)); } finally { setBusy(false); }
  };
  return <DialogFrame open onOpenChange={(open) => { if (!open && !busy) onClose(); }} title="Payer le reste" sub={member.fullName} width={500} lockOutside
    footer={<><span className="mr-auto text-[12.5px] text-muted-foreground">Fait par {staff?.agent?.name}</span><ActionButton onClick={onClose} disabled={busy}>Annuler</ActionButton><ActionButton kind="primary" disabled={!valid || busy} onClick={() => void submit()}>{busy ? "Paiement…" : `Payer · ${staffMoney(numericAmount || 0)} DT`}</ActionButton></>}>
    <div className="text-[14px] font-semibold">Reste à payer : {remaining === null ? "Chargement…" : `${staffMoney(remaining)} DT`}</div>
    {remaining === 0 && <Note tone="success" className="mt-3">Aucun reste à payer.</Note>}
    <FieldGrid>
      {terms.length > 1 && <FormField label="Vente à régler" full><Select disabled={busy} value={String(termId)} onValueChange={(id) => { const selected = terms.find((t) => t.termId === Number(id)); setTermId(Number(id)); if (selected) { setAmount(String(staffRemaining(selected.price, selected.payedPrice))); setDueDate(selected.remainingPaymentDueDate || ""); } }}><FieldSelectTrigger><SelectValue /></FieldSelectTrigger><SelectContent>{terms.map((t) => <SelectItem key={t.termId} value={String(t.termId)}>Vente {t.seq} · {t.planTitle} · {staffMoney(staffRemaining(t.price, t.payedPrice))} DT</SelectItem>)}</SelectContent></Select></FormField>}
      <FormField label="Montant à payer (DT)" full><FieldInput disabled={busy} type="number" min="0.001" step="0.001" max={remaining ?? undefined} value={amount} onChange={(e) => setAmount(e.target.value)} /></FormField>
      <StaffPaymentFields value={payment} onChange={setPayment} disabled={busy} />
      {remaining !== null && numericAmount < remaining && <FormField label="Échéance du reste (facultatif)" full><FieldInput disabled={busy} type="date" value={dueDate} onChange={(e) => setDueDate(e.target.value)} /></FormField>}
    </FieldGrid>
    {(hint || error) && <Note tone="error" className="mt-3">{hint || error}</Note>}
    {resultUnknown && <Note tone="warning" className="mt-3">Le résultat du paiement est inconnu. Vérifiez les paiements et le reste à payer dans le tableau de bord avant toute nouvelle tentative.</Note>}
  </DialogFrame>;
}
