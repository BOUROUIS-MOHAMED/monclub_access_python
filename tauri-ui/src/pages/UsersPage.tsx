
import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent, type ReactNode } from "react";
import { useUsers } from "@/api/hooks";
import { get, openSSE, patch, post } from "@/api/client";
import type {
  MemberCardResponse,
  MemberHistoryResponse,
  OfflineAttemptResponse,
  OfflineCreationKind,
  OfflineCreationRow,
  OfflineCreationState,
  OfflineFailureType,
  OfflineQueueListResponse,
  UserDto,
} from "@/api/types";
import { Select, SelectContent, SelectItem, SelectValue } from "@/components/ui/select";
import { ActionButton } from "@/components/ui/action-button";
import { Avatar, Chip } from "@/components/ui/chip";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { DialogFrame } from "@/components/ui/dialog-frame";
import { FieldGrid, FieldInput, FieldSection, FieldSelectTrigger, FormField } from "@/components/ui/form-field";
import { CellText, FlexCell, FlexRow, FlexTable } from "@/components/ui/flex-table";
import { LineTabs } from "@/components/ui/line-tabs";
import { Segmented } from "@/components/ui/segmented";
import { ListRow, Note, PageGrid, Panel, PanelHeader, PanelList } from "@/components/ui/panel";
import { INK, initialsOf, type Tone } from "@/components/ui/tone";
import {
  Archive,
  ArrowRightLeft,
  ChevronLeft,
  ChevronRight,
  CircleCheck,
  CirclePause,
  CirclePlay,
  CircleX,
  Clock3,
  CloudUpload,
  Copy,
  CreditCard,
  Eye,
  Fingerprint,
  History,
  IdCard,
  ImagePlus,
  Loader2,
  Pencil,
  QrCode,
  RefreshCw,
  Repeat,
  ScanLine,
  Search,
  Send,
  Snowflake,
  Trash2,
  TriangleAlert,
  UserPlus,
  Users as UsersIcon,
  X,
  type LucideIcon,
} from "lucide-react";
import { usePageChrome } from "@/context/PageChromeContext";
import { aDenyCopy } from "@/pages/PopupWindow";
import { cn } from "@/lib/utils";

type MembershipChoice = { id: number | string; title?: string };

type QueueDecision = {
  creationKind: OfflineCreationKind;
  payload: Record<string, any>;
  attempt: OfflineAttemptResponse;
};

type MemberRosterRow = {
  userId?: number | string;
  activeMembershipId?: number | string;
  membershipId?: number | string;
  membershipTitle?: string;
  fullName?: string;
  phone?: string;
  email?: string;
  accountUsernameId?: string;
  validTo?: string;
  status?: "active" | "expired" | "pending" | string;
  offlinePending?: boolean;
  offlinePendingLocalId?: string;
  firstCardId?: string;
  secondCardId?: string;
  validFrom?: string;
  version?: number | null;
  pendingMutations?: { localId: string; opKind: string; state: string; money: boolean }[];
  pendingDelete?: boolean;
  hasConflict?: boolean;
  /** Set on rows of sync_users_held: off the turnstile roster for the gym date (frozen, expired, not_started). */
  heldReason?: string | null;
  heldForDate?: string | null;
  /** Held for the gym date the PC last applied (not an older hold). */
  heldToday?: boolean;
};

type MutationRow = {
  local_id: string;
  op_kind: string;
  target_kind: string;
  target_id: number;
  state: string;
  money: boolean;
  failure_count?: number;
  last_error_message?: string | null;
  next_retry_at?: string | null;
  updated_at?: string | null;
  server_result_json?: string | null;
  expected_version?: number | null;
  payload?: Record<string, any>;
};

const MUTATION_ACTIVE_STATES = ["pending", "processing", "failed_retryable", "blocked_auth", "conflict"];

const HISTORY_STATES: OfflineCreationState[] = ["succeeded", "reconciled", "cancelled", "failed_terminal", "archived"];

// Mirrors the backend enums so the UI only ever sends values the API can deserialize.
const GENDERS = [{ v: "MALE", l: "Homme" }, { v: "FEMALE", l: "Femme" }];
const BLOOD_TYPES = ["A_PLUS", "B_PLUS", "AB_PLUS", "O_PLUS", "A_MINUS", "B_MINUS", "AB_MINUS", "O_MINUS", "UNDEFINED"];
const PAYMENT_METHODS = ["CASH", "TPE", "BANK_TRANSFER", "CHEQUE", "BALANCE"];
const PAYMENT_STATUSES = ["PENDING", "COMPLETED"];
const CITIES: { v: string; l: string }[] = [
  { v: "TUNISIA_TUNIS", l: "Tunis" },
  { v: "TUNISIA_ARIANA", l: "Ariana" },
  { v: "TUNISIA_BEN_AROUS", l: "Ben Arous" },
  { v: "TUNISIA_MANOUBA", l: "Manouba" },
  { v: "TUNISIA_NABEUL", l: "Nabeul" },
  { v: "TUNISIA_BIZERTE", l: "Bizerte" },
  { v: "TUNISIA_BEJA", l: "Béja" },
  { v: "TUNISIA_JENDOUBA", l: "Jendouba" },
  { v: "TUNISIA_KEF", l: "Kef" },
  { v: "TUNISIA_SILIANA", l: "Siliana" },
  { v: "TUNISIA_SOUSSE", l: "Sousse" },
  { v: "TUNISIA_MONASTIR", l: "Monastir" },
  { v: "TUNISIA_MAHDIA", l: "Mahdia" },
  { v: "TUNISIA_KAIRIOUAN", l: "Kairouan" },
  { v: "TUNISIA_KASSERINE", l: "Kasserine" },
  { v: "TUNISIA_SIDI_BOUZID", l: "Sidi Bouzid" },
  { v: "TUNISIA_SFAX", l: "Sfax" },
  { v: "TUNISIA_GABES", l: "Gabès" },
  { v: "TUNISIA_MEDENINE", l: "Médenine" },
  { v: "TUNISIA_TATAOUINE", l: "Tataouine" },
  { v: "TUNISIA_TOZEUR", l: "Tozeur" },
  { v: "TUNISIA_KEBILI", l: "Kebili" },
  { v: "TUNISIA_GAFSA", l: "Gafsa" },
  { v: "TUNISIA_ZAGHOUAN", l: "Zaghouan" },
];

const NONE = "__none__";
const ROSTER_SIZE = 25;
/** Passages listed on the member card (the endpoint caps at 200). */
const VISITS_SHOWN = 10;

/** Same words as the dashboard feed (DashboardPage methodLabel). */
function visitMethod(method: string): string {
  const m = (method || "").toUpperCase();
  if (m.includes("QR") || m.includes("TOTP")) return "QR Code";
  if (m.includes("FINGER") || m.includes("FP") || m.includes("BIO")) return "empreinte";
  return "carte";
}
/** "2026-10-16T14:32:05" (local wall clock) → "16/10/2026 14:32". */
function visitTime(at: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})/.exec(n(at));
  return m ? `${m[3]}/${m[2]}/${m[1]} ${m[4]}:${m[5]}` : (n(at) || "—");
}

const MEMBERSHIP_FORM_INIT = {
  accountUsernameId: "",
  membershipId: "",
  startDate: new Date().toISOString().slice(0, 10),
  endDate: new Date(Date.now() + 86400000 * 30).toISOString().slice(0, 10),
  cardId: "",
  secondCardId: "",
  note: "",
  price: "",
  payedPrice: "",
  paymentMethod: "CASH",
  paymentStatus: "PENDING",
  remainingPaymentDueDate: "",
};

const ACCOUNT_FORM_INIT = {
  firstname: "",
  lastname: "",
  email: "",
  phone: "",
  password: "",
  accountUsernameId: "",
  cin: "",
  birthday: "",
  gender: "",
  bloodType: "",
  city: "",
  emergencyContactName: "",
  emergencyContactPhone: "",
  emergencyNote: "",
  membershipId: "",
  startDate: new Date().toISOString().slice(0, 10),
  endDate: new Date(Date.now() + 86400000 * 30).toISOString().slice(0, 10),
  cardId: "",
  secondCardId: "",
  note: "",
  price: "",
  payedPrice: "",
  paymentMethod: "CASH",
  paymentStatus: "PENDING",
  remainingPaymentDueDate: "",
};

function n(v: unknown): string {
  return String(v ?? "").trim();
}
function nl(v: unknown): string {
  return n(v).toLowerCase();
}
function ts(v: string | null | undefined): string {
  if (!v) return "-";
  return String(v).replace("T", " ").replace("Z", "").slice(0, 19);
}
function stripLeadingZeros(card: string): string {
  const s = n(card);
  const stripped = s.replace(/^0+/, "");
  return stripped || s;
}

// ── French copy for the raw backend values (display only; the values sent stay raw) ──
const PAYMENT_METHOD_FR: Record<string, string> = {
  CASH: "Espèces", TPE: "TPE (carte)", BANK_TRANSFER: "Virement", CHEQUE: "Chèque", BALANCE: "Solde",
};
const PAYMENT_STATUS_FR: Record<string, string> = { PENDING: "En attente", COMPLETED: "Réglé" };

const KIND_FR: Record<OfflineCreationKind, string> = {
  account_plus_membership: "Membre + abonnement",
  membership_only: "Abonnement seul",
};

// Offline-creation states (active queue + processed history).
const CREATION_STATE: Record<OfflineCreationState, { l: string; tone: Tone }> = {
  pending: { l: "En attente", tone: "warning" },
  processing: { l: "Envoi…", tone: "info" },
  failed_retryable: { l: "Échec — nouvel essai", tone: "error" },
  blocked_auth: { l: "Bloqué (authentification)", tone: "warning" },
  succeeded: { l: "Créé", tone: "success" },
  reconciled: { l: "Rapproché", tone: "info" },
  cancelled: { l: "Annulé", tone: "grey" },
  failed_terminal: { l: "Échec définitif", tone: "error" },
  archived: { l: "Archivé", tone: "grey" },
};
const creationState = (s: string) => CREATION_STATE[s as OfflineCreationState] ?? { l: s || "—", tone: "grey" as Tone };

const FAILURE_TYPE_FR: Record<OfflineFailureType, string> = {
  network: "réseau", server: "serveur", auth: "authentification",
  validation: "validation", conflict: "conflit", unknown: "inconnu",
};

// Lifecycle-change states (/mutations).
const MUTATION_STATE: Record<string, { l: string; tone: Tone }> = {
  pending: { l: "En attente", tone: "warning" },
  processing: { l: "Envoi…", tone: "info" },
  failed_retryable: { l: "Échec — nouvel essai", tone: "error" },
  blocked_auth: { l: "Bloqué (authentification)", tone: "warning" },
  conflict: { l: "Conflit", tone: "error" },
  succeeded: { l: "Appliqué", tone: "success" },
  reconciled: { l: "Rapproché", tone: "success" },
  failed_terminal: { l: "Échec définitif", tone: "error" },
  cancelled: { l: "Annulé", tone: "grey" },
};
const mutationState = (s: string) => MUTATION_STATE[s] ?? { l: s || "—", tone: "grey" as Tone };

const OP_FR: Record<string, string> = {
  edit: "Modification",
  freeze_create: "Gel",
  delete: "Suppression",
  renew: "Renouvellement",
  freeze_cancel: "Fin du gel",
  balance_adjust: "Ajustement du solde",
  pay_rest: "Paiement du reste",
  pay_tolerance: "Paiement (tolérance)",
};
function opLabel(op: string): string {
  return OP_FR[op] ?? op;
}

// Roster status → French chip. The server decides the status; the UI only names it.
const STATUS: Record<string, { l: string; tone: Tone }> = {
  active: { l: "Actif", tone: "success" },
  expired: { l: "Expiré", tone: "error" },
  pending: { l: "En attente", tone: "info" },
};
const statusOf = (s?: string) => (s && STATUS[s]) || { l: s || "—", tone: "grey" as Tone };

/** "2027-03-11…" → local midnight Date (never `new Date("YYYY-MM-DD")`, which is UTC). */
function localDay(v?: string | null): Date | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(n(v));
  if (!m) return null;
  return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
}
function frDate(v?: string | null): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(n(v));
  return m ? `${m[3]}/${m[2]}/${m[1]}` : "—";
}
function todayLocal(): Date {
  const t = new Date();
  return new Date(t.getFullYear(), t.getMonth(), t.getDate());
}
/**
 * « encore 12 jours » / « dernier jour » / « expiré depuis 3 jours », computed from validTo.
 * Returns "" when the computed text would contradict the server's status.
 */
function daysLeftText(m: MemberRosterRow): string {
  if (m.status === "pending") return "pas encore sur le serveur";
  const end = localDay(m.validTo);
  if (!end) return "";
  const d = Math.round((end.getTime() - todayLocal().getTime()) / 86400000);
  if (m.status === "active" && d >= 0) return d === 0 ? "dernier jour" : `encore ${d} jour${d > 1 ? "s" : ""}`;
  if (m.status === "expired" && d < 0) return `expiré depuis ${-d} jour${-d > 1 ? "s" : ""}`;
  return "";
}
/** Share of the validFrom → validTo period already used, 0–100, or null without both dates. */
function periodUsedPct(m: MemberRosterRow): number | null {
  const s = localDay(m.validFrom);
  const e = localDay(m.validTo);
  if (!s || !e || e.getTime() <= s.getTime()) return null;
  const pct = ((todayLocal().getTime() - s.getTime()) / (e.getTime() - s.getTime())) * 100;
  return Math.max(0, Math.min(100, Math.round(pct)));
}

/** Flag of a row the PC took off the turnstiles for the gym date (sync_users_held). */
function heldFlag(m: MemberRosterRow): { label: string; tone: Tone } | null {
  if (!m.heldReason) return null;
  if (m.heldReason === "frozen") return { label: m.heldToday ? "gelé aujourd'hui" : "gelé", tone: "info" };
  if (m.heldReason === "not_started") return { label: "pas encore commencé", tone: "grey" };
  return { label: "hors des tourniquets", tone: "grey" };
}

/** The one flag shown next to a member's name (same priority as before; a held row second). */
function rowFlag(m: MemberRosterRow): { label: string; tone: Tone } | null {
  if (m.hasConflict) return { label: "conflit", tone: "error" };
  const held = heldFlag(m);
  if (held) return held;
  if (m.offlinePending) return { label: "créé hors ligne", tone: "info" };
  if (m.pendingDelete) return { label: "suppression…", tone: "warning" };
  if ((m.pendingMutations?.length ?? 0) > 0) return { label: "sync en attente", tone: "warning" };
  return null;
}

/** Name of the member behind an offline creation, read from its payload. */
function payloadName(p: Record<string, any> | undefined): string {
  const q = p || {};
  const full = [n(q.firstname || q.firstName || q.first_name), n(q.lastname || q.lastName || q.last_name)].filter(Boolean).join(" ");
  return full || n(q.accountUsernameId || q.account_username_id) || "—";
}

const memberKey = (m: MemberRosterRow) => `${m.userId}-${m.activeMembershipId || "na"}`;

// Turn a raw backend error into an operator-friendly hint for the decision dialog.
// The match keys stay English: they read the server's own (English) message.
function friendlyConflict(a: OfflineAttemptResponse | undefined): string | null {
  const msg = nl(a?.error);
  if (!msg) return null;
  if (msg.includes("card") && (msg.includes("use") || msg.includes("already"))) return "Cette carte est déjà attribuée à un autre membre de cette salle. Utilisez une autre carte.";
  if (msg.includes("email") && msg.includes("exist")) return "Un compte existe déjà avec cet e-mail.";
  if (msg.includes("username") && msg.includes("exist")) return "Cet identifiant est déjà pris.";
  if (msg.includes("already has this membership")) return "Ce membre a déjà cet abonnement.";
  if (msg.includes("maximum number of members")) return "Vous avez atteint le nombre maximal de membres autorisé pour cette salle.";
  if (msg.includes("password")) return "Le mot de passe doit contenir au moins 8 caractères.";
  return null;
}

function paymentPayload(form: any): Record<string, any> {
  const p: Record<string, any> = {};
  if (n(form.note)) p.note = n(form.note);
  if (n(form.price)) p.price = Number(form.price);
  if (n(form.payedPrice)) p.payedPrice = Number(form.payedPrice);
  if (n(form.paymentMethod)) p.paymentMethod = form.paymentMethod;
  if (n(form.paymentStatus)) p.paymentStatus = form.paymentStatus;
  if (n(form.remainingPaymentDueDate)) p.remainingPaymentDueDate = n(form.remainingPaymentDueDate);
  return p;
}

function profilePayload(form: any): Record<string, any> {
  const p: Record<string, any> = {};
  if (n(form.cin)) p.cin = n(form.cin);
  // backend birthday is LocalDateTime — send a full ISO datetime, not date-only.
  if (n(form.birthday)) p.birthday = `${n(form.birthday)}T00:00:00`;
  if (n(form.gender)) p.gender = form.gender;
  if (n(form.bloodType)) p.bloodType = form.bloodType;
  if (n(form.city)) p.city = form.city;
  if (n(form.emergencyContactName)) p.emergencyContactName = n(form.emergencyContactName);
  if (n(form.emergencyContactPhone)) p.emergencyContactPhone = n(form.emergencyContactPhone);
  if (n(form.emergencyNote)) p.emergencyNote = n(form.emergencyNote);
  return p;
}

function PaymentFields({ form, set }: { form: any; set: (patch: any) => void }) {
  return (
    <>
      <FieldSection>Paiement</FieldSection>
      <FormField label="Prix"><FieldInput type="number" inputMode="decimal" value={form.price} onChange={(e) => set({ price: e.target.value })} /></FormField>
      <FormField label="Payé"><FieldInput type="number" inputMode="decimal" value={form.payedPrice} onChange={(e) => set({ payedPrice: e.target.value })} /></FormField>
      <FormField label="Moyen de paiement">
        <Select value={form.paymentMethod || "CASH"} onValueChange={(v) => set({ paymentMethod: v })}>
          <FieldSelectTrigger><SelectValue /></FieldSelectTrigger>
          <SelectContent>{PAYMENT_METHODS.map((m) => <SelectItem key={m} value={m}>{PAYMENT_METHOD_FR[m] ?? m}</SelectItem>)}</SelectContent>
        </Select>
      </FormField>
      <FormField label="Statut du paiement">
        <Select value={form.paymentStatus || "PENDING"} onValueChange={(v) => set({ paymentStatus: v })}>
          <FieldSelectTrigger><SelectValue /></FieldSelectTrigger>
          <SelectContent>{PAYMENT_STATUSES.map((s) => <SelectItem key={s} value={s}>{PAYMENT_STATUS_FR[s] ?? s}</SelectItem>)}</SelectContent>
        </Select>
      </FormField>
      <FormField label="Échéance du reste (facultatif)" full>
        <FieldInput type="date" value={form.remainingPaymentDueDate} onChange={(e) => set({ remainingPaymentDueDate: e.target.value })} />
      </FormField>
    </>
  );
}

/** Card-number field with the « Scanner » button (POST /scan/quick through `onScan`). */
function CardField({ label, value, onChange, scanKey, scanning, onScan }: {
  label: string; value: string; onChange: (v: string) => void;
  scanKey: string; scanning: string | null; onScan: () => void;
}) {
  return (
    <FormField
      label={label}
      addon={(
        <ActionButton kind="outline" size="xs" icon={scanning === scanKey ? Clock3 : ScanLine} disabled={!!scanning} onClick={onScan} title="Scanner une carte RFID">
          {scanning === scanKey ? "Lecture…" : "Scanner"}
        </ActionButton>
      )}
    >
      <FieldInput className="font-mono" value={value} onChange={(e) => onChange(e.target.value)} />
    </FormField>
  );
}

function MembershipSelect({ value, memberships, onChange }: {
  value: string; memberships: MembershipChoice[]; onChange: (v: string) => void;
}) {
  return (
    <FormField label="Abonnement" full>
      <Select value={value || NONE} onValueChange={(v) => onChange(v === NONE ? "" : v)}>
        <FieldSelectTrigger><SelectValue placeholder="Choisir un abonnement" /></FieldSelectTrigger>
        <SelectContent>
          <SelectItem value={NONE}>Choisir un abonnement</SelectItem>
          {memberships.map((m) => <SelectItem key={String(m.id)} value={String(m.id)}>{m.title || `Abonnement ${m.id}`}</SelectItem>)}
        </SelectContent>
      </Select>
    </FormField>
  );
}

/** Error / success line shown inside an open dialog (the page alerts sit behind the overlay). */
function DialogMessages({ error, message }: { error: string | null; message?: string }) {
  if (!error && !message) return null;
  return (
    <div className="mt-3 space-y-2">
      {error ? <Note tone="error">{error}</Note> : null}
      {message ? <Note tone="success">{message}</Note> : null}
    </div>
  );
}

function EnrollDialog({ member, onClose }: { member: MemberRosterRow | null; onClose: () => void }) {
  const [fingerId, setFingerId] = useState("0");
  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [result, setResult] = useState<string | null>(null);
  const esRef = useRef<EventSource | null>(null);

  const closeStream = useCallback(() => {
    try { esRef.current?.close(); } catch { /* noop */ }
    esRef.current = null;
  }, []);

  useEffect(() => closeStream, [closeStream]);
  // reset when a new member opens the dialog
  useEffect(() => {
    setFingerId("0");
    setRunning(false);
    setLogs([]);
    setResult(null);
    closeStream();
  }, [member?.userId, closeStream]);

  const start = async () => {
    if (!member) return;
    setLogs([]);
    setResult(null);
    setRunning(true);
    closeStream();
    try {
      const es = openSSE("/enroll/events", (type, data) => {
        if (type === "log") setLogs((l) => [...l, String(data?.line ?? "")]);
        else if (type === "step") setLogs((l) => [...l, String(data?.step ?? "")]);
        else if (type === "success" || type === "failed" || type === "cancelled") {
          setResult(type);
          setRunning(false);
          closeStream();
        }
      });
      esRef.current = es;
      await post("/enroll/start", {
        userId: String(member.userId ?? ""),
        fingerId,
        type: "BACKEND",
        fullName: member.fullName || "",
      }, 20000);
    } catch (e: any) {
      setLogs((l) => [...l, "ERREUR : " + (e?.message || String(e))]);
      setResult("failed");
      setRunning(false);
      closeStream();
    }
  };

  const cancelScan = async () => {
    try { await post("/enroll/cancel", {}); } catch { /* noop */ }
  };

  const resultTone: Tone = result === "success" ? "success" : result === "cancelled" ? "warning" : "error";

  return (
    <DialogFrame
      open={!!member}
      onOpenChange={(o) => { if (!o) { closeStream(); onClose(); } }}
      lockOutside
      width={520}
      title={`Enrôler une empreinte — ${member?.fullName || ""}`}
      sub={member?.offlinePending
        ? "Membre créé hors ligne : l'empreinte est capturée maintenant et envoyée automatiquement quand il sera synchronisé avec le serveur."
        : "Posez le doigt sur le lecteur après « Démarrer » (3 captures)."}
      footer={<ActionButton kind="dark" className="px-4" onClick={() => { closeStream(); onClose(); }}>Fermer</ActionButton>}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[13.5px] font-semibold">Doigt</span>
        <Select value={fingerId} onValueChange={setFingerId} disabled={running}>
          <FieldSelectTrigger className="h-9 w-[90px] rounded-lg border border-grey/32 px-3"><SelectValue /></FieldSelectTrigger>
          <SelectContent>
            {Array.from({ length: 10 }, (_, i) => String(i)).map((f) => <SelectItem key={f} value={f}>#{f}</SelectItem>)}
          </SelectContent>
        </Select>
        <ActionButton kind="primary" icon={Fingerprint} onClick={start} disabled={running}>
          {running ? "Capture…" : "Démarrer"}
        </ActionButton>
        {running ? <ActionButton kind="outline" onClick={cancelScan}>Annuler la capture</ActionButton> : null}
      </div>
      <div className="mt-3 max-h-40 overflow-auto rounded-lg bg-muted p-2.5 font-mono text-[12px]">
        {logs.length === 0 ? <span className="text-muted-foreground">En attente.</span> : logs.map((l, i) => <div key={i}>{l}</div>)}
      </div>
      {result ? (
        <p className={cn("mt-3 text-[13.5px] font-semibold", INK[resultTone])}>
          {result === "success"
            ? (member?.offlinePending ? "Empreinte capturée : elle sera synchronisée avec le membre." : "Empreinte enregistrée pour le membre.")
            : result === "cancelled" ? "Annulé." : "Échec de l'enrôlement."}
        </p>
      ) : null}
    </DialogFrame>
  );
}

export default function UsersPage() {
  const { data, loading, error, reload: reloadUsers } = useUsers();
  const users: UserDto[] = data?.users ?? [];

  const [memberships, setMemberships] = useState<MembershipChoice[]>([]);
  const [activeRows, setActiveRows] = useState<OfflineCreationRow[]>([]);
  const [historyRows, setHistoryRows] = useState<OfflineCreationRow[]>([]);
  const [historyFilter, setHistoryFilter] = useState<"all" | OfflineCreationState>("all");

  const [editing, setEditing] = useState<OfflineCreationRow | null>(null);
  const [queueLoading, setQueueLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [queueError, setQueueError] = useState<string | null>(null);
  const [scanning, setScanning] = useState<string | null>(null);

  const [membershipForm, setMembershipForm] = useState({ ...MEMBERSHIP_FORM_INIT });
  const [accountForm, setAccountForm] = useState({ ...ACCOUNT_FORM_INIT });

  const setMembership = useCallback((patch: any) => setMembershipForm((s) => ({ ...s, ...patch })), []);
  const setAccount = useCallback((patch: any) => setAccountForm((s) => ({ ...s, ...patch })), []);

  const [decision, setDecision] = useState<QueueDecision | null>(null);
  const [decisionOpen, setDecisionOpen] = useState(false);

  // v5: the creation forms live in one dialog (two tabs) instead of an in-page panel.
  const [memberOpen, setMemberOpen] = useState(false);
  const [memberTab, setMemberTab] = useState<OfflineCreationKind>("account_plus_membership");

  // -------- roster (local-first searchable directory) --------
  const [roster, setRoster] = useState<MemberRosterRow[]>([]);
  const [rosterTotal, setRosterTotal] = useState(0);
  const [rosterCounts, setRosterCounts] = useState<Record<string, number>>({});
  const [rosterQInput, setRosterQInput] = useState("");
  const [rosterQ, setRosterQ] = useState("");
  const [rosterStatus, setRosterStatus] = useState<"all" | "active" | "expired" | "pending">("all");
  const [rosterPage, setRosterPage] = useState(0);
  const [rosterLoading, setRosterLoading] = useState(false);
  const [enrollMember, setEnrollMember] = useState<MemberRosterRow | null>(null);
  const photoInputRef = useRef<HTMLInputElement | null>(null);
  const [photoTarget, setPhotoTarget] = useState<MemberRosterRow | null>(null);
  const [photoBusy, setPhotoBusy] = useState(false);

  // -------- lifecycle mutations (edit / delete / freeze) on synced members --------
  const [mutations, setMutations] = useState<MutationRow[]>([]);
  const [editTarget, setEditTarget] = useState<MemberRosterRow | null>(null);
  const [editForm, setEditForm] = useState({ startDate: "", endDate: "", cardId: "", secondCardId: "", note: "" });
  const [freezeTarget, setFreezeTarget] = useState<MemberRosterRow | null>(null);
  const [freezeForm, setFreezeForm] = useState({ startFreezeDate: new Date().toISOString().slice(0, 10), durationInDays: "7", reason: "", note: "" });
  const [deleteTarget, setDeleteTarget] = useState<MemberRosterRow | null>(null);
  const [mutBusy, setMutBusy] = useState(false);

  const loadMutations = useCallback(async () => {
    try {
      const res = await get<{ rows: MutationRow[] }>("/mutations", { limit: "500" });
      setMutations(Array.isArray(res.rows) ? res.rows : []);
    } catch {
      setMutations([]);
    }
  }, []);

  useEffect(() => {
    void loadMutations();
  }, [loadMutations]);

  const loadMemberships = useCallback(async () => {
    try {
      const res = await get<{ memberships: MembershipChoice[] }>("/sync/cache/memberships");
      setMemberships(Array.isArray(res.memberships) ? res.memberships : []);
    } catch {
      setMemberships([]);
    }
  }, []);

  const loadActive = useCallback(async () => {
    const res = await get<OfflineQueueListResponse>("/offline-creations/active", { limit: "500" });
    setActiveRows(Array.isArray(res.rows) ? res.rows : []);
  }, []);

  const loadHistory = useCallback(async (filter: "all" | OfflineCreationState) => {
    const params: Record<string, string> = { limit: "500" };
    if (filter !== "all") params.state = filter;
    const res = await get<OfflineQueueListResponse>("/offline-creations/history", params);
    setHistoryRows(Array.isArray(res.rows) ? res.rows : []);
  }, []);

  const loadRoster = useCallback(async () => {
    setRosterLoading(true);
    try {
      const res = await get<{ rows: MemberRosterRow[]; total: number; counts: Record<string, number> }>("/members", {
        q: rosterQ,
        status: rosterStatus,
        limit: String(ROSTER_SIZE),
        offset: String(rosterPage * ROSTER_SIZE),
        sortBy: "name",
        sortDir: "asc",
      });
      setRoster(Array.isArray(res.rows) ? res.rows : []);
      setRosterTotal(Number(res.total) || 0);
      setRosterCounts(res.counts || {});
    } catch (e) {
      setQueueError(String(e));
    } finally {
      setRosterLoading(false);
    }
  }, [rosterQ, rosterStatus, rosterPage]);

  const submitMutation = useCallback(async (opKind: string, m: MemberRosterRow, payload: Record<string, any>, opts?: { money?: boolean }) => {
    setQueueError(null);
    setMessage("");
    setMutBusy(true);
    try {
      const res = await post<any>("/members/mutation", {
        opKind,
        targetKind: "active_membership",
        targetId: m.activeMembershipId,
        payload,
        money: opts?.money,
        expectedVersion: m.version ?? undefined,
      }, 30000);
      if (res.ok) setMessage(`Changement appliqué en ligne : ${opLabel(opKind)}.`);
      else if (res.conflict) setQueueError("Cet abonnement a changé sur le serveur entre-temps : rien n'a été envoyé. Rechargez puis recommencez la modification.");
      else if (res.queued) setMessage(res.gated ? `Changement mis en file : ${opLabel(opKind)}. Il s'appliquera quand le serveur acceptera les opérations d'argent.` : `Changement mis en file (hors ligne) : ${opLabel(opKind)}. Il sera synchronisé automatiquement.`);
      else if (res.needsFix) setQueueError(res.error || `Changement refusé : ${opLabel(opKind)}. Corrigez les valeurs et réessayez.`);
      else setQueueError(res.error || `Échec du changement : ${opLabel(opKind)}.`);
      await Promise.all([loadRoster(), loadMutations()]);
      return res;
    } catch (e: any) {
      setQueueError(e?.message || String(e));
      return { ok: false, error: String(e) };
    } finally {
      setMutBusy(false);
    }
  }, [loadRoster, loadMutations]);

  const runMutationAction = useCallback(async (fn: () => Promise<any>, okMsg?: string) => {
    setQueueError(null);
    try {
      await fn();
      if (okMsg) setMessage(okMsg);
      await Promise.all([loadRoster(), loadMutations()]);
    } catch (e) {
      setQueueError(String(e));
    }
  }, [loadRoster, loadMutations]);

  const openEdit = useCallback((m: MemberRosterRow) => {
    setEditTarget(m);
    setEditForm({
      startDate: n(m.validFrom).slice(0, 10),
      endDate: n(m.validTo).slice(0, 10),
      cardId: n(m.firstCardId),
      secondCardId: n(m.secondCardId),
      note: "",
    });
  }, []);

  const submitEdit = useCallback(async () => {
    const m = editTarget;
    if (!m) return;
    const payload: Record<string, any> = { id: m.activeMembershipId, activeMembershipId: m.activeMembershipId };
    if (n(editForm.startDate)) payload.startDate = n(editForm.startDate);
    if (n(editForm.endDate)) payload.endDate = n(editForm.endDate);
    payload.cardId = n(editForm.cardId);          // partial update; prefilled = no-op
    payload.secondCardId = n(editForm.secondCardId);
    if (n(editForm.note)) payload.note = n(editForm.note);
    const res = await submitMutation("edit", m, payload);
    if (res.ok || res.queued) setEditTarget(null);
  }, [editTarget, editForm, submitMutation]);

  const submitFreeze = useCallback(async () => {
    const m = freezeTarget;
    if (!m) return;
    const dur = parseInt(freezeForm.durationInDays, 10);
    if (!n(freezeForm.startFreezeDate) || !Number.isFinite(dur) || dur <= 0) {
      setQueueError("Le gel demande une date de début et une durée positive.");
      return;
    }
    const payload: Record<string, any> = {
      activeMembershipId: m.activeMembershipId,
      startFreezeDate: n(freezeForm.startFreezeDate),
      durationInDays: dur,
      reason: n(freezeForm.reason) || undefined,
      note: n(freezeForm.note) || undefined,
    };
    const res = await submitMutation("freeze_create", m, payload);
    if (res.ok || res.queued) setFreezeTarget(null);
  }, [freezeTarget, freezeForm, submitMutation]);

  const confirmDelete = useCallback(async () => {
    const m = deleteTarget;
    if (!m) return;
    const res = await submitMutation("delete", m, {});
    if (res.ok || res.queued) setDeleteTarget(null);
  }, [deleteTarget, submitMutation]);

  const refreshQueue = useCallback(async () => {
    setQueueLoading(true);
    setQueueError(null);
    try {
      await Promise.all([loadActive(), loadHistory(historyFilter)]);
    } catch (e) {
      setQueueError(String(e));
    } finally {
      setQueueLoading(false);
    }
  }, [historyFilter, loadActive, loadHistory]);

  useEffect(() => {
    void Promise.all([loadMemberships(), refreshQueue()]);
  }, [loadMemberships, refreshQueue]);

  useEffect(() => {
    void loadHistory(historyFilter);
  }, [historyFilter, loadHistory]);

  useEffect(() => {
    void loadRoster();
  }, [loadRoster]);

  // debounce the search box -> rosterQ (and reset to first page)
  useEffect(() => {
    const t = setTimeout(() => {
      setRosterPage(0);
      setRosterQ(rosterQInput.trim());
    }, 300);
    return () => clearTimeout(t);
  }, [rosterQInput]);

  const cards = useMemo(() => {
    const s = new Set<string>();
    for (const u of users) {
      const c1 = nl((u as any).firstCardId);
      const c2 = nl((u as any).secondCardId);
      if (c1) s.add(c1);
      if (c2) s.add(c2);
    }
    return s;
  }, [users]);

  const byUsername = useMemo(() => {
    const m = new Map<string, UserDto>();
    for (const u of users) {
      const key = nl((u as any).accountUsernameId);
      if (key) m.set(key, u);
    }
    return m;
  }, [users]);

  const scanCard = useCallback(async (fieldKey: string, apply: (card: string) => void) => {
    setScanning(fieldKey);
    setQueueError(null);
    try {
      const r = await post<{ ok: boolean; card?: string; error?: string }>("/scan/quick", { timeout_ms: 15000 }, 20000);
      if (r.ok && n(r.card)) {
        apply(stripLeadingZeros(String(r.card)));
        setMessage("Carte scannée.");
      } else {
        setQueueError(r.error || "Aucune carte détectée. Réessayez.");
      }
    } catch (e: any) {
      setQueueError(e?.message || String(e));
    } finally {
      setScanning(null);
    }
  }, []);

  const pickPhoto = useCallback((m: MemberRosterRow) => {
    setPhotoTarget(m);
    if (photoInputRef.current) {
      photoInputRef.current.value = "";
      photoInputRef.current.click();
    }
  }, []);

  const onPhotoFile = useCallback(async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    const m = photoTarget;
    if (!file || !m) return;
    setPhotoBusy(true);
    setQueueError(null);
    setMessage("");
    try {
      const dataUrl: string = await new Promise((resolve, reject) => {
        const r = new FileReader();
        r.onload = () => resolve(String(r.result || ""));
        r.onerror = () => reject(new Error("Impossible de lire le fichier image."));
        r.readAsDataURL(file);
      });
      const base64 = dataUrl.includes(",") ? dataUrl.split(",")[1] : dataUrl;
      const payload: Record<string, any> = {
        imageBase64: base64,
        contentType: file.type || "image/jpeg",
        fileName: file.name || "member.jpg",
      };
      if (m.offlinePending && m.offlinePendingLocalId) payload.offlinePendingLocalId = m.offlinePendingLocalId;
      else payload.activeMembershipId = m.activeMembershipId;
      const res = await post<{ ok: boolean; deferred?: boolean; error?: string }>("/members/photo", payload, 60000);
      if (res.ok) setMessage(res.deferred ? "Photo enregistrée : elle sera envoyée automatiquement quand le membre sera synchronisé." : "Photo envoyée.");
      else setQueueError(res.error || "Échec de l'envoi de la photo.");
      await loadRoster();
    } catch (err: any) {
      setQueueError(err?.message || String(err));
    } finally {
      setPhotoBusy(false);
      setPhotoTarget(null);
    }
  }, [photoTarget, loadRoster]);

  const checkDateRange = (startDate: string, endDate: string): string | null => {
    if (!n(startDate) || !n(endDate)) return "Les dates de début et de fin sont obligatoires.";
    const s = new Date(startDate);
    const e = new Date(endDate);
    if (Number.isNaN(s.getTime()) || Number.isNaN(e.getTime())) return "Format de date invalide.";
    if (e < s) return "La date de fin doit être après la date de début.";
    return null;
  };

  const validateMembership = (): string | null => {
    const username = nl(membershipForm.accountUsernameId);
    if (!username) return "L'identifiant compte est obligatoire.";
    if (!n(membershipForm.membershipId)) return "Choisissez un abonnement.";

    const d = checkDateRange(membershipForm.startDate, membershipForm.endDate);
    if (d) return d;

    if (!byUsername.get(username)) return "Identifiant compte inconnu dans la copie locale.";

    const duplicate = users.some((u) => nl((u as any).accountUsernameId) === username && n((u as any).membershipId) === n(membershipForm.membershipId));
    if (duplicate) return "Ce membre a déjà cet abonnement dans la copie locale.";

    const c1 = nl(membershipForm.cardId);
    const c2 = nl(membershipForm.secondCardId);
    if (c1 && cards.has(c1)) return "Ce numéro de carte existe déjà dans la copie locale.";
    if (c2 && cards.has(c2)) return "Ce deuxième numéro de carte existe déjà dans la copie locale.";
    return null;
  };

  const validateAccount = (): string | null => {
    if (!n(accountForm.firstname)) return "Le prénom est obligatoire.";
    if (!n(accountForm.lastname)) return "Le nom est obligatoire.";
    if (!n(accountForm.email)) return "L'e-mail est obligatoire.";
    if (!n(accountForm.phone)) return "Le téléphone est obligatoire.";
    if (!n(accountForm.membershipId)) return "Choisissez un abonnement.";
    if (n(accountForm.password).length < 8) return "Le mot de passe doit contenir au moins 8 caractères.";

    const email = nl(accountForm.email);
    if (!email.includes("@") || !email.split("@")[1]?.includes(".")) return "Format d'e-mail invalide.";
    if (users.some((u) => nl(u.email) === email)) return "Cet e-mail existe déjà dans la copie locale.";

    const username = nl(accountForm.accountUsernameId);
    if (username && users.some((u) => nl((u as any).accountUsernameId) === username)) {
      return "Cet identifiant compte existe déjà dans la copie locale.";
    }

    const d = checkDateRange(accountForm.startDate, accountForm.endDate);
    if (d) return d;

    const c1 = nl(accountForm.cardId);
    const c2 = nl(accountForm.secondCardId);
    if (c1 && cards.has(c1)) return "Ce numéro de carte existe déjà dans la copie locale.";
    if (c2 && cards.has(c2)) return "Ce deuxième numéro de carte existe déjà dans la copie locale.";
    return null;
  };

  const runAction = async (fn: () => Promise<any>, okMsg?: string) => {
    setQueueError(null);
    try {
      await fn();
      if (okMsg) setMessage(okMsg);
      await Promise.all([reloadUsers(), refreshQueue(), loadRoster()]);
    } catch (e) {
      setQueueError(String(e));
    }
  };

  const handleAttempt = useCallback(async (creationKind: OfflineCreationKind, payload: Record<string, any>) => {
    const attempt = await post<OfflineAttemptResponse>("/offline-creations/attempt", { creationKind, payload });
    if (attempt.ok) {
      setMessage(attempt.state === "reconciled" ? "Déjà présent sur le serveur : création rapprochée." : "Créé sur le serveur.");
      setEditing(null);
      setMemberOpen(false);
      setDecision(null);
      setDecisionOpen(false);
      if (creationKind === "membership_only") setMembershipForm({ ...MEMBERSHIP_FORM_INIT });
      else setAccountForm({ ...ACCOUNT_FORM_INIT });
      await Promise.all([reloadUsers(), refreshQueue(), loadRoster()]);
      return;
    }

    setDecision({ creationKind, payload, attempt });
    setDecisionOpen(true);
  }, [refreshQueue, reloadUsers, loadRoster]);

  const submitMembership = async () => {
    setMessage("");
    const err = validateMembership();
    if (err) {
      setQueueError(err);
      return;
    }

    const payload: Record<string, any> = {
      accountUsernameId: n(membershipForm.accountUsernameId),
      membershipId: n(membershipForm.membershipId),
      startDate: n(membershipForm.startDate),
      endDate: n(membershipForm.endDate),
      cardId: n(membershipForm.cardId) || undefined,
      secondCardId: n(membershipForm.secondCardId) || undefined,
      ...paymentPayload(membershipForm),
    };

    if (editing && editing.creation_kind === "membership_only") {
      await patch(`/offline-creations/${editing.local_id}`, { payload, tryToCreate: true });
      setEditing(null);
      setMemberOpen(false);
      setMembershipForm({ ...MEMBERSHIP_FORM_INIT });
      setMessage("Création en attente mise à jour.");
      await Promise.all([refreshQueue(), loadRoster()]);
      return;
    }

    await handleAttempt("membership_only", payload);
  };

  const submitAccount = async () => {
    setMessage("");
    const err = validateAccount();
    if (err) {
      setQueueError(err);
      return;
    }

    const payload: Record<string, any> = {
      firstname: n(accountForm.firstname),
      lastname: n(accountForm.lastname),
      email: n(accountForm.email),
      phone: n(accountForm.phone),
      password: n(accountForm.password),
      accountUsernameId: n(accountForm.accountUsernameId) || undefined,
      membershipId: n(accountForm.membershipId),
      startDate: n(accountForm.startDate),
      endDate: n(accountForm.endDate),
      cardId: n(accountForm.cardId) || undefined,
      secondCardId: n(accountForm.secondCardId) || undefined,
      ...profilePayload(accountForm),
      ...paymentPayload(accountForm),
    };

    if (editing && editing.creation_kind === "account_plus_membership") {
      await patch(`/offline-creations/${editing.local_id}`, { payload, tryToCreate: true });
      setEditing(null);
      setMemberOpen(false);
      setAccountForm({ ...ACCOUNT_FORM_INIT });
      setMessage("Création en attente mise à jour.");
      await Promise.all([refreshQueue(), loadRoster()]);
      return;
    }

    await handleAttempt("account_plus_membership", payload);
  };

  const cancelEdit = () => {
    setEditing(null);
    setMembershipForm({ ...MEMBERSHIP_FORM_INIT });
    setAccountForm({ ...ACCOUNT_FORM_INIT });
  };

  const editRow = (row: OfflineCreationRow) => {
    setEditing(row);
    setQueueError(null);
    const p: Record<string, any> = row.payload || {};
    const common = {
      startDate: n(p.startDate || p.start_date || p.validFrom || p.valid_from),
      endDate: n(p.endDate || p.end_date || p.validTo || p.valid_to),
      cardId: n(p.cardId || p.card_id || p.firstCardId || p.first_card_id),
      secondCardId: n(p.secondCardId || p.second_card_id),
      note: n(p.note),
      price: n(p.price),
      payedPrice: n(p.payedPrice),
      paymentMethod: n(p.paymentMethod) || "CASH",
      paymentStatus: n(p.paymentStatus) || "PENDING",
      remainingPaymentDueDate: n(p.remainingPaymentDueDate),
    };
    if (row.creation_kind === "membership_only") {
      setMembershipForm({
        ...MEMBERSHIP_FORM_INIT,
        accountUsernameId: n(p.accountUsernameId || p.account_username_id),
        membershipId: n(p.membershipId || p.membership_id),
        ...common,
      });
    } else {
      setAccountForm({
        ...ACCOUNT_FORM_INIT,
        firstname: n(p.firstname || p.firstName || p.first_name),
        lastname: n(p.lastname || p.lastName || p.last_name),
        email: n(p.email),
        phone: n(p.phone),
        password: n(p.password),
        accountUsernameId: n(p.accountUsernameId || p.account_username_id),
        cin: n(p.cin),
        birthday: n(p.birthday).slice(0, 10),
        gender: n(p.gender),
        bloodType: n(p.bloodType),
        city: n(p.city),
        emergencyContactName: n(p.emergencyContactName),
        emergencyContactPhone: n(p.emergencyContactPhone),
        emergencyNote: n(p.emergencyNote),
        membershipId: n(p.membershipId || p.membership_id),
        ...common,
      });
    }
    setMessage("");
    setMemberTab(row.creation_kind);
    setMemberOpen(true);
  };

  const saveLaterRecommended = decision?.attempt?.recommendation === "save_later";
  const conflictHint = friendlyConflict(decision?.attempt);

  // ── Access v5 layout ──────────────────────────────────────────────────
  // Four tabs: the directory (with the member card in the right rail), the
  // offline-creation queue, its processed history, and the lifecycle-change
  // queue. The creation forms open in one dialog (« Nouveau membre »). The
  // loaders and handlers above are the same ones as before; only where their
  // results are shown changed.
  type UsersTab = "roster" | "creations" | "history" | "mutations";
  const [tab, setTab] = useState<UsersTab>("roster");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  // Looked up in the current page so the card refreshes after a change and
  // falls back to the default rail when the row leaves the page.
  const selected = selectedKey ? roster.find((m) => memberKey(m) === selectedKey) ?? null : null;

  // The card's extra lines (prints, …) come from GET /members/{id}/card, read once when a
  // card opens and again after each roster reload — never per roster row. Keyed by the
  // membership id so a slow answer for a previous card is never shown on the next one.
  const selectedAmid = selected && !selected.offlinePending && Number(selected.activeMembershipId) > 0
    ? Number(selected.activeMembershipId) : 0;
  const [cardInfo, setCardInfo] = useState<{ amid: number; data: MemberCardResponse | null; error: string | null }>({ amid: 0, data: null, error: null });
  useEffect(() => {
    if (!selectedAmid) return;
    let alive = true;
    setCardInfo((c) => (c.amid === selectedAmid ? c : { amid: selectedAmid, data: null, error: null }));
    get<MemberCardResponse>(`/members/${selectedAmid}/card`)
      .then((d) => { if (alive) setCardInfo({ amid: selectedAmid, data: d, error: null }); })
      .catch((e) => { if (alive) setCardInfo({ amid: selectedAmid, data: null, error: e?.message || String(e) }); });
    return () => { alive = false; };
  }, [selectedAmid, roster]);
  const card = cardInfo.amid === selectedAmid ? cardInfo : { amid: selectedAmid, data: null, error: null };

  // « Derniers passages »: same rule — read when the card opens, keyed by membership id.
  const [visitInfo, setVisitInfo] = useState<{ amid: number; data: MemberHistoryResponse | null; error: string | null }>({ amid: 0, data: null, error: null });
  useEffect(() => {
    if (!selectedAmid) return;
    let alive = true;
    setVisitInfo((c) => (c.amid === selectedAmid ? c : { amid: selectedAmid, data: null, error: null }));
    get<MemberHistoryResponse>(`/members/${selectedAmid}/history`, { limit: String(VISITS_SHOWN) })
      .then((d) => { if (alive) setVisitInfo({ amid: selectedAmid, data: d, error: null }); })
      .catch((e) => { if (alive) setVisitInfo({ amid: selectedAmid, data: null, error: e?.message || String(e) }); });
    return () => { alive = false; };
  }, [selectedAmid, roster]);
  const visits = visitInfo.amid === selectedAmid ? visitInfo : { amid: selectedAmid, data: null, error: null };

  // Rail figures. Every one is derived from the roster page the API returned
  // (rosterCounts) or from flags the backend already sets on each row
  // (offlinePending / hasConflict / pendingDelete / pendingMutations).
  const railFacts = useMemo(() => {
    const conflicts = roster.filter((m) => m.hasConflict);
    const offlineNew = roster.filter((m) => m.offlinePending);
    const deleting = roster.filter((m) => m.pendingDelete);
    const syncing = roster.filter((m) => !m.hasConflict && !m.pendingDelete && (m.pendingMutations?.length ?? 0) > 0);
    return { conflicts, offlineNew, deleting, syncing };
  }, [roster]);

  const waitingCount = railFacts.offlineNew.length + railFacts.syncing.length + railFacts.deleting.length;

  const firstNames = (rows: MemberRosterRow[], max = 3) =>
    rows.slice(0, max).map((m) => (m.fullName || "—").split(/\s+/)[0]).join(", ") +
    (rows.length > max ? ` +${rows.length - max}` : "");

  const openNewMember = () => {
    setQueueError(null);
    setMessage("");
    setMemberTab("account_plus_membership");
    setMemberOpen(true);
  };
  // Closing the form while a pending row is being modified abandons that
  // modification (the old « Cancel edit »), so a later « Nouveau membre »
  // can never PATCH the pending row by surprise.
  const onMemberOpenChange = (o: boolean) => {
    if (o) return;
    if (editing) cancelEdit();
    setMemberOpen(false);
  };
  const openDialogFor = (fn: () => void) => {
    setQueueError(null);
    setMessage("");
    fn();
  };

  const activeMutations = mutations.filter((mu) => MUTATION_ACTIVE_STATES.includes(mu.state));
  const hasMutationConflict = mutations.some((mu) => mu.state === "conflict");
  const allCount = rosterCounts.all ?? 0;

  usePageChrome(() => ({
    subtitle: `${allCount} abonnement${allCount > 1 ? "s" : ""} sur ce poste · copie locale du serveur`,
    actions: (
      <>
        <ActionButton
          kind="outline"
          icon={RefreshCw}
          spin={loading || queueLoading}
          disabled={loading || queueLoading}
          onClick={() => runAction(async () => {
            await Promise.all([reloadUsers(), loadMemberships(), refreshQueue(), loadRoster()]);
          })}
        >
          Recharger
        </ActionButton>
        {tab === "creations" && (
          <ActionButton kind="outline" icon={Repeat} onClick={() => runAction(() => post("/offline-creations/process-due", {}), "Nouvel essai lancé.")}>
            Réessayer maintenant
          </ActionButton>
        )}
        {tab === "mutations" ? (
          <ActionButton kind="outline" icon={Send} onClick={() => runMutationAction(() => post("/mutations/process-due", {}), "Envoi lancé.")}>
            Envoyer maintenant
          </ActionButton>
        ) : (
          <ActionButton kind="primary" icon={UserPlus} onClick={openNewMember}>Nouveau membre</ActionButton>
        )}
      </>
    ),
    // Deps are PRIMITIVES ONLY on purpose. `runAction` is a plain arrow
    // function (not useCallback), so it is a new reference on every render —
    // including it here re-ran this effect every render, which called
    // setChrome, which re-rendered, which… "Maximum update depth exceeded".
    // The handlers below are only invoked from clicks, and the loaders they
    // call (reloadUsers / loadMemberships / refreshQueue / loadRoster) are
    // stable useCallbacks, so capturing them from the last committed render is
    // correct.
    // rosterQ / rosterStatus / rosterPage: « Recharger » calls loadRoster,
    // which is rebuilt when they change — re-publish so it never reloads a
    // previous page, filter or search.
  }), [allCount, loading, queueLoading, tab, rosterQ, rosterStatus, rosterPage]);
  const rosterTotalPages = Math.max(1, Math.ceil(rosterTotal / ROSTER_SIZE));

  const canMutate = (m: MemberRosterRow) => !m.offlinePending && Number(m.activeMembershipId) > 0;

  // One line of the card fed by GET /members/{id}/card: loading, honest error, or the value.
  // An offline-created member has no server id yet, so nothing is read for it.
  const cardDetailLine = (
    Icon: LucideIcon,
    label: string,
    m: MemberRosterRow,
    show: (d: MemberCardResponse) => { v: string; muted?: boolean; tone?: Tone; title?: string },
  ) => {
    let v: string;
    let cls = "text-muted-foreground";
    let title: string | undefined;
    if (m.offlinePending || !(Number(m.activeMembershipId) > 0)) {
      v = "après synchronisation";
    } else if (card.error) {
      v = "indisponible";
      cls = INK.error;
      title = card.error;
    } else if (!card.data) {
      v = "chargement…";
    } else {
      const r = show(card.data);
      v = r.v;
      cls = r.tone ? INK[r.tone] : r.muted ? "text-muted-foreground" : "text-foreground";
      title = r.title;
    }
    return (
      <div className="mt-[9px] flex items-center gap-2.5 text-[13.5px]">
        <Icon className="h-[17px] w-[17px] shrink-0 text-muted-foreground" />
        <span className="flex-1">{label}</span>
        <span className={cn("text-right text-[12.5px]", cls)} title={title}>{v}</span>
      </div>
    );
  };

  // « Derniers passages »: door events stored on THIS PC for the member (GET /members/{id}/history).
  const renderVisits = (m: MemberRosterRow) => {
    const amid = Number(m.activeMembershipId);
    const d = visits.data;
    const retention = d?.retentionDays ?? null;
    const footnote = [
      `Passages vus par ce PC${d ? ` (les ${d.limit} derniers au plus)` : ""}.`,
      retention ? `Ceux de plus de ${retention} jours peuvent avoir été effacés.` : "",
      "Un passage non rattaché à un membre n'apparaît pas.",
    ].filter(Boolean).join(" ");
    let body: ReactNode;
    if (m.offlinePending || !(amid > 0)) {
      body = <div className="mt-2 text-[12.5px] text-muted-foreground">Disponible après synchronisation.</div>;
    } else if (visits.error) {
      body = <div className={cn("mt-2 text-[12.5px]", INK.error)} title={visits.error}>Historique indisponible.</div>;
    } else if (!d) {
      body = <div className="mt-2 text-[12.5px] text-muted-foreground">Chargement…</div>;
    } else if (d.rows.length === 0) {
      body = <div className="mt-2 text-[12.5px] text-muted-foreground">Aucun passage enregistré sur ce PC.</div>;
    } else {
      body = (
        <div className="mt-1">
          {d.rows.map((r) => {
            const other = r.activeMembershipId != null && Number(r.activeMembershipId) !== amid;
            const where = [r.deviceName || (r.deviceId != null ? `Appareil #${r.deviceId}` : ""), r.doorId != null ? `porte ${r.doorId}` : ""].filter(Boolean).join(" · ");
            const sub = [r.allowed ? visitMethod(r.method) : aDenyCopy(r.reason).short, where, other ? "autre abonnement" : ""].filter(Boolean).join(" · ");
            return (
              <div key={r.id} className="mt-[7px] flex items-start gap-2.5 text-[13px]" title={r.allowed ? undefined : r.reason || undefined}>
                {r.allowed
                  ? <CircleCheck className={cn("mt-[1px] h-4 w-4 shrink-0", INK.success)} />
                  : <CircleX className={cn("mt-[1px] h-4 w-4 shrink-0", INK.error)} />}
                <div className="min-w-0 flex-1">
                  <div className="font-mono text-[12.5px]">{visitTime(r.at)}</div>
                  <div className="truncate text-[12px] text-muted-foreground">{sub || "—"}</div>
                </div>
              </div>
            );
          })}
        </div>
      );
    }
    return (
      <div className="border-b border-dashed border-grey/20 px-[18px] py-3">
        <div className="text-[12px] font-bold uppercase tracking-[0.04em] text-muted-foreground">Derniers passages</div>
        {body}
        {amid > 0 && !m.offlinePending ? <div className="mt-2 text-[11.5px] text-muted-foreground">{footnote}</div> : null}
      </div>
    );
  };

  // ── Fiche membre (right rail) ─────────────────────────────────────────
  const renderFiche = (m: MemberRosterRow) => {
    const st = statusOf(m.status);
    const flag = rowFlag(m);
    const left = daysLeftText(m);
    const pct = periodUsedPct(m);
    const headBg: Record<Tone, string> = {
      primary: "bg-primary/6", success: "bg-success/6", warning: "bg-warning/6",
      error: "bg-error/6", info: "bg-info/6", grey: "bg-grey/6",
    };
    const bar: Record<Tone, string> = {
      primary: "bg-primary", success: "bg-success", warning: "bg-warning",
      error: "bg-error", info: "bg-info", grey: "bg-grey",
    };
    const creds = [
      { icon: IdCard, l: "Identifiant compte", v: n(m.accountUsernameId) },
      { icon: CreditCard, l: "Carte", v: n(m.firstCardId) },
      { icon: CreditCard, l: "Deuxième carte", v: n(m.secondCardId) },
    ];
    return (
      <Panel className="col-span-4">
        <div className={cn("relative flex items-center gap-3.5 p-[18px] pr-12", headBg[st.tone])}>
          <Avatar initials={initialsOf(m.fullName || "")} tone={m.hasConflict ? "error" : st.tone} size={56} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-[17px] font-bold">{m.fullName || "—"}</div>
            <div className="truncate text-[12.5px] text-muted-foreground">
              {[n(m.phone), n(m.email)].filter(Boolean).join(" · ") || "—"}
            </div>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              <Chip tone={st.tone}>{st.l}</Chip>
              {flag ? <Chip tone={flag.tone}>{flag.label}</Chip> : null}
            </div>
          </div>
          <ActionButton kind="ghost" size="xs" iconOnly icon={X} className="absolute right-3 top-3" onClick={() => setSelectedKey(null)}>
            Fermer la fiche
          </ActionButton>
        </div>
        <div className="border-b border-dashed border-grey/20 px-[18px] py-3.5">
          <div className="flex items-baseline gap-2.5">
            <span className="min-w-0 truncate text-[14.5px] font-bold">{m.membershipTitle || (m.membershipId ?? "—")}</span>
            <span className="flex-1" />
            {left ? <span className={cn("whitespace-nowrap text-[13.5px] font-bold", INK[st.tone])}>{left}</span> : null}
          </div>
          {pct != null && (
            <div className="mt-2.5 h-2 rounded-full bg-muted">
              <div className={cn("h-2 rounded-full", bar[st.tone])} style={{ width: `${pct}%` }} />
            </div>
          )}
          <div className="mt-1.5 flex justify-between text-[12px] text-muted-foreground">
            <span>du {frDate(m.validFrom)}</span>
            <span>au {frDate(m.validTo)}</span>
          </div>
        </div>
        <div className="border-b border-dashed border-grey/20 px-[18px] py-3">
          <div className="text-[12px] font-bold uppercase tracking-[0.04em] text-muted-foreground">Identifiants</div>
          {creds.map((c) => (
            <div key={c.l} className="mt-[9px] flex items-center gap-2.5 text-[13.5px]">
              <c.icon className="h-[17px] w-[17px] shrink-0 text-muted-foreground" />
              <span className="flex-1">{c.l}</span>
              <span className={cn("font-mono text-[12.5px]", c.v ? "text-foreground" : "text-muted-foreground")}>{c.v || "—"}</span>
            </div>
          ))}
          {cardDetailLine(Fingerprint, "Empreintes", m, (d) => {
            if (d.fingerprintCount === 0) return { v: "aucune", muted: true };
            const ids = d.fingerprints.map((f) => (f.fingerId != null ? `#${f.fingerId}${f.enabled ? "" : " (désactivée)"}` : "?"));
            return { v: `${d.fingerprintCount} · ${ids.join(", ")}`, title: "Copie locale du serveur" };
          })}
          {cardDetailLine(Snowflake, "Gel", m, (d) => {
            const f = d.freeze;
            if (!f) {
              return { v: "non connu", muted: true, title: "Les jours de gel viennent de la synchronisation (protocole 2) ; ce poste ne les a pas, ou ses données de dates ne sont pas fiables." };
            }
            const fmt = (iso: string) => frDate(iso).slice(0, 5);
            const next = f.nextFreezeDays.slice(0, 4).map(fmt).join(", ") + (f.nextFreezeDays.length > 4 ? ` +${f.nextFreezeDays.length - 4}` : "");
            const title = [
              f.horizonEnd ? `Jours de gel connus jusqu'au ${frDate(f.horizonEnd)}${f.beyondHorizon ? " ; le serveur en signale d'autres après" : ""}.` : "",
              "Les dates de début et de fin du gel ne sont pas synchronisées : seuls ces jours sont connus.",
            ].filter(Boolean).join(" ");
            if (f.frozenToday) return { v: next ? `gelé aujourd'hui · puis ${next}` : "gelé aujourd'hui", tone: "info", title };
            if (next) return { v: `prochains jours : ${next}`, title };
            return { v: f.beyondHorizon ? "aucun jour proche" : "aucun jour prévu", muted: true, title };
          })}
          {cardDetailLine(QrCode, "QR code (application)", m, (d) => {
            const on = d.qrCredentials.filter((c) => c.enabled);
            const why = "Accordé à cet abonnement par le serveur (copie locale). Le contrôle QR peut encore refuser un passage (jours d'accès, liste des membres).";
            if (on.length > 0) return { v: "activé sur le compte", tone: "success", title: why };
            if (d.qrCredentials.length > 0) return { v: "désactivé", muted: true, title: why };
            return { v: "aucun", muted: true };
          })}
        </div>
        {renderVisits(m)}
        <div className="flex flex-wrap gap-2 px-[18px] pb-4 pt-3">
          {canMutate(m) ? (
            <>
              <ActionButton kind="dark" size="md" icon={Pencil} disabled={mutBusy} onClick={() => openDialogFor(() => openEdit(m))}>Modifier</ActionButton>
              <ActionButton kind="outline" size="md" icon={Snowflake} disabled={mutBusy} onClick={() => openDialogFor(() => setFreezeTarget(m))}>Geler</ActionButton>
            </>
          ) : null}
          <ActionButton kind="outline" size="md" icon={ImagePlus} disabled={photoBusy} onClick={() => pickPhoto(m)}>Photo</ActionButton>
          <ActionButton kind="outline" size="md" icon={Fingerprint} onClick={() => setEnrollMember(m)}>Empreinte</ActionButton>
          {canMutate(m) ? (
            <ActionButton kind="danger" size="md" icon={Trash2} disabled={mutBusy} onClick={() => openDialogFor(() => setDeleteTarget(m))}>Supprimer</ActionButton>
          ) : null}
        </div>
      </Panel>
    );
  };

  // ── Tab: Répertoire ───────────────────────────────────────────────────
  const rosterTab = (
    <PageGrid>
      <Panel className="col-span-8">
        <div className="flex flex-wrap items-center gap-2.5 px-[18px] pt-4">
          <div className="flex h-9 min-w-[200px] flex-1 items-center gap-2 rounded-lg border border-grey/32 bg-card px-3 focus-within:border-primary">
            <Search className="h-[17px] w-[17px] shrink-0 text-muted-foreground" />
            <input
              value={rosterQInput}
              onChange={(e) => setRosterQInput(e.target.value)}
              placeholder="Nom, e-mail, téléphone, carte…"
              aria-label="Rechercher un membre"
              className="min-w-0 flex-1 bg-transparent text-[13.5px] text-foreground outline-none placeholder:text-muted-foreground"
            />
            {rosterLoading ? <Loader2 className="h-4 w-4 shrink-0 animate-spin text-muted-foreground" /> : null}
          </div>
          <Segmented
            ariaLabel="Filtrer par statut"
            value={rosterStatus}
            onChange={(v) => { setRosterPage(0); setRosterStatus(v); }}
            items={[
              { value: "all", label: "Tous", count: rosterCounts.all ?? 0 },
              { value: "active", label: "Actifs", count: rosterCounts.active ?? 0 },
              { value: "expired", label: "Expirés", count: rosterCounts.expired ?? 0 },
              { value: "pending", label: "En attente", count: rosterCounts.pending ?? 0 },
            ]}
          />
        </div>
        <FlexTable
          label="Répertoire des abonnements"
          columns={[
            { label: "Nom complet", flex: 2.4 },
            { label: "Abonnement", flex: 1.3 },
            { label: "Fin", flex: 1.05 },
            { label: "Statut", flex: 0.8 },
            { label: "Actions", flex: 1.75, align: "right" },
          ]}
          empty={(
            <div className="flex flex-col items-center gap-1.5">
              <UsersIcon className="h-8 w-8 text-muted-foreground/40" />
              <span className="font-semibold text-foreground">Aucun membre ne correspond</span>
              <span className="max-w-[340px] text-[12.5px]">
                Ajustez la recherche ou le filtre, ou synchronisez pour charger le répertoire.
              </span>
            </div>
          )}
          footer={(
            <>
              <span className="flex-1">
                {rosterTotal} abonnement{rosterTotal > 1 ? "s" : ""} · page {rosterPage + 1} sur {rosterTotalPages}
              </span>
              <ActionButton kind="outline" size="sm" icon={ChevronLeft} disabled={rosterPage <= 0} onClick={() => setRosterPage((p) => Math.max(0, p - 1))}>
                Précédent
              </ActionButton>
              <ActionButton kind="outline" size="sm" disabled={rosterPage + 1 >= rosterTotalPages} onClick={() => setRosterPage((p) => p + 1)}>
                Suivant<ChevronRight />
              </ActionButton>
            </>
          )}
        >
          {roster.map((m) => {
            const st = statusOf(m.status);
            const flag = rowFlag(m);
            const left = daysLeftText(m);
            const key = memberKey(m);
            return (
              <FlexRow key={key} minHeight={58} selected={key === selectedKey}>
                <FlexCell flex={2.4}>
                  <Avatar initials={initialsOf(m.fullName || "")} tone={m.hasConflict ? "error" : st.tone} />
                  <CellText
                    title={m.fullName || "—"}
                    sub={m.email || m.accountUsernameId || ""}
                    strong
                    flags={flag ? [flag] : undefined}
                  />
                </FlexCell>
                <FlexCell flex={1.3}>
                  <CellText title={m.membershipTitle || (m.membershipId ?? "—")} sub={m.phone || ""} subMono />
                </FlexCell>
                <FlexCell flex={1.05}>
                  <CellText
                    title={frDate(m.validTo)}
                    sub={left}
                    mono
                    subClassName={m.status === "expired" ? INK.error : undefined}
                  />
                </FlexCell>
                <FlexCell flex={0.8}><Chip tone={st.tone}>{st.l}</Chip></FlexCell>
                <FlexCell flex={1.75} align="right" className="gap-1">
                  <ActionButton kind="outline" size="xs" iconOnly icon={Eye} title="Voir la fiche" onClick={() => setSelectedKey(key)}>Voir la fiche</ActionButton>
                  {canMutate(m) ? (
                    <>
                      <ActionButton kind="outline" size="xs" iconOnly icon={Pencil} title="Modifier l'abonnement" disabled={mutBusy} onClick={() => openDialogFor(() => openEdit(m))}>Modifier l'abonnement</ActionButton>
                      <ActionButton kind="outline" size="xs" iconOnly icon={Snowflake} title="Geler l'abonnement" disabled={mutBusy} onClick={() => openDialogFor(() => setFreezeTarget(m))}>Geler l'abonnement</ActionButton>
                    </>
                  ) : null}
                  <ActionButton kind="outline" size="xs" iconOnly icon={Fingerprint} title="Enrôler une empreinte" onClick={() => setEnrollMember(m)}>Enrôler une empreinte</ActionButton>
                  {canMutate(m) ? (
                    <ActionButton kind="danger" size="xs" iconOnly icon={Trash2} title="Supprimer l'abonnement" disabled={mutBusy} onClick={() => openDialogFor(() => setDeleteTarget(m))}>Supprimer l'abonnement</ActionButton>
                  ) : null}
                </FlexCell>
              </FlexRow>
            );
          })}
        </FlexTable>
      </Panel>

      {selected ? renderFiche(selected) : (
        <div className="col-span-4 flex flex-col gap-[18px]">
          <Panel>
            <PanelHeader title="À traiter" sub={`Sur la page affichée (${roster.length} abonnement${roster.length > 1 ? "s" : ""})`} />
            <PanelList>
              {railFacts.conflicts.length > 0 && (
                <ListRow
                  icon={TriangleAlert}
                  tone="error"
                  wrap
                  title={`${railFacts.conflicts.length} conflit${railFacts.conflicts.length > 1 ? "s" : ""} à arbitrer`}
                  sub={`${firstNames(railFacts.conflicts)} — modifié hors ligne et sur le serveur`}
                  actions={<ActionButton kind="outline" size="sm" onClick={() => setTab("mutations")}>Ouvrir la file</ActionButton>}
                />
              )}
              {waitingCount > 0 && (
                <ListRow
                  icon={CloudUpload}
                  tone="warning"
                  wrap
                  title={`${waitingCount} en attente de synchro`}
                  sub={[
                    railFacts.offlineNew.length > 0 ? `${firstNames(railFacts.offlineNew)} — créés hors ligne` : "",
                    railFacts.syncing.length > 0 ? `${railFacts.syncing.length} modification${railFacts.syncing.length > 1 ? "s" : ""}` : "",
                    railFacts.deleting.length > 0 ? `${railFacts.deleting.length} suppression${railFacts.deleting.length > 1 ? "s" : ""}` : "",
                  ].filter(Boolean).join(" · ")}
                  actions={(
                    <ActionButton
                      kind="outline"
                      size="sm"
                      icon={RefreshCw}
                      onClick={() => {
                        // Offline creations and offline changes/deletions are two queues.
                        if (railFacts.offlineNew.length > 0) void runAction(() => post("/offline-creations/process-due", {}), "Nouvel essai lancé.");
                        if (railFacts.syncing.length + railFacts.deleting.length > 0) void runMutationAction(() => post("/mutations/process-due", {}), "Envoi lancé.");
                      }}
                    >
                      Envoyer maintenant
                    </ActionButton>
                  )}
                />
              )}
              {railFacts.conflicts.length === 0 && waitingCount === 0 && (
                <ListRow icon={CircleCheck} tone="success" wrap title="Rien à traiter" sub="Aucun conflit ni fiche en attente sur cette page." />
              )}
            </PanelList>
          </Panel>

          <Panel>
            <PanelHeader title="L'effectif" sub="Un membre peut avoir plusieurs abonnements" />
            <div className="flex items-baseline gap-2.5 px-[18px] pt-3">
              <span className="font-num text-[30px] font-bold leading-none">{allCount}</span>
              <span className="text-[13px] text-muted-foreground">abonnement{allCount > 1 ? "s" : ""}</span>
            </div>
            <PanelList>
              {([
                ["Actifs", rosterCounts.active ?? 0, CircleCheck, "success"],
                ["Expirés", rosterCounts.expired ?? 0, CircleX, "error"],
                ["En attente (créés hors ligne)", rosterCounts.pending ?? 0, CloudUpload, "info"],
              ] as const).map(([l, v, icon, tone]) => (
                <ListRow
                  key={l}
                  icon={icon}
                  tone={tone}
                  title={l}
                  value={String(v)}
                  bar={allCount > 0 ? (v / allCount) * 100 : 0}
                  barTone={tone}
                />
              ))}
            </PanelList>
          </Panel>
        </div>
      )}
    </PageGrid>
  );

  // ── Tab: Créations hors ligne ─────────────────────────────────────────
  const creationsTab = (
    <Panel>
      <PanelHeader
        title="Créations en attente"
        sub="Tentées en ligne d'abord ; quand la création échoue et que vous choisissez « Enregistrer pour plus tard », elle attend ici"
      />
      <FlexTable
        label="Créations en attente"
        columns={[
          { label: "Membre", flex: 1.7 },
          { label: "Type", flex: 1.1 },
          { label: "État", flex: 1.15 },
          { label: "Essai auto", flex: 0.7 },
          { label: "Échecs", flex: 0.55, align: "right" },
          { label: "Prochain essai", flex: 1.1 },
          { label: "Dernière erreur", flex: 1.5 },
          { label: "Actions", flex: 1.55, align: "right" },
        ]}
        empty="Aucune création en attente."
      >
        {activeRows.map((row) => {
          const st = creationState(row.state);
          return (
            <FlexRow key={row.local_id} minHeight={60}>
              <FlexCell flex={1.7}><CellText title={payloadName(row.payload)} sub={row.local_id} strong subMono /></FlexCell>
              <FlexCell flex={1.1}><CellText title={KIND_FR[row.creation_kind] ?? row.creation_kind} /></FlexCell>
              <FlexCell flex={1.15}><Chip tone={st.tone}>{st.l}</Chip></FlexCell>
              <FlexCell flex={0.7}><CellText title={row.try_to_create ? "oui" : "non"} /></FlexCell>
              <FlexCell flex={0.55} align="right"><CellText title={String(row.failure_count ?? 0)} /></FlexCell>
              <FlexCell flex={1.1}><CellText title={ts(row.next_retry_at)} mono titleClassName="text-[12.5px] text-muted-foreground" /></FlexCell>
              <FlexCell flex={1.5} title={row.last_error_message || ""}>
                <CellText title={row.last_error_message || "—"} titleClassName={row.last_error_message ? INK.error : "text-muted-foreground"} />
              </FlexCell>
              <FlexCell flex={1.55} align="right" className="gap-1">
                <ActionButton kind="outline" size="xs" iconOnly icon={Pencil} title="Modifier" onClick={() => editRow(row)}>Modifier</ActionButton>
                <ActionButton kind="outline" size="xs" iconOnly icon={RefreshCw} title="Réessayer" onClick={() => runAction(() => post(`/offline-creations/${row.local_id}/retry`, {}), "Nouvel essai lancé pour cette création.")}>Réessayer</ActionButton>
                <ActionButton
                  kind="outline" size="xs" iconOnly
                  icon={row.try_to_create ? CirclePause : CirclePlay}
                  title={row.try_to_create ? "Mettre en pause l'essai auto" : "Reprendre l'essai auto"}
                  onClick={() => runAction(() => post(`/offline-creations/${row.local_id}/toggle`, { enabled: !row.try_to_create }), "Essai automatique mis à jour.")}
                >
                  {row.try_to_create ? "Mettre en pause l'essai auto" : "Reprendre l'essai auto"}
                </ActionButton>
                <ActionButton kind="outline" size="xs" iconOnly icon={Copy} title="Dupliquer" onClick={() => runAction(() => post(`/offline-creations/${row.local_id}/duplicate`, {}), "Création dupliquée.")}>Dupliquer</ActionButton>
                <ActionButton kind="danger" size="xs" iconOnly icon={X} title="Annuler la création" onClick={() => runAction(() => post(`/offline-creations/${row.local_id}/cancel`, {}), "Création annulée.")}>Annuler la création</ActionButton>
              </FlexCell>
            </FlexRow>
          );
        })}
      </FlexTable>
    </Panel>
  );

  // ── Tab: Historique traité ────────────────────────────────────────────
  const HISTORY_FILTER_FR: Record<"all" | OfflineCreationState, string> = {
    all: "Tous", succeeded: "Créés", reconciled: "Rapprochés", cancelled: "Annulés",
    failed_terminal: "Échec définitif", archived: "Archivés",
    pending: "En attente", processing: "Envoi", failed_retryable: "Échec", blocked_auth: "Bloqués",
  };
  const historyTab = (
    <Panel>
      <PanelHeader title="Historique traité" sub="Créations terminées : 500 dernières lignes">
        <Segmented<"all" | OfflineCreationState>
          ariaLabel="Filtrer par état final"
          value={historyFilter}
          onChange={setHistoryFilter}
          items={(["all", ...HISTORY_STATES] as ("all" | OfflineCreationState)[]).map((s) => ({ value: s, label: HISTORY_FILTER_FR[s] }))}
        />
      </PanelHeader>
      <FlexTable
        label="Historique traité"
        columns={[
          { label: "Membre", flex: 1.6 },
          { label: "Type", flex: 1.1 },
          { label: "État final", flex: 1 },
          { label: "Mis à jour", flex: 1.1 },
          { label: "Type d'échec", flex: 0.9 },
          { label: "Message", flex: 1.8 },
          { label: "Actions", flex: 0.8, align: "right" },
        ]}
        empty="Aucune création pour ce filtre."
      >
        {historyRows.map((row) => {
          const st = creationState(row.state);
          return (
            <FlexRow key={row.local_id} minHeight={58}>
              <FlexCell flex={1.6}><CellText title={payloadName(row.payload)} sub={row.local_id} strong subMono /></FlexCell>
              <FlexCell flex={1.1}><CellText title={KIND_FR[row.creation_kind] ?? row.creation_kind} /></FlexCell>
              <FlexCell flex={1}><Chip tone={st.tone}>{st.l}</Chip></FlexCell>
              <FlexCell flex={1.1}><CellText title={ts(row.updated_at)} mono titleClassName="text-[12.5px] text-muted-foreground" /></FlexCell>
              <FlexCell flex={0.9}>
                <CellText title={row.failure_type ? (FAILURE_TYPE_FR[row.failure_type] ?? row.failure_type) : "—"} titleClassName="text-muted-foreground" />
              </FlexCell>
              <FlexCell flex={1.8} title={row.last_error_message || ""}>
                <CellText title={row.last_error_message || "—"} titleClassName={row.last_error_message ? undefined : "text-muted-foreground"} />
              </FlexCell>
              <FlexCell flex={0.8} align="right" className="gap-1">
                <ActionButton kind="outline" size="xs" iconOnly icon={Copy} title="Dupliquer" onClick={() => runAction(() => post(`/offline-creations/${row.local_id}/duplicate`, {}), "Création dupliquée.")}>Dupliquer</ActionButton>
                {row.state !== "archived" ? (
                  <ActionButton kind="outline" size="xs" iconOnly icon={Archive} title="Archiver" onClick={() => runAction(() => post(`/offline-creations/${row.local_id}/archive`, {}), "Création archivée.")}>Archiver</ActionButton>
                ) : null}
              </FlexCell>
            </FlexRow>
          );
        })}
      </FlexTable>
    </Panel>
  );

  // ── Tab: Modifications d'abonnement ───────────────────────────────────
  const mutationsTab = (
    <Panel>
      <PanelHeader
        title="Modifications d'abonnement"
        sub="Modifier, geler, supprimer : appliqué en ligne si possible, sinon mis en file et envoyé automatiquement"
      />
      <FlexTable
        label="Modifications d'abonnement"
        columns={[
          { label: "Opération", flex: 1.2 },
          { label: "Abonnement", flex: 0.9 },
          { label: "État", flex: 1.1 },
          { label: "Argent", flex: 0.6 },
          { label: "Erreur", flex: 2 },
          { label: "Actions", flex: 1.9, align: "right" },
        ]}
        empty="Aucune modification en file."
      >
        {mutations.map((mu) => {
          const st = mutationState(mu.state);
          const days = mu.op_kind === "freeze_create" ? Number(mu.payload?.durationInDays) : NaN;
          const op = Number.isFinite(days) && days > 0 ? `${opLabel(mu.op_kind)} · ${days} jour${days > 1 ? "s" : ""}` : opLabel(mu.op_kind);
          return (
            <FlexRow key={mu.local_id} minHeight={60}>
              <FlexCell flex={1.2}><CellText title={op} strong /></FlexCell>
              <FlexCell flex={0.9}><CellText title={`#${mu.target_id}`} mono /></FlexCell>
              <FlexCell flex={1.1}><Chip tone={st.tone}>{st.l}</Chip></FlexCell>
              <FlexCell flex={0.6}>{mu.money ? <Chip tone="warning" size="sm">argent</Chip> : <CellText title="—" titleClassName="text-muted-foreground" />}</FlexCell>
              <FlexCell flex={2} title={mu.last_error_message || ""}>
                <CellText title={mu.last_error_message || "—"} titleClassName={mu.last_error_message ? INK.error : "text-muted-foreground"} />
              </FlexCell>
              <FlexCell flex={1.9} align="right" className="gap-1.5">
                {mu.state === "conflict" ? (
                  <ActionButton kind="danger" size="sm" onClick={() => runMutationAction(() => post(`/mutations/${mu.local_id}/resolve`, { action: "abort" }), "Modification abandonnée.")}>
                    Abandonner ma modification
                  </ActionButton>
                ) : null}
                {MUTATION_ACTIVE_STATES.includes(mu.state) && mu.state !== "conflict" ? (
                  <ActionButton kind="outline" size="sm" onClick={() => runMutationAction(() => post(`/mutations/${mu.local_id}/retry`, {}), "Nouvel essai lancé.")}>Réessayer</ActionButton>
                ) : null}
                {MUTATION_ACTIVE_STATES.includes(mu.state) ? (
                  <ActionButton kind="danger" size="sm" onClick={() => runMutationAction(() => post(`/mutations/${mu.local_id}/cancel`, {}), "Modification annulée.")}>Annuler</ActionButton>
                ) : null}
              </FlexCell>
            </FlexRow>
          );
        })}
      </FlexTable>
    </Panel>
  );

  const editingKind = editing?.creation_kind ?? null;
  const formKind: OfflineCreationKind = editingKind ?? memberTab;

  return (
    <div className="flex flex-col gap-[18px]">
      <LineTabs<UsersTab>
        className="-mt-1"
        value={tab}
        onChange={setTab}
        items={[
          { value: "roster", label: "Répertoire", icon: UsersIcon, count: allCount },
          { value: "creations", label: "Créations hors ligne", icon: CloudUpload, count: activeRows.length, countTone: activeRows.length > 0 ? "warning" : undefined },
          { value: "history", label: "Historique traité", icon: History },
          {
            value: "mutations", label: "Modifications d'abonnement", icon: ArrowRightLeft,
            count: activeMutations.length, countTone: hasMutationConflict ? "error" : activeMutations.length > 0 ? "warning" : undefined,
          },
        ]}
      />

      {error ? <Note tone="error">Impossible de charger la copie locale des membres : {error}</Note> : null}
      {queueError ? <Note tone="error">{queueError}</Note> : null}
      {message ? <Note tone="success">{message}</Note> : null}

      {tab === "roster" && rosterTab}
      {tab === "creations" && creationsTab}
      {tab === "history" && historyTab}
      {tab === "mutations" && mutationsTab}

      {/* ----- Nouveau membre / abonnement pour un membre existant ----- */}
      <DialogFrame
        open={memberOpen}
        onOpenChange={onMemberOpenChange}
        lockOutside
        width={640}
        title={formKind === "account_plus_membership" ? "Nouveau membre" : "Nouvel abonnement"}
        sub={formKind === "account_plus_membership"
          ? "Compte + premier abonnement · envoyé en ligne d'abord ; en cas d'échec, à corriger ou à garder pour plus tard"
          : "Pour un membre déjà présent dans la copie locale · envoyé en ligne d'abord ; en cas d'échec, à corriger ou à garder pour plus tard"}
        tabs={editingKind ? undefined : (
          <LineTabs<OfflineCreationKind>
            size="dialog"
            value={memberTab}
            onChange={setMemberTab}
            items={[
              { value: "account_plus_membership", label: "Nouveau membre" },
              { value: "membership_only", label: "Membre existant" },
            ]}
          />
        )}
        footer={(
          <>
            <ActionButton kind="outline" className="px-4" onClick={() => onMemberOpenChange(false)}>
              {editingKind ? "Annuler la modification" : "Fermer"}
            </ActionButton>
            {formKind === "account_plus_membership" ? (
              <ActionButton kind="primary" className="px-4" onClick={submitAccount}>
                {editingKind ? "Enregistrer la création en attente" : "Créer le membre"}
              </ActionButton>
            ) : (
              <ActionButton kind="primary" className="px-4" onClick={submitMembership}>
                {editingKind ? "Enregistrer la création en attente" : "Créer l'abonnement"}
              </ActionButton>
            )}
          </>
        )}
      >
        {editing ? (
          <Note className="mb-1">
            Modification de la création en attente <span className="font-mono">{editing.local_id}</span> : corrigez les valeurs puis enregistrez pour qu'elle reste valide.
          </Note>
        ) : null}
        {formKind === "account_plus_membership" ? (
          <FieldGrid>
            <FieldSection>Identité</FieldSection>
            <FormField label="Prénom"><FieldInput value={accountForm.firstname} onChange={(e) => setAccount({ firstname: e.target.value })} /></FormField>
            <FormField label="Nom"><FieldInput value={accountForm.lastname} onChange={(e) => setAccount({ lastname: e.target.value })} /></FormField>
            <FormField label="E-mail"><FieldInput value={accountForm.email} onChange={(e) => setAccount({ email: e.target.value })} /></FormField>
            <FormField label="Téléphone"><FieldInput value={accountForm.phone} onChange={(e) => setAccount({ phone: e.target.value })} /></FormField>
            <FormField label="Mot de passe (8 caractères min.)"><FieldInput type="password" value={accountForm.password} onChange={(e) => setAccount({ password: e.target.value })} /></FormField>
            <FormField label="Identifiant compte (facultatif)"><FieldInput value={accountForm.accountUsernameId} onChange={(e) => setAccount({ accountUsernameId: e.target.value })} /></FormField>

            <FieldSection>Profil</FieldSection>
            <FormField label="CIN"><FieldInput className="font-mono" value={accountForm.cin} onChange={(e) => setAccount({ cin: e.target.value })} /></FormField>
            <FormField label="Date de naissance"><FieldInput type="date" value={accountForm.birthday} onChange={(e) => setAccount({ birthday: e.target.value })} /></FormField>
            <FormField label="Genre">
              <Select value={accountForm.gender || NONE} onValueChange={(v) => setAccount({ gender: v === NONE ? "" : v })}>
                <FieldSelectTrigger><SelectValue placeholder="—" /></FieldSelectTrigger>
                <SelectContent>
                  <SelectItem value={NONE}>—</SelectItem>
                  {GENDERS.map((g) => <SelectItem key={g.v} value={g.v}>{g.l}</SelectItem>)}
                </SelectContent>
              </Select>
            </FormField>
            <FormField label="Groupe sanguin">
              <Select value={accountForm.bloodType || NONE} onValueChange={(v) => setAccount({ bloodType: v === NONE ? "" : v })}>
                <FieldSelectTrigger><SelectValue placeholder="—" /></FieldSelectTrigger>
                <SelectContent>
                  <SelectItem value={NONE}>—</SelectItem>
                  {BLOOD_TYPES.map((b) => <SelectItem key={b} value={b}>{b === "UNDEFINED" ? "Non précisé" : b.replace("_PLUS", "+").replace("_MINUS", "-")}</SelectItem>)}
                </SelectContent>
              </Select>
            </FormField>
            <FormField label="Gouvernorat">
              <Select value={accountForm.city || NONE} onValueChange={(v) => setAccount({ city: v === NONE ? "" : v })}>
                <FieldSelectTrigger><SelectValue placeholder="—" /></FieldSelectTrigger>
                <SelectContent>
                  <SelectItem value={NONE}>—</SelectItem>
                  {CITIES.map((c) => <SelectItem key={c.v} value={c.v}>{c.l}</SelectItem>)}
                </SelectContent>
              </Select>
            </FormField>
            <FormField label="Contact d'urgence"><FieldInput value={accountForm.emergencyContactName} onChange={(e) => setAccount({ emergencyContactName: e.target.value })} /></FormField>
            <FormField label="Téléphone d'urgence"><FieldInput value={accountForm.emergencyContactPhone} onChange={(e) => setAccount({ emergencyContactPhone: e.target.value })} /></FormField>

            <FieldSection>Abonnement</FieldSection>
            <MembershipSelect value={accountForm.membershipId} memberships={memberships} onChange={(v) => setAccount({ membershipId: v })} />
            <FormField label="Date de début"><FieldInput type="date" value={accountForm.startDate} onChange={(e) => setAccount({ startDate: e.target.value })} /></FormField>
            <FormField label="Date de fin"><FieldInput type="date" value={accountForm.endDate} onChange={(e) => setAccount({ endDate: e.target.value })} /></FormField>
            <CardField label="N° de carte" value={accountForm.cardId} onChange={(v) => setAccount({ cardId: v })}
              scanKey="a.cardId" scanning={scanning} onScan={() => scanCard("a.cardId", (c) => setAccount({ cardId: c }))} />
            <CardField label="Deuxième carte" value={accountForm.secondCardId} onChange={(v) => setAccount({ secondCardId: v })}
              scanKey="a.secondCardId" scanning={scanning} onScan={() => scanCard("a.secondCardId", (c) => setAccount({ secondCardId: c }))} />
            <FormField label="Note (facultatif)" full><FieldInput value={accountForm.note} onChange={(e) => setAccount({ note: e.target.value })} /></FormField>

            <PaymentFields form={accountForm} set={setAccount} />
          </FieldGrid>
        ) : (
          <FieldGrid>
            <FieldSection>Membre</FieldSection>
            <FormField label="Identifiant compte" full>
              <FieldInput value={membershipForm.accountUsernameId} onChange={(e) => setMembership({ accountUsernameId: e.target.value })} />
            </FormField>

            <FieldSection>Abonnement</FieldSection>
            <MembershipSelect value={membershipForm.membershipId} memberships={memberships} onChange={(v) => setMembership({ membershipId: v })} />
            <FormField label="Date de début"><FieldInput type="date" value={membershipForm.startDate} onChange={(e) => setMembership({ startDate: e.target.value })} /></FormField>
            <FormField label="Date de fin"><FieldInput type="date" value={membershipForm.endDate} onChange={(e) => setMembership({ endDate: e.target.value })} /></FormField>
            <CardField label="N° de carte" value={membershipForm.cardId} onChange={(v) => setMembership({ cardId: v })}
              scanKey="m.cardId" scanning={scanning} onScan={() => scanCard("m.cardId", (c) => setMembership({ cardId: c }))} />
            <CardField label="Deuxième carte" value={membershipForm.secondCardId} onChange={(v) => setMembership({ secondCardId: v })}
              scanKey="m.secondCardId" scanning={scanning} onScan={() => scanCard("m.secondCardId", (c) => setMembership({ secondCardId: c }))} />
            <FormField label="Note (facultatif)" full><FieldInput value={membershipForm.note} onChange={(e) => setMembership({ note: e.target.value })} /></FormField>

            <PaymentFields form={membershipForm} set={setMembership} />
          </FieldGrid>
        )}
        <DialogMessages error={queueError} message={message} />
      </DialogFrame>

      {/* ----- creation failed: modify or save for later ----- */}
      <ConfirmDialog
        open={decisionOpen}
        onOpenChange={setDecisionOpen}
        width={520}
        title="Échec de la création"
        description="Modifiez les valeurs, ou enregistrez cette création pour un nouvel essai plus tard."
        cancelLabel={`Modifier${saveLaterRecommended ? "" : " (recommandé)"}`}
        confirmKind={saveLaterRecommended ? "primary" : "outline"}
        confirmLabel={`Enregistrer pour plus tard${saveLaterRecommended ? " (recommandé)" : ""}`}
        onConfirm={() => {
          const d = decision;
          if (!d) {
            setDecisionOpen(false);
            return;
          }
          void runAction(
            async () => {
              await post("/offline-creations/queue", {
                creationKind: d.creationKind,
                payload: d.payload,
                failure: {
                  failureType: d.attempt.failureType,
                  failureCode: d.attempt.failureCode,
                  lastHttpStatus: d.attempt.lastHttpStatus,
                  error: d.attempt.error,
                },
              });
              // Queued: clear that form so a later « Nouveau membre » does not resend it.
              if (d.creationKind === "membership_only") setMembershipForm({ ...MEMBERSHIP_FORM_INIT });
              else setAccountForm({ ...ACCOUNT_FORM_INIT });
            },
            "Création enregistrée dans la file hors ligne.",
          );
          setDecisionOpen(false);
          setDecision(null);
          setMemberOpen(false);
        }}
      >
        <div className="space-y-2 text-[13.5px]">
          {conflictHint ? <Note tone="warning">{conflictHint}</Note> : null}
          <p className="text-foreground">{decision?.attempt.error || "Erreur inconnue"}</p>
          <p className="font-mono text-[12px] text-muted-foreground">
            failure_type={decision?.attempt.failureType || "unknown"} | failure_code={decision?.attempt.failureCode || "-"} | http={decision?.attempt.lastHttpStatus ?? "-"}
          </p>
        </div>
      </ConfirmDialog>

      {/* ----- edit membership dialog ----- */}
      <DialogFrame
        open={!!editTarget}
        onOpenChange={(o) => { if (!o) setEditTarget(null); }}
        lockOutside
        width={560}
        title={`Modifier l'abonnement — ${editTarget?.fullName || ""}`}
        sub="Appliqué en ligne si possible, sinon mis en file et synchronisé automatiquement"
        footer={(
          <>
            <ActionButton kind="outline" className="px-4" onClick={() => setEditTarget(null)}>Annuler</ActionButton>
            <ActionButton kind="primary" className="px-4" onClick={submitEdit} disabled={mutBusy}>Enregistrer</ActionButton>
          </>
        )}
      >
        <FieldGrid>
          <FormField label="Date de début"><FieldInput type="date" value={editForm.startDate} onChange={(e) => setEditForm((s) => ({ ...s, startDate: e.target.value }))} /></FormField>
          <FormField label="Date de fin"><FieldInput type="date" value={editForm.endDate} onChange={(e) => setEditForm((s) => ({ ...s, endDate: e.target.value }))} /></FormField>
          <CardField label="N° de carte" value={editForm.cardId} onChange={(v) => setEditForm((s) => ({ ...s, cardId: v }))}
            scanKey="edit.cardId" scanning={scanning} onScan={() => scanCard("edit.cardId", (c) => setEditForm((s) => ({ ...s, cardId: c })))} />
          <CardField label="Deuxième carte" value={editForm.secondCardId} onChange={(v) => setEditForm((s) => ({ ...s, secondCardId: v }))}
            scanKey="edit.secondCardId" scanning={scanning} onScan={() => scanCard("edit.secondCardId", (c) => setEditForm((s) => ({ ...s, secondCardId: c })))} />
          <FormField label="Note (facultatif)" full><FieldInput value={editForm.note} onChange={(e) => setEditForm((s) => ({ ...s, note: e.target.value }))} /></FormField>
        </FieldGrid>
        <DialogMessages error={queueError} message={message} />
      </DialogFrame>

      {/* ----- freeze membership dialog ----- */}
      <DialogFrame
        open={!!freezeTarget}
        onOpenChange={(o) => { if (!o) setFreezeTarget(null); }}
        lockOutside
        width={520}
        title={`Geler l'abonnement — ${freezeTarget?.fullName || ""}`}
        sub="Met l'abonnement en pause pour la durée choisie"
        footer={(
          <>
            <ActionButton kind="outline" className="px-4" onClick={() => setFreezeTarget(null)}>Annuler</ActionButton>
            <ActionButton kind="primary" className="px-4" icon={Snowflake} onClick={submitFreeze} disabled={mutBusy}>Geler</ActionButton>
          </>
        )}
      >
        <FieldGrid>
          <FormField label="Date de début"><FieldInput type="date" value={freezeForm.startFreezeDate} onChange={(e) => setFreezeForm((s) => ({ ...s, startFreezeDate: e.target.value }))} /></FormField>
          <FormField label="Durée (jours)"><FieldInput type="number" value={freezeForm.durationInDays} onChange={(e) => setFreezeForm((s) => ({ ...s, durationInDays: e.target.value }))} /></FormField>
          <FormField label="Motif (facultatif)" full><FieldInput value={freezeForm.reason} onChange={(e) => setFreezeForm((s) => ({ ...s, reason: e.target.value }))} /></FormField>
          <FormField label="Note (facultatif)" full><FieldInput value={freezeForm.note} onChange={(e) => setFreezeForm((s) => ({ ...s, note: e.target.value }))} /></FormField>
        </FieldGrid>
        <DialogMessages error={queueError} message={message} />
      </DialogFrame>

      {/* ----- delete membership confirm ----- */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(o) => { if (!o) setDeleteTarget(null); }}
        title={`Supprimer l'abonnement — ${deleteTarget?.fullName || ""} ?`}
        description="Retire l'abonnement et la carte du membre des tourniquets. Appliqué en ligne si possible, sinon mis en file et synchronisé automatiquement."
        confirmLabel="Supprimer"
        confirmKind="danger"
        confirmDisabled={mutBusy}
        onConfirm={() => { void confirmDelete(); }}
      >
        {queueError ? <Note tone="error">{queueError}</Note> : null}
      </ConfirmDialog>

      <EnrollDialog member={enrollMember} onClose={() => setEnrollMember(null)} />
      <input ref={photoInputRef} type="file" accept="image/*" className="hidden" onChange={onPhotoFile} />
    </div>
  );
}
