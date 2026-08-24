
import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import { useUsers } from "@/api/hooks";
import { get, openSSE, patch, post } from "@/api/client";
import type {
  OfflineAttemptResponse,
  OfflineCreationKind,
  OfflineCreationRow,
  OfflineCreationState,
  OfflineQueueListResponse,
  UserDto,
} from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  ChevronLeft,
  ChevronRight,
  Clock3,
  Edit3,
  Fingerprint,
  ImagePlus,
  Pencil,
  RefreshCw,
  Repeat,
  Save,
  ScanLine,
  Search,
  Snowflake,
  Trash2,
  Users as UsersIcon,
  XCircle,
  UserPlus,
  CloudUpload,
  GitMerge,
  AlertCircle,
  CheckCircle2,
} from "lucide-react";
import { usePageChrome } from "@/context/PageChromeContext";
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
const GENDERS = [{ v: "MALE", l: "Male" }, { v: "FEMALE", l: "Female" }];
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
function badgeForState(state: OfflineCreationState): "default" | "secondary" | "destructive" | "outline" | "success" | "warning" {
  if (state === "succeeded") return "success";
  if (state === "reconciled") return "secondary";
  if (state === "cancelled") return "warning";
  if (state === "failed_terminal") return "destructive";
  if (state === "blocked_auth") return "warning";
  if (state === "processing") return "secondary";
  return "outline";
}
function statusBadge(status?: string): "success" | "destructive" | "warning" | "outline" {
  if (status === "active") return "success";
  if (status === "expired") return "destructive";
  if (status === "pending") return "warning";
  return "outline";
}

// Turn a raw backend error into an operator-friendly hint for the decision dialog.
// ── Access v3 roster primitives ────────────────────────────────────────────
const ROSTER_GRID = "grid grid-cols-[2fr_1.1fr_1.15fr_0.8fr_0.75fr_1.25fr] gap-[13px] items-center";
const LB = "text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground";

function initialsOf(name: string | null | undefined): string {
  const p = String(name || "").trim().split(/\s+/).filter(Boolean);
  if (!p.length) return "—";
  return ((p[0][0] || "") + (p.length > 1 ? p[p.length - 1][0] : "")).toUpperCase();
}

function RosterChip({ tone, children }: { tone: "ok" | "no" | "wn" | "flat"; children: React.ReactNode }) {
  const tones = {
    ok: "bg-emerald-500/[0.055] text-emerald-700 dark:text-emerald-400",
    no: "bg-primary/[0.09] text-primary",
    wn: "bg-amber-500/[0.14] text-amber-700 dark:text-amber-400",
    flat: "bg-muted text-muted-foreground",
  } as const;
  return (
    <span className={cn("inline-flex h-[18px] shrink-0 items-center whitespace-nowrap rounded-lg px-2 text-[10px] font-bold", tones[tone])}>
      {children}
    </span>
  );
}

function IconAction({ title, disabled, onClick, children }: {
  title: string; disabled?: boolean; onClick: () => void; children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      title={title}
      disabled={disabled}
      onClick={onClick}
      className="flex h-[26px] w-[26px] shrink-0 items-center justify-center rounded-lg border border-border text-muted-foreground transition-colors hover:text-foreground disabled:opacity-40"
    >
      {children}
    </button>
  );
}

function friendlyConflict(a: OfflineAttemptResponse | undefined): string | null {
  const msg = nl(a?.error);
  if (!msg) return null;
  if (msg.includes("card") && (msg.includes("use") || msg.includes("already"))) return "This card is already assigned to another member in this gym. Use a different card.";
  if (msg.includes("email") && msg.includes("exist")) return "An account with this email already exists.";
  if (msg.includes("username") && msg.includes("exist")) return "This username is already taken.";
  if (msg.includes("already has this membership")) return "This member already has this membership.";
  if (msg.includes("maximum number of members")) return "You reached the maximum number of members allowed for this gym.";
  if (msg.includes("password")) return "Password must be at least 8 characters.";
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
    <div className="space-y-2 rounded-md border border-dashed p-2">
      <div className="text-xs font-medium text-muted-foreground">Payment</div>
      <div className="grid grid-cols-2 gap-2">
        <div className="space-y-1"><Label>price</Label><Input type="number" inputMode="decimal" value={form.price} onChange={(e) => set({ price: e.target.value })} /></div>
        <div className="space-y-1"><Label>payedPrice</Label><Input type="number" inputMode="decimal" value={form.payedPrice} onChange={(e) => set({ payedPrice: e.target.value })} /></div>
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div className="space-y-1">
          <Label>paymentMethod</Label>
          <Select value={form.paymentMethod || "CASH"} onValueChange={(v) => set({ paymentMethod: v })}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>{PAYMENT_METHODS.map((m) => <SelectItem key={m} value={m}>{m}</SelectItem>)}</SelectContent>
          </Select>
        </div>
        <div className="space-y-1">
          <Label>paymentStatus</Label>
          <Select value={form.paymentStatus || "PENDING"} onValueChange={(v) => set({ paymentStatus: v })}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>{PAYMENT_STATUSES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent>
          </Select>
        </div>
      </div>
      <div className="space-y-1"><Label>remaining payment due date (optional)</Label><Input type="date" value={form.remainingPaymentDueDate} onChange={(e) => set({ remainingPaymentDueDate: e.target.value })} /></div>
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
      setLogs((l) => [...l, "ERROR: " + (e?.message || String(e))]);
      setResult("failed");
      setRunning(false);
      closeStream();
    }
  };

  const cancelScan = async () => {
    try { await post("/enroll/cancel", {}); } catch { /* noop */ }
  };

  return (
    <AlertDialog open={!!member} onOpenChange={(o) => { if (!o) { closeStream(); onClose(); } }}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Enroll fingerprint — {member?.fullName || ""}</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-2">
              {member?.offlinePending ? (
                <p className="text-xs">This member was created offline — the fingerprint is captured now and pushed automatically once they sync to the server.</p>
              ) : (
                <p className="text-xs">Place the finger on the scanner after pressing Start (3 captures).</p>
              )}
              <div className="flex items-center gap-2">
                <Label>Finger</Label>
                <Select value={fingerId} onValueChange={setFingerId} disabled={running}>
                  <SelectTrigger className="w-[90px]"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {Array.from({ length: 10 }, (_, i) => String(i)).map((f) => <SelectItem key={f} value={f}>#{f}</SelectItem>)}
                  </SelectContent>
                </Select>
                <Button size="sm" onClick={start} disabled={running}>
                  <Fingerprint className="h-3.5 w-3.5" /> {running ? "Scanning…" : "Start"}
                </Button>
                {running ? <Button size="sm" variant="outline" onClick={cancelScan}>Cancel scan</Button> : null}
              </div>
              <div className="max-h-40 overflow-auto rounded bg-muted p-2 text-xs font-mono">
                {logs.length === 0 ? <span className="text-muted-foreground">Idle.</span> : logs.map((l, i) => <div key={i}>{l}</div>)}
              </div>
              {result ? (
                <p className={result === "success" ? "text-emerald-600" : result === "cancelled" ? "text-amber-600" : "text-red-600"}>
                  {result === "success"
                    ? (member?.offlinePending ? "Fingerprint captured — will sync with the member." : "Fingerprint saved to the member.")
                    : result === "cancelled" ? "Cancelled." : "Enrollment failed."}
                </p>
              ) : null}
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel asChild><Button variant="outline">Close</Button></AlertDialogCancel>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
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
      if (res.ok) setMessage(`${opKind} applied.`);
      else if (res.conflict) setQueueError("This member changed on the server. Open the queue below to re-base or abort the change.");
      else if (res.queued) setMessage(res.gated ? `${opKind} queued — it will apply once server money support is enabled.` : `${opKind} queued (offline) — it will sync automatically.`);
      else if (res.needsFix) setQueueError(res.error || `${opKind} was rejected — fix the values and retry.`);
      else setQueueError(res.error || `${opKind} failed.`);
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
      setQueueError("Freeze needs a start date and a positive duration.");
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
        setMessage("Card scanned.");
      } else {
        setQueueError(r.error || "No card detected. Try again.");
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
        r.onerror = () => reject(new Error("Could not read the image file."));
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
      if (res.ok) setMessage(res.deferred ? "Photo saved — it will upload automatically when the member syncs." : "Photo uploaded.");
      else setQueueError(res.error || "Photo upload failed.");
      await loadRoster();
    } catch (err: any) {
      setQueueError(err?.message || String(err));
    } finally {
      setPhotoBusy(false);
      setPhotoTarget(null);
    }
  }, [photoTarget, loadRoster]);

  const checkDateRange = (startDate: string, endDate: string): string | null => {
    if (!n(startDate) || !n(endDate)) return "startDate and endDate are required.";
    const s = new Date(startDate);
    const e = new Date(endDate);
    if (Number.isNaN(s.getTime()) || Number.isNaN(e.getTime())) return "Invalid date format.";
    if (e < s) return "endDate must be after startDate.";
    return null;
  };

  const validateMembership = (): string | null => {
    const username = nl(membershipForm.accountUsernameId);
    if (!username) return "accountUsernameId is required.";
    if (!n(membershipForm.membershipId)) return "membershipId is required.";

    const d = checkDateRange(membershipForm.startDate, membershipForm.endDate);
    if (d) return d;

    if (!byUsername.get(username)) return "Unknown accountUsernameId in local cache.";

    const duplicate = users.some((u) => nl((u as any).accountUsernameId) === username && n((u as any).membershipId) === n(membershipForm.membershipId));
    if (duplicate) return "Membership already exists locally for this user.";

    const c1 = nl(membershipForm.cardId);
    const c2 = nl(membershipForm.secondCardId);
    if (c1 && cards.has(c1)) return "cardId already exists locally.";
    if (c2 && cards.has(c2)) return "secondCardId already exists locally.";
    return null;
  };

  const validateAccount = (): string | null => {
    if (!n(accountForm.firstname)) return "firstname is required.";
    if (!n(accountForm.lastname)) return "lastname is required.";
    if (!n(accountForm.email)) return "email is required.";
    if (!n(accountForm.phone)) return "phone is required.";
    if (!n(accountForm.membershipId)) return "membershipId is required.";
    if (n(accountForm.password).length < 8) return "password must be at least 8 chars.";

    const email = nl(accountForm.email);
    if (!email.includes("@") || !email.split("@")[1]?.includes(".")) return "Invalid email format.";
    if (users.some((u) => nl(u.email) === email)) return "Email already exists locally.";

    const username = nl(accountForm.accountUsernameId);
    if (username && users.some((u) => nl((u as any).accountUsernameId) === username)) {
      return "accountUsernameId already exists locally.";
    }

    const d = checkDateRange(accountForm.startDate, accountForm.endDate);
    if (d) return d;

    const c1 = nl(accountForm.cardId);
    const c2 = nl(accountForm.secondCardId);
    if (c1 && cards.has(c1)) return "cardId already exists locally.";
    if (c2 && cards.has(c2)) return "secondCardId already exists locally.";
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
      const stateMsg = attempt.state === "reconciled" ? "reconciled" : "succeeded";
      setMessage(`Backend creation ${stateMsg}.`);
      setEditing(null);
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
      setMessage(`Pending row ${editing.local_id} updated.`);
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
      setMessage(`Pending row ${editing.local_id} updated.`);
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
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const saveLaterRecommended = decision?.attempt?.recommendation === "save_later";
  const conflictHint = friendlyConflict(decision?.attempt);

  // ── Access v3 layout ──────────────────────────────────────────────────
  // The design makes the directory the subject at full height and moves
  // creation/queue administration behind the header's "Nouveau membre" pill.
  // The existing forms and queue panels below are NOT rewritten — they are
  // toggled, so their wiring is untouched.
  const [showForms, setShowForms] = useState(false);

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

  const attentionCount =
    railFacts.conflicts.length + railFacts.offlineNew.length + railFacts.deleting.length + railFacts.syncing.length;

  const firstNames = (rows: MemberRosterRow[], max = 3) =>
    rows.slice(0, max).map((m) => (m.fullName || "—").split(/\s+/)[0]).join(", ") +
    (rows.length > max ? ` +${rows.length - max}` : "");

  usePageChrome(() => ({
    fill: true,
    subtitle: `${rosterTotal} membre${rosterTotal > 1 ? "s" : ""}`,
    actions: (
      <>
        <Button
          variant="outline"
          className="h-[30px] gap-1.5 rounded-[14px] px-[13px] text-[12px] font-semibold"
          disabled={loading || queueLoading}
          onClick={() => runAction(async () => {
            await Promise.all([reloadUsers(), loadMemberships(), refreshQueue(), loadRoster()]);
          })}
        >
          <RefreshCw className={`h-[15px] w-[15px] ${loading || queueLoading ? "animate-spin" : ""}`} />
          Recharger
        </Button>
        <Button
          className="h-[34px] gap-[7px] rounded-full px-[18px] text-[12.5px] font-bold shadow-[0_8px_20px_rgba(226,32,63,0.22)]"
          onClick={() => setShowForms((v) => !v)}
        >
          {showForms ? <ChevronLeft className="h-4 w-4" /> : <UserPlus className="h-4 w-4" />}
          {showForms ? "Retour au répertoire" : "Nouveau membre"}
        </Button>
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
  }), [rosterTotal, loading, queueLoading, showForms]);
  const rosterTotalPages = Math.max(1, Math.ceil(rosterTotal / ROSTER_SIZE));

  return (
    <div className="flex h-full min-h-0 gap-4">
      {/* ── Le sujet : le répertoire, pleine hauteur ────────────────────── */}
      <div className={cn("flex min-w-0 flex-1 flex-col gap-[11px]", showForms && "overflow-y-auto pr-1")}>

        {error ? <Alert variant="destructive"><AlertTitle>Users error</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}
        {queueError ? <Alert variant="destructive"><AlertTitle>Queue error</AlertTitle><AlertDescription>{queueError}</AlertDescription></Alert> : null}
        {message ? <Alert variant="success"><AlertTitle>Done</AlertTitle><AlertDescription>{message}</AlertDescription></Alert> : null}

        {editing ? (
          <Alert variant="info">
            <AlertTitle>Editing pending row {editing.local_id}</AlertTitle>
            <AlertDescription className="flex items-center justify-between gap-2">
              <span>Update values and submit to keep this pending row valid.</span>
              <Button size="sm" variant="outline" onClick={cancelEdit}>
                <XCircle className="h-3.5 w-3.5" /> Cancel edit
              </Button>
            </AlertDescription>
          </Alert>
        ) : null}

        {showForms ? (
          <div className="flex flex-none items-center justify-between gap-3">
            <div className="flex items-center gap-[9px]">
              <UserPlus className="h-[17px] w-[17px] text-primary" />
              <span className="font-display text-[13px] font-extrabold tracking-[-0.01em] text-foreground">Gestion</span>
              <span className="ml-1 text-[12px] text-muted-foreground">création, file d'attente et historique</span>
            </div>
            <Button size="sm" variant="outline" onClick={() => runAction(() => post("/offline-creations/process-due", {}), "Manual retry executed.")}>
              <Repeat className="h-3.5 w-3.5" /> Retry due now
            </Button>
          </div>
        ) : null}

      <div className={cn("grid grid-cols-1 xl:grid-cols-2 gap-4", !showForms && "hidden")}>
        {/* ----- existing-user subscription ----- */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">New subscription for existing user</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label>accountUsernameId</Label>
                <Input value={membershipForm.accountUsernameId} onChange={(e) => setMembership({ accountUsernameId: e.target.value })} />
              </div>
              <div className="space-y-1">
                <Label>membership</Label>
                <Select value={membershipForm.membershipId || NONE} onValueChange={(v) => setMembership({ membershipId: v === NONE ? "" : v })}>
                  <SelectTrigger><SelectValue placeholder="Select membership" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value={NONE}>Select membership</SelectItem>
                    {memberships.map((m) => <SelectItem key={String(m.id)} value={String(m.id)}>{m.title || `Membership ${m.id}`}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1"><Label>startDate</Label><Input type="date" value={membershipForm.startDate} onChange={(e) => setMembership({ startDate: e.target.value })} /></div>
              <div className="space-y-1"><Label>endDate</Label><Input type="date" value={membershipForm.endDate} onChange={(e) => setMembership({ endDate: e.target.value })} /></div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label>cardId</Label>
                <div className="flex gap-1">
                  <Input value={membershipForm.cardId} onChange={(e) => setMembership({ cardId: e.target.value })} />
                  <Button type="button" size="sm" variant="outline" disabled={!!scanning} onClick={() => scanCard("m.cardId", (c) => setMembership({ cardId: c }))} title="Scan RFID card">
                    {scanning === "m.cardId" ? <Clock3 className="h-3.5 w-3.5 animate-pulse" /> : <ScanLine className="h-3.5 w-3.5" />}
                  </Button>
                </div>
              </div>
              <div className="space-y-1">
                <Label>secondCardId</Label>
                <div className="flex gap-1">
                  <Input value={membershipForm.secondCardId} onChange={(e) => setMembership({ secondCardId: e.target.value })} />
                  <Button type="button" size="sm" variant="outline" disabled={!!scanning} onClick={() => scanCard("m.secondCardId", (c) => setMembership({ secondCardId: c }))} title="Scan RFID card">
                    {scanning === "m.secondCardId" ? <Clock3 className="h-3.5 w-3.5 animate-pulse" /> : <ScanLine className="h-3.5 w-3.5" />}
                  </Button>
                </div>
              </div>
            </div>
            <div className="space-y-1"><Label>note (optional)</Label><Input value={membershipForm.note} onChange={(e) => setMembership({ note: e.target.value })} /></div>
            <PaymentFields form={membershipForm} set={setMembership} />
            <Button onClick={submitMembership}>{editing?.creation_kind === "membership_only" ? <Save className="h-4 w-4" /> : <Edit3 className="h-4 w-4" />} Submit</Button>
          </CardContent>
        </Card>

        {/* ----- new account + first subscription ----- */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">New member (account + first subscription)</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1"><Label>firstname</Label><Input value={accountForm.firstname} onChange={(e) => setAccount({ firstname: e.target.value })} /></div>
              <div className="space-y-1"><Label>lastname</Label><Input value={accountForm.lastname} onChange={(e) => setAccount({ lastname: e.target.value })} /></div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1"><Label>email</Label><Input value={accountForm.email} onChange={(e) => setAccount({ email: e.target.value })} /></div>
              <div className="space-y-1"><Label>phone</Label><Input value={accountForm.phone} onChange={(e) => setAccount({ phone: e.target.value })} /></div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1"><Label>password (min 8)</Label><Input type="password" value={accountForm.password} onChange={(e) => setAccount({ password: e.target.value })} /></div>
              <div className="space-y-1"><Label>accountUsernameId (optional)</Label><Input value={accountForm.accountUsernameId} onChange={(e) => setAccount({ accountUsernameId: e.target.value })} /></div>
            </div>

            <div className="space-y-2 rounded-md border border-dashed p-2">
              <div className="text-xs font-medium text-muted-foreground">Profile</div>
              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-1"><Label>CIN</Label><Input value={accountForm.cin} onChange={(e) => setAccount({ cin: e.target.value })} /></div>
                <div className="space-y-1"><Label>birthday</Label><Input type="date" value={accountForm.birthday} onChange={(e) => setAccount({ birthday: e.target.value })} /></div>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-1">
                  <Label>gender</Label>
                  <Select value={accountForm.gender || NONE} onValueChange={(v) => setAccount({ gender: v === NONE ? "" : v })}>
                    <SelectTrigger><SelectValue placeholder="—" /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NONE}>—</SelectItem>
                      {GENDERS.map((g) => <SelectItem key={g.v} value={g.v}>{g.l}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1">
                  <Label>blood type</Label>
                  <Select value={accountForm.bloodType || NONE} onValueChange={(v) => setAccount({ bloodType: v === NONE ? "" : v })}>
                    <SelectTrigger><SelectValue placeholder="—" /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NONE}>—</SelectItem>
                      {BLOOD_TYPES.map((b) => <SelectItem key={b} value={b}>{b.replace("_PLUS", "+").replace("_MINUS", "-")}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="space-y-1">
                <Label>city</Label>
                <Select value={accountForm.city || NONE} onValueChange={(v) => setAccount({ city: v === NONE ? "" : v })}>
                  <SelectTrigger><SelectValue placeholder="—" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value={NONE}>—</SelectItem>
                    {CITIES.map((c) => <SelectItem key={c.v} value={c.v}>{c.l}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-1"><Label>emergency name</Label><Input value={accountForm.emergencyContactName} onChange={(e) => setAccount({ emergencyContactName: e.target.value })} /></div>
                <div className="space-y-1"><Label>emergency phone</Label><Input value={accountForm.emergencyContactPhone} onChange={(e) => setAccount({ emergencyContactPhone: e.target.value })} /></div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label>membership</Label>
                <Select value={accountForm.membershipId || NONE} onValueChange={(v) => setAccount({ membershipId: v === NONE ? "" : v })}>
                  <SelectTrigger><SelectValue placeholder="Select membership" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value={NONE}>Select membership</SelectItem>
                    {memberships.map((m) => <SelectItem key={String(m.id)} value={String(m.id)}>{m.title || `Membership ${m.id}`}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label>cardId</Label>
                <div className="flex gap-1">
                  <Input value={accountForm.cardId} onChange={(e) => setAccount({ cardId: e.target.value })} />
                  <Button type="button" size="sm" variant="outline" disabled={!!scanning} onClick={() => scanCard("a.cardId", (c) => setAccount({ cardId: c }))} title="Scan RFID card">
                    {scanning === "a.cardId" ? <Clock3 className="h-3.5 w-3.5 animate-pulse" /> : <ScanLine className="h-3.5 w-3.5" />}
                  </Button>
                </div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1"><Label>startDate</Label><Input type="date" value={accountForm.startDate} onChange={(e) => setAccount({ startDate: e.target.value })} /></div>
              <div className="space-y-1"><Label>endDate</Label><Input type="date" value={accountForm.endDate} onChange={(e) => setAccount({ endDate: e.target.value })} /></div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label>secondCardId</Label>
                <div className="flex gap-1">
                  <Input value={accountForm.secondCardId} onChange={(e) => setAccount({ secondCardId: e.target.value })} />
                  <Button type="button" size="sm" variant="outline" disabled={!!scanning} onClick={() => scanCard("a.secondCardId", (c) => setAccount({ secondCardId: c }))} title="Scan RFID card">
                    {scanning === "a.secondCardId" ? <Clock3 className="h-3.5 w-3.5 animate-pulse" /> : <ScanLine className="h-3.5 w-3.5" />}
                  </Button>
                </div>
              </div>
              <div className="space-y-1"><Label>note (optional)</Label><Input value={accountForm.note} onChange={(e) => setAccount({ note: e.target.value })} /></div>
            </div>
            <PaymentFields form={accountForm} set={setAccount} />
            <Button onClick={submitAccount}>{editing?.creation_kind === "account_plus_membership" ? <Save className="h-4 w-4" /> : <Edit3 className="h-4 w-4" />} Submit</Button>
          </CardContent>
        </Card>
      </div>

      <Card className={cn(!showForms && "hidden")}>
        <CardHeader><CardTitle className="text-sm">Pending queue (active rows)</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Local ID</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Try</TableHead>
                <TableHead>Failures</TableHead>
                <TableHead>Next retry</TableHead>
                <TableHead>Last error</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {activeRows.length === 0 ? (
                <TableRow><TableCell colSpan={8} className="h-20 text-center text-muted-foreground">No active pending rows.</TableCell></TableRow>
              ) : activeRows.map((row) => (
                <TableRow key={row.local_id}>
                  <TableCell className="font-mono text-xs">{row.local_id}</TableCell>
                  <TableCell>{row.creation_kind}</TableCell>
                  <TableCell><Badge variant={badgeForState(row.state)}>{row.state}</Badge></TableCell>
                  <TableCell>{row.try_to_create ? "on" : "off"}</TableCell>
                  <TableCell>{row.failure_count}</TableCell>
                  <TableCell className="text-xs">{ts(row.next_retry_at)}</TableCell>
                  <TableCell className="max-w-[260px] truncate text-xs" title={row.last_error_message || ""}>{row.last_error_message || "-"}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      <Button size="sm" variant="outline" onClick={() => editRow(row)}>Modify</Button>
                      <Button size="sm" variant="outline" onClick={() => runAction(() => post(`/offline-creations/${row.local_id}/retry`, {}), "Row retried.")}>Retry</Button>
                      <Button size="sm" variant="outline" onClick={() => runAction(() => post(`/offline-creations/${row.local_id}/toggle`, { enabled: !row.try_to_create }), "Row toggle updated.")}>{row.try_to_create ? "Pause" : "Resume"}</Button>
                      <Button size="sm" variant="outline" onClick={() => runAction(() => post(`/offline-creations/${row.local_id}/cancel`, {}), "Row cancelled.")}>Cancel</Button>
                      <Button size="sm" variant="outline" onClick={() => runAction(() => post(`/offline-creations/${row.local_id}/duplicate`, {}), "Row duplicated.")}>Duplicate</Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card className={cn(!showForms && "hidden")}>
        <CardHeader>
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <CardTitle className="text-sm">Processed history</CardTitle>
            <div className="flex items-center gap-2">
              <Label>State filter</Label>
              <Select value={historyFilter} onValueChange={(v) => setHistoryFilter(v as any)}>
                <SelectTrigger className="w-[220px]"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">all</SelectItem>
                  {HISTORY_STATES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Local ID</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Final state</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead>Failure type</TableHead>
                <TableHead>Message</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {historyRows.length === 0 ? (
                <TableRow><TableCell colSpan={7} className="h-20 text-center text-muted-foreground">No rows for this filter.</TableCell></TableRow>
              ) : historyRows.map((row) => (
                <TableRow key={row.local_id}>
                  <TableCell className="font-mono text-xs">{row.local_id}</TableCell>
                  <TableCell>{row.creation_kind}</TableCell>
                  <TableCell><Badge variant={badgeForState(row.state)}>{row.state}</Badge></TableCell>
                  <TableCell className="text-xs">{ts(row.updated_at)}</TableCell>
                  <TableCell>{row.failure_type || "-"}</TableCell>
                  <TableCell className="max-w-[260px] truncate text-xs" title={row.last_error_message || ""}>{row.last_error_message || "-"}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      <Button size="sm" variant="outline" onClick={() => runAction(() => post(`/offline-creations/${row.local_id}/duplicate`, {}), "Row duplicated.")}>Duplicate</Button>
                      {row.state !== "archived" ? <Button size="sm" variant="outline" onClick={() => runAction(() => post(`/offline-creations/${row.local_id}/archive`, {}), "Row archived.")}>Archive</Button> : null}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* ----- local-first searchable member roster (Access v3) ----- */}
      <div className={cn("flex min-h-0 flex-1 flex-col gap-[11px]", showForms && "hidden")}>
        <div className="flex flex-none items-center gap-[9px]">
          <div className="flex h-[34px] max-w-[340px] flex-1 items-center gap-[9px] rounded-xl border border-border bg-card px-3">
            <Search className="h-[17px] w-[17px] shrink-0 text-muted-foreground" />
            <input
              value={rosterQInput}
              onChange={(e) => setRosterQInput(e.target.value)}
              placeholder="Nom, e-mail, téléphone, carte…"
              className="min-w-0 flex-1 bg-transparent text-[13px] text-foreground outline-none placeholder:text-muted-foreground"
            />
          </div>
          <div className="flex gap-[5px]">
            {([
              ["all", "Tous", rosterCounts.all],
              ["active", "Actifs", rosterCounts.active],
              ["expired", "Expirés", rosterCounts.expired],
              ["pending", "En attente", rosterCounts.pending],
            ] as const).map(([key, label, count]) => (
              <button
                key={key}
                onClick={() => { setRosterPage(0); setRosterStatus(key as any); }}
                className={cn(
                  "inline-flex h-7 items-center whitespace-nowrap rounded-full px-[11px] text-[12px] transition-colors",
                  rosterStatus === key
                    ? "bg-foreground font-bold text-background"
                    : "border border-border bg-card font-semibold text-muted-foreground hover:text-foreground",
                )}
              >
                {label} {count ?? 0}
              </button>
            ))}
          </div>
          {rosterLoading ? <Clock3 className="h-4 w-4 animate-pulse text-muted-foreground" /> : null}
        </div>

        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-3xl bg-card shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
          <div className={cn(ROSTER_GRID, "flex-none border-b border-border px-6 py-[11px]")}>
            <span className={LB}>Nom complet</span>
            <span className={LB}>Téléphone</span>
            <span className={LB}>Abonnement</span>
            <span className={LB}>Fin</span>
            <span className={LB}>Statut</span>
            <span className={cn(LB, "text-right")}>Actions</span>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto">
            {roster.length === 0 ? (
              <div className="flex h-full min-h-[240px] flex-col items-center justify-center gap-2 text-center">
                <UsersIcon className="h-8 w-8 text-muted-foreground/40" />
                <p className="text-[13px] font-semibold text-foreground">Aucun membre ne correspond</p>
                <p className="max-w-[340px] text-[11.5px] text-muted-foreground">
                  Ajustez la recherche ou le filtre, ou synchronisez pour charger le répertoire.
                </p>
              </div>
            ) : roster.map((m) => {
              const flag = m.hasConflict ? "conflit"
                : m.offlinePending ? "créé hors ligne"
                : m.pendingDelete ? "suppression…"
                : (m.pendingMutations?.length ?? 0) > 0 ? "sync en attente"
                : null;
              const flagTone = m.hasConflict ? "no" : m.offlinePending || m.pendingDelete ? "wn" : "flat";
              const st = statusBadge(m.status);
              return (
                <div
                  key={`${m.userId}-${m.activeMembershipId || "na"}`}
                  className={cn(
                    ROSTER_GRID,
                    "border-b border-border/60 px-6 py-[9px] last:border-b-0",
                    m.hasConflict && "bg-primary/[0.035]",
                  )}
                >
                  <div className="flex min-w-0 items-center gap-[11px]">
                    <span className={cn(
                      "flex h-8 w-8 shrink-0 items-center justify-center rounded-[18px] text-[12px] font-bold",
                      m.hasConflict ? "bg-primary/[0.09] text-primary"
                        : m.offlinePending ? "bg-amber-500/[0.14] text-amber-700 dark:text-amber-400"
                        : "bg-muted text-muted-foreground",
                    )}>
                      {initialsOf(m.fullName)}
                    </span>
                    <div className="min-w-0">
                      <div className="flex items-center gap-[7px]">
                        <span className="truncate text-[13.5px] font-semibold text-foreground">{m.fullName || "—"}</span>
                        {flag ? <RosterChip tone={flagTone as any}>{flag}</RosterChip> : null}
                      </div>
                      <div className="truncate text-[11px] text-muted-foreground">{m.email || m.accountUsernameId || ""}</div>
                    </div>
                  </div>

                  <span className="truncate font-mono text-[12px] text-muted-foreground">{m.phone || "—"}</span>
                  <span className="truncate text-[12px] text-muted-foreground">{m.membershipTitle || (m.membershipId ?? "—")}</span>
                  <span className="truncate font-mono text-[12px] text-muted-foreground">
                    {n(m.validTo) ? String(m.validTo).slice(0, 10) : "—"}
                  </span>
                  <span>
                    <RosterChip tone={st === "success" ? "ok" : st === "destructive" ? "no" : st === "warning" ? "wn" : "flat"}>
                      {m.status || "—"}
                    </RosterChip>
                  </span>

                  <div className="flex items-center justify-end gap-[5px]">
                    {!m.offlinePending && Number(m.activeMembershipId) > 0 ? (
                      <>
                        <IconAction title="Modifier l'abonnement" disabled={mutBusy} onClick={() => openEdit(m)}><Pencil className="h-3.5 w-3.5" /></IconAction>
                        <IconAction title="Geler l'abonnement" disabled={mutBusy} onClick={() => setFreezeTarget(m)}><Snowflake className="h-3.5 w-3.5" /></IconAction>
                        <IconAction title="Supprimer l'abonnement" disabled={mutBusy} onClick={() => setDeleteTarget(m)}><Trash2 className="h-3.5 w-3.5" /></IconAction>
                      </>
                    ) : null}
                    <IconAction title="Ajouter / remplacer la photo" disabled={photoBusy} onClick={() => pickPhoto(m)}><ImagePlus className="h-3.5 w-3.5" /></IconAction>
                    <IconAction title="Enrôler une empreinte" onClick={() => setEnrollMember(m)}><Fingerprint className="h-3.5 w-3.5" /></IconAction>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="flex flex-none items-center justify-between border-t border-border px-6 py-2.5">
            <span className="text-[11.5px] text-muted-foreground">
              {rosterTotal} membre{rosterTotal > 1 ? "s" : ""} · page {rosterPage + 1} / {rosterTotalPages}
            </span>
            <div className="flex gap-1.5">
              <Button
                variant="outline"
                className="h-[26px] gap-1 rounded-[14px] px-2.5 text-[11.5px] font-semibold"
                disabled={rosterPage <= 0}
                onClick={() => setRosterPage((p) => Math.max(0, p - 1))}
              >
                <ChevronLeft className="h-3.5 w-3.5" />Précédent
              </Button>
              <Button
                variant="outline"
                className="h-[26px] gap-1 rounded-[14px] px-2.5 text-[11.5px] font-semibold"
                disabled={rosterPage + 1 >= rosterTotalPages}
                onClick={() => setRosterPage((p) => p + 1)}
              >
                Suivant<ChevronRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        </div>
      </div>

      <AlertDialog open={decisionOpen} onOpenChange={setDecisionOpen}>
        <AlertDialogContent className="rounded-3xl">
          <AlertDialogHeader>
            <AlertDialogTitle className="font-display text-[18px] font-extrabold tracking-[-0.02em]">Creation failed</AlertDialogTitle>
            <AlertDialogDescription className="space-y-2">
              {conflictHint ? <p className="font-medium text-foreground">{conflictHint}</p> : null}
              <p>{decision?.attempt.error || "Unknown error"}</p>
              <p>failure_type=<code>{decision?.attempt.failureType || "unknown"}</code> | failure_code=<code>{decision?.attempt.failureCode || "-"}</code> | http=<code>{decision?.attempt.lastHttpStatus ?? "-"}</code></p>
              <p>Modify values or save this row for later retry.</p>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel asChild>
              <Button variant={saveLaterRecommended ? "outline" : "default"}>Modify{saveLaterRecommended ? "" : " (Recommended)"}</Button>
            </AlertDialogCancel>
            <AlertDialogAction
              asChild
              onClick={(e) => {
                e.preventDefault();
                const d = decision;
                if (!d) {
                  setDecisionOpen(false);
                  return;
                }
                void runAction(
                  () => post("/offline-creations/queue", {
                    creationKind: d.creationKind,
                    payload: d.payload,
                    failure: {
                      failureType: d.attempt.failureType,
                      failureCode: d.attempt.failureCode,
                      lastHttpStatus: d.attempt.lastHttpStatus,
                      error: d.attempt.error,
                    },
                  }),
                  "Creation saved to offline queue.",
                );
                setDecisionOpen(false);
                setDecision(null);
              }}
            >
              <Button variant={saveLaterRecommended ? "default" : "outline"}>Save later{saveLaterRecommended ? " (Recommended)" : ""}</Button>
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ----- lifecycle changes queue ----- */}
      <Card className={cn(!showForms && "hidden")}>
        <CardHeader>
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <CardTitle className="text-sm">Lifecycle changes queue</CardTitle>
            <Button size="sm" variant="outline" onClick={() => runMutationAction(() => post("/mutations/process-due", {}), "Sync run executed.")}>
              <Repeat className="h-3.5 w-3.5" /> Sync now
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Op</TableHead>
                <TableHead>AM id</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Money</TableHead>
                <TableHead>Error</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {mutations.length === 0 ? (
                <TableRow><TableCell colSpan={6} className="h-16 text-center text-muted-foreground">No queued lifecycle changes.</TableCell></TableRow>
              ) : mutations.map((mu) => (
                <TableRow key={mu.local_id}>
                  <TableCell>{mu.op_kind}</TableCell>
                  <TableCell className="text-xs">{mu.target_id}</TableCell>
                  <TableCell>
                    <Badge variant={mu.state === "conflict" || mu.state === "failed_terminal" ? "destructive" : (mu.state === "succeeded" || mu.state === "reconciled") ? "success" : mu.state === "blocked_auth" ? "warning" : "outline"}>{mu.state}</Badge>
                  </TableCell>
                  <TableCell>{mu.money ? <Badge variant="warning">money</Badge> : "-"}</TableCell>
                  <TableCell className="max-w-[240px] truncate text-xs" title={mu.last_error_message || ""}>{mu.last_error_message || "-"}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      {mu.state === "conflict" ? (
                        <Button size="sm" variant="outline" onClick={() => runMutationAction(() => post(`/mutations/${mu.local_id}/resolve`, { action: "abort" }), "Conflict aborted.")}>Abort</Button>
                      ) : null}
                      {MUTATION_ACTIVE_STATES.includes(mu.state) && mu.state !== "conflict" ? (
                        <Button size="sm" variant="outline" onClick={() => runMutationAction(() => post(`/mutations/${mu.local_id}/retry`, {}), "Retried.")}>Retry</Button>
                      ) : null}
                      {MUTATION_ACTIVE_STATES.includes(mu.state) ? (
                        <Button size="sm" variant="outline" onClick={() => runMutationAction(() => post(`/mutations/${mu.local_id}/cancel`, {}), "Cancelled.")}>Cancel</Button>
                      ) : null}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
      </div>

      {/* ── Le rail ───────────────────────────────────────────────────────
          Everything below is derived from flags the backend already sets on
          each roster row — no state is inferred or invented here. */}
      <div className="flex w-[330px] flex-none flex-col gap-[11px]">
        <div className="flex flex-none items-center gap-[9px]">
          <span className={cn(
            "inline-flex h-[22px] items-center gap-1.5 rounded-lg px-[9px] text-[10.5px] font-bold uppercase tracking-[0.05em]",
            attentionCount > 0 ? "bg-primary/[0.08] text-primary" : "bg-muted text-muted-foreground",
          )}>
            <AlertCircle className="h-3 w-3" />À traiter
          </span>
          {attentionCount > 0 && (
            <span className="text-[11.5px] text-muted-foreground">
              {attentionCount} fiche{attentionCount > 1 ? "s" : ""}
            </span>
          )}
        </div>

        {attentionCount > 0 ? (
          <div className={cn(
            "flex-none rounded-3xl bg-card px-5 py-[17px] shadow-[0_8px_20px_rgba(0,0,0,0.08)]",
            railFacts.conflicts.length > 0 && "border-[1.5px] border-primary/30",
          )}>
            {railFacts.conflicts.length > 0 && (
              <>
                <div className="mb-[11px] flex items-center gap-3">
                  <span className="flex h-[38px] w-[38px] shrink-0 items-center justify-center rounded-[18px] bg-primary/[0.09] text-primary">
                    <GitMerge className="h-5 w-5" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="text-[13.5px] font-bold text-foreground">
                      {railFacts.conflicts.length} conflit{railFacts.conflicts.length > 1 ? "s" : ""} à arbitrer
                    </div>
                    <div className="mt-0.5 truncate text-[11px] leading-[1.45] text-muted-foreground">
                      {firstNames(railFacts.conflicts)} — modifié hors ligne <b className="text-foreground">et</b> sur le serveur
                    </div>
                  </div>
                </div>
                <Button
                  variant="outline"
                  className="h-8 w-full justify-center gap-1.5 rounded-[14px] border-[1.5px] border-primary/45 text-[12px] font-semibold text-primary hover:bg-primary/5"
                  onClick={() => setShowForms(true)}
                >
                  <GitMerge className="h-[15px] w-[15px] " />Ouvrir la file d'attente
                </Button>
              </>
            )}

            {railFacts.conflicts.length > 0 && (railFacts.offlineNew.length > 0 || railFacts.syncing.length > 0 || railFacts.deleting.length > 0) && (
              <div className="my-3.5 h-px bg-border" />
            )}

            {(railFacts.offlineNew.length > 0 || railFacts.syncing.length > 0 || railFacts.deleting.length > 0) && (
              <>
                <div className="mb-[11px] flex items-center gap-3">
                  <span className="flex h-[38px] w-[38px] shrink-0 items-center justify-center rounded-[18px] bg-amber-500/[0.14] text-amber-700 dark:text-amber-400">
                    <CloudUpload className="h-5 w-5" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="text-[13.5px] font-bold text-foreground">
                      {railFacts.offlineNew.length + railFacts.syncing.length + railFacts.deleting.length} en attente de synchro
                    </div>
                    <div className="mt-0.5 truncate text-[11px] leading-[1.45] text-muted-foreground">
                      {railFacts.offlineNew.length > 0 && `${firstNames(railFacts.offlineNew)} — créés hors ligne`}
                      {railFacts.offlineNew.length > 0 && railFacts.syncing.length > 0 && " · "}
                      {railFacts.syncing.length > 0 && `${railFacts.syncing.length} modification${railFacts.syncing.length > 1 ? "s" : ""}`}
                      {railFacts.deleting.length > 0 && ` · ${railFacts.deleting.length} suppression${railFacts.deleting.length > 1 ? "s" : ""}`}
                    </div>
                  </div>
                </div>
                <Button
                  variant="outline"
                  className="h-8 w-full justify-center gap-1.5 rounded-[14px] text-[12px] font-semibold"
                  onClick={() => runAction(() => post("/offline-creations/process-due", {}), "Manual retry executed.")}
                >
                  <RefreshCw className="h-[15px] w-[15px]" />Envoyer maintenant
                </Button>
              </>
            )}
          </div>
        ) : (
          <div className="flex-none rounded-3xl bg-card px-5 py-[17px] shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
            <div className="flex items-center gap-3">
              <span className="flex h-[38px] w-[38px] shrink-0 items-center justify-center rounded-[18px] bg-emerald-500/[0.055] text-emerald-700 dark:text-emerald-400">
                <CheckCircle2 className="h-5 w-5" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-[13.5px] font-bold text-foreground">Rien à traiter</div>
                <div className="mt-0.5 text-[11px] leading-[1.45] text-muted-foreground">
                  Aucun conflit ni fiche en attente sur cette page.
                </div>
              </div>
            </div>
          </div>
        )}

        <div className="mt-[3px] flex flex-none items-center gap-[9px]">
          <span className="inline-flex h-[22px] items-center gap-1.5 rounded-lg bg-muted px-[9px] text-[10.5px] font-bold uppercase tracking-[0.05em] text-muted-foreground">
            <UsersIcon className="h-3 w-3" />L'effectif
          </span>
        </div>
        <div className="flex min-h-0 flex-1 flex-col gap-[11px] overflow-y-auto rounded-[18px] bg-card px-5 py-4 shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
          <div className="mb-0.5 flex items-baseline gap-2.5">
            <span className="num text-[30px] leading-none">{rosterCounts.all ?? 0}</span>
            <span className="text-[13px] text-muted-foreground">membre{(rosterCounts.all ?? 0) > 1 ? "s" : ""}</span>
          </div>
          <div className="h-px bg-border" />
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Actifs</span>
            <span className="text-[12.5px] font-bold text-emerald-700 dark:text-emerald-400">{rosterCounts.active ?? 0}</span>
          </div>
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Expirés</span>
            <span className="text-[12.5px] font-bold text-primary">{rosterCounts.expired ?? 0}</span>
          </div>
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">En attente</span>
            <span className="text-[12.5px] font-bold text-amber-700 dark:text-amber-400">{rosterCounts.pending ?? 0}</span>
          </div>
          <p className="mt-auto pt-2 text-[10.5px] leading-[1.5] text-muted-foreground">
            Les indicateurs « à traiter » portent sur la page affichée ({roster.length} fiche
            {roster.length > 1 ? "s" : ""}) ; les totaux ci-dessus portent sur tout le répertoire.
          </p>
        </div>
      </div>

      {/* ----- edit membership dialog ----- */}
      <AlertDialog open={!!editTarget} onOpenChange={(o) => { if (!o) setEditTarget(null); }}>
        <AlertDialogContent className="rounded-3xl">
          <AlertDialogHeader>
            <AlertDialogTitle className="font-display text-[18px] font-extrabold tracking-[-0.02em]">Edit membership — {editTarget?.fullName}</AlertDialogTitle>
            <AlertDialogDescription>Applies online if connected, otherwise queues and syncs automatically.</AlertDialogDescription>
          </AlertDialogHeader>
          <div className="space-y-2">
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1"><Label>startDate</Label><Input type="date" value={editForm.startDate} onChange={(e) => setEditForm((s) => ({ ...s, startDate: e.target.value }))} /></div>
              <div className="space-y-1"><Label>endDate</Label><Input type="date" value={editForm.endDate} onChange={(e) => setEditForm((s) => ({ ...s, endDate: e.target.value }))} /></div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label>cardId</Label>
                <div className="flex gap-1">
                  <Input value={editForm.cardId} onChange={(e) => setEditForm((s) => ({ ...s, cardId: e.target.value }))} />
                  <Button type="button" size="sm" variant="outline" disabled={!!scanning} onClick={() => scanCard("edit.cardId", (c) => setEditForm((s) => ({ ...s, cardId: c })))}>{scanning === "edit.cardId" ? <Clock3 className="h-3.5 w-3.5 animate-pulse" /> : <ScanLine className="h-3.5 w-3.5" />}</Button>
                </div>
              </div>
              <div className="space-y-1">
                <Label>secondCardId</Label>
                <div className="flex gap-1">
                  <Input value={editForm.secondCardId} onChange={(e) => setEditForm((s) => ({ ...s, secondCardId: e.target.value }))} />
                  <Button type="button" size="sm" variant="outline" disabled={!!scanning} onClick={() => scanCard("edit.secondCardId", (c) => setEditForm((s) => ({ ...s, secondCardId: c })))}>{scanning === "edit.secondCardId" ? <Clock3 className="h-3.5 w-3.5 animate-pulse" /> : <ScanLine className="h-3.5 w-3.5" />}</Button>
                </div>
              </div>
            </div>
            <div className="space-y-1"><Label>note (optional)</Label><Input value={editForm.note} onChange={(e) => setEditForm((s) => ({ ...s, note: e.target.value }))} /></div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel asChild><Button variant="outline">Cancel</Button></AlertDialogCancel>
            <Button onClick={submitEdit} disabled={mutBusy}><Save className="h-4 w-4" /> Save changes</Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ----- freeze membership dialog ----- */}
      <AlertDialog open={!!freezeTarget} onOpenChange={(o) => { if (!o) setFreezeTarget(null); }}>
        <AlertDialogContent className="rounded-3xl">
          <AlertDialogHeader>
            <AlertDialogTitle className="font-display text-[18px] font-extrabold tracking-[-0.02em]">Freeze membership — {freezeTarget?.fullName}</AlertDialogTitle>
            <AlertDialogDescription>Pauses the membership for the given duration.</AlertDialogDescription>
          </AlertDialogHeader>
          <div className="space-y-2">
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1"><Label>start date</Label><Input type="date" value={freezeForm.startFreezeDate} onChange={(e) => setFreezeForm((s) => ({ ...s, startFreezeDate: e.target.value }))} /></div>
              <div className="space-y-1"><Label>duration (days)</Label><Input type="number" value={freezeForm.durationInDays} onChange={(e) => setFreezeForm((s) => ({ ...s, durationInDays: e.target.value }))} /></div>
            </div>
            <div className="space-y-1"><Label>reason (optional)</Label><Input value={freezeForm.reason} onChange={(e) => setFreezeForm((s) => ({ ...s, reason: e.target.value }))} /></div>
            <div className="space-y-1"><Label>note (optional)</Label><Input value={freezeForm.note} onChange={(e) => setFreezeForm((s) => ({ ...s, note: e.target.value }))} /></div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel asChild><Button variant="outline">Cancel</Button></AlertDialogCancel>
            <Button onClick={submitFreeze} disabled={mutBusy}><Snowflake className="h-4 w-4" /> Freeze</Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ----- delete membership confirm ----- */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(o) => { if (!o) setDeleteTarget(null); }}>
        <AlertDialogContent className="rounded-3xl">
          <AlertDialogHeader>
            <AlertDialogTitle className="font-display text-[18px] font-extrabold tracking-[-0.02em]">Delete membership — {deleteTarget?.fullName}?</AlertDialogTitle>
            <AlertDialogDescription>
              This removes the membership and drops the member's card from the turnstiles. Applies online if connected, otherwise queues and syncs automatically.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel asChild><Button variant="outline">Cancel</Button></AlertDialogCancel>
            <Button variant="destructive" onClick={confirmDelete} disabled={mutBusy}><Trash2 className="h-4 w-4" /> Delete</Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <EnrollDialog member={enrollMember} onClose={() => setEnrollMember(null)} />
      <input ref={photoInputRef} type="file" accept="image/*" className="hidden" onChange={onPhotoFile} />
    </div>
  );
}
