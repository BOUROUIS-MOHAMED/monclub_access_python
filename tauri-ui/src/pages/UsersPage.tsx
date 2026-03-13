
import { useCallback, useEffect, useMemo, useState } from "react";
import { useUsers } from "@/api/hooks";
import { get, patch, post } from "@/api/client";
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
import { Clock3, Edit3, RefreshCw, Repeat, Save, Users as UsersIcon, XCircle } from "lucide-react";

type MembershipChoice = { id: number | string; title?: string };

type QueueDecision = {
  creationKind: OfflineCreationKind;
  payload: Record<string, any>;
  attempt: OfflineAttemptResponse;
};

const HISTORY_STATES: OfflineCreationState[] = ["succeeded", "reconciled", "cancelled", "failed_terminal", "archived"];

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
function badgeForState(state: OfflineCreationState): "default" | "secondary" | "destructive" | "outline" | "success" | "warning" {
  if (state === "succeeded") return "success";
  if (state === "reconciled") return "secondary";
  if (state === "cancelled") return "warning";
  if (state === "failed_terminal") return "destructive";
  if (state === "blocked_auth") return "warning";
  if (state === "processing") return "secondary";
  return "outline";
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

  const [membershipForm, setMembershipForm] = useState({
    accountUsernameId: "",
    membershipId: "",
    startDate: new Date().toISOString().slice(0, 10),
    endDate: new Date(Date.now() + 86400000 * 30).toISOString().slice(0, 10),
    cardId: "",
    secondCardId: "",
  });
  const [accountForm, setAccountForm] = useState({
    firstname: "",
    lastname: "",
    email: "",
    phone: "",
    password: "",
    accountUsernameId: "",
    membershipId: "",
    startDate: new Date().toISOString().slice(0, 10),
    endDate: new Date(Date.now() + 86400000 * 30).toISOString().slice(0, 10),
    cardId: "",
    secondCardId: "",
  });

  const [decision, setDecision] = useState<QueueDecision | null>(null);
  const [decisionOpen, setDecisionOpen] = useState(false);

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
      await Promise.all([reloadUsers(), refreshQueue()]);
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
      await Promise.all([reloadUsers(), refreshQueue()]);
      return;
    }

    setDecision({ creationKind, payload, attempt });
    setDecisionOpen(true);
  }, [refreshQueue, reloadUsers]);

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
    };

    if (editing && editing.creation_kind === "membership_only") {
      await patch(`/offline-creations/${editing.local_id}`, { payload, tryToCreate: true });
      setEditing(null);
      setMessage(`Pending row ${editing.local_id} updated.`);
      await refreshQueue();
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
    };

    if (editing && editing.creation_kind === "account_plus_membership") {
      await patch(`/offline-creations/${editing.local_id}`, { payload, tryToCreate: true });
      setEditing(null);
      setMessage(`Pending row ${editing.local_id} updated.`);
      await refreshQueue();
      return;
    }

    await handleAttempt("account_plus_membership", payload);
  };

  const editRow = (row: OfflineCreationRow) => {
    setEditing(row);
    setQueueError(null);
    const p = row.payload || {};
    if (row.creation_kind === "membership_only") {
      setMembershipForm({
        accountUsernameId: n(p.accountUsernameId || p.account_username_id),
        membershipId: n(p.membershipId || p.membership_id),
        startDate: n(p.startDate || p.start_date || p.validFrom || p.valid_from),
        endDate: n(p.endDate || p.end_date || p.validTo || p.valid_to),
        cardId: n(p.cardId || p.card_id || p.firstCardId || p.first_card_id),
        secondCardId: n(p.secondCardId || p.second_card_id),
      });
    } else {
      setAccountForm({
        firstname: n(p.firstname || p.firstName || p.first_name),
        lastname: n(p.lastname || p.lastName || p.last_name),
        email: n(p.email),
        phone: n(p.phone),
        password: n(p.password),
        accountUsernameId: n(p.accountUsernameId || p.account_username_id),
        membershipId: n(p.membershipId || p.membership_id),
        startDate: n(p.startDate || p.start_date || p.validFrom || p.valid_from),
        endDate: n(p.endDate || p.end_date || p.validTo || p.valid_to),
        cardId: n(p.cardId || p.card_id || p.firstCardId || p.first_card_id),
        secondCardId: n(p.secondCardId || p.second_card_id),
      });
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const saveLaterRecommended = decision?.attempt?.recommendation === "save_later";

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-3">
          <UsersIcon className="h-5 w-5 text-primary" />
          <h1 className="text-lg font-semibold">Users</h1>
          <Badge variant="secondary" className="text-xs">{users.length}</Badge>
          {queueLoading ? <Clock3 className="h-4 w-4 animate-pulse text-muted-foreground" /> : null}
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={() => runAction(() => post("/offline-creations/process-due", {}), "Manual retry executed.") }>
            <Repeat className="h-3.5 w-3.5" /> Retry due now
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={loading || queueLoading}
            onClick={() => runAction(async () => {
              await Promise.all([reloadUsers(), loadMemberships(), refreshQueue()]);
            })}
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading || queueLoading ? "animate-spin" : ""}`} /> Refresh
          </Button>
        </div>
      </div>

      {error ? <Alert variant="destructive"><AlertTitle>Users error</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}
      {queueError ? <Alert variant="destructive"><AlertTitle>Queue error</AlertTitle><AlertDescription>{queueError}</AlertDescription></Alert> : null}
      {message ? <Alert variant="success"><AlertTitle>Done</AlertTitle><AlertDescription>{message}</AlertDescription></Alert> : null}

      {editing ? (
        <Alert variant="info">
          <AlertTitle>Editing pending row {editing.local_id}</AlertTitle>
          <AlertDescription className="flex items-center justify-between gap-2">
            <span>Update values and submit to keep this pending row valid.</span>
            <Button size="sm" variant="outline" onClick={() => setEditing(null)}>
              <XCircle className="h-3.5 w-3.5" /> Cancel edit
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Creation kind: membership_only</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label>accountUsernameId</Label>
                <Input value={membershipForm.accountUsernameId} onChange={(e) => setMembershipForm((s) => ({ ...s, accountUsernameId: e.target.value }))} />
              </div>
              <div className="space-y-1">
                <Label>membershipId</Label>
                <Select value={membershipForm.membershipId || "__none__"} onValueChange={(v) => setMembershipForm((s) => ({ ...s, membershipId: v === "__none__" ? "" : v }))}>
                  <SelectTrigger><SelectValue placeholder="Select membership" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__none__">Select membership</SelectItem>
                    {memberships.map((m) => <SelectItem key={String(m.id)} value={String(m.id)}>{m.title || `Membership ${m.id}`}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1"><Label>startDate</Label><Input type="date" value={membershipForm.startDate} onChange={(e) => setMembershipForm((s) => ({ ...s, startDate: e.target.value }))} /></div>
              <div className="space-y-1"><Label>endDate</Label><Input type="date" value={membershipForm.endDate} onChange={(e) => setMembershipForm((s) => ({ ...s, endDate: e.target.value }))} /></div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1"><Label>cardId</Label><Input value={membershipForm.cardId} onChange={(e) => setMembershipForm((s) => ({ ...s, cardId: e.target.value }))} /></div>
              <div className="space-y-1"><Label>secondCardId</Label><Input value={membershipForm.secondCardId} onChange={(e) => setMembershipForm((s) => ({ ...s, secondCardId: e.target.value }))} /></div>
            </div>
            <Button onClick={submitMembership}>{editing?.creation_kind === "membership_only" ? <Save className="h-4 w-4" /> : <Edit3 className="h-4 w-4" />} Submit</Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Creation kind: account_plus_membership</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1"><Label>firstname</Label><Input value={accountForm.firstname} onChange={(e) => setAccountForm((s) => ({ ...s, firstname: e.target.value }))} /></div>
              <div className="space-y-1"><Label>lastname</Label><Input value={accountForm.lastname} onChange={(e) => setAccountForm((s) => ({ ...s, lastname: e.target.value }))} /></div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1"><Label>email</Label><Input value={accountForm.email} onChange={(e) => setAccountForm((s) => ({ ...s, email: e.target.value }))} /></div>
              <div className="space-y-1"><Label>phone</Label><Input value={accountForm.phone} onChange={(e) => setAccountForm((s) => ({ ...s, phone: e.target.value }))} /></div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1"><Label>password</Label><Input type="password" value={accountForm.password} onChange={(e) => setAccountForm((s) => ({ ...s, password: e.target.value }))} /></div>
              <div className="space-y-1"><Label>accountUsernameId (optional)</Label><Input value={accountForm.accountUsernameId} onChange={(e) => setAccountForm((s) => ({ ...s, accountUsernameId: e.target.value }))} /></div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label>membershipId</Label>
                <Select value={accountForm.membershipId || "__none__"} onValueChange={(v) => setAccountForm((s) => ({ ...s, membershipId: v === "__none__" ? "" : v }))}>
                  <SelectTrigger><SelectValue placeholder="Select membership" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__none__">Select membership</SelectItem>
                    {memberships.map((m) => <SelectItem key={String(m.id)} value={String(m.id)}>{m.title || `Membership ${m.id}`}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1"><Label>cardId</Label><Input value={accountForm.cardId} onChange={(e) => setAccountForm((s) => ({ ...s, cardId: e.target.value }))} /></div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1"><Label>startDate</Label><Input type="date" value={accountForm.startDate} onChange={(e) => setAccountForm((s) => ({ ...s, startDate: e.target.value }))} /></div>
              <div className="space-y-1"><Label>endDate</Label><Input type="date" value={accountForm.endDate} onChange={(e) => setAccountForm((s) => ({ ...s, endDate: e.target.value }))} /></div>
            </div>
            <div className="space-y-1"><Label>secondCardId</Label><Input value={accountForm.secondCardId} onChange={(e) => setAccountForm((s) => ({ ...s, secondCardId: e.target.value }))} /></div>
            <Button onClick={submitAccount}>{editing?.creation_kind === "account_plus_membership" ? <Save className="h-4 w-4" /> : <Edit3 className="h-4 w-4" />} Submit</Button>
          </CardContent>
        </Card>
      </div>

      <Card>
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

      <Card>
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

      <Card>
        <CardHeader><CardTitle className="text-sm">Local users directory</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Full name</TableHead>
                <TableHead>Username</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Membership</TableHead>
                <TableHead>Valid to</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.length === 0 ? (
                <TableRow><TableCell colSpan={6} className="h-20 text-center text-muted-foreground">No users in cache.</TableCell></TableRow>
              ) : users.map((u) => (
                <TableRow key={`${u.userId}-${(u as any).activeMembershipId || "na"}`}>
                  <TableCell className="font-mono text-xs">{u.userId}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <span>{u.fullName || "-"}</span>
                      {u.offlinePending ? <Badge variant="warning">offline pending</Badge> : null}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs">{(u as any).accountUsernameId || "-"}</TableCell>
                  <TableCell className="text-xs">{u.email || "-"}</TableCell>
                  <TableCell>{u.membershipId ?? "-"}</TableCell>
                  <TableCell>{n(u.validTo) ? <Badge variant={new Date(String(u.validTo)) < new Date() ? "destructive" : "success"}>{String(u.validTo).slice(0, 10)}</Badge> : "-"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <AlertDialog open={decisionOpen} onOpenChange={setDecisionOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Creation failed</AlertDialogTitle>
            <AlertDialogDescription className="space-y-2">
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
    </div>
  );
}
