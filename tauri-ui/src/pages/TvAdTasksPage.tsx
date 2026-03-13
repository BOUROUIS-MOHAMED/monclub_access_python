import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw, RotateCcw, Send, Wrench } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  fetchTvAdTasks,
  getTvAdTasks,
  prepareTvAdTasks,
  retryTvAdTaskConfirm,
  retryTvAdTaskPrepare,
  runTvAdTasksCycle,
  injectTvAdTaskNow,
} from "@/api/tv";
import type { TvAdTaskRow } from "@/api/types";

const REMOTE_STATUS_FILTER = [
  "ALL",
  "PREPARATION_PHASE",
  "READY_TO_DISPLAY",
  "DISPLAYING",
  "DONE",
  "FAILED",
  "CANCELLED",
  "EXPIRED",
] as const;

const LOCAL_STATE_FILTER = [
  "ALL",
  "DISCOVERED",
  "DOWNLOADING",
  "READY_LOCAL",
  "READY_CONFIRM_PENDING",
  "READY_CONFIRMED",
  "FAILED",
  "CANCELLED",
  "EXPIRED",
] as const;

function statusVariant(value: string): "success" | "warning" | "destructive" | "secondary" {
  const v = String(value || "").toUpperCase();
  if (["READY_TO_DISPLAY", "DONE", "READY_CONFIRMED", "SENT"].includes(v)) return "success";
  if (["QUEUED", "SENDING", "DISCOVERED", "DOWNLOADING", "READY_CONFIRM_PENDING", "PREPARATION_PHASE"].includes(v)) return "warning";
  if (["FAILED", "FAILED_TERMINAL", "EXPIRED", "CANCELLED"].includes(v)) return "destructive";
  return "secondary";
}

function short(value: unknown, size = 48): string {
  const s = String(value || "");
  if (s.length <= size) return s;
  return `${s.slice(0, size)}...`;
}

export default function TvAdTasksPage() {
  const [rows, setRows] = useState<TvAdTaskRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [remoteFilter, setRemoteFilter] = useState<string>("ALL");
  const [localFilter, setLocalFilter] = useState<string>("ALL");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getTvAdTasks({
        q: q.trim() || undefined,
        remoteStatuses: remoteFilter === "ALL" ? undefined : remoteFilter,
        localStates: localFilter === "ALL" ? undefined : localFilter,
        limit: 500,
        offset: 0,
      });
      setRows((data.rows || []) as TvAdTaskRow[]);
      setTotal(Number(data.total || 0));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [q, remoteFilter, localFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  const runFetch = useCallback(async () => {
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      const res = await fetchTvAdTasks({ force: true, limit: 1500 });
      if (!res.ok) throw new Error(res.error || "Fetch failed");
      setInfo(`Fetched ${res.fetched || 0} ad tasks for gyms: ${(res.gymIds || []).join(",") || "-"}`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [load]);

  const runPrepare = useCallback(async () => {
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      const res = await prepareTvAdTasks({ force: false, processConfirm: true, limit: 500 });
      if (!res.ok) throw new Error("Prepare failed");
      setInfo(`Prepared=${Number(res.prepare?.prepared || 0)} reused=${Number(res.prepare?.reused || 0)} confirmSent=${Number(res.confirm?.sent || 0)}`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [load]);

  const runCycle = useCallback(async () => {
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      const res = await runTvAdTasksCycle({ forceFetch: true, forcePrepare: false, forceConfirm: true });
      if (!res.ok) throw new Error("Cycle failed");
      setInfo(
        `Cycle: fetched=${Number(res.fetch?.fetched || 0)} prepared=${Number(res.prepare?.prepared || 0)} sent=${Number(
          res.confirm?.sent || 0
        )}`
      );
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [load]);

  const onRetryPrepare = useCallback(
    async (taskId: number) => {
      setBusy(true);
      setError(null);
      setInfo(null);
      try {
        const res = await retryTvAdTaskPrepare(taskId, {});
        if (!res.ok) throw new Error("Retry prepare failed");
        setInfo(`Retry prepare submitted for task #${taskId}.`);
        await load();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
    },
    [load]
  );

  const onRetryConfirm = useCallback(
    async (taskId: number) => {
      setBusy(true);
      setError(null);
      setInfo(null);
      try {
        const res = await retryTvAdTaskConfirm(taskId, {});
        if (!res.ok) throw new Error("Retry confirm failed");
        setInfo(`Retry confirm submitted for task #${taskId}.`);
        await load();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
    },
    [load]
  );

  const onInjectNow = useCallback(
    async (taskId: number) => {
      setBusy(true);
      setError(null);
      setInfo(null);
      try {
        const res = await injectTvAdTaskNow(taskId, { support: true, confirm: true });
        if (!res.ok) throw new Error(res.error || res.reason || "Inject now failed");
        setInfo(`Inject-now started for task #${taskId}.`);
        await load();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
    },
    [load]
  );

  const counters = useMemo(() => {
    const out = {
      prep: 0,
      readyConfirmed: 0,
      pendingConfirm: 0,
      failed: 0,
      remoteTerminal: 0,
      displaying: 0,
    };
    for (const r of rows) {
      const lp = String(r.local_preparation_state || "").toUpperCase();
      const rs = String(r.remote_status || "").toUpperCase();
      if (lp === "READY_CONFIRMED") out.readyConfirmed += 1;
      if (lp === "READY_CONFIRM_PENDING") out.pendingConfirm += 1;
      if (lp === "FAILED") out.failed += 1;
      if (lp === "DISCOVERED" || lp === "DOWNLOADING" || lp === "READY_LOCAL") out.prep += 1;
      if (rs === "CANCELLED" || rs === "EXPIRED") out.remoteTerminal += 1;
      if (String(r.local_display_state || "").toUpperCase() === "DISPLAYING" || Boolean(r.currently_injected)) out.displaying += 1;
    }
    return out;
  }, [rows]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">TV Ad Tasks Preparation</h1>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => void load()} disabled={loading || busy}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
          <Button variant="outline" onClick={() => void runFetch()} disabled={busy}>
            <Send className="h-4 w-4" /> Fetch Now
          </Button>
          <Button variant="outline" onClick={() => void runPrepare()} disabled={busy}>
            <Wrench className="h-4 w-4" /> Prepare
          </Button>
          <Button onClick={() => void runCycle()} disabled={busy}>
            <RotateCcw className="h-4 w-4" /> Full Cycle
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTitle>Ad task error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {info && (
        <Alert>
          <AlertTitle>Info</AlertTitle>
          <AlertDescription>{info}</AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
        <Card><CardHeader><CardTitle className="text-sm">Total</CardTitle></CardHeader><CardContent className="text-xl font-semibold">{total}</CardContent></Card>
        <Card><CardHeader><CardTitle className="text-sm">Preparing</CardTitle></CardHeader><CardContent className="text-xl font-semibold">{counters.prep}</CardContent></Card>
        <Card><CardHeader><CardTitle className="text-sm">Ready Confirmed</CardTitle></CardHeader><CardContent className="text-xl font-semibold">{counters.readyConfirmed}</CardContent></Card>
        <Card><CardHeader><CardTitle className="text-sm">Confirm Pending</CardTitle></CardHeader><CardContent className="text-xl font-semibold">{counters.pendingConfirm}</CardContent></Card>
        <Card><CardHeader><CardTitle className="text-sm">Displaying</CardTitle></CardHeader><CardContent className="text-xl font-semibold">{counters.displaying}</CardContent></Card>
        <Card><CardHeader><CardTitle className="text-sm">Failed / Terminal</CardTitle></CardHeader><CardContent className="text-xl font-semibold">{counters.failed + counters.remoteTerminal}</CardContent></Card>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-sm">Filters</CardTitle></CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <p className="text-xs text-muted-foreground mb-1">Remote status</p>
            <Select value={remoteFilter} onValueChange={setRemoteFilter}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {REMOTE_STATUS_FILTER.map((v) => (
                  <SelectItem key={v} value={v}>{v}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <p className="text-xs text-muted-foreground mb-1">Local state</p>
            <Select value={localFilter} onValueChange={setLocalFilter}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {LOCAL_STATE_FILTER.map((v) => (
                  <SelectItem key={v} value={v}>{v}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <p className="text-xs text-muted-foreground mb-1">Search</p>
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="task id, gym id, media id, path, error..." />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm">Ad Tasks ({rows.length})</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Task</TableHead>
                <TableHead>Gym</TableHead>
                <TableHead>Media</TableHead>
                <TableHead>Scheduled</TableHead>
                <TableHead>Remote</TableHead>
                <TableHead>Local</TableHead>
                <TableHead>Outbox</TableHead>
                <TableHead>Runtime</TableHead>
                <TableHead>Validation</TableHead>
                <TableHead>Path</TableHead>
                <TableHead>Error</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r) => {
                const outboxState = String(r.outbox?.state || r.ready_confirm_outbox_state || "-");
                const runtimeState = String(r.local_display_state || "-");
                return (
                  <TableRow key={r.campaign_task_id}>
                    <TableCell className="font-mono">#{r.campaign_task_id}</TableCell>
                    <TableCell className="font-mono">{r.gym_id}</TableCell>
                    <TableCell className="font-mono">{r.ad_media_id}</TableCell>
                    <TableCell className="text-xs">{r.scheduled_at || "-"}</TableCell>
                    <TableCell><Badge variant={statusVariant(String(r.remote_status || ""))}>{String(r.remote_status || "-")}</Badge></TableCell>
                    <TableCell><Badge variant={statusVariant(String(r.local_preparation_state || ""))}>{String(r.local_preparation_state || "-")}</Badge></TableCell>
                    <TableCell><Badge variant={statusVariant(outboxState)}>{outboxState}</Badge></TableCell>
                    <TableCell><Badge variant={statusVariant(runtimeState)}>{runtimeState}</Badge>{Boolean(r.currently_injected) && <span className="ml-2 text-[10px] text-emerald-300">LIVE</span>}</TableCell>
                    <TableCell>{r.validation_strength || "-"}</TableCell>
                    <TableCell className="text-xs font-mono" title={r.expected_local_path || ""}>{short(r.expected_local_path || "-", 38)}</TableCell>
                    <TableCell className="text-xs" title={r.last_error_message || ""}>{short((r.display_abort_reason as string) || r.last_error_code || r.last_error_message || "-", 34)}</TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-2">
                        <Button size="sm" variant="outline" disabled={busy} onClick={() => void onRetryPrepare(Number(r.campaign_task_id))}>Retry Prepare</Button>
                        <Button size="sm" variant="outline" disabled={busy} onClick={() => void onRetryConfirm(Number(r.campaign_task_id))}>Retry Confirm</Button>
                        <Button size="sm" variant="outline" disabled={busy} onClick={() => void onInjectNow(Number(r.campaign_task_id))}>Inject Now</Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
              {!rows.length && (
                <TableRow>
                  <TableCell colSpan={12} className="text-center text-muted-foreground py-8">
                    No ad tasks in local cache.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
