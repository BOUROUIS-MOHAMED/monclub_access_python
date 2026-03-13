import { useCallback, useEffect, useMemo, useState } from "react";
import { Download, RefreshCw, RotateCcw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  getTvCacheAssets,
  getTvDownloadJobs,
  getTvLatestDownloadBatch,
  getTvSyncStatus,
  retryTvDownloadJob,
  runTvDownloads,
  runTvSync,
} from "@/api/tv";
import type {
  TvCacheAssetRow,
  TvCacheAssetsResponse,
  TvDownloadBatchSummary,
  TvDownloadJobRow,
  TvReadinessState,
} from "@/api/types";

const STATES: Array<{ value: string; label: string }> = [
  { value: "ALL", label: "All states" },
  { value: "VALID", label: "VALID" },
  { value: "NOT_PRESENT", label: "NOT_PRESENT" },
  { value: "INVALID_SIZE", label: "INVALID_SIZE" },
  { value: "INVALID_CHECKSUM", label: "INVALID_CHECKSUM" },
  { value: "INVALID_UNREADABLE", label: "INVALID_UNREADABLE" },
  { value: "STALE", label: "STALE" },
  { value: "ERROR", label: "ERROR" },
];

function readStateVariant(state: TvReadinessState | string): "success" | "warning" | "destructive" | "secondary" {
  if (state === "READY") return "success";
  if (state === "PARTIALLY_READY") return "warning";
  if (state === "EMPTY") return "secondary";
  return "destructive";
}

function readAssetStateVariant(state: string): "success" | "warning" | "destructive" | "secondary" {
  if (state === "VALID") return "success";
  if (state === "NOT_PRESENT" || state === "STALE") return "warning";
  if (state === "PRESENT_UNCHECKED") return "secondary";
  return "destructive";
}

function readDownloadStateVariant(state: string): "success" | "warning" | "destructive" | "secondary" {
  if (state === "SUCCEEDED" || state === "SKIPPED_ALREADY_VALID") return "success";
  if (state === "QUEUED" || state === "DOWNLOADING" || state === "VALIDATING" || state === "RETRY_WAIT") return "warning";
  if (state === "FAILED") return "destructive";
  return "secondary";
}

function readBatchCount(batch: TvDownloadBatchSummary | null, state: string): number {
  return Number((batch?.counts || {})[state] || 0);
}

export default function TvMediaCachePage() {
  const [payload, setPayload] = useState<TvCacheAssetsResponse | null>(null);
  const [latestBatch, setLatestBatch] = useState<TvDownloadBatchSummary | null>(null);
  const [jobs, setJobs] = useState<TvDownloadJobRow[]>([]);
  const [stateFilter, setStateFilter] = useState<string>("ALL");
  const [search, setSearch] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [syncing, setSyncing] = useState<boolean>(false);
  const [runningDownloads, setRunningDownloads] = useState<boolean>(false);
  const [retryingJobId, setRetryingJobId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const status = await getTvSyncStatus();
      const sid = status.screenId ?? undefined;
      const [res, batchRes] = await Promise.all([
        getTvCacheAssets({
          screenId: sid ?? undefined,
          states: stateFilter === "ALL" ? undefined : stateFilter,
          limit: 2000,
          offset: 0,
        }),
        getTvLatestDownloadBatch(sid ?? undefined),
      ]);
      setPayload(res);
      const batch = batchRes.batch || null;
      setLatestBatch(batch);

      if (batch?.batchId) {
        const jobsRes = await getTvDownloadJobs({
          screenId: sid ?? undefined,
          batchId: batch.batchId,
          limit: 500,
          offset: 0,
        });
        setJobs((jobsRes.rows || []) as TvDownloadJobRow[]);
      } else {
        setJobs([]);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPayload(null);
      setLatestBatch(null);
      setJobs([]);
    } finally {
      setLoading(false);
    }
  }, [stateFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  const onSync = useCallback(async () => {
    setSyncing(true);
    setError(null);
    setInfo(null);
    try {
      const status = await getTvSyncStatus();
      if (!status.screenId) {
        throw new Error("No bound screen. Set TV binding first.");
      }
      const res = await runTvSync({ screenId: status.screenId });
      if (!res.ok) {
        throw new Error(res.error || "TV sync failed");
      }
      setInfo(`Synced snapshot v${res.snapshotVersion ?? "?"}.`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSyncing(false);
    }
  }, [load]);

  const onDownloadMissing = useCallback(async () => {
    setRunningDownloads(true);
    setError(null);
    setInfo(null);
    try {
      const status = await getTvSyncStatus();
      if (!status.screenId) {
        throw new Error("No bound screen. Set TV binding first.");
      }
      const res = await runTvDownloads({ screenId: status.screenId, runInBackground: true, maxConcurrency: 1 });
      if (!res.ok) {
        throw new Error(res.error || "Download batch failed");
      }
      setInfo(`Download batch started (${res.batchId || "-"}).`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunningDownloads(false);
    }
  }, [load]);

  const onRetryFailedBatch = useCallback(async () => {
    setRunningDownloads(true);
    setError(null);
    setInfo(null);
    try {
      const status = await getTvSyncStatus();
      if (!status.screenId) {
        throw new Error("No bound screen. Set TV binding first.");
      }
      const res = await runTvDownloads({
        screenId: status.screenId,
        retryFailedOnly: true,
        runInBackground: true,
        maxConcurrency: 1,
      });
      if (!res.ok) {
        throw new Error(res.error || "Retry batch failed");
      }
      setInfo(`Retry batch started (${res.batchId || "-"}).`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunningDownloads(false);
    }
  }, [load]);

  const onRetryAsset = useCallback(
    async (mediaAssetId: string) => {
      setRunningDownloads(true);
      setError(null);
      setInfo(null);
      try {
        const status = await getTvSyncStatus();
        if (!status.screenId) {
          throw new Error("No bound screen. Set TV binding first.");
        }
        const res = await runTvDownloads({
          screenId: status.screenId,
          mediaAssetId,
          force: true,
          runInBackground: true,
          maxConcurrency: 1,
        });
        if (!res.ok) {
          throw new Error(res.error || "Asset retry failed");
        }
        setInfo(`Retry queued for asset ${mediaAssetId} (batch ${res.batchId || "-"}).`);
        await load();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setRunningDownloads(false);
      }
    },
    [load]
  );

  const onRetryJob = useCallback(
    async (jobId: number) => {
      setRetryingJobId(jobId);
      setError(null);
      setInfo(null);
      try {
        const res = await retryTvDownloadJob(jobId, { runInBackground: true });
        if (!res.ok) {
          throw new Error(res.error || "Job retry failed");
        }
        setInfo(`Retry started from job ${jobId} (batch ${res.batchId || "-"}).`);
        await load();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setRetryingJobId(null);
      }
    },
    [load]
  );

  const rows = useMemo(() => {
    const items = (payload?.rows || []) as TvCacheAssetRow[];
    const q = search.trim().toLowerCase();
    if (!q) return items;
    return items.filter((r) => {
      const hay = [
        r.media_asset_id,
        r.title || "",
        r.media_type || "",
        r.asset_state,
        r.download_state || "",
        r.state_reason || "",
        r.last_download_error_reason || "",
        r.last_download_error_message || "",
        r.last_download_batch_id || "",
        r.expected_local_path || "",
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [payload?.rows, search]);

  const readiness = payload?.latestReadiness as Record<string, any> | undefined;
  const readinessState = (readiness?.readiness_state || readiness?.readinessState || "UNKNOWN") as string;
  const readyCount = Number(readiness?.ready_asset_count ?? readiness?.readyAssetCount ?? 0);
  const missingCount = Number(readiness?.missing_asset_count ?? readiness?.missingAssetCount ?? 0);
  const invalidCount = Number(readiness?.invalid_asset_count ?? readiness?.invalidAssetCount ?? 0);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">TV Media Cache / Readiness</h1>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
          <Button onClick={() => void onSync()} disabled={syncing}>
            <RefreshCw className={`h-4 w-4 ${syncing ? "animate-spin" : ""}`} /> Sync Latest
          </Button>
          <Button onClick={() => void onDownloadMissing()} disabled={runningDownloads}>
            <Download className={`h-4 w-4 ${runningDownloads ? "animate-pulse" : ""}`} /> Download Missing
          </Button>
          <Button variant="outline" onClick={() => void onRetryFailedBatch()} disabled={runningDownloads}>
            <RotateCcw className="h-4 w-4" /> Retry Failed
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTitle>TV Cache Error</AlertTitle>
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
        <Card>
          <CardHeader><CardTitle className="text-sm">Snapshot Version</CardTitle></CardHeader>
          <CardContent className="text-xl font-semibold">{payload?.snapshotVersion ?? "-"}</CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Readiness</CardTitle></CardHeader>
          <CardContent><Badge variant={readStateVariant(readinessState)}>{readinessState}</Badge></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Ready / Missing / Invalid</CardTitle></CardHeader>
          <CardContent className="text-sm">{readyCount} / {missingCount} / {invalidCount}</CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Latest Batch</CardTitle></CardHeader>
          <CardContent className="text-xs font-mono">{latestBatch?.batchId || "-"}</CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Batch Success / Failed</CardTitle></CardHeader>
          <CardContent className="text-sm">{readBatchCount(latestBatch, "SUCCEEDED")} / {readBatchCount(latestBatch, "FAILED")}</CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Filters</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <p className="text-xs text-muted-foreground mb-1">Asset State</p>
            <Select value={stateFilter} onValueChange={setStateFilter}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {STATES.map((s) => (
                  <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="md:col-span-2">
            <p className="text-xs text-muted-foreground mb-1">Search</p>
            <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search by media ID, title, path, batch..." />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Local Asset Validation ({rows.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Asset</TableHead>
                <TableHead>Asset State</TableHead>
                <TableHead>Download</TableHead>
                <TableHead>Validation</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Expected Path</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>Batch</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row) => {
                const downloadState = String(row.download_state || "-");
                const canRetry = row.asset_state !== "VALID";
                return (
                  <TableRow key={`${row.media_asset_id}-${row.snapshot_version ?? "latest"}`}>
                    <TableCell className="font-mono text-xs">{row.media_asset_id}</TableCell>
                    <TableCell><Badge variant={readAssetStateVariant(row.asset_state)}>{row.asset_state}</Badge></TableCell>
                    <TableCell><Badge variant={readDownloadStateVariant(downloadState)}>{downloadState}</Badge></TableCell>
                    <TableCell>
                      {row.validation_mode ? (
                        <Badge variant={String(row.validation_mode).toUpperCase() === "WEAK" ? "warning" : "success"}>
                          {String(row.validation_mode).toUpperCase()}
                        </Badge>
                      ) : "-"}
                    </TableCell>
                    <TableCell>{row.media_type || "-"}</TableCell>
                    <TableCell className="font-mono text-xs max-w-[320px] truncate" title={row.expected_local_path}>{row.expected_local_path}</TableCell>
                    <TableCell className="text-xs text-muted-foreground max-w-[280px] truncate" title={row.last_download_error_message || row.state_reason || ""}>
                      {row.last_download_error_reason || row.state_reason || "-"}
                    </TableCell>
                    <TableCell className="font-mono text-xs max-w-[180px] truncate" title={row.last_download_batch_id || ""}>{row.last_download_batch_id || "-"}</TableCell>
                    <TableCell>
                      <Button size="sm" variant="outline" disabled={!canRetry || runningDownloads} onClick={() => void onRetryAsset(row.media_asset_id)}>
                        Retry
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
              {rows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={9} className="text-center text-sm text-muted-foreground">No assets found for current filter.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Download Jobs ({jobs.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Job ID</TableHead>
                <TableHead>Batch</TableHead>
                <TableHead>Asset</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Attempt</TableHead>
                <TableHead>Failure</TableHead>
                <TableHead>HTTP</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {jobs.map((job) => {
                const state = String(job.state || "-").toUpperCase();
                const canRetry = state === "FAILED";
                return (
                  <TableRow key={`${job.id}`}>
                    <TableCell className="font-mono text-xs">{job.id}</TableCell>
                    <TableCell className="font-mono text-xs max-w-[180px] truncate" title={job.batch_id}>{job.batch_id}</TableCell>
                    <TableCell className="font-mono text-xs">{job.media_asset_id}</TableCell>
                    <TableCell><Badge variant={readDownloadStateVariant(state)}>{state}</Badge></TableCell>
                    <TableCell>{job.attempt_no ?? 0} / {job.max_attempts ?? 0}</TableCell>
                    <TableCell className="text-xs text-muted-foreground max-w-[260px] truncate" title={job.failure_message || job.failure_reason || ""}>{job.failure_reason || "-"}</TableCell>
                    <TableCell>{job.http_status ?? "-"}</TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={!canRetry || retryingJobId === job.id}
                        onClick={() => void onRetryJob(job.id)}
                      >
                        Retry Job
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
              {jobs.length === 0 && (
                <TableRow>
                  <TableCell colSpan={8} className="text-center text-sm text-muted-foreground">No download jobs yet.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Alert>
        <AlertTitle>Operational Rule</AlertTitle>
        <AlertDescription>
          <strong>PARTIALLY_READY</strong> remains informational. Only <strong>READY</strong> is fully ready for future activation.
        </AlertDescription>
      </Alert>
    </div>
  );
}
