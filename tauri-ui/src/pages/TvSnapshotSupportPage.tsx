import { useCallback, useEffect, useMemo, useState } from "react";
import { Play, RefreshCw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  activateTvLatestReady,
  getTvActivationHistory,
  getTvActivationStatus,
  getTvLatestSnapshot,
  getTvSnapshotManifest,
  getTvSyncStatus,
  runTvSync,
} from "@/api/tv";
import type { TvActivationAttemptRow, TvSnapshotCacheRow } from "@/api/types";

function readSnapshot(row: TvSnapshotCacheRow | null | undefined) {
  const r = (row || {}) as Record<string, any>;
  return {
    id: String(r.snapshot_id ?? r.snapshotId ?? ""),
    version: String(r.snapshot_version ?? r.snapshotVersion ?? ""),
    generatedAt: String(r.generated_at ?? r.generatedAt ?? ""),
    fetchedAt: String(r.fetched_at ?? r.fetchedAt ?? ""),
    day: String(r.resolved_day_of_week ?? r.resolvedDayOfWeek ?? ""),
    preset: String(r.resolved_preset_id ?? r.resolvedPresetId ?? ""),
    policy: String(r.resolved_policy_id ?? r.resolvedPolicyId ?? ""),
    layout: String(r.resolved_layout_preset_id ?? r.resolvedLayoutPresetId ?? ""),
    syncStatus: String(r.sync_status ?? r.syncStatus ?? ""),
    manifestStatus: String(r.manifest_status ?? r.manifestStatus ?? ""),
  };
}

function badgeForResult(result: string): "success" | "warning" | "destructive" | "secondary" {
  const r = (result || "").toUpperCase();
  if (r === "ACTIVATED") return "success";
  if (r.startsWith("SKIPPED")) return "warning";
  if (r === "FAILED") return "destructive";
  return "secondary";
}

export default function TvSnapshotSupportPage() {
  const [latest, setLatest] = useState<TvSnapshotCacheRow | null>(null);
  const [latestReady, setLatestReady] = useState<TvSnapshotCacheRow | null>(null);
  const [previousReady, setPreviousReady] = useState<TvSnapshotCacheRow | null>(null);
  const [activeSnapshot, setActiveSnapshot] = useState<TvSnapshotCacheRow | null>(null);
  const [previousActiveSnapshot, setPreviousActiveSnapshot] = useState<TvSnapshotCacheRow | null>(null);
  const [activationState, setActivationState] = useState<Record<string, any> | null>(null);
  const [activationHistory, setActivationHistory] = useState<TvActivationAttemptRow[]>([]);
  const [manifest, setManifest] = useState<Record<string, any> | null>(null);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [activating, setActivating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const status = await getTvSyncStatus();
      if (!status.screenId) {
        throw new Error("No bound screen. Set TV binding first.");
      }
      const [snap, act, hist] = await Promise.all([
        getTvLatestSnapshot(status.screenId),
        getTvActivationStatus(status.screenId),
        getTvActivationHistory({ screenId: status.screenId, limit: 50, offset: 0 }),
      ]);

      setLatest((snap.latest || null) as TvSnapshotCacheRow | null);
      setLatestReady((snap.latestReady || null) as TvSnapshotCacheRow | null);
      setPreviousReady((snap.previousReady || null) as TvSnapshotCacheRow | null);
      setActivationState((act.activation?.state || null) as Record<string, any> | null);
      setActiveSnapshot((act.activation?.activeSnapshot || null) as TvSnapshotCacheRow | null);
      setPreviousActiveSnapshot((act.activation?.previousActiveSnapshot || null) as TvSnapshotCacheRow | null);
      setActivationHistory((hist.rows || []) as TvActivationAttemptRow[]);

      const latestId = String((snap.latest as any)?.snapshot_id ?? (snap.latest as any)?.snapshotId ?? "");
      if (latestId) {
        const m = await getTvSnapshotManifest(latestId);
        setManifest(m.manifest || null);
      } else {
        setManifest(null);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setLatest(null);
      setLatestReady(null);
      setPreviousReady(null);
      setActiveSnapshot(null);
      setPreviousActiveSnapshot(null);
      setActivationState(null);
      setActivationHistory([]);
      setManifest(null);
    } finally {
      setLoading(false);
    }
  }, []);

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

  const onActivate = useCallback(async () => {
    setActivating(true);
    setError(null);
    setInfo(null);
    try {
      const status = await getTvSyncStatus();
      if (!status.screenId) {
        throw new Error("No bound screen. Set TV binding first.");
      }
      const res = await activateTvLatestReady({ screenId: status.screenId });
      if (!res.ok) {
        throw new Error(res.error || "Activation failed");
      }
      setInfo(`Activation result: ${res.result}.`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setActivating(false);
    }
  }, [load]);

  const latestView = useMemo(() => readSnapshot(latest), [latest]);
  const latestReadyView = useMemo(() => readSnapshot(latestReady), [latestReady]);
  const previousReadyView = useMemo(() => readSnapshot(previousReady), [previousReady]);
  const activeView = useMemo(() => readSnapshot(activeSnapshot), [activeSnapshot]);
  const previousActiveView = useMemo(() => readSnapshot(previousActiveSnapshot), [previousActiveSnapshot]);
  const manifestItems = useMemo(() => {
    const items = manifest?.items;
    return Array.isArray(items) ? items : [];
  }, [manifest]);

  const activationStateLabel = String(activationState?.activation_state || "-");
  const blockedReason = String(activationState?.blocked_reason || "-");

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">TV Snapshot Support</h1>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
          <Button onClick={() => void onSync()} disabled={syncing}>
            <RefreshCw className={`h-4 w-4 ${syncing ? "animate-spin" : ""}`} /> Sync Latest
          </Button>
          <Button onClick={() => void onActivate()} disabled={activating || !latestReadyView.id}>
            <Play className="h-4 w-4" /> Activate Ready
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTitle>Snapshot Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {info && (
        <Alert>
          <AlertTitle>Info</AlertTitle>
          <AlertDescription>{info}</AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader><CardTitle className="text-sm">Activation State</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-muted-foreground">State</span><Badge variant="outline">{activationStateLabel}</Badge></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Blocked Reason</span><span className="max-w-[170px] truncate" title={blockedReason}>{blockedReason}</span></div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-sm">Active / Previous Active</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-muted-foreground">Active</span><span>{activeView.version || "-"}</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Previous Active</span><span>{previousActiveView.version || "-"}</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Active ID</span><span className="font-mono text-xs max-w-[130px] truncate" title={activeView.id}>{activeView.id || "-"}</span></div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-sm">Latest / Latest Ready / Prev Ready</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-muted-foreground">Latest</span><span>{latestView.version || "-"}</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Latest Ready</span><span>{latestReadyView.version || "-"}</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Prev Ready</span><span>{previousReadyView.version || "-"}</span></div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Activation Attempts ({activationHistory.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Trigger</TableHead>
                <TableHead>Target Version</TableHead>
                <TableHead>Result</TableHead>
                <TableHead>Failure</TableHead>
                <TableHead>Started</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {activationHistory.map((row) => (
                <TableRow key={row.id}>
                  <TableCell className="font-mono text-xs">{row.id}</TableCell>
                  <TableCell>{row.trigger_source}</TableCell>
                  <TableCell>{row.target_snapshot_version ?? "-"}</TableCell>
                  <TableCell><Badge variant={badgeForResult(String(row.result || ""))}>{String(row.result || "-")}</Badge></TableCell>
                  <TableCell className="text-xs text-muted-foreground max-w-[260px] truncate" title={row.failure_message || row.failure_reason || ""}>{row.failure_reason || "-"}</TableCell>
                  <TableCell>{row.started_at}</TableCell>
                </TableRow>
              ))}
              {activationHistory.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-sm text-muted-foreground">No activation attempts recorded.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Required Asset Manifest ({manifestItems.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Media Asset ID</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Checksum</TableHead>
                <TableHead>Download Link</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {manifestItems.map((item: any, idx: number) => (
                <TableRow key={`${item.mediaAssetId ?? item.media_asset_id ?? idx}`}>
                  <TableCell className="font-mono text-xs">{String(item.mediaAssetId ?? item.media_asset_id ?? "-")}</TableCell>
                  <TableCell>{String(item.mediaType ?? item.media_type ?? "-")}</TableCell>
                  <TableCell>{String(item.title ?? "-")}</TableCell>
                  <TableCell className="font-mono text-xs max-w-[220px] truncate" title={String(item.checksumSha256 ?? item.checksum_sha256 ?? "")}>{String(item.checksumSha256 ?? item.checksum_sha256 ?? "-")}</TableCell>
                  <TableCell className="font-mono text-xs max-w-[420px] truncate" title={String(item.downloadLink ?? item.download_link ?? "")}>{String(item.downloadLink ?? item.download_link ?? "-")}</TableCell>
                </TableRow>
              ))}
              {manifestItems.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-sm text-muted-foreground">No manifest items available for the latest snapshot.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
