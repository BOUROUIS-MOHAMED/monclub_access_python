import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getTvObservabilityScreenDetails, getTvObservabilityScreenTimeline } from "@/api/tv";
import type {
  TvObservabilityScreenDetailsResponse,
  TvObservabilityTimelineItem,
  TvObservabilityTimelineResponse,
} from "@/api/types";

function formatUtc(ts?: string | null): string {
  if (!ts) return "-";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts);
  return d.toLocaleString();
}

function sevBadge(sev: string): "secondary" | "warning" | "destructive" | "success" {
  const s = String(sev || "").toUpperCase();
  if (s === "ERROR") return "destructive";
  if (s === "WARNING") return "warning";
  if (s === "INFO") return "success";
  return "secondary";
}

function healthBadge(state: string): "success" | "warning" | "destructive" | "secondary" {
  const s = String(state || "").toUpperCase();
  if (s === "HEALTHY") return "success";
  if (s === "WARNING" || s === "DEGRADED") return "warning";
  if (s === "OFFLINE" || s === "UNKNOWN") return "secondary";
  return "destructive";
}

export default function TvScreenDiagnosticsPage() {
  const params = useParams();
  const screenId = Number(params.screenId || 0);

  const [details, setDetails] = useState<TvObservabilityScreenDetailsResponse | null>(null);
  const [timeline, setTimeline] = useState<TvObservabilityTimelineResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!(screenId > 0)) return;
    setLoading(true);
    setError(null);
    try {
      const [d, t] = await Promise.all([
        getTvObservabilityScreenDetails(screenId),
        getTvObservabilityScreenTimeline(screenId, { limit: 300, offset: 0 }),
      ]);
      setDetails(d);
      setTimeline(t);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setDetails(null);
      setTimeline(null);
    } finally {
      setLoading(false);
    }
  }, [screenId]);

  useEffect(() => {
    void load();
  }, [load]);

  const screen = details?.screen;
  const timelineRows = useMemo(() => (timeline?.rows || []) as TvObservabilityTimelineItem[], [timeline]);
  const heartbeatRows = useMemo(() => details?.heartbeats?.rows || [], [details]);
  const runtimeRows = useMemo(() => details?.runtimeEvents?.rows || [], [details]);
  const proofRows = useMemo(() => details?.proofEvents?.rows || [], [details]);
  const supportRows = useMemo(() => details?.supportActions?.rows || [], [details]);
  const activationRows = useMemo(() => details?.activationAttempts?.rows || [], [details]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">TV Screen Diagnostics #{screenId || "-"}</h1>
        <Button variant="outline" disabled={loading} onClick={() => void load()}>
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} /> Refresh
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Load Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Operational Summary</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
          <div className="border rounded p-2">
            <div>Screen: <strong>{screen?.screenName || "-"}</strong></div>
            <div>ID: {screen?.screenId ?? "-"}</div>
            <div>Binding: {screen?.bindingId ?? "-"}</div>
          </div>
          <div className="border rounded p-2">
            <div>Health: <Badge variant={healthBadge(String(screen?.health || "UNKNOWN"))}>{String(screen?.health || "UNKNOWN")}</Badge></div>
            <div>Runtime: {screen?.runtimeState || "-"}</div>
            <div>Readiness: {screen?.readinessState || "-"}</div>
          </div>
          <div className="border rounded p-2">
            <div>Latest: {screen?.latestSnapshotVersion ?? "-"}</div>
            <div>Latest Ready: {screen?.latestReadySnapshotVersion ?? "-"}</div>
            <div>Active: {screen?.activeSnapshotVersion ?? "-"}</div>
          </div>
          <div className="border rounded p-2">
            <div>Heartbeat: {formatUtc(screen?.latestHeartbeatAtUtc || null)}</div>
            <div>Proof: {formatUtc(screen?.latestProofAtUtc || null)}</div>
            <div>Failed Downloads: {screen?.failedDownloadCount ?? 0}</div>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="timeline" className="space-y-3">
        <TabsList>
          <TabsTrigger value="timeline">Unified Timeline</TabsTrigger>
          <TabsTrigger value="runtime">Runtime</TabsTrigger>
          <TabsTrigger value="proof">Proof</TabsTrigger>
          <TabsTrigger value="heartbeats">Heartbeats</TabsTrigger>
          <TabsTrigger value="support">Support/Activation</TabsTrigger>
        </TabsList>

        <TabsContent value="timeline">
          <Card>
            <CardHeader><CardTitle className="text-sm">Merged Diagnostic Timeline</CardTitle></CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>UTC Time</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Title</TableHead>
                    <TableHead>Message</TableHead>
                    <TableHead>Correlation</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {timelineRows.map((row, idx) => (
                    <TableRow key={`${row.source}-${row.timestampUtc || "-"}-${idx}`}>
                      <TableCell className="text-xs">{formatUtc(row.timestampUtc || null)}</TableCell>
                      <TableCell className="text-xs">{row.source || "-"}</TableCell>
                      <TableCell><Badge variant={sevBadge(String(row.severity || "INFO"))}>{String(row.severity || "INFO")}</Badge></TableCell>
                      <TableCell className="text-xs">{row.title || "-"}</TableCell>
                      <TableCell className="text-xs max-w-[420px] truncate" title={row.message || ""}>{row.message || "-"}</TableCell>
                      <TableCell className="text-xs">{row.correlationId || "-"}</TableCell>
                    </TableRow>
                  ))}
                  {timelineRows.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-sm text-muted-foreground">No timeline entries.</TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="runtime">
          <Card>
            <CardHeader><CardTitle className="text-sm">Runtime Events ({runtimeRows.length})</CardTitle></CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>UTC Time</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Code</TableHead>
                    <TableHead>Message</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {runtimeRows.map((row) => (
                    <TableRow key={String(row.id)}>
                      <TableCell className="text-xs">{formatUtc(String(row.occurred_at_utc || ""))}</TableCell>
                      <TableCell className="text-xs">{String(row.event_type || "-")}</TableCell>
                      <TableCell><Badge variant={sevBadge(String(row.severity || "INFO"))}>{String(row.severity || "INFO")}</Badge></TableCell>
                      <TableCell className="text-xs">{String(row.error_code || "-")}</TableCell>
                      <TableCell className="text-xs max-w-[460px] truncate" title={String(row.message || "")}>{String(row.message || "-")}</TableCell>
                    </TableRow>
                  ))}
                  {runtimeRows.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-sm text-muted-foreground">No runtime events.</TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="proof">
          <Card>
            <CardHeader><CardTitle className="text-sm">Proof Events ({proofRows.length})</CardTitle></CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>UTC Time</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Timeline</TableHead>
                    <TableHead>Asset</TableHead>
                    <TableHead>Snapshot</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {proofRows.map((row) => (
                    <TableRow key={String(row.id)}>
                      <TableCell className="text-xs">{formatUtc(String(row.proof_at_utc || ""))}</TableCell>
                      <TableCell className="text-xs">{String(row.status || "-")}</TableCell>
                      <TableCell className="text-xs">{String(row.proof_type || "-")}</TableCell>
                      <TableCell className="text-xs">{String(row.timeline_type || "-")}</TableCell>
                      <TableCell className="text-xs">{String(row.media_asset_id || "-")}</TableCell>
                      <TableCell className="text-xs">{String(row.snapshot_version || "-")}</TableCell>
                    </TableRow>
                  ))}
                  {proofRows.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-sm text-muted-foreground">No proof events.</TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="heartbeats">
          <Card>
            <CardHeader><CardTitle className="text-sm">Heartbeats ({heartbeatRows.length})</CardTitle></CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>UTC Time</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Binding</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {heartbeatRows.map((row) => (
                    <TableRow key={String(row.id)}>
                      <TableCell className="text-xs">{formatUtc(String(row.heartbeat_at_utc || ""))}</TableCell>
                      <TableCell className="text-xs">{String(row.status || "-")}</TableCell>
                      <TableCell className="text-xs">{String(row.source || "-")}</TableCell>
                      <TableCell className="text-xs">{String(row.binding_id || "-")}</TableCell>
                    </TableRow>
                  ))}
                  {heartbeatRows.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={4} className="text-center text-sm text-muted-foreground">No heartbeats.</TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="support">
          <Card>
            <CardHeader><CardTitle className="text-sm">Support Actions ({supportRows.length}) / Activation Attempts ({activationRows.length})</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              <div>
                <div className="text-xs font-medium mb-2">Support Actions</div>
                <div className="space-y-1 max-h-56 overflow-auto">
                  {supportRows.length === 0 && <div className="text-xs text-muted-foreground">No support actions.</div>}
                  {supportRows.map((row) => (
                    <div key={String(row.id)} className="text-xs border rounded p-2">
                      <div className="font-mono">#{String(row.id)} {String(row.action_type || "-")} [{String(row.result || "-")}]</div>
                      <div className="text-muted-foreground">{String(row.message || row.error_code || "-")}</div>
                      <div className="text-muted-foreground">corr={String(row.correlation_id || "-")} at {formatUtc(String(row.finished_at || row.created_at || ""))}</div>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <div className="text-xs font-medium mb-2">Activation Attempts</div>
                <div className="space-y-1 max-h-56 overflow-auto">
                  {activationRows.length === 0 && <div className="text-xs text-muted-foreground">No activation attempts.</div>}
                  {activationRows.map((row) => (
                    <div key={String(row.id)} className="text-xs border rounded p-2">
                      <div className="font-mono">#{String(row.id)} [{String(row.result || "-")}] target={String(row.target_snapshot_version || "-")}</div>
                      <div className="text-muted-foreground">{String(row.failure_reason || row.failure_message || "-")}</div>
                      <div className="text-muted-foreground">{formatUtc(String(row.finished_at || row.started_at || ""))}</div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
