import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getTvObservabilityHeartbeats, getTvObservabilityRuntimeEvents, getTvObservabilityRuntimeStats } from "@/api/tv";

function toUtcIso(localValue: string): string | undefined {
  const v = String(localValue || "").trim();
  if (!v) return undefined;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return undefined;
  return d.toISOString();
}

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

export default function TvRuntimeDiagnosticsPage() {
  const [screenId, setScreenId] = useState("");
  const [severities, setSeverities] = useState("WARNING,ERROR");
  const [eventTypes, setEventTypes] = useState("");
  const [fromLocal, setFromLocal] = useState("");
  const [toLocal, setToLocal] = useState("");

  const [stats, setStats] = useState<Record<string, any> | null>(null);
  const [events, setEvents] = useState<Array<Record<string, any>>>([]);
  const [heartbeats, setHeartbeats] = useState<Array<Record<string, any>>>([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [heartbeatsTotal, setHeartbeatsTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const sid = Number(screenId || 0);
      const fromUtc = toUtcIso(fromLocal);
      const toUtc = toUtcIso(toLocal);
      const [s, e, h] = await Promise.all([
        getTvObservabilityRuntimeStats({ screenId: sid > 0 ? sid : undefined, fromUtc, toUtc }),
        getTvObservabilityRuntimeEvents({
          screenId: sid > 0 ? sid : undefined,
          severities: severities.trim() || undefined,
          eventTypes: eventTypes.trim() || undefined,
          fromUtc,
          toUtc,
          limit: 300,
          offset: 0,
        }),
        getTvObservabilityHeartbeats({
          screenId: sid > 0 ? sid : undefined,
          fromUtc,
          toUtc,
          limit: 120,
          offset: 0,
        }),
      ]);
      setStats(s);
      setEvents(e.rows || []);
      setHeartbeats(h.rows || []);
      setEventsTotal(Number(e.total || 0));
      setHeartbeatsTotal(Number(h.total || 0));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStats(null);
      setEvents([]);
      setHeartbeats([]);
      setEventsTotal(0);
      setHeartbeatsTotal(0);
    } finally {
      setLoading(false);
    }
  }, [screenId, severities, eventTypes, fromLocal, toLocal]);

  useEffect(() => {
    void load();
  }, [load]);

  const sevCounts = useMemo(() => stats?.severityCounts || {}, [stats]);
  const typeCounts = useMemo(() => stats?.eventTypeCounts || {}, [stats]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">TV Runtime Diagnostics</h1>
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
        <CardHeader><CardTitle className="text-sm">Filters (UTC Query, Local Display)</CardTitle></CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-6 gap-3">
          <Input value={screenId} onChange={(e) => setScreenId(e.target.value)} placeholder="Screen ID (optional)" />
          <Input value={severities} onChange={(e) => setSeverities(e.target.value)} placeholder="Severities CSV" />
          <Input value={eventTypes} onChange={(e) => setEventTypes(e.target.value)} placeholder="Event types CSV" />
          <Input type="datetime-local" value={fromLocal} onChange={(e) => setFromLocal(e.target.value)} />
          <Input type="datetime-local" value={toLocal} onChange={(e) => setToLocal(e.target.value)} />
          <div className="text-sm text-muted-foreground flex items-center">Events: {eventsTotal}</div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <Card>
          <CardHeader><CardTitle className="text-sm">Total Runtime Events</CardTitle></CardHeader>
          <CardContent className="text-2xl font-semibold">{Number(stats?.totalRuntimeEvents || 0)}</CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Severity Counts</CardTitle></CardHeader>
          <CardContent className="flex flex-wrap gap-2 text-xs">
            {Object.entries(sevCounts).map(([k, v]) => <Badge key={k} variant={sevBadge(k)}>{k}: {String(v)}</Badge>)}
            {Object.keys(sevCounts).length === 0 && <span className="text-muted-foreground">No data</span>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Event Type Counts</CardTitle></CardHeader>
          <CardContent className="flex flex-wrap gap-2 text-xs">
            {Object.entries(typeCounts).map(([k, v]) => <Badge key={k} variant="outline">{k}: {String(v)}</Badge>)}
            {Object.keys(typeCounts).length === 0 && <span className="text-muted-foreground">No data</span>}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-sm">Runtime Events ({eventsTotal})</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>UTC Time</TableHead>
                <TableHead>Screen</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Code</TableHead>
                <TableHead>Message</TableHead>
                <TableHead>Correlation</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {events.map((row) => (
                <TableRow key={String(row.id)}>
                  <TableCell className="text-xs">{formatUtc(String(row.occurred_at_utc || ""))}</TableCell>
                  <TableCell className="text-xs">{String(row.screen_id || "-")}</TableCell>
                  <TableCell className="text-xs">{String(row.event_type || "-")}</TableCell>
                  <TableCell><Badge variant={sevBadge(String(row.severity || "INFO"))}>{String(row.severity || "INFO")}</Badge></TableCell>
                  <TableCell className="text-xs">{String(row.error_code || "-")}</TableCell>
                  <TableCell className="text-xs max-w-[400px] truncate" title={String(row.message || "")}>{String(row.message || "-")}</TableCell>
                  <TableCell className="text-xs">{String(row.correlation_id || "-")}</TableCell>
                </TableRow>
              ))}
              {events.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-sm text-muted-foreground">No runtime events.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm">Heartbeats ({heartbeatsTotal})</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>UTC Time</TableHead>
                <TableHead>Screen</TableHead>
                <TableHead>Binding</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Source</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {heartbeats.map((row) => (
                <TableRow key={String(row.id)}>
                  <TableCell className="text-xs">{formatUtc(String(row.heartbeat_at_utc || ""))}</TableCell>
                  <TableCell className="text-xs">{String(row.screen_id || "-")}</TableCell>
                  <TableCell className="text-xs">{String(row.binding_id || "-")}</TableCell>
                  <TableCell className="text-xs">{String(row.status || "-")}</TableCell>
                  <TableCell className="text-xs">{String(row.source || "-")}</TableCell>
                </TableRow>
              ))}
              {heartbeats.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-sm text-muted-foreground">No heartbeats.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
