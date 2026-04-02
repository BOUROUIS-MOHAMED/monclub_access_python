import { startTransition, useDeferredValue, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Loader2, RefreshCw, ScreenShare } from "lucide-react";

import { ApiError } from "@/api/client";
import {
  getTvDashboardScreen,
  getTvDashboardScreenContentPlan,
  getTvDashboardScreenLatestSnapshot,
  getTvDashboardScreenSnapshots,
  getTvDashboardScreens,
  getTvDashboardSnapshot,
  getTvDashboardSnapshotManifest,
} from "@/tv/api";
import type {
  TvDashboardResolvedSnapshot,
  TvDashboardScreen,
  TvDashboardScreenContentPlan,
  TvDashboardSnapshotAssetManifest,
  TvDashboardTimelineItem,
} from "@/tv/api/types";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const EMPTY_SELECT = "__none__";
const DAY_LABELS: Record<string, string> = {
  MONDAY: "Monday",
  TUESDAY: "Tuesday",
  WEDNESDAY: "Wednesday",
  THURSDAY: "Thursday",
  FRIDAY: "Friday",
  SATURDAY: "Saturday",
  SUNDAY: "Sunday",
};
const DAY_ORDER = ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"] as const;

function formatTimestamp(value: string | null | undefined) {
  if (!value) return "n/a";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatMinuteOfDay(value: number | null | undefined) {
  if (value == null || Number.isNaN(value)) return "n/a";
  const minute = Math.max(0, Math.floor(value));
  const hour = Math.floor(minute / 60) % 24;
  return `${String(hour).padStart(2, "0")}:${String(minute % 60).padStart(2, "0")}`;
}

function formatBytes(value: number | null | undefined) {
  if (value == null || Number.isNaN(value)) return "n/a";
  if (value === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let current = value;
  let index = 0;
  while (current >= 1024 && index < units.length - 1) {
    current /= 1024;
    index += 1;
  }
  const digits = current >= 100 || index === 0 ? 0 : current >= 10 ? 1 : 2;
  return `${current.toFixed(digits)} ${units[index]}`;
}

function formatPresetValue(value: number | null | undefined) {
  return value == null ? "none" : `#${value}`;
}

function getVisualItems(snapshot: TvDashboardResolvedSnapshot | null) {
  const raw = snapshot?.payload?.timelines?.VISUAL;
  return Array.isArray(raw) ? raw : [];
}

function renderTimelineRow(item: TvDashboardTimelineItem, index: number) {
  const start = Math.max(0, Math.min(1440, Number(item.startMinuteOfDay ?? 0)));
  const end = Math.max(start, Math.min(1440, Number(item.endMinuteOfDay ?? start)));
  const left = (start / 1440) * 100;
  const width = Math.max(((end - start) / 1440) * 100, 2.5);
  const assetTitle = item.mediaAsset?.title || `Asset #${item.mediaAsset?.id ?? "?"}`;

  return (
    <div
      key={`${item.presetItemId ?? "preset"}-${item.mediaAsset?.id ?? index}-${index}`}
      className="rounded-lg border border-border bg-card p-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="font-medium text-foreground">{assetTitle}</div>
          <div className="text-xs text-muted-foreground">
            {item.mediaAsset?.mediaType || "UNKNOWN"} - Asset #{item.mediaAsset?.id ?? "?"}
          </div>
        </div>
        <Badge variant="outline">
          {formatMinuteOfDay(start)} - {formatMinuteOfDay(end)}
        </Badge>
      </div>
      <div className="mt-3 h-2 overflow-hidden rounded-full bg-muted/80">
        <div className="relative h-full w-full">
          <div className="absolute inset-y-0 left-1/4 w-px bg-border/90" />
          <div className="absolute inset-y-0 left-2/4 w-px bg-border/90" />
          <div className="absolute inset-y-0 left-3/4 w-px bg-border/90" />
          <div
            className="absolute inset-y-0 rounded-full bg-primary"
            style={{ left: `${left}%`, width: `${width}%` }}
          />
        </div>
      </div>
    </div>
  );
}

export default function TvScreensPage() {
  const navigate = useNavigate();
  const { screenId } = useParams<{ screenId?: string }>();
  const activeScreenId = Number(screenId || 0);

  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [refreshToken, setRefreshToken] = useState(0);

  const [screens, setScreens] = useState<TvDashboardScreen[]>([]);
  const [screensLoading, setScreensLoading] = useState(true);
  const [screensError, setScreensError] = useState<string | null>(null);

  const [screenDetail, setScreenDetail] = useState<TvDashboardScreen | null>(null);
  const [contentPlan, setContentPlan] = useState<TvDashboardScreenContentPlan | null>(null);
  const [snapshots, setSnapshots] = useState<TvDashboardResolvedSnapshot[]>([]);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const [selectedSnapshotId, setSelectedSnapshotId] = useState("");
  const [snapshotDetail, setSnapshotDetail] = useState<TvDashboardResolvedSnapshot | null>(null);
  const [snapshotManifest, setSnapshotManifest] = useState<TvDashboardSnapshotAssetManifest | null>(null);
  const [snapshotLoading, setSnapshotLoading] = useState(false);
  const [snapshotError, setSnapshotError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const loadScreens = async () => {
      setScreensLoading(true);
      setScreensError(null);
      try {
        const response = await getTvDashboardScreens({
          q: deferredQuery.trim() || undefined,
          includeArchived: true,
          page: 0,
          size: 100,
          sortBy: "name",
          sortDir: "asc",
        });
        if (!cancelled) {
          startTransition(() => setScreens(response.items ?? []));
        }
      } catch (error) {
        if (!cancelled) {
          setScreensError(error instanceof Error ? error.message : "Failed to load dashboard screens.");
        }
      } finally {
        if (!cancelled) {
          setScreensLoading(false);
        }
      }
    };

    void loadScreens();
    return () => {
      cancelled = true;
    };
  }, [deferredQuery, refreshToken]);

  useEffect(() => {
    let cancelled = false;

    if (!Number.isFinite(activeScreenId) || activeScreenId <= 0) {
      setScreenDetail(null);
      setContentPlan(null);
      setSnapshots([]);
      setSelectedSnapshotId("");
      return;
    }

    const loadDetail = async () => {
      setDetailLoading(true);
      setDetailError(null);
      try {
        const [screenResponse, contentResponse, snapshotPage, latestSnapshot] = await Promise.all([
          getTvDashboardScreen(activeScreenId),
          getTvDashboardScreenContentPlan(activeScreenId).catch((error) => {
            if (error instanceof ApiError && error.status === 404) return null;
            throw error;
          }),
          getTvDashboardScreenSnapshots(activeScreenId, {
            page: 0,
            size: 100,
            sortBy: "version",
            sortDir: "desc",
          }),
          getTvDashboardScreenLatestSnapshot(activeScreenId).catch((error) => {
            if (error instanceof ApiError && error.status === 404) return null;
            throw error;
          }),
        ]);
        if (!cancelled) {
          startTransition(() => {
            setScreenDetail(screenResponse);
            setContentPlan(contentResponse);
            setSnapshots(snapshotPage.items ?? []);
            setSelectedSnapshotId(String(latestSnapshot?.id ?? snapshotPage.items?.[0]?.id ?? ""));
          });
        }
      } catch (error) {
        if (!cancelled) {
          setDetailError(error instanceof Error ? error.message : "Failed to load screen details.");
        }
      } finally {
        if (!cancelled) {
          setDetailLoading(false);
        }
      }
    };

    void loadDetail();
    return () => {
      cancelled = true;
    };
  }, [activeScreenId, refreshToken]);

  useEffect(() => {
    let cancelled = false;

    if (!selectedSnapshotId) {
      setSnapshotDetail(null);
      setSnapshotManifest(null);
      setSnapshotError(null);
      return;
    }

    const loadSnapshot = async () => {
      setSnapshotLoading(true);
      setSnapshotError(null);
      try {
        const [snapshotResponse, manifestResponse] = await Promise.all([
          getTvDashboardSnapshot(selectedSnapshotId),
          getTvDashboardSnapshotManifest(selectedSnapshotId).catch((error) => {
            if (error instanceof ApiError && error.status === 404) return null;
            throw error;
          }),
        ]);
        if (!cancelled) {
          startTransition(() => {
            setSnapshotDetail(snapshotResponse);
            setSnapshotManifest(manifestResponse);
          });
        }
      } catch (error) {
        if (!cancelled) {
          setSnapshotError(error instanceof Error ? error.message : "Failed to load snapshot details.");
        }
      } finally {
        if (!cancelled) {
          setSnapshotLoading(false);
        }
      }
    };

    void loadSnapshot();
    return () => {
      cancelled = true;
    };
  }, [selectedSnapshotId]);

  const visualItems = useMemo(() => getVisualItems(snapshotDetail), [snapshotDetail]);
  const manifestItems = snapshotManifest?.items ?? snapshotDetail?.assetManifest?.items ?? [];
  const manifestByAssetId = useMemo(() => {
    const next = new Map<number, TvDashboardSnapshotAssetManifest["items"][number]>();
    for (const item of manifestItems) next.set(item.mediaAssetId, item);
    return next;
  }, [manifestItems]);

  return (
    <div className="space-y-6 p-6">
      <div>
        <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.25em] text-muted-foreground">
          <ScreenShare className="h-4 w-4" />
          Read-only dashboard mirror
        </div>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-foreground">Screens</h1>
        <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
          Browse dashboard screens from MonClub TV, inspect their content plan, and view the resolved visual timeline for any snapshot.
        </p>
      </div>
      {!screenId ? (
        <Card className="border-border">
          <CardHeader className="gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <CardTitle>Dashboard Screens</CardTitle>
              <CardDescription>Read-only list sourced from the MonClub dashboard backend.</CardDescription>
            </div>
            <div className="flex w-full gap-2 md:w-auto">
              <Input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search by screen name or id"
                className="md:w-72"
              />
              <Button variant="outline" onClick={() => setRefreshToken((value) => value + 1)}>
                <RefreshCw className="mr-2 h-4 w-4" />
                Refresh
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {screensError && (
              <Alert variant="destructive" className="mb-4">
                <AlertDescription>{screensError}</AlertDescription>
              </Alert>
            )}
            {screensLoading ? (
              <div className="flex items-center gap-2 py-8 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
                Loading dashboard screens...
              </div>
            ) : screens.length === 0 ? (
              <div className="rounded-lg border border-dashed border-border px-4 py-8 text-sm text-muted-foreground">
                No dashboard screens matched this filter.
              </div>
            ) : (
              <div className="overflow-hidden rounded-xl border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Screen</TableHead>
                      <TableHead>Gym</TableHead>
                      <TableHead>Display</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Latest sync</TableHead>
                      <TableHead className="text-right">Open</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {screens.map((screen) => (
                      <TableRow key={screen.id}>
                        <TableCell>
                          <div className="font-medium text-foreground">{screen.name}</div>
                          <div className="mt-1 text-xs text-muted-foreground">Screen #{screen.id}</div>
                        </TableCell>
                        <TableCell>Gym #{screen.gymId}</TableCell>
                        <TableCell>
                          {screen.resolutionWidth}x{screen.resolutionHeight} {screen.orientation.toLowerCase()}
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-2">
                            <Badge variant={screen.enabled ? "default" : "secondary"}>
                              {screen.enabled ? "Enabled" : "Disabled"}
                            </Badge>
                            <Badge variant={screen.readyForProgramming ? "outline" : "secondary"}>
                              {screen.readyForProgramming ? "Ready" : "Not ready"}
                            </Badge>
                            {screen.archivedAt && <Badge variant="secondary">Archived</Badge>}
                          </div>
                        </TableCell>
                        <TableCell>{formatTimestamp(screen.lastSyncAt)}</TableCell>
                        <TableCell className="text-right">
                          <Button variant="ghost" onClick={() => navigate(`/tv-screens/${screen.id}`)}>
                            Details
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-6">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" onClick={() => navigate("/tv-screens")}>
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to screens
              </Button>
              <Button variant="outline" onClick={() => setRefreshToken((value) => value + 1)}>
                <RefreshCw className="mr-2 h-4 w-4" />
                Refresh
              </Button>
            </div>
            <div className="grid gap-3 md:grid-cols-2 lg:w-[34rem]">
              <Select
                value={activeScreenId > 0 ? String(activeScreenId) : EMPTY_SELECT}
                onValueChange={(value) => value !== EMPTY_SELECT && navigate(`/tv-screens/${value}`)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select a screen" />
                </SelectTrigger>
                <SelectContent>
                  {screens.map((screen) => (
                    <SelectItem key={screen.id} value={String(screen.id)}>
                      {screen.name} (#{screen.id})
                    </SelectItem>
                  ))}
                  {screens.length === 0 && <SelectItem value={EMPTY_SELECT} disabled>No screens available</SelectItem>}
                </SelectContent>
              </Select>
              <Select
                value={selectedSnapshotId || EMPTY_SELECT}
                onValueChange={(value) => setSelectedSnapshotId(value === EMPTY_SELECT ? "" : value)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select a snapshot" />
                </SelectTrigger>
                <SelectContent>
                  {snapshots.map((snapshot) => (
                    <SelectItem key={snapshot.id} value={String(snapshot.id)}>
                      v{snapshot.version} - {formatTimestamp(snapshot.generatedAt)}
                    </SelectItem>
                  ))}
                  {snapshots.length === 0 && <SelectItem value={EMPTY_SELECT} disabled>No snapshots yet</SelectItem>}
                </SelectContent>
              </Select>
            </div>
          </div>
          {screensError && <Alert variant="destructive"><AlertDescription>{screensError}</AlertDescription></Alert>}
          {detailError && <Alert variant="destructive"><AlertDescription>{detailError}</AlertDescription></Alert>}
          {snapshotError && <Alert variant="destructive"><AlertDescription>{snapshotError}</AlertDescription></Alert>}
          {detailLoading ? (
            <div className="flex items-center gap-2 rounded-xl border border-border bg-card px-4 py-8 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading screen details...
            </div>
          ) : !screenDetail ? (
            <Alert variant="destructive">
              <AlertDescription>Screen details could not be loaded.</AlertDescription>
            </Alert>
          ) : (
            <>
              <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
                <Card className="border-border">
                  <CardHeader>
                    <CardTitle>{screenDetail.name}</CardTitle>
                    <CardDescription>Read-only dashboard screen details mirrored into MonClub TV.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex flex-wrap gap-2">
                      <Badge variant={screenDetail.enabled ? "default" : "secondary"}>
                        {screenDetail.enabled ? "Enabled" : "Disabled"}
                      </Badge>
                      <Badge variant={screenDetail.readyForProgramming ? "outline" : "secondary"}>
                        {screenDetail.readyForProgramming ? "Ready for programming" : "Needs attention"}
                      </Badge>
                      {screenDetail.archivedAt && <Badge variant="secondary">Archived</Badge>}
                    </div>
                    {screenDetail.description && (
                      <p className="text-sm text-muted-foreground">{screenDetail.description}</p>
                    )}
                    <div className="grid gap-3 md:grid-cols-2">
                      <div className="rounded-lg border border-border bg-muted/30 p-3">
                        <div className="text-xs uppercase tracking-[0.2em] text-muted-foreground">Identity</div>
                        <div className="mt-2 text-sm text-foreground">Screen #{screenDetail.id}</div>
                        <div className="mt-1 text-sm text-muted-foreground">Gym #{screenDetail.gymId}</div>
                      </div>
                      <div className="rounded-lg border border-border bg-muted/30 p-3">
                        <div className="text-xs uppercase tracking-[0.2em] text-muted-foreground">Display</div>
                        <div className="mt-2 text-sm text-foreground">
                          {screenDetail.resolutionWidth}x{screenDetail.resolutionHeight} {screenDetail.orientation.toLowerCase()}
                        </div>
                        <div className="mt-1 text-sm text-muted-foreground">{screenDetail.timezone}</div>
                      </div>
                      <div className="rounded-lg border border-border bg-muted/30 p-3">
                        <div className="text-xs uppercase tracking-[0.2em] text-muted-foreground">Policy</div>
                        <div className="mt-2 text-sm text-foreground">
                          Layout {formatPresetValue(screenDetail.layoutPresetId)} - Policy {formatPresetValue(screenDetail.playbackPolicyId)}
                        </div>
                        <div className="mt-1 text-sm text-muted-foreground">{screenDetail.policyNote || "No policy note."}</div>
                      </div>
                      <div className="rounded-lg border border-border bg-muted/30 p-3">
                        <div className="text-xs uppercase tracking-[0.2em] text-muted-foreground">Activity</div>
                        <div className="mt-2 text-sm text-foreground">Last sync: {formatTimestamp(screenDetail.lastSyncAt)}</div>
                        <div className="mt-1 text-sm text-muted-foreground">Last heartbeat: {formatTimestamp(screenDetail.lastHeartbeatAt)}</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-border">
                  <CardHeader>
                    <CardTitle>Weekly Content Plan</CardTitle>
                    <CardDescription>Current preset assignment for this screen.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {!contentPlan ? (
                      <div className="text-sm text-muted-foreground">No content plan returned for this screen.</div>
                    ) : (
                      <div className="space-y-3">
                        <div className="flex flex-wrap gap-2">
                          <Badge variant={contentPlan.enabled ? "default" : "secondary"}>
                            {contentPlan.enabled ? "Plan enabled" : "Plan disabled"}
                          </Badge>
                          <Badge variant="outline">Default preset {formatPresetValue(contentPlan.defaultPresetId)}</Badge>
                        </div>
                        <div className="overflow-hidden rounded-xl border border-border">
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead>Day</TableHead>
                                <TableHead>Preset</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {DAY_ORDER.map((day) => (
                                <TableRow key={day}>
                                  <TableCell>{DAY_LABELS[day]}</TableCell>
                                  <TableCell>{formatPresetValue(contentPlan.dayAssignments?.[day])}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
              <Card className="border-border">
                <CardHeader>
                  <CardTitle>Visual Timeline</CardTitle>
                  <CardDescription>The resolved VISUAL timeline from the selected snapshot payload.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {snapshotLoading ? (
                    <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Loading snapshot details...
                    </div>
                  ) : !snapshotDetail ? (
                    <div className="rounded-lg border border-dashed border-border px-4 py-8 text-sm text-muted-foreground">
                      Select a snapshot to view its visual timeline.
                    </div>
                  ) : visualItems.length === 0 ? (
                    <div className="rounded-lg border border-dashed border-border px-4 py-8 text-sm text-muted-foreground">
                      No visual timeline was found in this snapshot payload.
                    </div>
                  ) : (
                    <>
                      <div className="grid grid-cols-5 gap-2 text-[11px] uppercase tracking-[0.2em] text-muted-foreground">
                        <div>00:00</div>
                        <div className="text-center">06:00</div>
                        <div className="text-center">12:00</div>
                        <div className="text-center">18:00</div>
                        <div className="text-right">24:00</div>
                      </div>
                      <div className="space-y-3">{visualItems.map((item, index) => renderTimelineRow(item, index))}</div>
                    </>
                  )}
                </CardContent>
              </Card>

              <div className="grid gap-4 xl:grid-cols-[1.05fr_0.95fr]">
                <Card className="border-border">
                  <CardHeader>
                    <CardTitle>Visual Items</CardTitle>
                    <CardDescription>Resolved VISUAL rows with joined asset manifest details.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {visualItems.length === 0 ? (
                      <div className="text-sm text-muted-foreground">No visual items available for this snapshot.</div>
                    ) : (
                      <div className="overflow-hidden rounded-xl border border-border">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Window</TableHead>
                              <TableHead>Media</TableHead>
                              <TableHead>Asset</TableHead>
                              <TableHead>Audio</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {visualItems.map((item, index) => {
                              const manifest = item.mediaAsset?.id != null ? manifestByAssetId.get(item.mediaAsset.id) : undefined;
                              return (
                                <TableRow key={`${item.presetItemId ?? "preset"}-${item.mediaAsset?.id ?? index}-${index}`}>
                                  <TableCell>
                                    {formatMinuteOfDay(item.startMinuteOfDay)} - {formatMinuteOfDay(item.endMinuteOfDay)}
                                  </TableCell>
                                  <TableCell>
                                    <div className="font-medium text-foreground">{item.mediaAsset?.title || "Untitled asset"}</div>
                                    <div className="mt-1 text-xs text-muted-foreground">
                                      {item.mediaAsset?.mediaType || "UNKNOWN"} - Preset item #{item.presetItemId ?? "?"}
                                    </div>
                                  </TableCell>
                                  <TableCell>
                                    <div className="text-sm text-foreground">Asset #{item.mediaAsset?.id ?? "?"}</div>
                                    <div className="mt-1 text-xs text-muted-foreground">
                                      {(manifest?.mimeType || item.mediaAsset?.mimeType || "mime n/a")} - {formatBytes(manifest?.sizeBytes ?? item.mediaAsset?.sizeBytes)}
                                    </div>
                                  </TableCell>
                                  <TableCell>
                                    <div className="text-sm text-foreground">
                                      {item.videoAudioEnabled == null ? "n/a" : item.videoAudioEnabled ? "Video audio on" : "Video audio off"}
                                    </div>
                                    <div className="mt-1 text-xs text-muted-foreground">
                                      {item.audioOverriddenByTimeline ? "Overridden by audio timeline" : "No audio override"}
                                    </div>
                                  </TableCell>
                                </TableRow>
                              );
                            })}
                          </TableBody>
                        </Table>
                      </div>
                    )}
                  </CardContent>
                </Card>

                <Card className="border-border">
                  <CardHeader>
                    <CardTitle>Snapshot Assets</CardTitle>
                    <CardDescription>Asset manifest rows attached to this snapshot.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {manifestItems.length === 0 ? (
                      <div className="rounded-lg border border-dashed border-border px-4 py-8 text-sm text-muted-foreground">
                        No asset manifest was returned for this snapshot.
                      </div>
                    ) : (
                      <div className="overflow-hidden rounded-xl border border-border">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Asset</TableHead>
                              <TableHead>Type</TableHead>
                              <TableHead>Usage</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {manifestItems.map((item) => (
                              <TableRow key={item.mediaAssetId}>
                                <TableCell>
                                  <div className="font-medium text-foreground">{item.title}</div>
                                  <div className="mt-1 text-xs text-muted-foreground">
                                    Asset #{item.mediaAssetId} - {formatBytes(item.sizeBytes)}
                                  </div>
                                </TableCell>
                                <TableCell>
                                  <div className="text-sm text-foreground">{item.mediaType}</div>
                                  <div className="mt-1 text-xs text-muted-foreground">{item.mimeType || "mime n/a"}</div>
                                </TableCell>
                                <TableCell>
                                  <div className="text-sm text-foreground">{item.requiredInTimelines.join(", ") || "n/a"}</div>
                                  <div className="mt-1 text-xs text-muted-foreground">
                                    Source items {item.sourcePresetItemIds.length > 0 ? item.sourcePresetItemIds.join(", ") : "none"}
                                  </div>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>

              {snapshotDetail && (
                <Card className="border-border">
                  <CardHeader>
                    <CardTitle>Snapshot Summary</CardTitle>
                    <CardDescription>Selected snapshot metadata.</CardDescription>
                  </CardHeader>
                  <CardContent className="grid gap-3 md:grid-cols-3">
                    <div className="rounded-lg border border-border bg-muted/30 p-3">
                      <div className="text-xs uppercase tracking-[0.2em] text-muted-foreground">Version</div>
                      <div className="mt-2 text-sm text-foreground">v{snapshotDetail.version}</div>
                      <div className="mt-1 text-sm text-muted-foreground">{snapshotDetail.activationState}</div>
                    </div>
                    <div className="rounded-lg border border-border bg-muted/30 p-3">
                      <div className="text-xs uppercase tracking-[0.2em] text-muted-foreground">Generated</div>
                      <div className="mt-2 text-sm text-foreground">{formatTimestamp(snapshotDetail.generatedAt)}</div>
                      <div className="mt-1 text-sm text-muted-foreground">{DAY_LABELS[snapshotDetail.resolvedDayOfWeek] ?? snapshotDetail.resolvedDayOfWeek}</div>
                    </div>
                    <div className="rounded-lg border border-border bg-muted/30 p-3">
                      <div className="text-xs uppercase tracking-[0.2em] text-muted-foreground">Assets</div>
                      <div className="mt-2 text-sm text-foreground">{snapshotDetail.assetCount} assets</div>
                      <div className="mt-1 text-sm text-muted-foreground">{snapshotDetail.warningCount} warning(s)</div>
                    </div>
                  </CardContent>
                </Card>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
