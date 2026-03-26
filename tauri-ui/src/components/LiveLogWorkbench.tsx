import {
  startTransition,
  useCallback,
  useDeferredValue,
  useEffect,
  useEffectEvent,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  Activity,
  Download,
  FolderOpen,
  Loader2,
  Pause,
  Play,
  RefreshCw,
  Search,
  Trash2,
  Wifi,
  WifiOff,
} from "lucide-react";

import type { LogLine } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import { formatLogClock, matchesLogLine, normalizeLogLine, type LogFilters, upsertLogLine } from "@/lib/logs";

interface LogLoadResponse {
  lines?: LogLine[];
  total?: number;
  ok?: boolean;
}

interface LiveLogWorkbenchProps {
  eyebrow: string;
  title: string;
  description: string;
  exportPrefix: string;
  emptyText: string;
  accentClassName?: string;
  loadRecent: (limit: number) => Promise<LogLoadResponse>;
  openStream: (
    onEvent: (type: string, data: unknown) => void,
    onError?: (event: Event) => void,
  ) => EventSource;
  openFolder?: () => Promise<unknown>;
  defaultLimit?: number;
  maxLines?: number;
}

const LEVEL_OPTIONS = ["ALL", "ERROR", "WARNING", "INFO", "DEBUG"] as const;
const SCROLL_BOTTOM_THRESHOLD_PX = 40;

function levelBadgeClass(level: string): string {
  switch (level.toUpperCase()) {
    case "ERROR":
    case "CRITICAL":
      return "border-red-500/20 bg-red-500/10 text-red-300";
    case "WARNING":
    case "WARN":
      return "border-amber-500/20 bg-amber-500/10 text-amber-300";
    case "DEBUG":
      return "border-slate-500/20 bg-slate-500/10 text-slate-300";
    default:
      return "border-sky-500/20 bg-sky-500/10 text-sky-300";
  }
}

function levelDotClass(level: string): string {
  switch (level.toUpperCase()) {
    case "ERROR":
    case "CRITICAL":
      return "bg-red-400";
    case "WARNING":
    case "WARN":
      return "bg-amber-400";
    case "DEBUG":
      return "bg-slate-400";
    default:
      return "bg-sky-400";
  }
}

function toSafeString(value: string | number | null | undefined): string {
  return value == null ? "" : String(value);
}

function isNearBottom(viewport: HTMLDivElement, threshold = SCROLL_BOTTOM_THRESHOLD_PX): boolean {
  return viewport.scrollHeight - viewport.clientHeight - viewport.scrollTop <= threshold;
}

export default function LiveLogWorkbench({
  eyebrow,
  title,
  description,
  exportPrefix,
  emptyText,
  accentClassName = "border-sky-500/20 bg-sky-500/10 text-sky-300",
  loadRecent,
  openStream,
  openFolder,
  defaultLimit = 600,
  maxLines = 2000,
}: LiveLogWorkbenchProps) {
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [loading, setLoading] = useState(true);
  const [reloading, setReloading] = useState(false);
  const [liveFollow, setLiveFollow] = useState(true);
  const [search, setSearch] = useState("");
  const [levelFilter, setLevelFilter] = useState("ALL");
  const [categoryFilter, setCategoryFilter] = useState("ALL");
  const [doorFilter, setDoorFilter] = useState("");
  const [cardFilter, setCardFilter] = useState("");
  const [deviceFilter, setDeviceFilter] = useState("");
  const [repeatedOnly, setRepeatedOnly] = useState(false);
  const [streamLive, setStreamLive] = useState(false);
  const [streamError, setStreamError] = useState<string | null>(null);
  const [lastActivityAt, setLastActivityAt] = useState<string | null>(null);
  const viewportRef = useRef<HTMLDivElement | null>(null);
  const loadRecentRef = useRef(loadRecent);
  const openStreamRef = useRef(openStream);
  const logsRef = useRef<LogLine[]>([]);
  const programmaticScrollRef = useRef(false);

  const deferredSearch = useDeferredValue(search);

  useEffect(() => {
    loadRecentRef.current = loadRecent;
  }, [loadRecent]);

  useEffect(() => {
    openStreamRef.current = openStream;
  }, [openStream]);

  useEffect(() => {
    logsRef.current = logs;
  }, [logs]);

  const scrollToBottom = useCallback((behavior: ScrollBehavior = "auto") => {
    const viewport = viewportRef.current;
    if (!viewport) {
      return;
    }
    programmaticScrollRef.current = true;
    viewport.scrollTo({ top: viewport.scrollHeight, behavior });
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        programmaticScrollRef.current = false;
      });
    });
  }, []);

  const refreshLogs = useCallback(async (showReloadState = false) => {
    const shouldShowLoadingState = !showReloadState && logsRef.current.length === 0;
    if (showReloadState) {
      setReloading(true);
    }
    if (shouldShowLoadingState) {
      setLoading(true);
    }
    try {
      const response = await loadRecentRef.current(defaultLimit);
      const normalized = (response.lines ?? [])
        .map((line) => normalizeLogLine(line))
        .filter((line): line is LogLine => Boolean(line));
      logsRef.current = normalized;
      setLogs(normalized);
      const latest = normalized.length > 0 ? normalized[normalized.length - 1] : null;
      setLastActivityAt(toSafeString(latest?.lastSeenAt || latest?.ts) || null);
    } finally {
      if (shouldShowLoadingState) {
        setLoading(false);
      }
      setReloading(false);
    }
  }, [defaultLimit]);

  useEffect(() => {
    void refreshLogs(false);
  }, [refreshLogs]);

  const handleStreamEvent = useEffectEvent((type: string, payload: unknown) => {
    if (type !== "log") {
      return;
    }
    const normalized = normalizeLogLine(payload);
    if (!normalized) {
      return;
    }
    setLastActivityAt(toSafeString(normalized.lastSeenAt || normalized.ts) || null);
    startTransition(() => {
      setLogs((current) => {
        const next = upsertLogLine(current, normalized, maxLines);
        logsRef.current = next;
        return next;
      });
    });
  });

  useEffect(() => {
    const stream = openStreamRef.current(
      (type, payload) => {
        handleStreamEvent(type, payload);
      },
      () => {
        setStreamLive(false);
        setStreamError("Reconnecting to the local stream...");
      },
    );

    stream.onopen = () => {
      setStreamLive(true);
      setStreamError(null);
    };

    return () => {
      stream.close();
    };
  }, []);

  const categories = useMemo(() => {
    const values = logs
      .map((line) => toSafeString(line.tokens?.category).trim().toUpperCase())
      .filter(Boolean);
    return Array.from(new Set(values)).sort();
  }, [logs]);

  const filters = useMemo<LogFilters>(() => ({
    query: deferredSearch.trim(),
    level: levelFilter,
    category: categoryFilter,
    door: doorFilter.trim(),
    card: cardFilter.trim(),
    device: deviceFilter.trim(),
    repeatedOnly,
  }), [cardFilter, categoryFilter, deferredSearch, deviceFilter, doorFilter, levelFilter, repeatedOnly]);

  const filteredLogs = useMemo(
    () => logs.filter((line) => matchesLogLine(line, filters)),
    [filters, logs],
  );

  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) {
      return;
    }
    const handleScroll = () => {
      if (programmaticScrollRef.current) {
        return;
      }
      if (liveFollow && !isNearBottom(viewport)) {
        setLiveFollow(false);
      }
    };
    viewport.addEventListener("scroll", handleScroll, { passive: true });
    return () => {
      viewport.removeEventListener("scroll", handleScroll);
    };
  }, [liveFollow]);

  const collapsedRows = filteredLogs.filter((line) => Math.max(1, Number(line.repeatCount ?? 1)) > 1).length;
  const collapsedEvents = filteredLogs.reduce((sum, line) => sum + Math.max(0, Number(line.repeatCount ?? 1) - 1), 0);
  const errorRows = filteredLogs.filter((line) => ["ERROR", "WARNING", "WARN", "CRITICAL"].includes(toSafeString(line.level).toUpperCase())).length;
  const latestVisible = filteredLogs.length > 0 ? filteredLogs[filteredLogs.length - 1] : null;
  const latestVisibleMarker = useMemo(() => {
    if (!latestVisible) {
      return "";
    }
    return [
      toSafeString(latestVisible.id),
      toSafeString(latestVisible.revision),
      toSafeString(latestVisible.repeatCount),
      toSafeString(latestVisible.lastSeenAt || latestVisible.ts),
    ].join(":");
  }, [latestVisible]);

  useEffect(() => {
    if (!liveFollow) {
      return;
    }
    scrollToBottom("auto");
  }, [liveFollow, scrollToBottom]);

  useEffect(() => {
    if (!liveFollow || !latestVisibleMarker) {
      return;
    }
    scrollToBottom("auto");
  }, [latestVisibleMarker, liveFollow, scrollToBottom]);

  const exportLogs = useCallback(() => {
    const text = filteredLogs
      .map((line) => {
        const when = toSafeString(line.firstSeenAt || line.ts);
        const level = toSafeString(line.level) || "INFO";
        const message = toSafeString(line.text || line.rawText);
        return `${when} [${level}] ${message}`;
      })
      .join("\n");
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${exportPrefix}-${new Date().toISOString().replace(/[:.]/g, "-")}.txt`;
    anchor.click();
    URL.revokeObjectURL(url);
  }, [exportPrefix, filteredLogs]);

  const resetFilters = () => {
    setSearch("");
    setLevelFilter("ALL");
    setCategoryFilter("ALL");
    setDoorFilter("");
    setCardFilter("");
    setDeviceFilter("");
    setRepeatedOnly(false);
  };

  const renderTokenButton = (
    label: string,
    value: string | null | undefined,
    onClick: (value: string) => void,
    extraClassName?: string,
  ) => {
    const normalized = toSafeString(value).trim();
    if (!normalized) {
      return null;
    }
    return (
      <button
        type="button"
        onClick={() => onClick(normalized)}
        className={cn(
          "rounded-full border border-white/10 bg-white/[0.04] px-2 py-1 text-[11px] text-slate-300 transition-colors hover:bg-white/[0.09] hover:text-white",
          extraClassName,
        )}
      >
        {label} {normalized}
      </button>
    );
  };

  return (
    <div className="space-y-6">
      <Card className="border-border/70 bg-card/80 shadow-sm">
        <CardHeader className="space-y-5">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div className="space-y-3">
              <div className={cn("inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium", accentClassName)}>
                <Activity className="h-3.5 w-3.5" />
                {eyebrow}
              </div>
              <div className="space-y-2">
                <CardTitle className="text-2xl">{title}</CardTitle>
                <CardDescription>{description}</CardDescription>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <Badge variant="outline" className="border-emerald-500/20 bg-emerald-500/10 text-emerald-300">
                  Adjacent duplicates collapse automatically
                </Badge>
                <Badge variant="outline" className={cn(
                  "border-white/10 bg-white/[0.04]",
                  streamLive ? "text-emerald-300" : "text-amber-300",
                )}>
                  {streamLive ? (
                    <>
                      <Wifi className="mr-1 h-3 w-3" />
                      Stream live
                    </>
                  ) : (
                    <>
                      <WifiOff className="mr-1 h-3 w-3" />
                      Reconnecting
                    </>
                  )}
                </Badge>
                <Badge variant="outline" className="border-white/10 bg-white/[0.04] text-slate-300">
                  Last activity {formatLogClock(toSafeString(latestVisible?.lastSeenAt || latestVisible?.ts || lastActivityAt))}
                </Badge>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant={liveFollow ? "default" : "outline"}
                size="sm"
                onClick={() => setLiveFollow((current) => !current)}
              >
                {liveFollow ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                {liveFollow ? "Freeze view" : "Follow live"}
              </Button>
              <Button variant="outline" size="sm" onClick={() => void refreshLogs(true)}>
                {reloading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                Reload
              </Button>
              <Button variant="outline" size="sm" onClick={exportLogs}>
                <Download className="h-4 w-4" />
                Export
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  logsRef.current = [];
                  setLogs([]);
                  setLastActivityAt(null);
                  setLoading(false);
                }}
              >
                <Trash2 className="h-4 w-4" />
                Clear view
              </Button>
              {openFolder && (
                <Button variant="outline" size="sm" onClick={() => void openFolder()}>
                  <FolderOpen className="h-4 w-4" />
                  Open folder
                </Button>
              )}
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
              <div className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Visible rows</div>
              <div className="mt-2 text-2xl font-semibold">{filteredLogs.length}</div>
              <div className="mt-1 text-xs text-muted-foreground">{logs.length} buffered locally</div>
            </div>
            <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
              <div className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Duplicate savings</div>
              <div className="mt-2 text-2xl font-semibold">{collapsedEvents}</div>
              <div className="mt-1 text-xs text-muted-foreground">{collapsedRows} collapsed rows</div>
            </div>
            <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
              <div className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Signal rows</div>
              <div className="mt-2 text-2xl font-semibold">{errorRows}</div>
              <div className="mt-1 text-xs text-muted-foreground">Warnings and errors in view</div>
            </div>
            <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
              <div className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Stream state</div>
              <div className="mt-2 flex items-center gap-2 text-sm font-medium">
                <span className={cn("h-2.5 w-2.5 rounded-full", streamLive ? "bg-emerald-400" : "bg-amber-400")} />
                {streamLive ? "Connected" : "Recovering"}
              </div>
              <div className="mt-1 text-xs text-muted-foreground">{streamError || (liveFollow ? "Auto-follow enabled" : "View is frozen")}</div>
            </div>
          </div>
        </CardHeader>

        <CardContent className="space-y-5">
          <div className="rounded-2xl border border-border/60 bg-muted/20 p-4">
            <div className="grid gap-3 lg:grid-cols-3">
              <div className="relative lg:col-span-2">
                <Search className="pointer-events-none absolute left-3 top-3.5 h-4 w-4 text-muted-foreground" />
                <Input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search message text, level, device, door, card, or category"
                  className="pl-9"
                />
              </div>
              <Select value={levelFilter} onValueChange={setLevelFilter}>
                <SelectTrigger>
                  <SelectValue placeholder="Filter by level" />
                </SelectTrigger>
                <SelectContent>
                  {LEVEL_OPTIONS.map((option) => (
                    <SelectItem key={option} value={option}>
                      {option === "ALL" ? "All levels" : option}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select value={categoryFilter} onValueChange={setCategoryFilter}>
                <SelectTrigger>
                  <SelectValue placeholder="Filter by category" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ALL">All categories</SelectItem>
                  {categories.map((category) => (
                    <SelectItem key={category} value={category}>
                      {category}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Input
                value={doorFilter}
                onChange={(event) => setDoorFilter(event.target.value)}
                placeholder="Door"
              />
              <Input
                value={cardFilter}
                onChange={(event) => setCardFilter(event.target.value)}
                placeholder="Card / code"
              />
              <Input
                value={deviceFilter}
                onChange={(event) => setDeviceFilter(event.target.value)}
                placeholder="Device"
              />
            </div>

            <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
              <label className="flex items-center gap-2 text-sm text-muted-foreground">
                <Switch checked={repeatedOnly} onCheckedChange={setRepeatedOnly} />
                Show collapsed duplicates only
              </label>
              <Button variant="ghost" size="sm" onClick={resetFilters}>
                Reset filters
              </Button>
            </div>
          </div>

          <Card className="overflow-hidden border-border/70 bg-slate-950">
            <ScrollArea className="h-[68vh] min-h-[26rem]" viewportRef={viewportRef}>
              <div className="space-y-2 p-4">
                {loading && (
                  <div className="flex items-center gap-3 rounded-xl border border-dashed border-slate-700 px-4 py-5 text-sm text-slate-400">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading recent logs...
                  </div>
                )}

                {!loading && logs.length === 0 && (
                  <div className="rounded-xl border border-dashed border-slate-700 px-4 py-10 text-center text-slate-400">
                    {emptyText}
                  </div>
                )}

                {!loading && logs.length > 0 && filteredLogs.length === 0 && (
                  <div className="rounded-xl border border-dashed border-slate-700 px-4 py-10 text-center text-slate-400">
                    No log rows match the current filters.
                    <div className="mt-4">
                      <Button variant="outline" size="sm" onClick={resetFilters}>
                        Reset filters
                      </Button>
                    </div>
                  </div>
                )}

                {!loading && filteredLogs.map((line) => {
                  const repeatCount = Math.max(1, Number(line.repeatCount ?? 1));
                  const rawText = toSafeString(line.rawText || line.text) || "(empty log line)";
                  const category = toSafeString(line.tokens?.category).trim().toUpperCase();
                  return (
                    <div
                      key={toSafeString(line.id) || `${toSafeString(line.firstSeenAt || line.ts)}:${rawText}`}
                      className="rounded-2xl border border-white/8 bg-white/[0.03] p-3 shadow-sm transition-colors hover:bg-white/[0.05]"
                    >
                      <div className="flex flex-wrap items-center gap-2 text-[11px]">
                        <span className="rounded-full border border-white/10 bg-white/[0.04] px-2 py-1 text-slate-300">
                          {formatLogClock(toSafeString(line.lastSeenAt || line.ts))}
                        </span>
                        <span className={cn("rounded-full border px-2 py-1 font-semibold", levelBadgeClass(toSafeString(line.level)))}>
                          {toSafeString(line.level).toUpperCase()}
                        </span>
                        {repeatCount > 1 && (
                          <span className="rounded-full border border-amber-500/20 bg-amber-500/10 px-2 py-1 font-semibold text-amber-300">
                            x{repeatCount}
                          </span>
                        )}
                        {category && renderTokenButton("category", category, setCategoryFilter, "font-medium")}
                        {renderTokenButton("device", line.tokens?.deviceId, setDeviceFilter)}
                        {renderTokenButton("door", line.tokens?.door, setDoorFilter)}
                        {renderTokenButton("card", line.tokens?.cardId, setCardFilter)}
                      </div>

                      <div className="mt-3 flex items-start gap-3">
                        <span className={cn("mt-1 h-2.5 w-2.5 shrink-0 rounded-full", levelDotClass(toSafeString(line.level)))} />
                        <div className="min-w-0 flex-1">
                          <div className="break-words font-mono text-[12px] leading-6 text-slate-100">
                            {rawText}
                            {repeatCount > 1 && (
                              <span className="ml-2 text-amber-300">(x{repeatCount})</span>
                            )}
                          </div>
                          {repeatCount > 1 && (
                            <div className="mt-2 text-[11px] text-slate-400">
                              Collapsed duplicates from {formatLogClock(toSafeString(line.firstSeenAt || line.ts))} to {formatLogClock(toSafeString(line.lastSeenAt || line.ts))}.
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </ScrollArea>
          </Card>
        </CardContent>
      </Card>
    </div>
  );
}
