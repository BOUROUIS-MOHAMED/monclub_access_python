import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Download, Pause, Play, RotateCcw, ScrollText, Search } from "lucide-react";

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
import { cn } from "@/lib/utils";
import { getTvRecentLogs, openTvLogsStream } from "@/tv/api";

interface TvLogLine {
  ts: string;
  level: string;
  text: string;
}

function levelClass(level: string) {
  switch (level) {
    case "ERROR":
      return "text-red-400";
    case "WARNING":
    case "WARN":
      return "text-amber-400";
    case "DEBUG":
      return "text-slate-400";
    default:
      return "text-slate-100";
  }
}

export default function TvLogsPage() {
  const [logs, setLogs] = useState<TvLogLine[]>([]);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("");
  const [levelFilter, setLevelFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const endRef = useRef<HTMLDivElement | null>(null);
  const pausedRef = useRef(false);

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  const loadRecentLogs = useCallback(async () => {
    setLoading(true);
    try {
      const response = await getTvRecentLogs({ limit: 400 });
      setLogs(
        (response.lines ?? []).map((line, index) => ({
          ts: new Date(Date.now() - Math.max(0, response.lines.length - index) * 1000).toISOString(),
          level: String(line.level || "INFO"),
          text: String(line.text || ""),
        })),
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadRecentLogs();
  }, [loadRecentLogs]);

  useEffect(() => {
    const stream = openTvLogsStream((type, payload) => {
      if (type !== "log" || pausedRef.current) {
        return;
      }
      const line = typeof payload === "object" && payload !== null ? payload as Record<string, unknown> : {};
      setLogs((current) => [
        ...current.slice(-1999),
        {
          ts: new Date().toISOString(),
          level: String(line.level || "INFO"),
          text: String(line.text || line.message || ""),
        },
      ]);
    });

    return () => {
      stream.close();
    };
  }, []);

  useEffect(() => {
    if (!paused) {
      endRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs.length, paused]);

  const filteredLogs = useMemo(() => {
    return logs.filter((line) => {
      if (levelFilter !== "ALL" && line.level !== levelFilter) {
        return false;
      }
      if (!filter.trim()) {
        return true;
      }
      const needle = filter.trim().toLowerCase();
      return line.text.toLowerCase().includes(needle) || line.level.toLowerCase().includes(needle);
    });
  }, [filter, levelFilter, logs]);

  const exportLogs = useCallback(() => {
    const text = filteredLogs.map((line) => `${line.ts} [${line.level}] ${line.text}`).join("\n");
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const anchor = document.createElement("a");
    anchor.href = URL.createObjectURL(blob);
    anchor.download = `monclub-tv-logs-${new Date().toISOString().replace(/[:.]/g, "-")}.txt`;
    anchor.click();
    URL.revokeObjectURL(anchor.href);
  }, [filteredLogs]);

  return (
    <div className="space-y-6">
      <Card className="border-border/70 bg-card/80 shadow-sm">
        <CardHeader className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 rounded-full border border-border bg-muted/40 px-3 py-1 text-xs font-medium text-muted-foreground">
              <ScrollText className="h-3.5 w-3.5" />
              TV runtime log stream
            </div>
            <CardTitle className="text-2xl">MonClub TV logs</CardTitle>
            <CardDescription>
              Watch player launch, recovery, update, and host orchestration logs without leaving the TV shell.
            </CardDescription>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="border-sky-500/20 bg-sky-500/10 text-sky-300">
              {filteredLogs.length} visible
            </Badge>
            <Button variant={paused ? "default" : "outline"} size="sm" onClick={() => setPaused((value) => !value)}>
              {paused ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
              {paused ? "Resume" : "Pause"}
            </Button>
            <Button variant="outline" size="sm" onClick={() => void loadRecentLogs()}>
              <RotateCcw className="h-4 w-4" />
              Reload
            </Button>
            <Button variant="outline" size="sm" onClick={exportLogs}>
              <Download className="h-4 w-4" />
              Export
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-col gap-3 md:flex-row">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-3 top-3.5 h-4 w-4 text-muted-foreground" />
              <Input
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
                placeholder="Filter logs by text or level"
                className="pl-9"
              />
            </div>
            <Select value={levelFilter} onValueChange={setLevelFilter}>
              <SelectTrigger className="w-full md:w-44">
                <SelectValue placeholder="Filter by level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ALL">All levels</SelectItem>
                <SelectItem value="ERROR">ERROR</SelectItem>
                <SelectItem value="WARNING">WARNING</SelectItem>
                <SelectItem value="INFO">INFO</SelectItem>
                <SelectItem value="DEBUG">DEBUG</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Card className="overflow-hidden border-border/70 bg-slate-950">
            <ScrollArea className="h-[calc(100vh-24rem)] min-h-[28rem]">
              <div className="space-y-1 p-4 font-mono text-xs leading-6">
                {!loading && filteredLogs.length === 0 && (
                  <div className="rounded-lg border border-dashed border-slate-700 px-4 py-10 text-center text-slate-400">
                    No TV logs matched the current filter yet.
                  </div>
                )}
                {filteredLogs.map((line, index) => (
                  <div key={`${line.ts}-${index}`} className="grid grid-cols-[92px_72px_minmax(0,1fr)] gap-3 rounded-md px-2 py-1 hover:bg-white/5">
                    <span className="text-slate-500">
                      {new Date(line.ts).toLocaleTimeString()}
                    </span>
                    <span className={cn("font-semibold", levelClass(line.level))}>
                      [{line.level}]
                    </span>
                    <span className="break-words text-slate-200">{line.text}</span>
                  </div>
                ))}
                <div ref={endRef} />
              </div>
            </ScrollArea>
          </Card>
        </CardContent>
      </Card>
    </div>
  );
}
