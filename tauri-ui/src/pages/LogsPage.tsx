import { useState, useEffect, useRef, useCallback } from "react";
import { openSSE } from "@/api/client";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { FileText, Trash2, Download, Search, Pause, Play } from "lucide-react";
import { cn } from "@/lib/utils";

interface LogLine {
  ts: string;
  level: string;
  msg: string;
}

export default function LogsPage() {
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("");
  const [levelFilter, setLevelFilter] = useState("ALL");
  const endRef = useRef<HTMLDivElement>(null);
  const esRef = useRef<EventSource | null>(null);
  const pausedRef = useRef(false);

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    const es = openSSE("/logs/stream", (type, data) => {
      if (type === "log" && !pausedRef.current) {
        // SSE sends {level, text} — normalize to {ts, level, msg}
        let line: LogLine;
        if (data && typeof data === "object") {
          line = {
            ts: data.ts || data.timestamp || new Date().toISOString(),
            level: data.level || "INFO",
            msg: data.text || data.msg || data.message || JSON.stringify(data),
          };
        } else {
          line = {
            ts: new Date().toISOString(),
            level: "INFO",
            msg: String(data ?? ""),
          };
        }
        setLogs((prev) => [...prev.slice(-2000), line]);
      }
    });
    esRef.current = es;
    return () => {
      es.close();
    };
  }, []);

  useEffect(() => {
    if (!paused) endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs.length, paused]);

  const filtered = logs.filter((l) => {
    if (levelFilter !== "ALL" && l.level !== levelFilter) return false;
    if (filter) {
      const f = filter.toLowerCase();
      if (
        !l.msg.toLowerCase().includes(f) &&
        !l.level.toLowerCase().includes(f)
      )
        return false;
    }
    return true;
  });

  const handleExport = useCallback(() => {
    const text = filtered
      .map((l) => `${l.ts} [${l.level}] ${l.msg}`)
      .join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `monclub-logs-${new Date()
      .toISOString()
      .split("T")[0]}.txt`;
    a.click();
  }, [filtered]);

  const levelColor = (level: string) => {
    switch (level) {
      case "ERROR":
        return "text-red-400";
      case "WARNING":
      case "WARN":
        return "text-amber-400";
      case "DEBUG":
        return "text-zinc-500";
      default:
        return "text-zinc-300";
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileText className="h-5 w-5 text-primary" />
          <h1 className="text-lg font-semibold">Logs en direct</h1>
          <Badge variant="secondary" className="text-xs">
            {logs.length} lignes
          </Badge>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant={paused ? "default" : "outline"}
            onClick={() => setPaused(!paused)}
          >
            {paused ? (
              <>
                <Play className="h-3.5 w-3.5" /> Reprendre
              </>
            ) : (
              <>
                <Pause className="h-3.5 w-3.5" /> Pause
              </>
            )}
          </Button>
          <Button size="sm" variant="outline" onClick={handleExport}>
            <Download className="h-3.5 w-3.5" /> Exporter
          </Button>
          <Button size="sm" variant="outline" onClick={() => setLogs([])}>
            <Trash2 className="h-3.5 w-3.5" /> Effacer
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Filtrer les logs…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="pl-8"
          />
        </div>
        <Select value={levelFilter} onValueChange={setLevelFilter}>
          <SelectTrigger className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="ALL">Tous</SelectItem>
            <SelectItem value="ERROR">ERROR</SelectItem>
            <SelectItem value="WARNING">WARNING</SelectItem>
            <SelectItem value="INFO">INFO</SelectItem>
            <SelectItem value="DEBUG">DEBUG</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Log viewer */}
      <Card className="p-0 overflow-hidden">
        <ScrollArea className="h-[calc(100vh-280px)]">
          <div className="p-3 font-mono text-xs leading-relaxed bg-background min-h-full">
            {filtered.length === 0 ? (
              <p className="text-muted-foreground/60 italic py-8 text-center">
                Aucun log à afficher… En attente de données SSE.
              </p>
            ) : (
              filtered.map((l, i) => (
                <div
                  key={i}
                  className={cn("py-0.5 flex gap-2", levelColor(l.level))}
                >
                  <span className="text-muted-foreground/60 shrink-0">
                    {l.ts?.includes("T")
                      ? l.ts.split("T")[1]?.substring(0, 8)
                      : l.ts?.substring(11, 19) || ""}
                  </span>
                  <span className={cn("shrink-0 w-14", levelColor(l.level))}>
                    [{l.level}]
                  </span>
                  <span className="break-all text-foreground/70">{l.msg}</span>
                </div>
              ))
            )}
            <div ref={endRef} />
          </div>
        </ScrollArea>
      </Card>
    </div>
  );
}
