// Logs — Access v3, from `Access v3 - Partie 2 Diagnostic.dc.html` (screen 04).
//
// "La console reste la console" — the mono stream is the subject at full height.
// What the page gains is the rail: it lifts the ERROR lines out of the scroll
// instead of letting them drown, and summarises the buffer by level and by
// category.
//
// NOTE ON THE SHARED COMPONENT: the previous implementation delegated to
// <LiveLogWorkbench>, which is ALSO rendered by tv/pages/TvLogsPage.tsx. That
// component is deliberately left untouched so the TV app is not restyled as a
// side effect; this page instead builds on the same shared, already-tested
// primitives in lib/logs.ts (normalizeLogLine / upsertLogLine / formatLogClock),
// so the stream semantics — including duplicate collapsing — are identical.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { LogLine } from "@/api/types";
import { get, openSSE } from "@/api/client";
import { usePageChrome } from "@/context/PageChromeContext";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { formatLogClock, normalizeLogLine, upsertLogLine } from "@/lib/logs";
import {
  Search, Download, Trash2, FolderOpen, AlertCircle, FileText, Pause, Play,
} from "lucide-react";

const RECENT_LIMIT = 500;
const MAX_LINES = 2000;

type LevelKey = "ALL" | "ERROR" | "WARNING" | "INFO";

function levelOf(line: LogLine): string {
  return String(line.level || "INFO").toUpperCase();
}

/** ERROR / WARNING / everything-else — the three buckets the design filters on. */
function bucketOf(line: LogLine): "ERROR" | "WARNING" | "INFO" {
  const l = levelOf(line);
  if (l === "ERROR" || l === "CRITICAL" || l === "FATAL") return "ERROR";
  if (l === "WARNING" || l === "WARN") return "WARNING";
  return "INFO";
}

function categoryOf(line: LogLine): string {
  return String(line.tokens?.category || "").trim().toUpperCase() || "—";
}

function Chip({ tone, children, className }: { tone: "ok" | "no" | "wn"; children: React.ReactNode; className?: string }) {
  const tones = {
    ok: "bg-emerald-500/[0.055] text-emerald-700 dark:text-emerald-400",
    no: "bg-primary/[0.09] text-primary",
    wn: "bg-amber-500/[0.14] text-amber-700 dark:text-amber-400",
  } as const;
  return (
    <span className={cn("inline-flex h-[17px] shrink-0 items-center justify-center rounded-lg text-[9.5px] font-bold", tones[tone], className)}>
      {children}
    </span>
  );
}

const BUCKET_TONE = { ERROR: "no", WARNING: "wn", INFO: "ok" } as const;

export default function LogsPage() {
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [search, setSearch] = useState("");
  const [level, setLevel] = useState<LevelKey>("ALL");
  const [category, setCategory] = useState<string>("ALL");
  const [live, setLive] = useState(false);
  const [follow, setFollow] = useState(true);
  const logsRef = useRef<LogLine[]>([]);
  const scrollRef = useRef<HTMLDivElement | null>(null);

  // Initial buffer
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const res = await get<{ lines?: LogLine[] }>("/logs/recent", { limit: String(RECENT_LIMIT) });
        if (cancelled) return;
        const normalized = (res.lines ?? [])
          .map((l) => normalizeLogLine(l))
          .filter((l): l is LogLine => Boolean(l));
        logsRef.current = normalized;
        setLogs(normalized);
      } catch { /* the stream below still fills the console */ }
    })();
    return () => { cancelled = true; };
  }, []);

  // Live stream — same event name and normalisation as LiveLogWorkbench.
  useEffect(() => {
    const stream = openSSE("/logs/stream", (type, payload) => {
      if (type !== "log") return;
      const normalized = normalizeLogLine(payload);
      if (!normalized) return;
      setLogs((current) => {
        const next = upsertLogLine(current, normalized, MAX_LINES);
        logsRef.current = next;
        return next;
      });
    }, () => setLive(false));
    stream.onopen = () => setLive(true);
    return () => { stream.close(); };
  }, []);

  const counts = useMemo(() => {
    const byBucket = { ERROR: 0, WARNING: 0, INFO: 0 };
    const byCategory = new Map<string, number>();
    for (const l of logs) {
      byBucket[bucketOf(l)] += 1;
      const c = categoryOf(l);
      byCategory.set(c, (byCategory.get(c) ?? 0) + 1);
    }
    return {
      byBucket,
      byCategory: [...byCategory.entries()].sort((a, b) => b[1] - a[1]),
    };
  }, [logs]);

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    return logs.filter((l) => {
      if (level !== "ALL" && bucketOf(l) !== level) return false;
      if (category !== "ALL" && categoryOf(l) !== category) return false;
      if (q && !String(l.rawText || l.text || "").toLowerCase().includes(q)) return false;
      return true;
    });
  }, [logs, search, level, category]);

  /** The design's point: the errors, lifted out of the scroll. */
  const errors = useMemo(
    () => logs.filter((l) => bucketOf(l) === "ERROR").slice(-4).reverse(),
    [logs],
  );

  useEffect(() => {
    if (!follow) return;
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [visible.length, follow]);

  const handleExport = useCallback(() => {
    const body = logs
      .map((l) => `${formatLogClock(l.lastSeenAt || l.ts)}\t${levelOf(l)}\t${categoryOf(l)}\t${l.rawText || l.text}`)
      .join("\n");
    const url = URL.createObjectURL(new Blob([body], { type: "text/plain;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `monclub-access-logs-${new Date().toISOString().slice(0, 10)}.log`;
    a.click();
    URL.revokeObjectURL(url);
  }, [logs]);

  const handleClear = useCallback(() => { logsRef.current = []; setLogs([]); }, []);
  const handleOpenFolder = useCallback(() => {
    void get<{ ok: boolean; path: string }>("/logs/open-dir").catch(() => {});
  }, []);

  usePageChrome(() => ({
    fill: true,
    subtitle: `${logs.length} ligne${logs.length > 1 ? "s" : ""}${follow ? " · suivi automatique" : ""}`,
    actions: (
      <>
        <Button variant="outline" className="h-[30px] gap-1.5 rounded-[14px] px-[13px] text-[12px] font-semibold" onClick={handleOpenFolder}>
          <FolderOpen className="h-[15px] w-[15px]" />Dossier
        </Button>
        <Button variant="outline" className="h-[30px] gap-1.5 rounded-[14px] px-[13px] text-[12px] font-semibold" onClick={handleExport}>
          <Download className="h-[15px] w-[15px]" />Exporter
        </Button>
        <Button variant="outline" className="h-[30px] gap-1.5 rounded-[14px] px-[13px] text-[12px] font-semibold" onClick={handleClear}>
          <Trash2 className="h-[15px] w-[15px]" />Vider
        </Button>
      </>
    ),
  }), [logs.length, follow, handleExport, handleClear, handleOpenFolder]);

  const pill = (active: boolean) =>
    cn(
      "inline-flex h-7 items-center whitespace-nowrap rounded-full px-[11px] text-[12px] transition-colors",
      active
        ? "bg-foreground font-bold text-background"
        : "border border-border bg-card font-semibold text-muted-foreground hover:text-foreground",
    );

  return (
    <div className="flex h-full min-h-0 gap-4">
      {/* ── La console ──────────────────────────────────────────────────── */}
      <div className="flex min-w-0 flex-1 flex-col gap-[11px]">
        <div className="flex flex-none items-center gap-[9px]">
          <div className="flex h-[34px] max-w-[300px] flex-1 items-center gap-[9px] rounded-xl border border-border bg-card px-3">
            <Search className="h-[17px] w-[17px] shrink-0 text-muted-foreground" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filtrer les messages…"
              className="min-w-0 flex-1 bg-transparent text-[13px] text-foreground outline-none placeholder:text-muted-foreground"
            />
          </div>
          <div className="flex gap-[5px]">
            <button className={pill(level === "ALL")} onClick={() => setLevel("ALL")}>Tous {logs.length}</button>
            <button className={pill(level === "ERROR")} onClick={() => setLevel("ERROR")}>Erreurs {counts.byBucket.ERROR}</button>
            <button className={pill(level === "WARNING")} onClick={() => setLevel("WARNING")}>Alertes {counts.byBucket.WARNING}</button>
            <button className={pill(level === "INFO")} onClick={() => setLevel("INFO")}>Infos {counts.byBucket.INFO}</button>
          </div>
          <Button
            variant="outline"
            className="ml-auto h-[30px] gap-1.5 rounded-[14px] px-[13px] text-[12px] font-semibold"
            onClick={() => setFollow((f) => !f)}
          >
            {follow ? <Pause className="h-[15px] w-[15px]" /> : <Play className="h-[15px] w-[15px]" />}
            {follow ? "Suivi" : "Figé"}
          </Button>
        </div>

        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-3xl bg-card shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
          <div className="flex flex-none items-center justify-between gap-3.5 border-b border-border px-6 py-3">
            <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground">
              Flux{category !== "ALL" ? ` · ${category}` : ""}
            </span>
            <div className="flex items-center gap-3">
              {category !== "ALL" && (
                <button className="text-[11px] font-semibold text-primary" onClick={() => setCategory("ALL")}>
                  tout afficher
                </button>
              )}
              <span className="inline-flex items-center gap-[7px] text-[11.5px] text-muted-foreground">
                <span className="relative inline-block h-[7px] w-[7px]">
                  {live && <span className="absolute inset-0 animate-ping rounded-full bg-emerald-500 opacity-60" />}
                  <span className={cn("absolute inset-0 rounded-full", live ? "bg-emerald-500" : "bg-muted-foreground/50")} />
                </span>
                {live ? "en direct" : "hors ligne"}
              </span>
            </div>
          </div>

          <div ref={scrollRef} className="min-h-0 flex-1 overflow-y-auto px-6 py-2.5 font-mono text-[11.5px] font-medium leading-[1.9]">
            {visible.length === 0 && (
              <div className="flex h-full min-h-[220px] flex-col items-center justify-center gap-2 text-center font-sans">
                <FileText className="h-7 w-7 text-muted-foreground/40" />
                <p className="text-[13px] font-semibold text-foreground">
                  {logs.length === 0 ? "Aucune ligne de log capturée" : "Aucune ligne ne correspond au filtre"}
                </p>
              </div>
            )}
            {visible.map((l, i) => {
              const b = bucketOf(l);
              return (
                <div
                  key={String(l.id ?? `${l.ts}-${i}`)}
                  className={cn(
                    "flex gap-3",
                    b === "ERROR" && "-mx-2 rounded-lg bg-primary/[0.05] px-2",
                  )}
                >
                  <span className="shrink-0 text-muted-foreground">{formatLogClock(l.lastSeenAt || l.ts)}</span>
                  <Chip tone={BUCKET_TONE[b]} className="w-[46px]">{b === "WARNING" ? "WARN" : b}</Chip>
                  <span className="w-[52px] shrink-0 truncate text-muted-foreground">{categoryOf(l)}</span>
                  <span className={cn("min-w-0 break-all", b === "ERROR" ? "text-primary" : b === "WARNING" ? "text-amber-700 dark:text-amber-400" : "text-foreground")}>
                    {l.rawText || l.text}
                    {(l.repeatCount ?? 0) > 1 && (
                      <span className="ml-2 text-muted-foreground">×{l.repeatCount}</span>
                    )}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── Le rail ─────────────────────────────────────────────────────── */}
      <div className="flex w-[330px] flex-none flex-col gap-[11px]">
        <div className="flex flex-none items-center gap-[9px]">
          <span className={cn(
            "inline-flex h-[22px] items-center gap-1.5 rounded-lg px-[9px] text-[10.5px] font-bold uppercase tracking-[0.05em]",
            errors.length ? "bg-primary/[0.08] text-primary" : "bg-muted text-muted-foreground",
          )}>
            <AlertCircle className="h-3 w-3" />À traiter
          </span>
          <span className="text-[11.5px] text-muted-foreground">
            {counts.byBucket.ERROR} erreur{counts.byBucket.ERROR > 1 ? "s" : ""}
          </span>
        </div>

        {errors.length > 0 ? (
          <div className="flex max-h-[46%] flex-none flex-col gap-2 overflow-y-auto">
            {errors.map((l, i) => (
              <div
                key={String(l.id ?? `err-${i}`)}
                className="flex-none rounded-3xl border-[1.5px] border-primary/30 bg-card px-5 py-4 shadow-[0_8px_20px_rgba(0,0,0,0.08)]"
              >
                <div className="mb-2 flex items-center gap-2.5">
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[18px] bg-primary/[0.09] text-primary">
                    <AlertCircle className="h-[19px] w-[19px]" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13px] font-bold text-foreground">{categoryOf(l)}</div>
                    <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                      {formatLogClock(l.lastSeenAt || l.ts)}
                      {(l.repeatCount ?? 0) > 1 ? ` · ×${l.repeatCount}` : ""}
                    </div>
                  </div>
                </div>
                {/* The raw message, verbatim — no invented translation. */}
                <p className="break-all font-mono text-[11px] leading-[1.55] text-primary">
                  {l.rawText || l.text}
                </p>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex-none rounded-3xl bg-card px-5 py-4 shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
            <div className="text-[13px] font-bold text-foreground">Aucune erreur</div>
            <div className="mt-1 text-[11.5px] text-muted-foreground">
              Rien d'anormal dans les {logs.length} dernières lignes chargées.
            </div>
          </div>
        )}

        <div className="mt-[3px] flex flex-none items-center gap-[9px]">
          <span className="inline-flex h-[22px] items-center gap-1.5 rounded-lg bg-muted px-[9px] text-[10.5px] font-bold uppercase tracking-[0.05em] text-muted-foreground">
            <FileText className="h-3 w-3" />Tampon courant
          </span>
        </div>
        <div className="flex min-h-0 flex-1 flex-col gap-[9px] overflow-y-auto rounded-[18px] bg-card px-5 py-4 shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
          <div className="flex items-baseline gap-2.5">
            <span className="num text-[30px] leading-none">{logs.length}</span>
            <span className="text-[13px] text-muted-foreground">ligne{logs.length > 1 ? "s" : ""} chargée{logs.length > 1 ? "s" : ""}</span>
          </div>
          <div className="h-px bg-border" />
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Erreurs</span>
            <span className="text-[12.5px] font-bold text-primary">{counts.byBucket.ERROR}</span>
          </div>
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Alertes</span>
            <span className="text-[12.5px] font-bold text-amber-700 dark:text-amber-400">{counts.byBucket.WARNING}</span>
          </div>
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Infos</span>
            <span className="text-[12.5px] font-bold text-emerald-700 dark:text-emerald-400">{counts.byBucket.INFO}</span>
          </div>
          {counts.byCategory.length > 0 && (
            <>
              <div className="h-px bg-border" />
              <div className="mb-0.5 text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground">
                Par catégorie
              </div>
              {counts.byCategory.map(([cat, n]) => (
                <button
                  key={cat}
                  onClick={() => setCategory((c) => (c === cat ? "ALL" : cat))}
                  className={cn(
                    "flex items-center justify-between gap-2.5 rounded-lg px-1 py-0.5 text-left transition-colors hover:bg-muted",
                    category === cat && "bg-muted",
                  )}
                >
                  <span className="font-mono text-[12px] text-muted-foreground">{cat}</span>
                  <span className="text-[12px] font-semibold text-foreground">{n}</span>
                </button>
              ))}
            </>
          )}
          <p className="mt-auto pt-2 text-[10.5px] leading-[1.5] text-muted-foreground">
            Compteurs calculés sur le tampon chargé ({RECENT_LIMIT} dernières lignes au démarrage,
            puis le flux en direct) — pas sur la journée entière.
          </p>
        </div>
      </div>
    </div>
  );
}
