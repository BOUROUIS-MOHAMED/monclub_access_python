// Logs — Access v5 (board S19).
//
// The console is the subject: the mono stream at full height on the left. The
// rail lifts the last ERROR lines out of the scroll (verbatim — log content is
// never translated) and summarises the buffer by category (click = filter).
//
// NOTE ON THE SHARED COMPONENT: an earlier implementation delegated to
// <LiveLogWorkbench>, which is ALSO rendered by tv/pages/TvLogsPage.tsx. That
// component is deliberately left untouched so the TV app is not restyled as a
// side effect; this page instead builds on the same shared, already-tested
// primitives in lib/logs.ts (normalizeLogLine / upsertLogLine / formatLogClock),
// so the stream semantics — including duplicate collapsing — are identical.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { LogLine } from "@/api/types";
import { get, openSSE, post } from "@/api/client";
import { usePageChrome } from "@/context/PageChromeContext";
import { ActionButton } from "@/components/ui/action-button";
import { Segmented } from "@/components/ui/segmented";
import { ListRow, Panel, PanelHeader, PanelList } from "@/components/ui/panel";
import { cn } from "@/lib/utils";
import { formatLogClock, normalizeLogLine, upsertLogLine } from "@/lib/logs";
import { formatDate, relativeTimeFr } from "@/lib/historyCopy";
import { useNowTick } from "@/hooks/useNowTick";
import {
  Search, Download, Trash2, FolderOpen, CircleX, FileText, Pause, Play, CircleCheck, Tag, Send, X,
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

const LEVEL_INK = { ERROR: "text-error-ink", WARNING: "text-warning-ink", INFO: "text-success-ink" } as const;

export default function LogsPage() {
  // Keeps the « À traiter » times (« il y a … ») current (display only, no request).
  const now = useNowTick();
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [search, setSearch] = useState("");
  const [level, setLevel] = useState<LevelKey>("ALL");
  const [category, setCategory] = useState<string>("ALL");
  const [live, setLive] = useState(false);
  const [follow, setFollow] = useState(true);
  // « Envoyer à MonClub » — POST /logs/flush (the same call as the web dashboard's
  // « Sync logs now »): closes the current log file and queues it for upload. The
  // answer says what was queued, not that the upload finished, and the text says so.
  const [uploading, setUploading] = useState(false);
  const [uploadNote, setUploadNote] = useState<{ tone: "info" | "error"; text: string } | null>(null);
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

  /** The errors, lifted out of the scroll. */
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
    // The route is POST-only (access/local_api_routes.py); a GET never opened the folder.
    void post<{ ok: boolean; path: string }>("/logs/open-dir").catch(() => {});
  }, []);
  const handleUpload = useCallback(async () => {
    setUploading(true);
    setUploadNote(null);
    try {
      const res = await post<{ ok?: boolean; pendingNow?: string[] }>("/logs/flush");
      const n = Array.isArray(res?.pendingNow) ? res.pendingNow.length : 0;
      setUploadNote({
        tone: "info",
        text: n > 0
          ? `Journal mis en file d'envoi vers MonClub : ${n} fichier${n > 1 ? "s" : ""} en attente. L'envoi se fait en arrière-plan dès que le serveur répond.`
          : "Journal mis en file d'envoi vers MonClub. L'envoi se fait en arrière-plan dès que le serveur répond.",
      });
    } catch (e) {
      setUploadNote({ tone: "error", text: `Envoi impossible : ${e instanceof Error ? e.message : String(e)}` });
    } finally {
      setUploading(false);
    }
  }, []);

  usePageChrome(() => ({
    fill: true,
    subtitle: `${logs.length} ligne${logs.length > 1 ? "s" : ""} chargée${logs.length > 1 ? "s" : ""}${follow ? " · suivi automatique" : " · défilement figé"}`,
    actions: (
      <>
        <ActionButton kind="outline" icon={FolderOpen} onClick={handleOpenFolder}>Dossier</ActionButton>
        <ActionButton kind="outline" icon={Download} onClick={handleExport}>Exporter</ActionButton>
        <ActionButton kind="outline" icon={Trash2} onClick={handleClear}>Vider</ActionButton>
        <ActionButton kind="outline" icon={Send} spin={uploading} disabled={uploading} onClick={() => { void handleUpload(); }}>
          Envoyer à MonClub
        </ActionButton>
      </>
    ),
  }), [logs.length, follow, uploading, handleExport, handleClear, handleOpenFolder, handleUpload]);

  return (
    <div className="grid h-full min-h-0 grid-cols-12 gap-[18px]">
      {/* ── La console ──────────────────────────────────────────────────── */}
      <Panel className="col-span-8 flex min-h-0 flex-col">
        <PanelHeader title={category !== "ALL" ? `Console · ${category}` : "Console"} className="flex-none">
          <span className="inline-flex items-center gap-[7px] text-[12.5px] text-muted-foreground">
            <span className="relative inline-block h-[7px] w-[7px]">
              {live && <span className="absolute inset-0 animate-ping rounded-full bg-success opacity-60" />}
              <span className={cn("absolute inset-0 rounded-full", live ? "bg-success" : "bg-grey/60")} />
            </span>
            {live ? "en direct" : "hors ligne"}
          </span>
          {category !== "ALL" && (
            <ActionButton kind="ghost" size="sm" onClick={() => setCategory("ALL")}>Tout afficher</ActionButton>
          )}
          <ActionButton kind="outline" size="md" icon={follow ? Pause : Play} onClick={() => setFollow((f) => !f)}>
            {follow ? "Suivi" : "Figé"}
          </ActionButton>
        </PanelHeader>
        <div className="flex flex-none flex-wrap items-center gap-2.5 px-[18px] pt-3">
          <div className="flex h-9 min-w-[180px] flex-1 items-center gap-2 rounded-lg border border-grey/32 bg-card px-3 focus-within:border-primary">
            <Search className="h-[17px] w-[17px] shrink-0 text-muted-foreground" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filtrer les messages…"
              aria-label="Filtrer les messages"
              className="min-w-0 flex-1 bg-transparent text-[13.5px] text-foreground outline-none placeholder:text-muted-foreground"
            />
          </div>
          <Segmented<LevelKey>
            ariaLabel="Filtrer par niveau"
            value={level}
            onChange={setLevel}
            items={[
              { value: "ALL", label: "Tous", count: logs.length },
              { value: "ERROR", label: "Erreurs", count: counts.byBucket.ERROR },
              { value: "WARNING", label: "Alertes", count: counts.byBucket.WARNING },
              { value: "INFO", label: "Infos", count: counts.byBucket.INFO },
            ]}
          />
        </div>

        <div ref={scrollRef} className="mt-3 min-h-0 flex-1 overflow-y-auto border-t border-dashed border-grey/20 px-[18px] py-2.5 font-mono text-[12px] leading-[1.85]">
          {visible.length === 0 && (
            <div className="flex h-full min-h-[220px] flex-col items-center justify-center gap-2 text-center font-sans">
              <FileText className="h-7 w-7 text-muted-foreground/40" />
              <p className="text-[13.5px] font-semibold text-foreground">
                {logs.length === 0 ? "Aucune ligne de log capturée" : "Aucune ligne ne correspond au filtre"}
              </p>
            </div>
          )}
          {visible.map((l, i) => {
            const b = bucketOf(l);
            return (
              <div
                key={String(l.id ?? `${l.ts}-${i}`)}
                className={cn("flex gap-3", b === "ERROR" && "-mx-2 rounded-md bg-error/10 px-2")}
              >
                <span className="w-[64px] shrink-0 text-muted-foreground">{formatLogClock(l.lastSeenAt || l.ts)}</span>
                <span className={cn("w-[46px] shrink-0 font-bold", LEVEL_INK[b])}>{b === "WARNING" ? "WARN" : b}</span>
                <span className="w-[56px] shrink-0 truncate text-muted-foreground">{categoryOf(l)}</span>
                <span className="min-w-0 break-all text-foreground">
                  {l.rawText || l.text}
                  {(l.repeatCount ?? 0) > 1 && (
                    <span className="ml-2 text-muted-foreground">×{l.repeatCount}</span>
                  )}
                </span>
              </div>
            );
          })}
        </div>
      </Panel>

      {/* ── Le rail ─────────────────────────────────────────────────────── */}
      <div className="col-span-4 flex min-h-0 flex-col gap-[18px] overflow-y-auto">
        {uploadNote && (
          <div
            role="status"
            className={cn(
              "flex flex-none items-start gap-2.5 rounded-2xl px-4 py-3 text-[13px] leading-normal",
              uploadNote.tone === "error" ? "bg-error/16 text-error-ink" : "bg-info/16 text-info-ink",
            )}
          >
            {uploadNote.tone === "error"
              ? <CircleX className="mt-px h-[17px] w-[17px] shrink-0" />
              : <Send className="mt-px h-[17px] w-[17px] shrink-0" />}
            <span className="min-w-0 flex-1">{uploadNote.text}</span>
            <button type="button" aria-label="Fermer" onClick={() => setUploadNote(null)} className="shrink-0 cursor-pointer opacity-70 hover:opacity-100">
              <X className="h-4 w-4" />
            </button>
          </div>
        )}
        <Panel className="flex-none">
          <PanelHeader
            title="À traiter"
            sub={errors.length ? "Dernières erreurs, telles qu'écrites dans le journal" : undefined}
          />
          <PanelList>
            {errors.length > 0 ? errors.map((l, i) => (
              <ListRow
                key={String(l.id ?? `err-${i}`)}
                icon={CircleX}
                tone="error"
                wrap
                mono
                title={<span className="break-all text-[12.5px]">{l.rawText || l.text}</span>}
                sub={(
                  <span title={formatDate(l.lastSeenAt || l.ts)}>
                    {`${categoryOf(l)} · ${relativeTimeFr(l.lastSeenAt || l.ts, now) ?? formatLogClock(l.lastSeenAt || l.ts)}${(l.repeatCount ?? 0) > 1 ? ` · ×${l.repeatCount}` : ""}`}
                  </span>
                )}
              />
            )) : (
              <ListRow
                icon={CircleCheck}
                tone="success"
                wrap
                title="Aucune erreur"
                sub={`Rien d'anormal dans les ${logs.length} dernières lignes chargées.`}
              />
            )}
          </PanelList>
        </Panel>

        <Panel className="flex-none">
          <PanelHeader title="Par catégorie" sub="Cliquez une catégorie pour filtrer la console" />
          <PanelList>
            {counts.byCategory.length === 0 && (
              <div className="py-2 text-[13px] text-muted-foreground">Aucune ligne chargée.</div>
            )}
            {counts.byCategory.map(([cat, n]) => (
              <button
                key={cat}
                type="button"
                aria-pressed={category === cat}
                onClick={() => setCategory((c) => (c === cat ? "ALL" : cat))}
                className="block w-full cursor-pointer text-left"
              >
                <ListRow icon={Tag} tone="grey" title={cat} mono value={String(n)} valueMono selected={category === cat} className="hover:bg-muted" />
              </button>
            ))}
          </PanelList>
          <div className="border-t border-dashed border-grey/20 px-[18px] py-3 text-[12px] leading-normal text-muted-foreground">
            Compteurs calculés sur le tampon chargé ({RECENT_LIMIT} dernières lignes au démarrage,
            puis le flux en direct) — pas sur la journée entière.
          </div>
        </Panel>
      </div>
    </div>
  );
}
