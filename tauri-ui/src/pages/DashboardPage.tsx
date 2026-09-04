// Dashboard — "Fil + rail double", from the Claude Design Access v3 refonte
// (`Access v3 - Partie 1 Pilotage.dc.html`, screen 01).
//
// The grammar the whole refonte inherits: one subject at full height on the
// left (here the day's timeline of entries), and a 330px rail on the right cut
// in two — "Maintenant" (what needs an action now) on top, "Aujourd'hui" (the
// summary, machine included) below, with action tiles at the foot of the rail.
//
// Where the data comes from:
//   · the timeline and the day's totals/curve → GET /api/v2/dashboard/overview,
//     which resolves access_history rows to members (that table stores only a
//     card number, so unresolved rows fall back to "Carte ####" by design);
//   · the sync/agent/reader/session/update lines → the existing /status poll;
//   · the popup tile → usePopupStream, unchanged.

import { useCallback, useEffect, useMemo, useState } from "react";
import { useApp } from "@/context/AppContext";
import { usePopupStream } from "@/api/hooks";
import { get, post } from "@/api/client";
import { usePageChrome } from "@/context/PageChromeContext";
import { Button } from "@/components/ui/button";
import ScanCardModal from "@/components/ScanCardModal";
import { LiveDot } from "@/layouts/MainLayout";
import { cn } from "@/lib/utils";
import type { DashboardFeedItem, DashboardOverview, DashboardToday } from "@/api/types";
import {
  RefreshCw, RotateCcw, Users, Monitor, Bug, Upload, CreditCard, Fingerprint,
  QrCode, Play, Square, WifiOff, History, Clock, DownloadCloud, AlertTriangle,
} from "lucide-react";

const OVERVIEW_POLL_MS = 5000;

// ── small design primitives ───────────────────────────────────────────────
/** Section marker above a column ("Passages", "Maintenant", "Aujourd'hui"). */
function ZoneTitle({ children }: { children: React.ReactNode }) {
  return <div className="flex flex-none items-center gap-[9px]">{children}</div>;
}

/** Uppercase micro-label used on card headers. */
function Lb({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={cn("text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground", className)}>
      {children}
    </span>
  );
}

function Card({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("rounded-3xl bg-card shadow-[0_8px_20px_rgba(0,0,0,0.08)]", className)}>{children}</div>;
}

function Tile({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("rounded-[18px] bg-card shadow-[0_8px_20px_rgba(0,0,0,0.08)]", className)}>{children}</div>;
}

function Chip({ tone, children }: { tone: "ok" | "no" | "wn" | "flat"; children: React.ReactNode }) {
  const tones = {
    ok: "bg-emerald-500/[0.055] text-emerald-700 dark:text-emerald-400",
    no: "bg-primary/[0.09] text-primary",
    wn: "bg-amber-500/[0.14] text-amber-700 dark:text-amber-400",
    flat: "bg-muted text-muted-foreground",
  } as const;
  return (
    <span className={cn("inline-flex h-[22px] shrink-0 items-center whitespace-nowrap rounded-lg px-2 text-[11px] font-bold", tones[tone])}>
      {children}
    </span>
  );
}

function Sep({ className }: { className?: string }) {
  return <div className={cn("h-px bg-border", className)} />;
}

function initialsOf(name: string): string {
  const p = name.trim().split(/\s+/).filter(Boolean);
  if (!p.length) return "—";
  return ((p[0][0] || "") + (p.length > 1 ? p[p.length - 1][0] : "")).toUpperCase();
}

function methodIcon(method: string) {
  const m = (method || "").toUpperCase();
  if (m.includes("QR") || m.includes("TOTP")) return QrCode;
  if (m.includes("FINGER") || m.includes("FP") || m.includes("BIO")) return Fingerprint;
  return CreditCard;
}

function methodLabel(method: string): string {
  const m = (method || "").toUpperCase();
  if (m.includes("QR") || m.includes("TOTP")) return "QR Code";
  if (m.includes("FINGER") || m.includes("FP") || m.includes("BIO")) return "empreinte";
  return "carte";
}

/** Backend timestamps are LOCAL wall-clock with no zone ("…THH:MM:SS"). */
function hhmm(iso: string): string {
  const t = String(iso || "");
  const i = t.indexOf("T") >= 0 ? t.indexOf("T") : t.indexOf(" ");
  return i > 0 ? t.slice(i + 1, i + 6) : "--:--";
}

/** Local HH:MM for live rows — never toISOString(), which would print UTC. */
function clockOf(d: Date): string {
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

/** "ZKPIN:<pin>" is NOT a card.
 *
 * A standalone terminal (MB2000) reports a fingerprint punch with no card number
 * at all, so the driver synthesises this marker from the device PIN when its
 * pin->card map has no entry — and flags it as an anomaly (ZKEM_PIN_UNMAPPED).
 * On a fingerprint-only gym that is the NORMAL case, so the feed was telling the
 * operator "Carte ZKPIN:1234" about a member who has no card and never presented
 * one. Show it for what it is: an unmatched device PIN. */
const ZKPIN_PREFIX = "ZKPIN:";
function isDevicePin(cardNo: string): boolean {
  return cardNo.startsWith(ZKPIN_PREFIX);
}
/** Primary label for a feed row — the member, or the credential when unresolved. */
function rowTitle(it: DashboardFeedItem): string {
  if (it.userFullName.trim()) return it.userFullName;
  if (!it.cardNo) return "Badge inconnu";
  // Unresolved AND no card: the device PIN matched no member in the local roster.
  return isDevicePin(it.cardNo)
    ? `PIN ${it.cardNo.slice(ZKPIN_PREFIX.length)} — membre inconnu`
    : `Carte ${it.cardNo}`;
}

/** Secondary label — plan and credential, mirroring "Annuel salle · carte 0042 8871". */
function rowDetail(it: DashboardFeedItem): string {
  const bits: string[] = [];
  if (it.membershipTitle.trim()) bits.push(it.membershipTitle);
  if (it.userFullName.trim() && it.cardNo) bits.push(`${methodLabel(it.method)} ${isDevicePin(it.cardNo) ? it.cardNo.slice(ZKPIN_PREFIX.length) : it.cardNo}`);
  else bits.push(methodLabel(it.method));
  if (it.deviceName) bits.push(it.deviceName);
  return bits.join(" · ");
}

export default function DashboardPage() {
  const { status, syncNow, hardSyncNow } = useApp();
  const { openPopupWindow, sendTestNotification } = usePopupStream();
  const [scanOpen, setScanOpen] = useState(false);
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [now, setNow] = useState<Date>(() => new Date());

  // Tray "Scanner carte"
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    import("@tauri-apps/api/event").then(({ listen }) => {
      listen("tray-scan-card", () => setScanOpen(true)).then((fn) => { unlisten = fn; });
    }).catch(() => {/* not in Tauri context */});
    return () => { if (unlisten) unlisten(); };
  }, []);

  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);

  // Timeline + day aggregates. Independent request per tick, so a stalled
  // response can never wedge the page.
  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    const tick = async () => {
      try {
        const res = await get<DashboardOverview>("/dashboard/overview", { limit: "40" });
        if (!cancelled) setOverview(res);
      } catch { /* transient — the next tick retries */ }
      finally { if (!cancelled) timer = window.setTimeout(tick, OVERVIEW_POLL_MS); }
    };
    void tick();
    return () => { cancelled = true; if (timer) window.clearTimeout(timer); };
  }, []);

  const syncRunning = status?.sync?.running ?? false;
  const feed = overview?.feed ?? [];
  const today: DashboardToday = overview?.today ?? { total: 0, granted: 0, denied: 0, hourly: [], peakHour: null };
  const lastEntry = useMemo(() => feed.find((f) => f.allowed && f.userFullName.trim()) ?? null, [feed]);
  const headDevice = feed[0]?.deviceName ?? "";

  const handleSync = useCallback(() => { void syncNow(); }, [syncNow]);

  // Publish the header's subtitle + actions into the shell.
  usePageChrome(() => ({
    fill: true,
    subtitle: `${headDevice ? `${headDevice} · ` : ""}${clockOf(now)}`,
    actions: (
      <>
        <Button
          variant="outline"
          className="h-[34px] gap-[7px] rounded-[14px] border-[1.5px] border-primary/45 bg-card px-[14px] text-[12.5px] font-semibold text-primary hover:bg-primary/5"
          onClick={() => setScanOpen(true)}
        >
          <CreditCard className="h-4 w-4" />
          Scanner une carte
        </Button>
        <Button
          className="h-[34px] gap-[7px] rounded-full px-[18px] text-[12.5px] font-bold shadow-[0_8px_20px_rgba(226,32,63,0.22)]"
          onClick={handleSync}
          disabled={syncRunning}
        >
          <RefreshCw className={cn("h-4 w-4", syncRunning && "animate-spin")} />
          {syncRunning ? "En cours…" : "Synchroniser"}
        </Button>
      </>
    ),
  }), [headDevice, now.getMinutes(), syncRunning, handleSync]);

  if (!status) return <p className="text-[13px] text-muted-foreground">Chargement…</p>;

  const agent = status.agent;
  const sync = status.sync;
  const mode = status.mode;
  const s = status.session;
  const dsp = status.deviceSync?.progress;
  const dspActive = !!dsp?.running;
  const dspPct = dspActive && dsp!.total > 0 ? Math.round((dsp!.current / dsp!.total) * 100) : 0;
  const devicesTotal = mode.DEVICE + mode.AGENT + (mode.ULTRA ?? 0) + mode.UNKNOWN;

  // "Lecteur" = is ANY reader actually attached right now?
  //
  // status.pullsdk is fed ONLY by the manual Connect button's session pool, so a
  // ZK_STANDALONE terminal (MB2000 over zkemkeeper) can never appear there: its
  // driver owns its own COM connection and the ULTRA worker holds it. Reading only
  // pullsdk left such a gym permanently showing "Lecteur non connecté" while the
  // turnstile was working perfectly, next to a "Recharger" button that fixed
  // nothing. Take the real per-worker `connected` flag into account too -- this
  // reports actual state, it does not assume success.
  const ultraDevices = Object.values(status.ultra?.devices ?? {});
  const ultraConnected = ultraDevices.filter((d) => d?.connected);
  const readerConnected = status.pullsdk.connected || ultraConnected.length > 0;
  const readerLabel =
    status.pullsdk.ip
    ?? (ultraConnected.length === 1 ? ultraConnected[0].device_name : null)
    ?? (ultraConnected.length > 1 ? `${ultraConnected.length} appareils` : null)
    ?? (readerConnected ? "connecté" : "hors ligne");

  // The design's third "Maintenant" line is an alert. Only real, currently
  // observable faults are surfaced — /status carries no per-device reachability,
  // so "device offline" is deliberately not synthesised here.
  const alert =
    !agent.running ? { icon: Square, text: "Agent temps réel arrêté", action: "Démarrer", run: () => post("/agent/start") }
    : !readerConnected ? { icon: WifiOff, text: "Lecteur non connecté", action: "Recharger", run: () => window.location.reload() }
    : !sync.lastOk ? { icon: AlertTriangle, text: "Dernière synchronisation en échec", action: "Relancer", run: handleSync }
    : null;

  const maxBar = Math.max(1, ...today.hourly);

  return (
    <div className="flex h-full min-h-0 gap-4">
      {/* ── Le sujet : le fil de la journée ─────────────────────────────── */}
      <div className="flex min-w-0 flex-1 flex-col gap-[11px]">
        <ZoneTitle>
          <Users className="h-[17px] w-[17px] text-primary" />
          <span className="font-display text-[13px] font-extrabold tracking-[-0.01em] text-foreground">Passages</span>
          <span className="ml-1 text-[12px] text-muted-foreground">
            {today.total} aujourd'hui{today.denied > 0 ? ` · ${today.denied} refusé${today.denied > 1 ? "s" : ""}` : ""}
          </span>
        </ZoneTitle>

        <Card className="flex min-h-0 flex-1 flex-col overflow-hidden">
          <div className="flex flex-none items-center justify-between gap-3.5 border-b border-border px-6 pb-3 pt-3.5">
            <Lb>Fil de la journée</Lb>
            <div className="flex items-center gap-2.5">
              <span className="inline-flex items-center gap-[5px] text-[11px] text-muted-foreground">
                <span className="h-[7px] w-[7px] rounded-full bg-emerald-500" />passages
              </span>
              <span className="inline-flex items-center gap-[5px] text-[11px] text-muted-foreground">
                <span className="h-[7px] w-[7px] rounded-sm bg-muted-foreground" />système
              </span>
            </div>
          </div>

          <div className="relative min-h-0 flex-1 overflow-y-auto px-6 pt-2.5">
            {/* the rule the timeline hangs from */}
            <div className="pointer-events-none absolute bottom-2 left-[60px] top-3 w-px bg-border" />

            {/* Live system row — real, from /status */}
            {dspActive && (
              <div className="relative flex items-center gap-3.5 py-[7px]">
                <span className="w-9 shrink-0 font-mono text-[12px] text-muted-foreground">{clockOf(now)}</span>
                <span className="h-[11px] w-[11px] shrink-0 animate-pulse rounded-[3px] bg-primary shadow-[0_0_0_3px_hsl(var(--card))]" />
                <span className="flex w-8 shrink-0 justify-center"><Upload className="h-[18px] w-[18px] text-primary" /></span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13.5px] text-foreground">
                    Envoi des membres vers l'appareil{dsp!.deviceName ? ` « ${dsp!.deviceName} »` : ""}
                  </div>
                  <div className="truncate text-[11px] text-muted-foreground">
                    {dsp!.total > 0 ? `${dsp!.current} / ${dsp!.total} — ne fermez pas l'application` : "Connexion à l'appareil…"}
                  </div>
                </div>
                {dsp!.total > 0 && <Chip tone="no">{dspPct} %</Chip>}
              </div>
            )}

            {feed.length === 0 && !dspActive && (
              <div className="flex h-full min-h-[220px] flex-col items-center justify-center gap-2 text-center">
                <History className="h-7 w-7 text-muted-foreground/50" />
                <p className="text-[13px] font-semibold text-foreground">Aucun passage enregistré</p>
                <p className="max-w-[320px] text-[11.5px] text-muted-foreground">
                  Le fil se remplit dès qu'un membre se présente à un lecteur.
                </p>
              </div>
            )}

            {feed.map((it) => {
              const MIcon = methodIcon(it.method);
              const resolved = !!it.userFullName.trim();
              return (
                <div key={it.eventId || `${it.at}-${it.cardNo}`} className="relative flex items-center gap-3.5 py-[7px]">
                  <span className="w-9 shrink-0 font-mono text-[12px] text-muted-foreground">{hhmm(it.at)}</span>
                  <span
                    className={cn(
                      "h-[11px] w-[11px] shrink-0 rounded-full shadow-[0_0_0_3px_hsl(var(--card))]",
                      it.allowed ? "bg-emerald-500" : "bg-primary",
                    )}
                  />
                  <span
                    className={cn(
                      "flex h-8 w-8 shrink-0 items-center justify-center rounded-[18px] text-[12px] font-bold",
                      resolved
                        ? it.allowed ? "bg-muted text-muted-foreground" : "bg-primary/[0.09] text-primary"
                        : "bg-muted text-muted-foreground",
                    )}
                  >
                    {resolved ? initialsOf(it.userFullName) : <MIcon className="h-[18px] w-[18px]" />}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13.5px] font-semibold text-foreground">{rowTitle(it)}</div>
                    <div className={cn("truncate text-[11px]", it.allowed ? "text-muted-foreground" : "text-primary")}>
                      {it.allowed ? rowDetail(it) : (it.reason || "Accès refusé")}
                    </div>
                  </div>
                  <Chip tone={it.allowed ? "ok" : "no"}>{it.allowed ? "Autorisé" : "Refusé"}</Chip>
                </div>
              );
            })}
          </div>
        </Card>
      </div>

      {/* ── Le rail ─────────────────────────────────────────────────────── */}
      <div className="flex w-[330px] flex-none flex-col gap-[11px]">
        {/* Maintenant */}
        <ZoneTitle>
          <span className="inline-flex h-[22px] items-center gap-1.5 rounded-lg bg-primary/[0.08] px-[9px] text-[10.5px] font-bold uppercase tracking-[0.05em] text-primary">
            <LiveDot className="h-[6px] w-[6px]" />
            Maintenant
          </span>
        </ZoneTitle>

        <Card className="flex-none px-[22px] py-[18px]">
          {lastEntry ? (
            <div className="mb-[15px] flex items-center gap-3.5">
              <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-3xl bg-emerald-500/[0.055] text-[17px] font-bold text-emerald-700 dark:text-emerald-400">
                {initialsOf(lastEntry.userFullName)}
              </span>
              <div className="min-w-0 flex-1">
                <Lb className="mb-1 block text-emerald-700 dark:text-emerald-400">
                  Vient d'entrer · {hhmm(lastEntry.at)}
                </Lb>
                <div className="truncate font-display text-[17px] font-extrabold leading-[1.15] tracking-[-0.02em] text-foreground">
                  {lastEntry.userFullName}
                </div>
              </div>
            </div>
          ) : (
            <div className="mb-[15px] flex items-center gap-3.5">
              <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-3xl bg-muted text-muted-foreground">
                <Users className="h-5 w-5" />
              </span>
              <div className="min-w-0 flex-1">
                <Lb className="mb-1 block">En attente</Lb>
                <div className="truncate text-[13px] text-muted-foreground">Aucun passage pour l'instant</div>
              </div>
            </div>
          )}

          <Sep className="mb-[13px]" />

          <div className="mb-[9px] flex items-center justify-between gap-2.5">
            <span className="text-[12px] font-semibold text-foreground">
              {dspActive ? "Envoi des membres" : "Synchronisation"}
            </span>
            <span className="text-[12.5px] font-bold text-primary">
              {dspActive ? `${dspPct} %` : sync.lastOk ? "à jour" : "à relancer"}
            </span>
          </div>
          <div className="mb-[13px] h-1.5 overflow-hidden rounded-full bg-muted">
            <div
              className="h-full rounded-full bg-primary transition-[width] duration-300"
              style={{ width: `${dspActive ? dspPct : sync.lastOk ? 100 : 8}%` }}
            />
          </div>

          {alert ? (
            <div className="flex items-center gap-2.5">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-primary/[0.09] text-primary">
                <alert.icon className="h-4 w-4" />
              </span>
              <span className="min-w-0 flex-1 truncate text-[11.5px] text-foreground">{alert.text}</span>
              <Button
                variant="outline"
                className="h-[26px] shrink-0 rounded-[14px] px-3 text-[11.5px] font-semibold"
                onClick={() => { void alert.run(); }}
              >
                {alert.action}
              </Button>
            </div>
          ) : (
            <div className="flex items-center gap-2.5">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-emerald-500/[0.055] text-emerald-700 dark:text-emerald-400">
                <Play className="h-3.5 w-3.5" />
              </span>
              <span className="min-w-0 flex-1 truncate text-[11.5px] text-foreground">Tout fonctionne</span>
            </div>
          )}
        </Card>

        {/* Aujourd'hui */}
        <ZoneTitle>
          <span className="mt-[3px] inline-flex h-[22px] items-center gap-1.5 rounded-lg bg-muted px-[9px] text-[10.5px] font-bold uppercase tracking-[0.05em] text-muted-foreground">
            <History className="h-3 w-3" />
            Aujourd'hui
          </span>
        </ZoneTitle>

        <Tile className="flex min-h-0 flex-1 flex-col px-5 py-4">
          <div className="mb-3.5 flex items-end gap-5">
            <div>
              <div className="num text-[30px] leading-none">{today.total}</div>
              <div className="mt-1 whitespace-nowrap text-[10.5px] text-muted-foreground">passages</div>
            </div>
            <div>
              <div className="text-[15px] font-bold text-emerald-700 dark:text-emerald-400">{today.granted}</div>
              <div className="mt-[3px] text-[10.5px] text-muted-foreground">ok</div>
            </div>
            <div>
              <div className="text-[15px] font-bold text-primary">{today.denied}</div>
              <div className="mt-[3px] text-[10.5px] text-muted-foreground">refusés</div>
            </div>
            {today.peakHour != null && (
              <div className="ml-auto text-right">
                <div className="text-[13px] font-bold text-foreground">{today.peakHour} h</div>
                <div className="mt-[3px] whitespace-nowrap text-[10.5px] text-muted-foreground">pointe</div>
              </div>
            )}
          </div>

          {/* Hourly curve — 24 slots, the peak in the accent colour */}
          <div className="mb-3.5 flex h-[34px] items-end gap-[2px]">
            {(today.hourly.length === 24 ? today.hourly : new Array(24).fill(0)).map((v, h) => (
              <span
                key={h}
                title={`${h} h — ${v}`}
                className={cn("flex-1 rounded-sm", h === today.peakHour && v > 0 ? "bg-primary" : "bg-muted")}
                style={{ height: `${Math.max(6, Math.round((v / maxBar) * 100))}%` }}
              />
            ))}
          </div>

          <Sep className="mb-3" />

          <div className="flex flex-col gap-2.5">
            <div className="flex items-center gap-2.5">
              <LiveDot className="h-2 w-2" tone={agent.running ? "ok" : "off"} />
              <span className="flex-1 text-[12px] text-foreground">Agent</span>
              <span className="font-mono text-[12px] text-muted-foreground">
                {agent.eventQueueDepth} · {agent.avgDecisionMs.toFixed(1)} ms
              </span>
            </div>
            <div className="flex items-center gap-2.5">
              <span className={cn("h-2 w-2 shrink-0 rounded-full", readerConnected ? "bg-emerald-500" : "bg-primary")} />
              <span className="flex-1 text-[12px] text-foreground">Lecteur</span>
              <span className="truncate font-mono text-[12px] text-muted-foreground">
                {readerLabel}
              </span>
            </div>
            <div className="flex items-center gap-2.5">
              <span className={cn("h-2 w-2 shrink-0 rounded-full", devicesTotal > 0 ? "bg-emerald-500" : "bg-muted-foreground")} />
              <span className="flex-1 text-[12px] text-foreground">Appareils</span>
              <span className="text-[12px] font-semibold text-muted-foreground">
                {devicesTotal} déclaré{devicesTotal > 1 ? "s" : ""}
              </span>
            </div>
          </div>

          <div className="mt-auto flex flex-col gap-2.5 border-t border-border pt-3">
            {s.loginDaysRemaining != null && (
              <div className="flex items-center gap-2.5">
                <span className={cn(
                  "flex h-[22px] w-[22px] shrink-0 items-center justify-center rounded-[7px]",
                  s.loginWarning ? "bg-amber-500/[0.14] text-amber-700 dark:text-amber-400" : "bg-muted text-muted-foreground",
                )}>
                  <Clock className="h-[15px] w-[15px]" />
                </span>
                <span className="flex-1 text-[12px] text-foreground">Session</span>
                <span className={cn(
                  "whitespace-nowrap text-[12.5px] font-bold",
                  s.loginWarning ? "text-amber-700 dark:text-amber-400" : "text-muted-foreground",
                )}>
                  {s.loginDaysRemaining} jour{s.loginDaysRemaining > 1 ? "s" : ""} restant{s.loginDaysRemaining > 1 ? "s" : ""}
                </span>
              </div>
            )}
            <div className="flex items-center gap-2.5">
              <span className="flex h-[22px] w-[22px] shrink-0 items-center justify-center rounded-[7px] bg-muted text-muted-foreground">
                <DownloadCloud className="h-[15px] w-[15px]" />
              </span>
              <span className="flex-1 text-[12px] text-foreground">Mise à jour</span>
              <span className="whitespace-nowrap text-[12px] text-muted-foreground">
                {status.updates.updateAvailable
                  ? `${status.updates.latestVersion ?? ""} ${status.updates.downloaded ? "prête" : "disponible"}`.trim()
                  : "à jour"}
              </span>
            </div>
          </div>
        </Tile>

        {/* Action tile */}
        <Tile className="flex-none px-5 py-[15px]">
          <div className="mb-3 flex items-center gap-2.5">
            <Monitor className="h-[18px] w-[18px] shrink-0 text-primary" />
            <div className="min-w-0 flex-1">
              <div className="text-[12.5px] font-bold text-foreground">Écran d'entrée</div>
              <div className="truncate text-[10.5px] text-muted-foreground">Affiche les accès en temps réel</div>
            </div>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              className="h-8 flex-1 gap-1.5 rounded-[14px] text-[12px] font-semibold"
              onClick={openPopupWindow}
            >
              <Monitor className="h-[15px] w-[15px]" />Ouvrir
            </Button>
            <Button
              variant="outline"
              className="h-8 flex-1 gap-1.5 rounded-[14px] text-[12px] font-semibold"
              onClick={sendTestNotification}
            >
              <Bug className="h-[15px] w-[15px]" />Tester
            </Button>
          </div>
        </Tile>

        {/* Hard reset stays reachable — it is a destructive action the old
            dashboard exposed, and the design has no other home for it. */}
        <Button
          variant="ghost"
          className="h-8 shrink-0 gap-1.5 self-start px-2 text-[11.5px] text-muted-foreground hover:text-primary"
          onClick={() => { void hardSyncNow(); }}
          disabled={syncRunning}
          title="Réinitialisation complète — recharge tous les membres sur les appareils"
        >
          <RotateCcw className={cn("h-3.5 w-3.5", syncRunning && "animate-spin")} />
          Réinitialisation complète
        </Button>
      </div>

      <ScanCardModal open={scanOpen} onClose={() => setScanOpen(false)} />
    </div>
  );
}
