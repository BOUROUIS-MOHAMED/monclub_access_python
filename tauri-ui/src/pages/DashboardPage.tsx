// Dashboard — Access v5 redesign (docs/access-redesign-v5: the `tp === 'home'`
// branch and the `reset` modal of main.logic.js; boards S01, S02, S03).
//
// 12-column grid: "Maintenant" (who just came in + the two live status lines)
// and "Aujourd'hui" (day totals + 24 h curve) on top; "Passages" (the 40 latest
// rows) and "État du poste" (machine, session, update, entry screen, full
// reset) below.
//
// Where the data comes from (unchanged):
//   · feed + day totals/curve → GET /api/v2/dashboard/overview, polled every 5 s
//     (access_history stores only a card number, so unresolved rows fall back to
//     "Carte ####" / "PIN #### — membre inconnu" by design);
//   · sync / agent / reader / session / update → the existing /status poll;
//   · entry screen → usePopupStream, unchanged.
// Refusal texts use the entry screen's French copy (A_DENY in PopupWindow.tsx);
// an ULTRA device refusal (`DEVICE_DENIED`, no "why") reads "Accès refusé".

import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useApp } from "@/context/AppContext";
import { usePopupStream } from "@/api/hooks";
import { get, post } from "@/api/client";
import { usePageChrome } from "@/context/PageChromeContext";
import ScanCardModal from "@/components/ScanCardModal";
import { ActionButton } from "@/components/ui/action-button";
import { Avatar, Chip } from "@/components/ui/chip";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { FlexCell, FlexRow, FlexTable, IconCell, PersonCell } from "@/components/ui/flex-table";
import { ListRow, Note, PageGrid, Panel, PanelHeader, PanelList } from "@/components/ui/panel";
import { INK, initialsOf, type Tone } from "@/components/ui/tone";
import { hasAgentDevices } from "@/lib/agentMode";
import { aDenyCopy } from "@/pages/PopupWindow";
import { cn } from "@/lib/utils";
import type { DashboardFeedItem, DashboardOverview, DashboardToday } from "@/api/types";
import {
  RefreshCw, RotateCcw, Users, MonitorPlay, Play, Upload, CreditCard, Fingerprint,
  QrCode, WifiOff, Clock, Download, AlertTriangle, CircleCheck, Router, Bot,
  ScanLine, ExternalLink, type LucideIcon,
} from "lucide-react";

const OVERVIEW_POLL_MS = 5000;

function methodIcon(method: string): LucideIcon {
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

const MONTHS_FR = [
  "janv.", "févr.", "mars", "avr.", "mai", "juin",
  "juil.", "août", "sept.", "oct.", "nov.", "déc.",
];

/** "18:40" today, "12 oct. · 18:40" another day, "" when unknown. */
function whenLabel(iso: string | null | undefined, now: Date): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  const sameDay = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  return sameDay ? clockOf(d) : `${d.getDate()} ${MONTHS_FR[d.getMonth()]} · ${clockOf(d)}`;
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

/** "carte 0042 8871" for a resolved member, just the method otherwise. */
function credentialBit(it: DashboardFeedItem): string {
  if (it.userFullName.trim() && it.cardNo) {
    return `${methodLabel(it.method)} ${isDevicePin(it.cardNo) ? it.cardNo.slice(ZKPIN_PREFIX.length) : it.cardNo}`;
  }
  return methodLabel(it.method);
}

/** Secondary label — plan and credential, mirroring "Annuel standard · empreinte · Tourniquet principal". */
function rowDetail(it: DashboardFeedItem): string {
  const bits: string[] = [];
  if (it.membershipTitle.trim()) bits.push(it.membershipTitle);
  bits.push(credentialBit(it));
  if (it.deviceName) bits.push(it.deviceName);
  return bits.join(" · ");
}

/** Refused row — the short French reason first ("Carte non reconnue · carte · Tourniquet principal"). */
function refusedDetail(it: DashboardFeedItem): string {
  const bits: string[] = [aDenyCopy(it.reason).short, credentialBit(it)];
  if (it.deviceName) bits.push(it.deviceName);
  return bits.join(" · ");
}

interface HeroLine {
  key: string;
  icon: LucideIcon;
  tone: Tone;
  title: string;
  sub?: string;
  action?: { label: string; kind: "danger" | "outline"; run: () => void | Promise<unknown> };
}

export default function DashboardPage() {
  const { status, syncNow, hardSyncNow } = useApp();
  const { openPopupWindow, sendTestNotification } = usePopupStream();
  const navigate = useNavigate();
  const [scanOpen, setScanOpen] = useState(false);
  const [resetOpen, setResetOpen] = useState(false);
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
    subtitle: `${headDevice ? `${headDevice} · ` : ""}${clockOf(now)}`,
    actions: (
      <>
        <ActionButton kind="outline" icon={ScanLine} onClick={() => setScanOpen(true)}>
          Scanner une carte
        </ActionButton>
        <ActionButton kind="primary" icon={RefreshCw} spin={syncRunning} onClick={handleSync} disabled={syncRunning}>
          {syncRunning ? "En cours…" : "Synchroniser"}
        </ActionButton>
      </>
    ),
  }), [headDevice, now.getMinutes(), syncRunning, handleSync]);

  if (!status) return <p className="text-[13px] text-muted-foreground">Chargement…</p>;

  const agent = status.agent;
  const showAgent = hasAgentDevices(status);
  const sync = status.sync;
  const mode = status.mode;
  const s = status.session;
  const dsp = status.deviceSync?.progress;
  const dspActive = !!dsp?.running;
  const dspPct = dspActive && dsp!.total > 0 ? Math.round((dsp!.current / dsp!.total) * 100) : 0;
  const devicesTotal = mode.DEVICE + mode.AGENT + (mode.ULTRA ?? 0) + mode.UNKNOWN;
  const devicesDeclared = `${devicesTotal} appareil${devicesTotal > 1 ? "s" : ""} déclaré${devicesTotal > 1 ? "s" : ""}`;

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
  const ultraOff = ultraDevices.filter((d) => !d?.connected);
  const readerConnected = status.pullsdk.connected || ultraConnected.length > 0;
  // A READER PC never connects to a turnstile, so "not connected" is its normal state.
  const expectsReader = mode.DEVICE > 0 || mode.AGENT > 0 || (status.ultra?.drivesTurnstiles ?? true);
  const readerLabel =
    status.pullsdk.ip
    ?? (ultraConnected.length === 1 ? ultraConnected[0].device_name : null)
    ?? (ultraConnected.length > 1 ? `${ultraConnected.length} appareils` : null)
    ?? (readerConnected ? "connecté" : "hors ligne");
  const offNames = ultraOff.map((d) => d.device_name).filter(Boolean).join(", ");

  // ── "Maintenant" lines: the sync line, then the machine line. Only real,
  // currently observable faults are surfaced.
  const lastSyncWhen = whenLabel(sync.lastSyncAt, now);
  const syncLine: HeroLine = dspActive
    ? { key: "sync", icon: Upload, tone: "primary", title: "Envoi des membres", sub: dsp!.total > 0 ? `${dspPct} %` : "Connexion à l'appareil…" }
    : sync.lastOk
      ? { key: "sync", icon: RefreshCw, tone: "success", title: "Synchronisation à jour", sub: lastSyncWhen ? `dernière ${lastSyncWhen}` : undefined }
      : { key: "sync", icon: AlertTriangle, tone: "warning", title: "Dernière synchronisation en échec", sub: lastSyncWhen || undefined, action: { label: "Relancer", kind: "outline", run: handleSync } };

  const machineLine: HeroLine =
    showAgent && !agent.running
      ? { key: "machine", icon: Bot, tone: "error", title: "Agent temps réel arrêté", action: { label: "Démarrer", kind: "danger", run: () => post("/agent/start") } }
      : expectsReader && !readerConnected
        ? { key: "machine", icon: WifiOff, tone: "error", title: "Lecteur non connecté", sub: offNames || undefined, action: { label: "Recharger", kind: "danger", run: () => window.location.reload() } }
        : expectsReader && ultraOff.length > 0
          ? { key: "machine", icon: WifiOff, tone: "error", title: ultraOff.length > 1 ? `${ultraOff.length} lecteurs non connectés` : "Lecteur non connecté", sub: offNames || undefined }
          : { key: "machine", icon: CircleCheck, tone: "success", title: "Tout fonctionne", sub: expectsReader && ultraDevices.length > 0 ? `${ultraConnected.length} / ${ultraDevices.length} lecteurs connectés` : undefined };

  // ── "État du poste" › Lecteurs
  const readerTone: Tone = !expectsReader ? "grey" : (ultraOff.length > 0 || !readerConnected) ? "error" : "success";
  const readerValue = ultraDevices.length > 0 ? `${ultraConnected.length} / ${ultraDevices.length}` : readerLabel;
  const readerSub = expectsReader && ultraOff.length > 0 && offNames
    ? `${offNames} non connecté${ultraOff.length > 1 ? "s" : ""}`
    : devicesDeclared;

  const updates = status.updates;
  const updateSub = updates.updateAvailable
    ? `${updates.latestVersion ?? ""} ${updates.downloaded ? "prête · à installer à la fermeture" : "disponible"}`.trim()
    : "à jour";

  const hourly = today.hourly.length === 24 ? today.hourly : new Array<number>(24).fill(0);
  const maxBar = Math.max(1, ...hourly);

  return (
    <PageGrid>
      {/* ── Maintenant ─────────────────────────────────────────────────── */}
      <Panel className="col-span-8" aria-label="Maintenant">
        <PanelHeader title="Maintenant" />
        <div className="mt-3">
          {lastEntry ? (
            <div className="flex items-center gap-[18px] bg-[linear-gradient(135deg,hsl(var(--success)/0.10),hsl(var(--success)/0.02))] px-5 pb-[18px] pt-5">
              <Avatar
                initials={initialsOf(lastEntry.userFullName)}
                tone="success"
                size={76}
                className="shadow-[0_0_0_4px_hsl(var(--card)),0_0_0_6px_hsl(var(--success))]"
              />
              <div className="min-w-0 flex-1">
                <div className="text-[13px] font-bold text-success-ink">Vient d'entrer · {hhmm(lastEntry.at)}</div>
                <div className="truncate font-num text-[30px] font-extrabold leading-[1.15] text-foreground">
                  {lastEntry.userFullName}
                </div>
                <div className="mt-1 truncate text-[13.5px] text-muted-foreground">{rowDetail(lastEntry)}</div>
              </div>
              <span className="inline-flex h-10 shrink-0 items-center gap-2 rounded-[10px] bg-success px-4 text-[15px] font-extrabold text-white">
                <CircleCheck className="h-5 w-5" strokeWidth={2.2} />Autorisé
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-[18px] px-5 pb-[18px] pt-5">
              <span className="grid h-[76px] w-[76px] shrink-0 place-items-center rounded-full bg-muted text-muted-foreground">
                <Users className="h-7 w-7" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-[13px] font-bold text-muted-foreground">En attente</div>
                <div className="truncate text-[17px] font-semibold text-foreground">Aucun passage pour l'instant</div>
              </div>
            </div>
          )}
          {[syncLine, machineLine].map((l) => (
            <div
              key={l.key}
              className={cn("flex items-center gap-2.5 border-t border-dashed border-grey/20 px-5 py-2.5 text-[13.5px]", INK[l.tone])}
            >
              <l.icon className="h-[18px] w-[18px] shrink-0" />
              <span className="min-w-0 flex-1 truncate font-semibold">{l.title}</span>
              {l.sub && <span className="truncate text-muted-foreground">{l.sub}</span>}
              {l.action && (
                <ActionButton kind={l.action.kind} size="xs" onClick={() => { void l.action!.run(); }}>
                  {l.action.label}
                </ActionButton>
              )}
            </div>
          ))}
        </div>
      </Panel>

      {/* ── Aujourd'hui ────────────────────────────────────────────────── */}
      <Panel className="col-span-4" aria-label="Aujourd'hui">
        <PanelHeader title="Aujourd'hui" />
        <div className="px-[18px] pb-[18px] pt-3">
          <div className="flex items-baseline gap-2">
            <span className="font-num text-[38px] font-extrabold leading-none text-foreground">{today.total}</span>
            <span className="text-[14px] text-muted-foreground">passages</span>
          </div>
          <div className="mt-1.5 flex flex-wrap gap-3.5 text-[13px]">
            <span><strong className="text-success-ink">{today.granted}</strong> <span className="text-muted-foreground">ok</span></span>
            <span><strong className="text-error-ink">{today.denied}</strong> <span className="text-muted-foreground">refusés</span></span>
            {today.peakHour != null && (
              <span><strong className="text-foreground">{today.peakHour} h</strong> <span className="text-muted-foreground">pointe</span></span>
            )}
          </div>
          {/* Hourly curve — 24 slots, the peak in the accent colour */}
          <div aria-hidden="true" className="mt-3.5 flex h-16 items-end gap-[3px]">
            {hourly.map((v, h) => (
              <span
                key={h}
                title={`${h} h — ${v}`}
                className={cn(
                  "flex-1 rounded-[3px]",
                  h === today.peakHour && v > 0 ? "bg-primary" : v > 0 ? "bg-primary/32" : "bg-muted",
                )}
                style={{ height: `${Math.max(4, Math.round((v / maxBar) * 100))}%` }}
              />
            ))}
          </div>
          <div className="mt-1.5 flex justify-between text-[11.5px] text-muted-foreground">
            <span>0 h</span><span>6 h</span><span>12 h</span><span>18 h</span><span>23 h</span>
          </div>
        </div>
      </Panel>

      {/* ── Passages ───────────────────────────────────────────────────── */}
      <Panel className="col-span-8" aria-label="Passages">
        <PanelHeader
          title="Passages"
          sub={`${today.total} aujourd'hui · ${today.denied} refusé${today.denied > 1 ? "s" : ""}${feed.length >= 40 ? " · les 40 derniers" : ""}`}
        />
        <FlexTable
          label="Passages"
          columns={[{ label: "Heure", flex: 0.5 }, { label: "Membre", flex: 3.4 }, { label: "", flex: 0.8, align: "right" }]}
          empty={
            <>
              <div className="font-semibold text-foreground">Aucun passage enregistré</div>
              <div className="mt-1 text-[12.5px]">Le fil se remplit dès qu'un membre se présente à un lecteur.</div>
            </>
          }
        >
          {/* Live system row — real, from /status */}
          {dspActive && (
            <FlexRow key="live-sync" minHeight={54}>
              <FlexCell flex={0.5}><span className="font-mono text-[13px] text-muted-foreground">{clockOf(now)}</span></FlexCell>
              <FlexCell flex={3.4}>
                <IconCell
                  icon={Upload}
                  tone="primary"
                  title={`Envoi des membres vers l'appareil${dsp!.deviceName ? ` « ${dsp!.deviceName} »` : ""}`}
                  sub={dsp!.total > 0 ? `${dsp!.current} / ${dsp!.total} — ne fermez pas l'application` : "Connexion à l'appareil…"}
                />
              </FlexCell>
              <FlexCell flex={0.8} align="right">{dsp!.total > 0 && <Chip tone="primary">{dspPct} %</Chip>}</FlexCell>
            </FlexRow>
          )}
          {feed.map((it) => {
            const resolved = !!it.userFullName.trim();
            const tone: Tone = it.allowed ? "success" : "error";
            const detail = it.allowed ? rowDetail(it) : refusedDetail(it);
            return (
              <FlexRow key={it.eventId || `${it.at}-${it.cardNo}`} minHeight={54}>
                <FlexCell flex={0.5}><span className="font-mono text-[13px] text-muted-foreground">{hhmm(it.at)}</span></FlexCell>
                <FlexCell flex={3.4}>
                  {resolved
                    ? <PersonCell name={rowTitle(it)} initials={initialsOf(it.userFullName)} tone={tone} sub={detail} />
                    : <IconCell icon={methodIcon(it.method)} tone="grey" title={rowTitle(it)} sub={detail} />}
                </FlexCell>
                <FlexCell flex={0.8} align="right"><Chip tone={tone}>{it.allowed ? "Autorisé" : "Refusé"}</Chip></FlexCell>
              </FlexRow>
            );
          })}
        </FlexTable>
      </Panel>

      {/* ── État du poste ──────────────────────────────────────────────── */}
      <Panel className="col-span-4" aria-label="État du poste">
        <PanelHeader title="État du poste" />
        <PanelList>
          <ListRow
            icon={Router}
            tone={readerTone}
            title="Lecteurs"
            sub={readerSub}
            subTone={readerTone === "error" && ultraOff.length > 0 ? "error" : undefined}
            value={readerValue}
            valueTone={readerTone === "grey" ? undefined : readerTone}
          />
          {showAgent && (
            <ListRow
              icon={Bot}
              tone={agent.running ? "success" : "grey"}
              title="Agent"
              sub={`${agent.eventQueueDepth} · ${agent.avgDecisionMs.toFixed(1)} ms`}
              value={agent.running ? "actif" : "arrêté"}
              valueTone={agent.running ? "success" : undefined}
            />
          )}
          {s.loginDaysRemaining != null && (
            <ListRow
              icon={Clock}
              tone={s.loginWarning ? "warning" : "grey"}
              title="Session"
              sub={s.loginWarning ? "Reconnexion bientôt nécessaire" : "Connexion de ce poste"}
              value={`${s.loginDaysRemaining} jour${s.loginDaysRemaining > 1 ? "s" : ""}`}
              valueTone={s.loginWarning ? "warning" : undefined}
            />
          )}
          <ListRow
            icon={Download}
            tone={updates.updateAvailable ? "primary" : "grey"}
            title="Mise à jour"
            sub={updateSub}
            actions={updates.updateAvailable
              ? <ActionButton kind="outline" size="sm" onClick={() => navigate("/update")}>Voir</ActionButton>
              : undefined}
          />
          <ListRow
            icon={MonitorPlay}
            tone="info"
            title="Écran d'entrée"
            sub="Affiche les accès en temps réel"
            actions={
              <>
                <ActionButton kind="outline" size="sm" icon={ExternalLink} onClick={openPopupWindow}>Ouvrir</ActionButton>
                <ActionButton kind="outline" size="sm" icon={Play} onClick={sendTestNotification}>Tester</ActionButton>
              </>
            }
          />
          {/* Destructive: confirmed in a dialog first (owner-approved addition). */}
          <ListRow
            icon={RotateCcw}
            tone="error"
            title="Réinitialisation complète"
            sub="Recharge tous les membres sur les appareils"
            actions={
              <ActionButton kind="danger" size="sm" onClick={() => setResetOpen(true)} disabled={syncRunning}>
                Lancer…
              </ActionButton>
            }
          />
        </PanelList>
      </Panel>

      <ConfirmDialog
        open={resetOpen}
        onOpenChange={setResetOpen}
        title="Réinitialisation complète ?"
        description="Recharge tous les membres sur tous les appareils"
        confirmLabel="Réinitialiser"
        confirmDisabled={syncRunning}
        onConfirm={() => { setResetOpen(false); void hardSyncNow(); }}
      >
        <Note tone="warning">Ne fermez pas l'application avant la fin.</Note>
      </ConfirmDialog>

      <ScanCardModal open={scanOpen} onClose={() => setScanOpen(false)} />
    </PageGrid>
  );
}
