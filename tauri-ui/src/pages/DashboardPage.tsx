import { useApp } from "@/context/AppContext";
import { usePopupStream } from "@/api/hooks";
import { post } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import StatusChip from "@/components/StatusChip2";
import { cn } from "@/lib/utils";
import {
  RefreshCw, Router, Bot, Users, CheckCircle, Monitor,
  Bug, AlertTriangle, Play, Square, Upload,
} from "lucide-react";

function Panel({
  title,
  icon,
  children,
  className,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("rounded-xl border border-border bg-card overflow-hidden", className)}>
      <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-border/60">
        {icon}
        <span className="text-[13px] font-semibold tracking-tight">{title}</span>
      </div>
      <div className="px-5 py-4">{children}</div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 py-[3px]">
      <span className="text-[12px] text-muted-foreground shrink-0">{label}</span>
      <span className="text-[13px] text-right font-medium">{value ?? "—"}</span>
    </div>
  );
}

function StatusDot({ ok, pulse }: { ok: boolean; pulse?: boolean }) {
  return (
    <span
      className={cn(
        "inline-block h-1.5 w-1.5 rounded-full",
        ok ? "bg-emerald-400" : "bg-zinc-500",
        pulse && ok && "animate-pulse",
      )}
    />
  );
}

export default function DashboardPage() {
  const { status, syncNow } = useApp();
  const { openPopupWindow, sendTestNotification } = usePopupStream();

  if (!status) return <p className="text-[13px] text-muted-foreground">Chargement…</p>;

  const s = status.session;
  const mode = status.mode;
  const sync = status.sync;
  const agent = status.agent;
  const dsp = status.deviceSync?.progress;
  const dspActive = !!(dsp?.running && dsp.total > 0);
  const dspPct = dspActive ? Math.round((dsp.current / dsp.total) * 100) : 0;

  return (
    <div className="space-y-5">
      {/* Device-sync progress banner */}
      {dspActive && (
        <div className="rounded-xl border border-primary/30 bg-primary/5 px-5 py-4 space-y-3">
          <div className="flex items-center gap-2.5">
            <Upload className="h-4 w-4 text-primary animate-pulse" />
            <span className="text-[13px] font-semibold tracking-tight">
              Envoi des utilisateurs vers l'appareil
              {dsp.deviceName ? ` "${dsp.deviceName}"` : ""}
            </span>
          </div>
          <Progress value={dspPct} className="h-2" />
          <div className="flex items-center justify-between text-[12px] text-muted-foreground">
            <span>
              <span className="font-mono font-semibold text-foreground">{dsp.current}</span>
              {" / "}
              <span className="font-mono font-semibold text-foreground">{dsp.total}</span>
              {" utilisateurs"}
            </span>
            <span className="font-mono">{dspPct}%</span>
          </div>
          <p className="text-[11px] text-muted-foreground/80">
            Veuillez ne pas fermer l'application pendant la synchronisation.
          </p>
        </div>
      )}

      {/* Expiry warnings */}
      {s.loginWarning && s.loginDaysRemaining != null && s.loginDaysRemaining > 0 && (
        <Alert variant="warning">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Session expirante</AlertTitle>
          <AlertDescription>
            Votre session expire dans{" "}
            <strong>{s.loginDaysRemaining} jour{s.loginDaysRemaining > 1 ? "s" : ""}</strong>.{" "}
            Veuillez vous reconnecter.
          </AlertDescription>
        </Alert>
      )}
      {s.contractWarning && s.contractDaysRemaining != null && s.contractDaysRemaining > 0 && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Contrat en fin de validité</AlertTitle>
          <AlertDescription>
            Votre contrat expire dans{" "}
            <strong>{s.contractDaysRemaining} jour{s.contractDaysRemaining > 1 ? "s" : ""}</strong>.{" "}
            Contactez l'équipe MonClub pour renouveler.
          </AlertDescription>
        </Alert>
      )}

      {/* System status strip — no card, horizontal info row */}
      <div className="flex items-center gap-5 text-[12px] pb-4 border-b border-border/60">
        <div className="flex items-center gap-1.5">
          <StatusDot ok={agent.running} pulse />
          <span className="text-muted-foreground">Agent</span>
          <span className="font-medium">{agent.running ? "Actif" : "Arrêté"}</span>
        </div>

        <div className="h-3.5 w-px bg-border" />

        <div className="flex items-center gap-1.5">
          <StatusDot ok={sync.lastOk} />
          <span className="text-muted-foreground">Sync</span>
          <span className="font-mono font-medium">
            {sync.lastSyncAt ? sync.lastSyncAt.replace("T", " ").slice(0, 16) : "—"}
          </span>
        </div>

        <div className="h-3.5 w-px bg-border" />

        <div className="flex items-center gap-1.5">
          <StatusDot ok={status.pullsdk.connected} />
          <span className="text-muted-foreground">PullSDK</span>
          <span className="font-medium">
            {status.pullsdk.connected ? "Connecté" : "Non connecté"}
          </span>
        </div>

        <div className="h-3.5 w-px bg-border" />

        <div className="flex items-center gap-1 text-muted-foreground font-mono">
          <span className="text-foreground">{mode.DEVICE}</span>
          <span>D</span>
          <span className="mx-1 opacity-40">·</span>
          <span className="text-foreground">{mode.AGENT}</span>
          <span>A</span>
          {mode.UNKNOWN > 0 && (
            <>
              <span className="mx-1 opacity-40">·</span>
              <span className="text-amber-400">{mode.UNKNOWN}</span>
              <span>?</span>
            </>
          )}
        </div>

        <Button
          size="sm"
          variant="outline"
          className="ml-auto h-7 text-[12px] gap-1.5 px-3"
          onClick={syncNow}
          disabled={sync.running}
        >
          <RefreshCw className={cn("h-3 w-3", sync.running && "animate-spin")} />
          {sync.running ? "En cours…" : "Synchroniser"}
        </Button>
      </div>

      {/* Main grid — 3 columns, varying spans */}
      <div className="grid grid-cols-3 gap-4">

        {/* Agent — dominant, spans 2 columns */}
        <Panel
          className="col-span-2"
          title="Agent Temps Réel"
          icon={
            <Bot
              className={cn(
                "h-3.5 w-3.5",
                agent.running ? "text-emerald-400" : "text-amber-400",
              )}
            />
          }
        >
          <div className="flex items-start gap-10 mb-5">
            <div>
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1.5">
                File d'attente
              </div>
              <div className="text-3xl font-bold font-mono leading-none tabular-nums">
                {agent.eventQueueDepth}
              </div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1.5">
                Décision moy.
              </div>
              <div className="text-3xl font-bold font-mono leading-none tabular-nums">
                {agent.avgDecisionMs.toFixed(1)}
                <span className="text-sm font-normal text-muted-foreground ml-1.5">ms</span>
              </div>
            </div>
            <div className="ml-auto">
              <StatusChip
                variant={agent.running ? "online" : "offline"}
                label={agent.running ? "Actif" : "Arrêté"}
              />
            </div>
          </div>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              className="flex-1 h-8 text-[12px]"
              disabled={agent.running}
              onClick={() => post("/agent/start")}
            >
              <Play className="h-3 w-3" /> Démarrer
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="flex-1 h-8 text-[12px]"
              disabled={!agent.running}
              onClick={() => post("/agent/stop")}
            >
              <Square className="h-3 w-3" /> Arrêter
            </Button>
          </div>
        </Panel>

        {/* Session — right column */}
        <Panel
          title="Session"
          icon={<CheckCircle className="h-3.5 w-3.5 text-emerald-400" />}
        >
          <div className="space-y-[2px]">
            <Row
              label="Email"
              value={<span className="font-mono text-[12px]">{s.email}</span>}
            />
            <Row
              label="Dernière connexion"
              value={
                <span className="font-mono text-[12px]">
                  {s.lastLoginAt?.replace("T", " ").slice(0, 16) ?? "—"}
                </span>
              }
            />
            <Row
              label="Session"
              value={
                s.loginDaysRemaining != null ? (
                  <Badge
                    className={
                      s.loginWarning
                        ? "border-amber-500/30 bg-amber-500/10 text-amber-400 text-[11px]"
                        : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-[11px]"
                    }
                  >
                    {s.loginDaysRemaining}j
                  </Badge>
                ) : (
                  "—"
                )
              }
            />
            <Row
              label="Contrat"
              value={
                <Badge
                  className={
                    s.contractStatus
                      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-[11px]"
                      : "border-red-500/30 bg-red-500/10 text-red-400 text-[11px]"
                  }
                >
                  {s.contractStatus ? "Actif" : "Inactif"}
                </Badge>
              }
            />
            {s.contractEndDate && (
              <Row
                label="Échéance"
                value={
                  <span className="font-mono text-[12px]">{s.contractEndDate}</span>
                }
              />
            )}
          </div>
        </Panel>

        {/* Sync */}
        <Panel
          title="Synchronisation"
          icon={<RefreshCw className="h-3.5 w-3.5 text-primary" />}
        >
          <div className="space-y-[2px]">
            <Row
              label="Statut"
              value={
                <StatusChip
                  variant={sync.running ? "syncing" : sync.lastOk ? "online" : "error"}
                  label={sync.running ? "En cours" : sync.lastOk ? "OK" : "Échoué"}
                />
              }
            />
            <Row
              label="Dernière sync"
              value={
                <span className="font-mono text-[12px]">
                  {sync.lastSyncAt?.replace("T", " ").slice(0, 16) ?? "Jamais"}
                </span>
              }
            />
          </div>
        </Panel>

        {/* PullSDK */}
        <Panel
          title="PullSDK"
          icon={<Users className="h-3.5 w-3.5 text-primary" />}
        >
          <div className="space-y-[2px]">
            <Row
              label="Connecté"
              value={
                <StatusChip
                  variant={status.pullsdk.connected ? "online" : "offline"}
                  label={status.pullsdk.connected ? "Oui" : "Non"}
                />
              }
            />
            {status.pullsdk.deviceId && (
              <Row
                label="Appareil"
                value={
                  <span className="font-mono text-[12px]">#{status.pullsdk.deviceId}</span>
                }
              />
            )}
            {status.pullsdk.ip && (
              <Row
                label="IP"
                value={
                  <span className="font-mono text-[12px]">{status.pullsdk.ip}</span>
                }
              />
            )}
          </div>
        </Panel>

        {/* Notification Screen */}
        <Panel
          title="Écran Notification"
          icon={<Monitor className="h-3.5 w-3.5 text-primary" />}
        >
          <p className="text-[12px] text-muted-foreground mb-3 leading-relaxed">
            Ouvrez l'écran pour afficher les accès en temps réel.
          </p>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              className="flex-1 h-8 text-[12px]"
              onClick={openPopupWindow}
            >
              <Monitor className="h-3 w-3" /> Ouvrir
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-8 text-[12px]"
              onClick={sendTestNotification}
            >
              <Bug className="h-3 w-3" /> Test
            </Button>
          </div>
        </Panel>

        {/* Appareils */}
        <Panel
          title="Appareils"
          icon={<Router className="h-3.5 w-3.5 text-primary" />}
        >
          <div className="flex gap-6">
            <div>
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1">
                Device
              </div>
              <div className="text-2xl font-bold font-mono tabular-nums">{mode.DEVICE}</div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1">
                Agent
              </div>
              <div className="text-2xl font-bold font-mono tabular-nums">{mode.AGENT}</div>
            </div>
            {mode.UNKNOWN > 0 && (
              <div>
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1">
                  Inconnu
                </div>
                <div className="text-2xl font-bold font-mono tabular-nums text-amber-400">
                  {mode.UNKNOWN}
                </div>
              </div>
            )}
          </div>
        </Panel>

      </div>
    </div>
  );
}
