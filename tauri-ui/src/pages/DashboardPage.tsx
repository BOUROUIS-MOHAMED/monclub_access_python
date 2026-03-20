import { useApp } from "@/context/AppContext";
import { usePopupStream } from "@/api/hooks";
import { post } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import StatusChip from "@/components/StatusChip2";
import {
  RefreshCw, Router, Bot, Users, CheckCircle, Monitor,
  Bug, AlertTriangle, Play, Square,
} from "lucide-react";

function Section({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-border bg-card overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
        {icon}
        <span className="text-[13px] font-semibold text-foreground">{title}</span>
      </div>
      <div className="px-4 py-3 space-y-2 text-[13px]">{children}</div>
    </div>
  );
}

function KV({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-0.5">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right text-foreground">{value ?? "—"}</span>
    </div>
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

  return (
    <div className="space-y-4">
      {/* Expiry warnings */}
      {s.loginWarning && s.loginDaysRemaining != null && s.loginDaysRemaining > 0 && (
        <Alert variant="warning">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Session expirante</AlertTitle>
          <AlertDescription>
            Votre session expire dans <strong>{s.loginDaysRemaining} jour{s.loginDaysRemaining > 1 ? "s" : ""}</strong>. Veuillez vous reconnecter.
          </AlertDescription>
        </Alert>
      )}
      {s.contractWarning && s.contractDaysRemaining != null && s.contractDaysRemaining > 0 && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Contrat en fin de validité</AlertTitle>
          <AlertDescription>
            Votre contrat expire dans <strong>{s.contractDaysRemaining} jour{s.contractDaysRemaining > 1 ? "s" : ""}</strong>. Contactez l'équipe MonClub pour renouveler.
          </AlertDescription>
        </Alert>
      )}

      {/* Overview stat row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {[
          { label: "Mode global", value: mode.globalMode, accent: false },
          { label: "Mode DEVICE", value: String(mode.summary.DEVICE), accent: false },
          { label: "Mode AGENT", value: String(mode.summary.AGENT), accent: false },
          { label: "Dernière sync", value: sync.lastSyncAt ? sync.lastSyncAt.replace("T", " ").substring(0, 16) : "Jamais", accent: false },
        ].map(({ label, value }) => (
          <div key={label} className="rounded-lg border border-border bg-muted/40 px-4 py-3">
            <div className="text-[11px] uppercase tracking-widest text-muted-foreground font-medium">{label}</div>
            <div className="mt-2 text-sm font-semibold text-foreground">{value}</div>
          </div>
        ))}
      </div>

      {/* Cards grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        {/* Session */}
        <Section title="Session" icon={<CheckCircle className="h-4 w-4 text-emerald-400" />}>
          <KV label="Email" value={s.email} />
          <KV label="Dernière connexion" value={s.lastLoginAt?.replace("T", " ") ?? "—"} />
          <KV label="Session" value={
            s.loginDaysRemaining != null ? (
              <Badge className={s.loginWarning
                ? "border-amber-500/30 bg-amber-500/10 text-amber-400 text-[11px]"
                : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-[11px]"
              }>
                {s.loginDaysRemaining}j
              </Badge>
            ) : "—"
          } />
          <KV label="Contrat" value={
            <Badge className={s.contractStatus
              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-[11px]"
              : "border-red-500/30 bg-red-500/10 text-red-400 text-[11px]"
            }>
              {s.contractStatus ? "Actif" : "Inactif"}
            </Badge>
          } />
          {s.contractEndDate && <KV label="Fin contrat" value={s.contractEndDate} />}
        </Section>

        {/* Appareils */}
        <Section title="Appareils" icon={<Router className="h-4 w-4 text-primary" />}>
          <KV label="Mode global" value={<Badge variant="outline" className="text-[11px]">{mode.globalMode}</Badge>} />
          <KV label="Mode DEVICE" value={mode.summary.DEVICE} />
          <KV label="Mode AGENT" value={mode.summary.AGENT} />
          {mode.summary.UNKNOWN > 0 && <KV label="Inconnu" value={mode.summary.UNKNOWN} />}
        </Section>

        {/* Sync */}
        <Section title="Synchronisation" icon={<RefreshCw className="h-4 w-4 text-primary" />}>
          <KV label="Statut" value={
            <StatusChip variant={sync.running ? "syncing" : sync.lastOk ? "online" : "error"}
              label={sync.running ? "En cours" : sync.lastOk ? "OK" : "Échoué"} />
          } />
          <KV label="Dernière sync" value={sync.lastSyncAt?.replace("T", " ") ?? "Jamais"} />
          <Separator className="my-1" />
          <Button size="sm" variant="outline" className="w-full h-8 text-[13px]" onClick={syncNow} disabled={sync.running}>
            <RefreshCw className="h-3.5 w-3.5" /> Synchroniser
          </Button>
        </Section>

        {/* Agent */}
        <Section title="Agent Temps Réel" icon={<Bot className={`h-4 w-4 ${agent.running ? "text-emerald-400" : "text-amber-400"}`} />}>
          <KV label="Statut" value={
            <StatusChip variant={agent.running ? "online" : "offline"} label={agent.running ? "Actif" : "Arrêté"} />
          } />
          <KV label="File d'attente" value={agent.eventQueueDepth} />
          <KV label="Décision moy." value={`${agent.avgDecisionMs.toFixed(1)} ms`} />
          <Separator className="my-1" />
          <div className="flex gap-2">
            <Button size="sm" variant="outline" className="flex-1 h-8 text-[13px]" disabled={agent.running} onClick={() => post("/agent/start")}>
              <Play className="h-3.5 w-3.5" /> Start
            </Button>
            <Button size="sm" variant="outline" className="flex-1 h-8 text-[13px]" disabled={!agent.running} onClick={() => post("/agent/stop")}>
              <Square className="h-3.5 w-3.5" /> Stop
            </Button>
          </div>
        </Section>

        {/* PullSDK */}
        <Section title="PullSDK" icon={<Users className="h-4 w-4 text-primary" />}>
          <KV label="Connecté" value={
            <StatusChip variant={status.pullsdk.connected ? "online" : "offline"} label={status.pullsdk.connected ? "Oui" : "Non"} />
          } />
          {status.pullsdk.deviceId && <KV label="Appareil" value={`#${status.pullsdk.deviceId}`} />}
          {status.pullsdk.ip && <KV label="IP" value={status.pullsdk.ip} />}
        </Section>

        {/* Notification screen */}
        <Section title="Écran Notification" icon={<Monitor className="h-4 w-4 text-primary" />}>
          <p className="text-muted-foreground text-[12px] mb-2">Ouvrez l'écran de notification pour afficher les accès en temps réel.</p>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" className="flex-1 h-8 text-[13px]" onClick={openPopupWindow}>
              <Monitor className="h-3.5 w-3.5" /> Ouvrir
            </Button>
            <Button size="sm" variant="outline" className="h-8 text-[13px]" onClick={sendTestNotification}>
              <Bug className="h-3.5 w-3.5" /> Test
            </Button>
          </div>
        </Section>
      </div>
    </div>
  );
}
