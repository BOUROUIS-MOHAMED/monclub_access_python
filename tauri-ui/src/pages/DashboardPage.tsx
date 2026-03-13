import { useApp } from "@/context/AppContext";
import { usePopupStream } from "@/api/hooks";
import { post } from "@/api/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import StatusChip from "@/components/StatusChip2";
import {
  RefreshCw, Router, Bot, Users, CheckCircle, Monitor,
  Bug, AlertTriangle, Play, Square,
} from "lucide-react";

function InfoCard({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm font-semibold">
          {icon}
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">{children}</CardContent>
    </Card>
  );
}

function KV({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-0.5">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right">{value ?? "—"}</span>
    </div>
  );
}

export default function DashboardPage() {
  const { status, syncNow } = useApp();
  const { openPopupWindow, sendTestNotification } = usePopupStream();

  if (!status) return <p className="text-muted-foreground">Chargement…</p>;

  const s = status.session;
  const mode = status.mode;
  const sync = status.sync;
  const agent = status.agent;

  return (
    <div className="space-y-6">
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
            Votre contrat expire dans <strong>{s.contractDaysRemaining} jour{s.contractDaysRemaining > 1 ? "s" : ""}</strong>.
            Contactez l'équipe MonClub pour renouveler.
          </AlertDescription>
        </Alert>
      )}

      {/* Cards grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {/* Session */}
        <InfoCard title="Session" icon={<CheckCircle className="h-4 w-4 text-emerald-500" />}>
          <KV label="Email" value={s.email} />
          <KV label="Dernière connexion" value={s.lastLoginAt?.replace("T", " ") ?? "—"} />
          <KV label="Session expire dans" value={
            s.loginDaysRemaining != null ? (
              <Badge variant={s.loginWarning ? "warning" : "success"} className="text-xs">
                {s.loginDaysRemaining}j
              </Badge>
            ) : "—"
          } />
          <KV label="Contrat" value={
            <Badge variant={s.contractStatus ? "success" : "destructive"} className="text-xs">
              {s.contractStatus ? "Actif" : "Inactif"}
            </Badge>
          } />
          {s.contractEndDate && <KV label="Fin contrat" value={s.contractEndDate} />}
        </InfoCard>

        {/* Devices mode */}
        <InfoCard title="Appareils" icon={<Router className="h-4 w-4 text-primary" />}>
          <KV label="Mode global" value={<Badge variant="outline" className="text-xs">{mode.globalMode}</Badge>} />
          <KV label="Mode DEVICE" value={mode.summary.DEVICE} />
          <KV label="Mode AGENT" value={mode.summary.AGENT} />
          {mode.summary.UNKNOWN > 0 && <KV label="Inconnu" value={mode.summary.UNKNOWN} />}
        </InfoCard>

        {/* Sync */}
        <InfoCard title="Synchronisation" icon={<RefreshCw className="h-4 w-4 text-sky-500" />}>
          <KV label="Statut" value={
            <StatusChip variant={sync.running ? "syncing" : sync.lastOk ? "online" : "error"}
              label={sync.running ? "En cours" : sync.lastOk ? "OK" : "Échoué"} />
          } />
          <KV label="Dernière sync" value={sync.lastSyncAt?.replace("T", " ") ?? "Jamais"} />
          <Separator className="my-1" />
          <Button size="sm" variant="outline" className="w-full" onClick={syncNow} disabled={sync.running}>
            <RefreshCw className="h-3.5 w-3.5" /> Synchroniser
          </Button>
        </InfoCard>

        {/* Agent */}
        <InfoCard title="Agent Temps Réel" icon={<Bot className={`h-4 w-4 ${agent.running ? "text-emerald-500" : "text-amber-500"}`} />}>
          <KV label="Statut" value={
            <StatusChip variant={agent.running ? "online" : "offline"} label={agent.running ? "Actif" : "Arrêté"} />
          } />
          <KV label="File d'attente" value={agent.eventQueueDepth} />
          <KV label="Décision moy." value={`${agent.avgDecisionMs.toFixed(1)} ms`} />
          <Separator className="my-1" />
          <div className="flex gap-2">
            <Button size="sm" variant="outline" className="flex-1" disabled={agent.running} onClick={() => post("/agent/start")}>
              <Play className="h-3.5 w-3.5" /> Start
            </Button>
            <Button size="sm" variant="outline" className="flex-1" disabled={!agent.running} onClick={() => post("/agent/stop")}>
              <Square className="h-3.5 w-3.5" /> Stop
            </Button>
          </div>
        </InfoCard>

        {/* PullSDK */}
        <InfoCard title="PullSDK" icon={<Users className="h-4 w-4 text-purple-500" />}>
          <KV label="Connecté" value={
            <StatusChip variant={status.pullsdk.connected ? "online" : "offline"} label={status.pullsdk.connected ? "Oui" : "Non"} />
          } />
          {status.pullsdk.deviceId && <KV label="Appareil" value={`#${status.pullsdk.deviceId}`} />}
          {status.pullsdk.ip && <KV label="IP" value={status.pullsdk.ip} />}
        </InfoCard>

        {/* Notification screen */}
        <InfoCard title="Écran Notification" icon={<Monitor className="h-4 w-4 text-sky-500" />}>
          <p className="text-muted-foreground text-xs mb-2">Ouvrez l'écran de notification pour afficher les accès en temps réel.</p>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" className="flex-1" onClick={openPopupWindow}>
              <Monitor className="h-3.5 w-3.5" /> Ouvrir
            </Button>
            <Button size="sm" variant="outline" onClick={sendTestNotification}>
              <Bug className="h-3.5 w-3.5" /> Test
            </Button>
          </div>
        </InfoCard>
      </div>
    </div>
  );
}
