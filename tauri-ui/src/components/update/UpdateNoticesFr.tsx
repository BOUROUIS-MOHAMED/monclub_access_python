// French copy of UpdateNotices for the Access app (v5 redesign: the Mise à jour
// page is in French). Same conditions, same data, one-to-one with
// UpdateNotices.tsx — which stays English because the TV build uses it.
// Keep both in step when the updater adds a result or a reason.
import { AlertCircle, CheckCircle2, ShieldAlert, Undo2 } from "lucide-react";
import type { UpdateLastResult, UpdateStatusResponse } from "@/api/types";
import { Note } from "@/components/ui/panel";

const REASONS: Record<string, string> = {
  crash: "la nouvelle version s'est arrêtée juste après son démarrage",
  health_timeout: "la nouvelle version n'a pas fini de démarrer à temps",
  interrupted: "l'installation a été interrompue (coupure de courant ou redémarrage)",
  backup_failed: "la version actuelle n'a pas pu être sauvegardée",
  setup_failed: "l'installateur a échoué",
  restore_failed: "la version précédente n'a pas pu être entièrement restaurée",
  same_version: "cette version était déjà installée",
  no_result: "l'installateur n'a renvoyé aucun résultat",
};

function reasonText(reason: string | null | undefined): string {
  if (!reason) return "";
  if (reason.startsWith("setup_exit_")) return `l'installateur s'est arrêté (code ${reason.slice("setup_exit_".length)})`;
  return REASONS[reason] ?? reason;
}

function formatWhen(at: string | null | undefined): string {
  if (!at) return "";
  const d = new Date(at);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString("fr-FR");
}

function Line({ icon: Icon, children }: { icon: typeof AlertCircle; children: React.ReactNode }) {
  return (
    <span className="flex items-start gap-2">
      <Icon className="mt-0.5 h-4 w-4 shrink-0" />
      <span>{children}</span>
    </span>
  );
}

function LastResult({ result }: { result: UpdateLastResult }) {
  const when = formatWhen(result.at);
  if (result.result === "INSTALLED") {
    return (
      <Note tone="success">
        <Line icon={CheckCircle2}>
          Dernière mise à jour : {result.from || "?"} → {result.to || "?"} installée{when ? ` (${when})` : ""}.
        </Line>
      </Note>
    );
  }
  const rolledBack = result.result === "ROLLED_BACK";
  return (
    <Note tone="warning">
      <Line icon={rolledBack ? Undo2 : AlertCircle}>
        La mise à jour vers {result.to || "?"} {rolledBack ? "a été annulée" : "ne s'est pas installée"}
        {result.reason ? ` : ${reasonText(result.reason)}` : ""}. La version {result.installedNow || result.from || "?"} est en service
        {when ? ` (${when})` : ""}.
      </Line>
    </Note>
  );
}

/** The installer's last result, a refused (unsigned / tampered) offer, the loop-guard
 *  warning and the last install error. */
export default function UpdateNoticesFr({ status, installError }: { status: UpdateStatusResponse | null; installError: string | null }) {
  if (!status && !installError) return null;
  const items = [
    status?.lastResult ? <LastResult key="last" result={status.lastResult} /> : null,
    status?.verifyError ? (
      <Note key="verify" tone="error">
        <Line icon={ShieldAlert}>
          Mise à jour {status.latestVersion ?? ""} refusée : ce n'est pas une version MonClub vérifiée ({status.verifyError}).
        </Line>
      </Note>
    ) : null,
    status?.updateAvailable && status.autoInstallBlocked ? (
      <Note key="blocked" tone="warning">
        <Line icon={AlertCircle}>
          La version {status.latestVersion} a déjà échoué ({reasonText(status.autoInstallBlockedReason)}) et ne sera plus
          installée automatiquement. « Redémarrer et installer » la tente quand même — la version précédente revient en cas d'échec.
        </Line>
      </Note>
    ) : null,
    installError ? (
      <Note key="error" tone="error">
        <Line icon={AlertCircle}>La mise à jour n'a pas démarré : {installError}. L'application continue de fonctionner.</Line>
      </Note>
    ) : null,
  ].filter(Boolean);
  if (items.length === 0) return null;
  return <div className="flex flex-col gap-2">{items}</div>;
}
