// Mise à jour — Access v5 redesign (docs/access-redesign-v5: `tp === 'update'`
// in main.logic.js, board S25), translated to French.
//
// Same calls and polling as before: /update/status every 3 s, /update/version
// once, and the check / download / install / cancel actions. A server rollback
// arrives as an offer (`status.rollback`), titled "Retour à une version
// précédente". « Revenir à la version précédente » (Card B) is the other way
// back: POST /update/rollback puts back the previous\ folder Setup kept, shown
// only when `status.localRollback.available` (shared/update_runtime.py).

import { useCallback, useEffect, useRef, useState } from "react";
import {
  getAccessUpdateStatus,
  checkAccessUpdate,
  downloadAccessUpdate,
  installAccessUpdate,
  cancelAccessUpdate,
  getAccessVersionInfo,
  rollbackAccessUpdate,
} from "@/api/accessUpdate";
import { ApiError } from "@/api/client";
import type { UpdateStatusResponse, UpdateVersionInfoResponse } from "@/api/types";
import { usePageChrome } from "@/context/PageChromeContext";
import { ActionButton } from "@/components/ui/action-button";
import { ToneIcon } from "@/components/ui/chip";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { KpiCard, KpiRow } from "@/components/ui/kpi-card";
import { DashedRule, ListRow, Note, PageGrid, Panel, PanelHeader, PanelList } from "@/components/ui/panel";
import {
  CircleCheck,
  Download,
  Info,
  Loader2,
  Power,
  RefreshCw,
  ScrollText,
  Trash2,
  Undo2,
} from "lucide-react";
import ReleaseNotes from "@/components/update/ReleaseNotes";
import UpdateNoticesFr from "@/components/update/UpdateNoticesFr";

function formatBytes(bytes: number | null | undefined): string {
  if (!bytes) return "—";
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1).replace(".", ",")} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(1).replace(".", ",")} Mo`;
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString("fr-FR", {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}

// POST /update/rollback refusal codes (shared/update_runtime.py RollbackRefused).
const ROLLBACK_ERRORS: Record<string, string> = {
  changed: "les versions ont changé depuis l'ouverture de cette fenêtre ; rechargez la page",
  busy: "une installation est déjà en train de démarrer",
  setup_running: "un installateur MonClub Access est en cours",
  journal_present: "une installation ou une restauration est en cours",
  update_in_progress: "une mise à jour est en cours",
  launch_failed: "le programme de restauration n'a pas démarré",
  no_previous: "la version précédente n'est plus complète sur ce poste",
  previous_not_older: "la version gardée n'est pas plus ancienne que celle en service",
  previous_too_old: "la version gardée est trop ancienne pour ce retour",
  helper_missing: "le programme de restauration installé est introuvable",
};

function rollbackErrorText(e: unknown): string {
  const code = e instanceof ApiError ? e.code : null;
  if (code && ROLLBACK_ERRORS[code]) return ROLLBACK_ERRORS[code];
  return e instanceof Error && e.message ? e.message : "erreur inconnue";
}

function withCodename(version: string, codename?: string | null): string {
  return codename ? `${version} « ${codename} »` : version;
}

export default function UpdatePage() {
  const [status, setStatus] = useState<UpdateStatusResponse | null>(null);
  const [versionInfo, setVersionInfo] = useState<UpdateVersionInfoResponse | null>(null);
  const [checking, setChecking] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [installError, setInstallError] = useState<string | null>(null);
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const [rollbackBusy, setRollbackBusy] = useState(false);
  const [rollbackStarted, setRollbackStarted] = useState(false);
  const [rollbackError, setRollbackError] = useState<string | null>(null);
  // The versions the dialog names, frozen when it opens: the server refuses if they changed since.
  const [rollbackTarget, setRollbackTarget] = useState<{ previousVersion: string; currentVersion: string } | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const s = await getAccessUpdateStatus();
      setStatus(s);
    } catch {
      // silent
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    getAccessVersionInfo().then(setVersionInfo).catch(() => {});
    pollRef.current = setInterval(fetchStatus, 3000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [fetchStatus]);

  const handleCheck = useCallback(async () => {
    setChecking(true);
    try {
      await checkAccessUpdate();
      await fetchStatus();
    } catch {
      // silent
    } finally {
      setChecking(false);
    }
  }, [fetchStatus]);

  const handleDownload = async () => {
    setDownloading(true);
    try {
      await downloadAccessUpdate();
    } catch {
      // silent
    } finally {
      setDownloading(false);
    }
  };

  const handleInstall = async () => {
    setInstalling(true);
    setInstallError(null);
    try {
      // Answers OK only once the installer really started; the app then restarts.
      await installAccessUpdate();
    } catch (e) {
      // The app keeps running: show why (updater v2, D1).
      setInstallError(e instanceof Error && e.message ? e.message : "erreur inconnue");
      setInstalling(false);
      await fetchStatus();
    }
  };

  const openRollback = () => {
    const lr = status?.localRollback;
    if (!lr?.available || !lr.previousVersion || !lr.currentVersion) return;
    setRollbackTarget({ previousVersion: lr.previousVersion, currentVersion: lr.currentVersion });
    setRollbackError(null);
    setRollbackStarted(false);
    setRollbackOpen(true);
  };

  const handleRollback = async () => {
    if (!rollbackTarget) return;
    setRollbackBusy(true);
    setRollbackError(null);
    try {
      // Answers OK only once the restore helper runs; the app then quits and restarts.
      await rollbackAccessUpdate(rollbackTarget);
      setRollbackStarted(true);
    } catch (e) {
      // Nothing changed and the app keeps running.
      setRollbackError(rollbackErrorText(e));
      await fetchStatus();
    } finally {
      setRollbackBusy(false);
    }
  };

  const handleCancel = async () => {
    setCancelling(true);
    try {
      await cancelAccessUpdate();
      await fetchStatus();
    } catch {
      // silent
    } finally {
      setCancelling(false);
    }
  };

  usePageChrome(() => ({
    subtitle: "Logiciel et notes de version",
    actions: (
      <ActionButton kind="outline" icon={checking ? Loader2 : RefreshCw} spin={checking} onClick={() => { void handleCheck(); }} disabled={checking}>
        Rechercher une mise à jour
      </ActionButton>
    ),
  }), [checking, handleCheck]);

  const curVersion = status?.currentVersion ?? versionInfo?.currentVersion ?? "0.0.0";
  const curCodename = status?.currentCodename ?? versionInfo?.currentCodename ?? "";
  const isDownloading = status?.downloading ?? false;
  const progress = status?.progressPercent ?? null;
  const updateAvailable = status?.updateAvailable ?? false;
  const channelPlatform = [
    status?.channel ? `canal ${status.channel}` : "",
    status?.platform ? status.platform : "",
  ].filter(Boolean).join(" · ");
  const lastCheck = status?.lastCheckAt ? new Date(status.lastCheckAt * 1000).toLocaleTimeString("fr-FR") : null;

  // Third KPI: the download state of the offered version.
  const dl = !updateAvailable
    ? { value: "—", sub: "aucune mise à jour", tone: "grey" as const, subTone: undefined }
    : isDownloading
      ? { value: progress != null ? `${progress} %` : "…", sub: "en cours", tone: "primary" as const, subTone: "primary" as const }
      : status?.downloaded
        ? { value: "100 %", sub: "prête à installer", tone: "success" as const, subTone: "success" as const }
        : { value: "—", sub: "pas encore téléchargée", tone: "grey" as const, subTone: undefined };

  const publishedBits = [
    status?.releaseDate ? `Publiée le ${formatDate(status.releaseDate)}` : "",
    status?.sizeBytes ? `taille ${formatBytes(status.sizeBytes)}` : "",
    status?.availableUntil ? `disponible jusqu'au ${formatDate(status.availableUntil)}` : "",
  ].filter(Boolean).join(" · ");

  return (
    <div className="flex flex-col gap-[18px]">
      <KpiRow cols={3}>
        <KpiCard
          label="Version installée"
          value={withCodename(curVersion, curCodename)}
          sub={channelPlatform || undefined}
          icon={Info}
          tone="grey"
        />
        <KpiCard
          label="Dernière version"
          value={updateAvailable && status?.latestVersion ? withCodename(status.latestVersion, status.latestCodename) : withCodename(curVersion, curCodename)}
          sub={updateAvailable ? (status?.rollback ? "retour à une version précédente" : "mise à jour disponible") : "à jour"}
          subTone={updateAvailable ? "primary" : "success"}
          icon={Download}
          tone="primary"
        />
        <KpiCard label="Téléchargement" value={dl.value} sub={dl.sub} subTone={dl.subTone} icon={CircleCheck} tone={dl.tone} />
      </KpiRow>

      <UpdateNoticesFr status={status} installError={installError} />

      <PageGrid>
        {updateAvailable && status ? (
          <Panel className="col-span-8" aria-label="Mise à jour disponible">
            <PanelHeader
              title={`${status.rollback ? "Retour à une version précédente — " : ""}MonClub Access ${status.latestVersion ? withCodename(status.latestVersion, status.latestCodename) : ""}`.trim()}
              sub={publishedBits || undefined}
            />
            <PanelList>
              {status.releaseNotes && (
                <div className="-mx-2.5 flex gap-3 rounded-xl p-2.5">
                  <ToneIcon icon={ScrollText} tone="grey" />
                  <div className="min-w-0 flex-1">
                    <div className="text-[13.5px] font-semibold">Notes de version</div>
                    <ReleaseNotes
                      className="mt-1 text-[12.5px] leading-[1.55] text-muted-foreground [&_h1]:text-[13.5px] [&_h1]:font-semibold [&_h2]:text-[13px] [&_h2]:font-semibold [&_h3]:text-[13px] [&_h3]:font-semibold [&_li]:my-0.5 [&_p]:my-1 [&_ul]:list-disc [&_ul]:pl-4 [&_ol]:list-decimal [&_ol]:pl-4"
                      html={status.releaseNotes}
                    />
                  </div>
                </div>
              )}
              <ListRow
                icon={Power}
                tone="primary"
                title="Installer"
                sub="L'application redémarre : à faire quand le club est fermé."
                wrap
                bar={isDownloading && progress !== null ? progress : undefined}
                actions={
                  isDownloading ? (
                    <span className="inline-flex items-center gap-2 text-[12.5px] text-muted-foreground">
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      {progress !== null ? `Téléchargement de la mise à jour… ${progress} %` : "Téléchargement…"}
                    </span>
                  ) : !status.downloaded ? (
                    <ActionButton kind="primary" size="sm" icon={downloading ? Loader2 : Download} spin={downloading} onClick={handleDownload} disabled={downloading}>
                      Télécharger la mise à jour
                    </ActionButton>
                  ) : (
                    <>
                      <ActionButton kind="primary" size="sm" icon={installing ? Loader2 : Download} spin={installing} onClick={handleInstall} disabled={installing}>
                        Redémarrer et installer
                      </ActionButton>
                      <ActionButton kind="ghost" size="sm" icon={cancelling ? Loader2 : Trash2} spin={cancelling} onClick={handleCancel} disabled={cancelling}>
                        Supprimer le fichier téléchargé
                      </ActionButton>
                    </>
                  )
                }
              />
            </PanelList>
          </Panel>
        ) : status ? (
          <Panel className="col-span-8" aria-label="Vous êtes à jour">
            <div className="flex items-center gap-3.5 px-[18px] py-5">
              <ToneIcon icon={CircleCheck} tone="success" size={44} />
              <div className="min-w-0">
                <div className="text-[16px] font-bold">Vous êtes à jour</div>
                <div className="text-[13px] text-muted-foreground">
                  MonClub Access {withCodename(curVersion, curCodename)} est la dernière version.
                </div>
              </div>
            </div>
          </Panel>
        ) : (
          <Panel className="col-span-8" aria-label="Chargement">
            <div className="px-[18px] py-5 text-[13px] text-muted-foreground">Chargement…</div>
          </Panel>
        )}

        <div className="col-span-4 flex flex-col gap-[18px]">
          <Panel aria-label="Ce poste">
            <PanelHeader title="Ce poste" />
            <PanelList>
              <ListRow title="Composant" value={status?.componentDisplayName || versionInfo?.componentDisplayName || "MonClub Access"} />
              <DashedRule />
              <ListRow title="Canal" value={status?.channel || "—"} />
              <DashedRule />
              <ListRow title="Plateforme" value={status?.platform || "—"} />
              <DashedRule />
              <ListRow title="Dernière vérification" value={lastCheck ?? "—"} />
            </PanelList>
          </Panel>

          {status?.localRollback?.available && status.localRollback.previousVersion ? (
            <Panel aria-label="Revenir en arrière">
              <PanelHeader title="Revenir en arrière" />
              <PanelList>
                <ListRow
                  icon={Undo2}
                  tone="grey"
                  title="Version précédente"
                  sub={`Réinstalle la version ${status.localRollback.previousVersion}, gardée sur ce poste par la dernière mise à jour.`}
                  wrap
                  actions={
                    <ActionButton kind="outline" size="sm" icon={Undo2} onClick={openRollback} disabled={installing || !!status.installing}>
                      Revenir à la version précédente
                    </ActionButton>
                  }
                />
              </PanelList>
            </Panel>
          ) : null}
        </div>
      </PageGrid>

      {rollbackTarget && (
        <ConfirmDialog
          open={rollbackOpen}
          onOpenChange={(open) => { if (!rollbackBusy && !rollbackStarted) setRollbackOpen(open); }}
          title={`Revenir à la version ${rollbackTarget.previousVersion} ?`}
          description={`MonClub Access ${rollbackTarget.currentVersion} sera remplacé par la version ${rollbackTarget.previousVersion}.`}
          confirmLabel={rollbackStarted ? "Redémarrage…" : `Revenir à la ${rollbackTarget.previousVersion}`}
          confirmKind="danger"
          confirmDisabled={rollbackBusy || rollbackStarted}
          onConfirm={() => { void handleRollback(); }}
        >
          <div className="flex flex-col gap-2">
            <Note tone="warning">
              L'application se ferme puis redémarre sur la version {rollbackTarget.previousVersion} : les tourniquets sont
              en pause pendant ce temps. À faire quand le club est fermé.
            </Note>
            <Note tone="grey">
              La version {rollbackTarget.currentVersion} ne sera plus installée automatiquement ; « Redémarrer et installer »
              pourra toujours la réinstaller. Une version plus récente s'installera normalement.
            </Note>
            {rollbackStarted && (
              <Note tone="info">
                Restauration lancée : l'application va se fermer puis redémarrer sur la version {rollbackTarget.previousVersion}.
              </Note>
            )}
            {rollbackError && (
              <Note tone="error">Le retour n'a pas démarré : {rollbackError}. L'application continue de fonctionner.</Note>
            )}
          </div>
        </ConfirmDialog>
      )}
    </div>
  );
}
