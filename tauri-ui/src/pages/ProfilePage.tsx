// Profil — Access v3, from `Access v3 - Partie 3 Compte et dialogues.dc.html`
// (screen 08). The account card is the subject; the rail carries the session
// countdown, the contract, and the log-out action.
//
// Everything rendered here comes from the /status snapshot the app already
// polls (session / mode / sync / pullsdk / updates / deviceSync). Two lines the
// design shows are NOT rendered because no data source exists for them:
//   · "3 / 4 en ligne" — there is no per-device reachability field anywhere in
//     the device payload (see DevicesPage for the full note); the row shows the
//     declared fleet and this app's PullSDK session instead.
//   · a member count — /status carries none, and this page does not fetch the
//     roster. The row states the capability without inventing a number.

import { useEffect, useState } from "react";
import { useApp } from "@/context/AppContext";
import { usePageChrome } from "@/context/PageChromeContext";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import {
  AlertTriangle, LogOut, Router, Users, Database, RefreshCw, Clock,
  FileText, LifeBuoy, LogIn,
} from "lucide-react";

// Same key LocalDbPage writes its unlock lease under — read-only here so the
// profile can state whether the local database is currently open.
const LOCALDB_UNLOCK_KEY = "monclub:localdb-unlock";

const MONTHS_FR = [
  "janvier", "février", "mars", "avril", "mai", "juin",
  "juillet", "août", "septembre", "octobre", "novembre", "décembre",
];

function frDateTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const h = String(d.getHours()).padStart(2, "0");
  const m = String(d.getMinutes()).padStart(2, "0");
  return `${d.getDate()} ${MONTHS_FR[d.getMonth()]} · ${h}:${m}`;
}

function frDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return `${d.getDate()} ${MONTHS_FR[d.getMonth()]} ${d.getFullYear()}`;
}

function Chip({ tone, children }: { tone: "ok" | "no" | "wn" | "flat"; children: React.ReactNode }) {
  const tones = {
    ok: "bg-emerald-500/[0.055] text-emerald-700 dark:text-emerald-400",
    no: "bg-primary/[0.09] text-primary",
    wn: "bg-amber-500/[0.14] text-amber-700 dark:text-amber-400",
    flat: "bg-muted text-muted-foreground",
  } as const;
  return (
    <span className={cn("inline-flex h-[22px] shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg px-2 text-[11px] font-bold", tones[tone])}>
      {children}
    </span>
  );
}

function AccessRow({ icon: Icon, title, sub, chip, last }: {
  icon: typeof Router; title: string; sub: string; chip: React.ReactNode; last?: boolean;
}) {
  return (
    <div className={cn("flex items-center gap-3.5 py-3", !last && "border-b border-border/60")}>
      <span className="flex h-[34px] w-[34px] shrink-0 items-center justify-center rounded-[18px] bg-muted text-muted-foreground">
        <Icon className="h-[18px] w-[18px]" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="truncate text-[13.5px] font-semibold text-foreground">{title}</div>
        <div className="truncate text-[11.5px] text-muted-foreground">{sub}</div>
      </div>
      {chip}
    </div>
  );
}

export default function ProfilePage() {
  const { status, logout } = useApp();
  const [logoutConfirm, setLogoutConfirm] = useState(false);

  // Live local-DB lock state (LocalDbPage keeps a 5-minute sessionStorage lease).
  const [dbUnlocked, setDbUnlocked] = useState(false);
  useEffect(() => {
    const read = () => {
      try {
        const raw = sessionStorage.getItem(LOCALDB_UNLOCK_KEY);
        if (!raw) return setDbUnlocked(false);
        const { exp } = JSON.parse(raw) as { exp: number };
        setDbUnlocked(exp - Date.now() > 0);
      } catch { setDbUnlocked(false); }
    };
    read();
    const id = window.setInterval(read, 5000);
    return () => window.clearInterval(id);
  }, []);

  const s = status?.session;
  const dsp = status?.deviceSync?.progress;
  const dspActive = !!dsp?.running;
  const dspPct = dspActive && dsp!.total > 0 ? Math.round((dsp!.current / dsp!.total) * 100) : 0;
  const devicesTotal = (status?.mode?.DEVICE ?? 0) + (status?.mode?.AGENT ?? 0)
    + (status?.mode?.ULTRA ?? 0) + (status?.mode?.UNKNOWN ?? 0);

  usePageChrome(() => ({ fill: true, subtitle: "compte du poste" }), []);

  if (!status || !s) return <p className="text-[13px] text-muted-foreground">Chargement…</p>;

  const accountName = s.email ? s.email.split("@")[0] : "Compte";
  const avatarLetter = (accountName[0] || "?").toUpperCase();

  const handleLogout = async () => {
    setLogoutConfirm(false);
    await logout();
  };

  return (
    <div className="flex h-full min-h-0 gap-4">
      {/* ── Le sujet : le compte ────────────────────────────────────────── */}
      <div className="flex min-w-0 flex-1 flex-col gap-[11px]">
        <div className="relative flex-none overflow-hidden rounded-3xl bg-card px-[30px] py-[26px] shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
          <div className="relative flex items-center gap-[22px]">
            <span className="flex h-[78px] w-[78px] shrink-0 items-center justify-center rounded-3xl bg-primary/10 text-[28px] font-bold text-primary">
              {avatarLetter}
            </span>
            <div className="min-w-0 flex-1">
              <h2 className="mb-[7px] truncate font-display text-[27px] font-extrabold leading-[1.1] tracking-[-0.025em] text-foreground">
                {accountName}
              </h2>
              <p className="mb-[11px] truncate text-[13.5px] text-muted-foreground">{s.email ?? "—"}</p>
              <div className="flex flex-wrap items-center gap-[7px]">
                {s.restricted ? (
                  <Chip tone="no">Accès restreint</Chip>
                ) : (
                  <Chip tone="ok">
                    <span className="relative inline-block h-1.5 w-1.5">
                      <span className="absolute inset-0 animate-ping rounded-full bg-emerald-500 opacity-60" />
                      <span className="absolute inset-0 rounded-full bg-emerald-500" />
                    </span>
                    Connecté
                  </Chip>
                )}
                {s.restricted && s.reasons.map((r) => <Chip key={r} tone="no">{r}</Chip>)}
              </div>
            </div>
            <div className="flex-none text-right">
              <div className="mb-1.5 text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground">
                Dernière connexion
              </div>
              <div className="whitespace-nowrap text-[14px] font-semibold text-foreground">
                {frDateTime(s.lastLoginAt)}
              </div>
            </div>
          </div>
        </div>

        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-3xl bg-card shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
          <div className="flex-none border-b border-border px-[26px] pb-[11px] pt-[13px]">
            <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground">
              Ce compte donne accès à
            </span>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-[26px] py-1">
            <AccessRow
              icon={Router}
              title={`${devicesTotal} appareil${devicesTotal > 1 ? "s" : ""}`}
              sub={`${status.mode?.DEVICE ?? 0} en direct · ${status.mode?.AGENT ?? 0} agent · ${status.mode?.ULTRA ?? 0} ultra`}
              chip={
                // A standalone terminal is held by its ULTRA worker and never
                // appears in the manual PullSDK session pool, so pullsdk alone
                // reported "non connecté" on a gym whose reader was live.
                (status.pullsdk?.connected ||
                  Object.values((status as any).ultra?.devices ?? {}).some((d: any) => d?.connected))
                  ? <Chip tone="ok">lecteur connecté</Chip>
                  : <Chip tone="flat">lecteur non connecté</Chip>
              }
            />
            <AccessRow
              icon={Users}
              title="Membres"
              sub="consultation et modification"
              chip={<Chip tone="ok">autorisé</Chip>}
            />
            <AccessRow
              icon={Database}
              title="Base locale"
              sub="protégée par mot de passe administrateur"
              chip={dbUnlocked ? <Chip tone="ok">déverrouillée</Chip> : <Chip tone="flat">verrouillée</Chip>}
            />
            <AccessRow
              icon={RefreshCw}
              last
              title="Dernière synchronisation"
              sub={status.sync?.lastSyncAt ? frDateTime(status.sync.lastSyncAt) : "jamais"}
              chip={
                dspActive
                  ? <Chip tone="no">en cours · {dspPct} %</Chip>
                  : status.sync?.lastOk
                    ? <Chip tone="ok">à jour</Chip>
                    : <Chip tone="no">en échec</Chip>
              }
            />
          </div>
        </div>
      </div>

      {/* ── Le rail ─────────────────────────────────────────────────────── */}
      <div className="flex w-[330px] flex-none flex-col gap-[11px]">
        <div className="flex flex-none items-center gap-[9px]">
          <span className={cn(
            "inline-flex h-[22px] items-center gap-1.5 rounded-lg px-[9px] text-[10.5px] font-bold uppercase tracking-[0.05em]",
            s.loginWarning ? "bg-amber-500/[0.14] text-amber-700 dark:text-amber-400" : "bg-muted text-muted-foreground",
          )}>
            <Clock className="h-3 w-3" />{s.loginWarning ? "Expire bientôt" : "Session"}
          </span>
        </div>

        <div className={cn(
          "flex-none rounded-3xl bg-card px-5 py-[18px] shadow-[0_8px_20px_rgba(0,0,0,0.08)]",
          s.loginWarning && "border-[1.5px] border-amber-500/40",
        )}>
          <div className="mb-3 flex items-center gap-[13px]">
            <span className={cn(
              "flex h-[42px] w-[42px] shrink-0 items-center justify-center rounded-[18px]",
              s.loginWarning
                ? "bg-amber-500/[0.14] text-amber-700 dark:text-amber-400"
                : "bg-emerald-500/[0.055] text-emerald-700 dark:text-emerald-400",
            )}>
              <Clock className="h-[21px] w-[21px]" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="num text-[22px] leading-none">
                {s.loginDaysRemaining != null ? `${s.loginDaysRemaining} jour${s.loginDaysRemaining > 1 ? "s" : ""}` : "—"}
              </div>
              <div className="mt-1 text-[11.5px] text-muted-foreground">avant expiration de la session</div>
            </div>
          </div>
          <p className="mb-[13px] text-[11.5px] leading-[1.55] text-muted-foreground">
            Passé ce délai, le poste demandera une reconnexion&nbsp;; les portes continueront de
            fonctionner en mode hors ligne.
          </p>
          <Button
            variant="outline"
            className="h-[34px] w-full justify-center gap-[7px] rounded-[14px] border-[1.5px] border-primary/45 text-[12.5px] font-semibold text-primary hover:bg-primary/5"
            onClick={() => setLogoutConfirm(true)}
          >
            <LogIn className="h-4 w-4" />Renouveler maintenant
          </Button>
        </div>

        <div className="mt-[3px] flex flex-none items-center gap-[9px]">
          <span className="inline-flex h-[22px] items-center gap-1.5 rounded-lg bg-muted px-[9px] text-[10.5px] font-bold uppercase tracking-[0.05em] text-muted-foreground">
            <FileText className="h-3 w-3" />Contrat
          </span>
        </div>
        <div className="flex min-h-0 flex-1 flex-col gap-[11px] overflow-y-auto rounded-[18px] bg-card px-5 py-4 shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Statut</span>
            {s.contractStatus ? <Chip tone="ok">Actif</Chip> : <Chip tone="no">Inactif</Chip>}
          </div>
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Échéance</span>
            <span className="text-[12px] font-semibold text-foreground">{frDate(s.contractEndDate)}</span>
          </div>
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Jours restants</span>
            <span className={cn(
              "text-[12.5px] font-bold",
              s.contractWarning ? "text-amber-700 dark:text-amber-400" : "text-foreground",
            )}>
              {s.contractDaysRemaining ?? "—"}
            </span>
          </div>
          {s.contractWarning && (
            <div className="flex items-start gap-2 rounded-xl bg-amber-500/[0.1] px-3 py-2">
              <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0 text-amber-700 dark:text-amber-400" />
              <span className="text-[11px] leading-[1.5] text-amber-700 dark:text-amber-400">
                Votre contrat arrive à échéance. Contactez l'équipe MonClub pour le renouveler.
              </span>
            </div>
          )}

          <div className="h-px bg-border" />
          <div className="mb-0.5 text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground">
            Application
          </div>
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Version</span>
            <span className="font-mono text-[12px] text-foreground">
              {status.updates?.currentVersion ?? "—"}
            </span>
          </div>
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Agent temps réel</span>
            <span className={cn(
              "text-[12px] font-semibold",
              status.agent?.running ? "text-emerald-700 dark:text-emerald-400" : "text-muted-foreground",
            )}>
              {status.agent?.running ? "actif" : "arrêté"}
            </span>
          </div>

          <div className="mt-auto flex items-start gap-[9px] border-t border-border pt-3">
            <LifeBuoy className="mt-px h-4 w-4 shrink-0 text-muted-foreground" />
            <div className="min-w-0">
              <div className="text-[11.5px] font-semibold text-foreground">Besoin d'aide&nbsp;?</div>
              <div className="mt-0.5 text-[10.5px] leading-[1.5] text-muted-foreground">
                L'équipe MonClub peut prendre la main à distance.
              </div>
            </div>
          </div>
        </div>

        <div className="flex-none rounded-[18px] bg-card px-5 py-[15px] shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
          <p className="mb-[11px] text-[11.5px] leading-[1.55] text-muted-foreground">
            Vous devrez saisir à nouveau vos identifiants pour rouvrir l'application.
          </p>
          <Button
            className="h-[34px] w-full justify-center gap-[7px] rounded-full text-[12.5px] font-bold shadow-[0_8px_20px_rgba(226,32,63,0.22)]"
            onClick={() => setLogoutConfirm(true)}
          >
            <LogOut className="h-4 w-4" />Se déconnecter
          </Button>
        </div>
      </div>

      <Dialog open={logoutConfirm} onOpenChange={setLogoutConfirm}>
        <DialogContent className="max-w-sm rounded-3xl">
          <DialogHeader>
            <DialogTitle className="font-display text-[19px] font-extrabold tracking-[-0.02em]">
              Se déconnecter&nbsp;?
            </DialogTitle>
            <DialogDescription className="text-[13px] leading-[1.55]">
              Vous devrez saisir à nouveau vos identifiants pour rouvrir l'application. Les portes
              continueront de fonctionner en mode hors ligne.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" className="rounded-[14px]" onClick={() => setLogoutConfirm(false)}>
              Annuler
            </Button>
            <Button className="gap-1.5 rounded-full" onClick={handleLogout}>
              <LogOut className="h-3.5 w-3.5" />Se déconnecter
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
