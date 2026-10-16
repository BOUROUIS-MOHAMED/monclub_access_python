// Profil — Access v5 redesign (docs/access-redesign-v5: `tp === 'profile'` in
// main.logic.js, board S24). The account card is the subject (what this account
// gives access to); the rail carries the session, the contract, the app version.
//
// Everything rendered here comes from the /status snapshot the app already
// polls (session / mode / sync / pullsdk / ultra / updates / deviceSync) plus
// LocalDbPage's unlock lease. Card P (guide §3.15): the session row reads the
// stored token's window (sessionIssuedAt → sessionExpiresAt) for its days and
// bar; the role comes from the token's `roles` claim; the gym name from
// GET gym/me, cached per login; the account name is the holder's name from
// that same answer (Card P2), else the e-mail's local part. Not rendered
// because no data source exists: · a member count.

import { useEffect, useState } from "react";
import { useApp } from "@/context/AppContext";
import { usePageChrome } from "@/context/PageChromeContext";
import { ActionButton } from "@/components/ui/action-button";
import { Avatar, Chip } from "@/components/ui/chip";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { ListRow, Note, PageGrid, Panel, PanelHeader, PanelList } from "@/components/ui/panel";
import { hasAgentDevices } from "@/lib/agentMode";
import { tokenWindow } from "@/lib/sessionWindow";
import {
  Bot, Clock, Database, Info, LogIn, LogOut, Mail, RefreshCw, Router, ShieldCheck, Users,
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

function plural(n: number, one: string, many: string): string {
  return `${n} ${n > 1 ? many : one}`;
}

// The backend's two login roles (the Access login refuses the others); an
// unknown code shows no label rather than a guess.
const ROLE_LABEL: Record<string, string> = {
  GYM: "Compte salle",
  ADMIN: "Administrateur",
};

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

  usePageChrome(() => ({
    subtitle: "Compte de ce poste",
    actions: (
      <ActionButton kind="danger" icon={LogOut} onClick={() => setLogoutConfirm(true)}>
        Se déconnecter
      </ActionButton>
    ),
  }), []);

  const s = status?.session;
  if (!status || !s) return <p className="text-[13px] text-muted-foreground">Chargement…</p>;

  const dsp = status.deviceSync?.progress;
  const dspActive = !!dsp?.running;
  const dspPct = dspActive && dsp!.total > 0 ? Math.round((dsp!.current / dsp!.total) * 100) : 0;
  const mode = status.mode;
  const showAgent = hasAgentDevices(status);
  const devicesTotal = (mode?.DEVICE ?? 0) + (mode?.AGENT ?? 0) + (mode?.ULTRA ?? 0) + (mode?.UNKNOWN ?? 0);

  // Device summary: the AGENT count only when AGENT devices exist (lib/agentMode).
  const modeBits: string[] = [];
  if ((mode?.ULTRA ?? 0) > 0 && mode.ULTRA === devicesTotal) modeBits.push("tous en mode ULTRA");
  else {
    if ((mode?.DEVICE ?? 0) > 0) modeBits.push(`${mode.DEVICE} en direct`);
    if (showAgent) modeBits.push(`${mode.AGENT} agent`);
    if ((mode?.ULTRA ?? 0) > 0) modeBits.push(`${mode.ULTRA} en mode ULTRA`);
  }
  const devicesSub = [plural(devicesTotal, "appareil", "appareils"), ...modeBits].join(" · ");

  // Reader state: a standalone terminal is held by its ULTRA worker and never
  // appears in the manual PullSDK session pool, so pullsdk alone would report
  // "non connecté" on a gym whose reader is live.
  const ultraWorkers = Object.values(status.ultra?.devices ?? {});
  const ultraConnected = ultraWorkers.filter((d) => d?.connected).length;
  const readerConnected = status.pullsdk?.connected || ultraConnected > 0;

  // Card P2: the holder's name set in the dashboard; without it, the e-mail's local part.
  const accountName = s.accountName || (s.email ? s.email.split("@")[0] : "Compte");
  const avatarLetter = (accountName[0] || "?").toUpperCase();
  const roleLabel = s.accountRole ? ROLE_LABEL[s.accountRole] : undefined;

  // Session row: the token's clock when its window is readable (days, bar and
  // the 7-day warning all from it), otherwise the server's loginDaysRemaining.
  const tw = tokenWindow(s.sessionIssuedAt, s.sessionExpiresAt);
  const sessionDays = tw ? tw.daysLeft : s.loginDaysRemaining;
  const sessionWarning = tw ? tw.daysLeft <= 7 : s.loginWarning;

  const handleLogout = async () => {
    setLogoutConfirm(false);
    await logout();
  };

  return (
    <PageGrid>
      {/* ── Le compte ──────────────────────────────────────────────────── */}
      <Panel className="col-span-8" aria-label="Compte">
        <div className="flex items-center gap-3.5 px-[18px] pt-4">
          <Avatar initials={avatarLetter} tone="primary" size={56} />
          <div className="min-w-0 flex-1">
            <h2 className="m-0 truncate text-[17px] font-bold">{accountName}</h2>
            {s.gymName && (
              <div className="truncate text-[13px] font-semibold">{s.gymName}</div>
            )}
            <div className="truncate text-[13px] text-muted-foreground">
              {s.email ?? "—"} · dernière connexion {frDateTime(s.lastLoginAt)}
            </div>
          </div>
          <div className="flex flex-wrap justify-end gap-1.5">
            {roleLabel && <Chip tone="grey">{roleLabel}</Chip>}
            {s.restricted ? (
              <>
                <Chip tone="error">Accès restreint</Chip>
                {s.reasons.map((r) => <Chip key={r} tone="error">{r}</Chip>)}
              </>
            ) : (
              <Chip tone="success" dot>Connecté</Chip>
            )}
          </div>
        </div>
        <div className="px-[18px] pt-3 text-[12px] font-bold uppercase tracking-[0.04em] text-muted-foreground">
          Ce compte donne accès à
        </div>
        <PanelList className="pt-1">
          <ListRow
            icon={Router}
            tone="primary"
            title="Appareils"
            sub={devicesSub}
            value={ultraWorkers.length > 0 ? `${ultraConnected} / ${ultraWorkers.length} connectés` : undefined}
            trailing={ultraWorkers.length > 0 ? undefined : (
              readerConnected
                ? <Chip tone="success">lecteur connecté</Chip>
                : <Chip tone="grey">lecteur non connecté</Chip>
            )}
          />
          <ListRow
            icon={Users}
            tone="success"
            title="Membres"
            sub="Consultation et modification"
            trailing={<Chip tone="success">autorisé</Chip>}
          />
          <ListRow
            icon={Database}
            tone="grey"
            title="Base locale"
            sub="Protégée par mot de passe administrateur"
            trailing={dbUnlocked ? <Chip tone="success">déverrouillée</Chip> : <Chip tone="grey">verrouillée</Chip>}
          />
          <ListRow
            icon={RefreshCw}
            tone={dspActive ? "primary" : status.sync?.lastOk ? "success" : "error"}
            title="Dernière synchronisation"
            sub={status.sync?.lastSyncAt ? frDateTime(status.sync.lastSyncAt) : "jamais"}
            trailing={
              dspActive
                ? <Chip tone="primary">en cours · {dspPct} %</Chip>
                : status.sync?.lastOk
                  ? <Chip tone="success">à jour</Chip>
                  : <Chip tone="error">en échec</Chip>
            }
          />
        </PanelList>
      </Panel>

      {/* ── Session et contrat ─────────────────────────────────────────── */}
      <Panel className="col-span-4" aria-label="Session et contrat">
        <PanelHeader title="Session et contrat" />
        <PanelList>
          <ListRow
            icon={Clock}
            tone={sessionWarning ? "warning" : "primary"}
            title="Session"
            sub={sessionDays != null
              ? `${plural(sessionDays, "jour", "jours")} avant expiration`
              : "durée restante inconnue"}
            subTone={sessionWarning ? "warning" : undefined}
            trailing={sessionWarning ? <Chip tone="warning">Expire bientôt</Chip> : undefined}
            bar={tw ? tw.pctLeft : undefined}
            barTone={sessionWarning ? "warning" : "primary"}
            actions={
              <ActionButton kind="outline" size="sm" icon={LogIn} onClick={() => setLogoutConfirm(true)}>
                Renouveler maintenant
              </ActionButton>
            }
          />
          <ListRow
            icon={ShieldCheck}
            tone={s.contractStatus ? (s.contractWarning ? "warning" : "success") : "error"}
            title="Contrat"
            sub={[
              s.contractStatus ? "Actif" : "Inactif",
              `échéance ${frDate(s.contractEndDate)}`,
              s.contractDaysRemaining != null ? plural(s.contractDaysRemaining, "jour", "jours") : "",
            ].filter(Boolean).join(" · ")}
            subTone={s.contractWarning ? "warning" : undefined}
            wrap
          />
          {s.contractWarning && (
            <Note tone="warning" className="mb-1">
              Votre contrat arrive à échéance. Contactez l'équipe MonClub pour le renouveler.
            </Note>
          )}
          <ListRow
            icon={Info}
            tone="grey"
            title="Application"
            sub={`Version ${status.updates?.currentVersion ?? "—"}`}
          />
          {showAgent && (
            <ListRow
              icon={Bot}
              tone={status.agent?.running ? "success" : "grey"}
              title="Agent temps réel"
              value={status.agent?.running ? "actif" : "arrêté"}
              valueTone={status.agent?.running ? "success" : undefined}
            />
          )}
          <ListRow
            icon={Mail}
            tone="grey"
            title="Besoin d'aide ?"
            sub="Contactez l'équipe MonClub"
          />
        </PanelList>
      </Panel>

      <ConfirmDialog
        open={logoutConfirm}
        onOpenChange={setLogoutConfirm}
        title="Se déconnecter ?"
        description="Vous devrez saisir à nouveau vos identifiants pour rouvrir l'application. Les portes continueront de fonctionner en mode hors ligne."
        confirmLabel="Se déconnecter"
        onConfirm={() => { void handleLogout(); }}
      />
    </PageGrid>
  );
}
