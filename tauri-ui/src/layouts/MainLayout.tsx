// App shell — sidebar + header, per the Access v5 redesign
// (docs/access-redesign-v5: `NAV` / `shell` in main.logic.js, the <aside> and
// <header> of main.template.html).
//
// Sidebar: 216 px (64 px collapsed), 60 px brand row (blue ShieldCheck tile +
// "monclub / ACCESS"), nav under three caps labels (Pilotage / Membres /
// Diagnostic), footer = warning pills, update card, account row (avatar → Profil,
// theme, Configuration, Déconnexion). Header: 60 px, title over a muted subtitle,
// per-page actions published through PageChromeContext, then the
// "x / y lecteurs connectés" pill computed from status.ultra.devices.
//
// Kept beyond the design (dropping them would be a functional regression): the
// collapse toggle, the theme toggle, the "Synchronisation…" header indicator,
// the Agent nav item (only when AGENT devices exist), the logout and tray-quit
// dialogs, and the PC identity banner under the header.

import { useState } from "react";
import { Outlet, NavLink, useLocation, useNavigate } from "react-router-dom";
import { useApp } from "@/context/AppContext";
import { useTrayIntegration } from "@/hooks/useTrayIntegration";
import { usePageChromeValue } from "@/context/PageChromeContext";
import { ThemeToggle } from "@/components/theme-toggle";
import PcIdentityBanner from "@/components/PcIdentityBanner";
import { ScrollArea } from "@/components/ui/scroll-area";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { SOFT, type Tone } from "@/components/ui/tone";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { hasAgentDevices } from "@/lib/agentMode";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard,
  RadioTower,
  Router,
  Users,
  Fingerprint,
  Bot,
  Activity,
  Send,
  FileText,
  Settings,
  Database,
  LogOut,
  ChevronLeft,
  Menu,
  AlertTriangle,
  Clock,
  ShieldCheck,
  Download,
  type LucideIcon,
} from "lucide-react";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** Shows the breathing status dot on the right (the Agent item). */
  live?: boolean;
}
interface NavGroup {
  label: string;
  items: NavItem[];
}

// The design's three nav groups, in its order. Every entry is an existing route.
const NAV_GROUPS: NavGroup[] = [
  {
    label: "Pilotage",
    items: [
      { to: "/", label: "Dashboard", icon: LayoutDashboard },
      { to: "/devices", label: "Appareils", icon: Router },
      { to: "/agent", label: "Agent", icon: Bot, live: true },
      { to: "/realtime", label: "Pilote / Lecteur", icon: RadioTower },
    ],
  },
  {
    label: "Membres",
    items: [
      { to: "/users", label: "Utilisateurs", icon: Users },
      { to: "/enroll", label: "Enrôlement", icon: Fingerprint },
    ],
  },
  {
    label: "Diagnostic",
    items: [
      { to: "/sync-history", label: "Historique sync", icon: Activity },
      { to: "/push-history", label: "Historique push", icon: Send },
      { to: "/logs", label: "Logs", icon: FileText },
      { to: "/local-db", label: "Base locale", icon: Database },
    ],
  },
];

const ALL_ROUTES: { to: string; label: string }[] = [
  ...NAV_GROUPS.flatMap((g) => g.items),
  { to: "/profile", label: "Profil" },
  { to: "/config", label: "Configuration" },
  { to: "/update", label: "Mise à jour" },
];

function isRouteActive(to: string, pathname: string): boolean {
  return to === "/" ? pathname === "/" : pathname.startsWith(to);
}

/** Breathing status dot (a solid core under an expanding halo). */
export function LiveDot({ className, tone = "ok" }: { className?: string; tone?: "ok" | "off" }) {
  const color = tone === "ok" ? "bg-success" : "bg-muted-foreground/50";
  return (
    <span className={cn("relative inline-block h-[7px] w-[7px] shrink-0", className)}>
      {tone === "ok" && (
        <span className={cn("absolute inset-0 rounded-full animate-ping opacity-60", color)} />
      )}
      <span className={cn("absolute inset-0 rounded-full", color)} />
    </span>
  );
}

/** Small icon button of the sidebar (collapse, Configuration, Déconnexion). */
function SideIconButton({ label, icon: Icon, onClick, side }: {
  label: string; icon: LucideIcon; onClick: () => void; side: "top" | "right";
}) {
  return (
    <Tooltip delayDuration={0}>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={label}
          onClick={onClick}
          className="grid h-7 w-7 shrink-0 cursor-pointer place-items-center rounded-lg text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
        >
          <Icon className="h-4 w-4" />
        </button>
      </TooltipTrigger>
      <TooltipContent side={side}>{label}</TooltipContent>
    </Tooltip>
  );
}

interface FooterPill {
  key: string;
  label: string;
  tip?: string;
  icon: LucideIcon;
  tone: Tone;
}

export default function MainLayout() {
  const { status, logout } = useApp();
  const { quitRequested, confirmQuit, cancelQuit } = useTrayIntegration(8788);
  const { subtitle, actions, fill } = usePageChromeValue();
  const location = useLocation();
  const navigate = useNavigate();

  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [logoutConfirm, setLogoutConfirm] = useState(false);

  const updateAvailable = status?.updates?.updateAvailable ?? false;
  const latestVersion = status?.updates?.latestVersion ?? null;
  const updateDownloaded = status?.updates?.downloaded ?? false;
  const updateDownloading = status?.updates?.downloading ?? false;
  const updateProgressPercent = status?.updates?.progressPercent ?? null;

  const s = status?.session;
  const hasLoginWarning = s?.loginWarning && (s?.loginDaysRemaining ?? 99) > 0;
  const hasContractWarning = s?.contractWarning && (s?.contractDaysRemaining ?? 99) > 0;
  const hasClockSuspectWarning = s?.clockSuspectWarning ?? false;
  const clockSuspectTooltip =
    `L'heure de ce PC est incohérente (motif: ${s?.clockSuspectReason ?? "inconnu"}). ` +
    "Les dates d'accès n'avancent pas au-delà de la dernière date connue. " +
    "Vérifiez la date et l'heure de Windows.";
  const agentRunning = status?.agent?.running ?? false;
  const navGroups = hasAgentDevices(status)
    ? NAV_GROUPS
    : NAV_GROUPS.map((g) => ({ ...g, items: g.items.filter((i) => i.to !== "/agent") }));

  // Footer warning pills — the same three conditions as before, one shape.
  const pills: FooterPill[] = [];
  if (hasLoginWarning) {
    pills.push({
      key: "session", icon: Clock, tone: "warning",
      label: `Session : ${s!.loginDaysRemaining} j`,
      tip: `La session de ce poste expire dans ${s!.loginDaysRemaining} jour${s!.loginDaysRemaining! > 1 ? "s" : ""}`,
    });
  }
  if (hasContractWarning) {
    pills.push({
      key: "contract", icon: AlertTriangle, tone: "error",
      label: `Contrat : ${s!.contractDaysRemaining} j`,
      tip: `Le contrat expire dans ${s!.contractDaysRemaining} jour${s!.contractDaysRemaining! > 1 ? "s" : ""}`,
    });
  }
  if (hasClockSuspectWarning) {
    pills.push({ key: "clock", icon: AlertTriangle, tone: "warning", label: "Horloge du PC suspecte", tip: clockSuspectTooltip });
  }

  // Header pill "x / y lecteurs connectés": the ULTRA workers this PC runs and
  // their real `connected` flag. Hidden on a READER PC (it drives no turnstile)
  // and when there is no ULTRA worker at all — "0 / 0" would say nothing.
  const ultraWorkers = Object.values(status?.ultra?.devices ?? {});
  const showHealth = status?.ultra?.drivesTurnstiles !== false && ultraWorkers.length > 0;
  const healthConnected = ultraWorkers.filter((d) => d?.connected).length;
  const healthTone: Tone = healthConnected === ultraWorkers.length ? "success" : "error";

  // The account row shows the e-mail's local part — SessionBlock carries no
  // person name or role.
  const email = s?.email ?? "";
  const accountName = email ? email.split("@")[0] : "Compte";
  const accountInitial = (accountName[0] || "?").toUpperCase();
  const contractActive = !!s?.contractStatus;

  const pageTitle =
    ALL_ROUTES.find(({ to }) => isRouteActive(to, location.pathname))?.label ?? "MonClub Access";

  const handleLogout = async () => {
    setLogoutConfirm(false);
    await logout();
  };

  const updateSubLabel = updateDownloading
    ? updateProgressPercent != null
      ? `Téléchargement ${updateProgressPercent} %`
      : "Téléchargement…"
    : updateDownloaded
      ? "Prête à installer"
      : "Disponible";

  const tipSide = sidebarOpen ? "top" : "right";

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* ── Sidebar ─────────────────────────────────────────────────────── */}
      <aside
        className={cn(
          // min-w-0 + overflow-hidden are load-bearing: as a flex item the rail
          // gets `min-width:auto`, which floors it at its content's min-content
          // width and would keep it at 216px when collapsed.
          "flex min-w-0 shrink-0 flex-col overflow-hidden border-r border-dashed border-grey/24 bg-sidebar transition-[width] duration-200 ease-in-out",
          sidebarOpen ? "w-[216px]" : "w-[64px]",
        )}
      >
        {/* Brand row */}
        <div className={cn("flex h-[60px] shrink-0 items-center gap-2.5", sidebarOpen ? "pl-4 pr-3" : "justify-center")}>
          <span className="grid h-8 w-8 shrink-0 place-items-center rounded-[10px] bg-primary text-primary-foreground">
            <ShieldCheck className="h-[19px] w-[19px]" />
          </span>
          {sidebarOpen && (
            <>
              <div className="min-w-0 flex-1 leading-none">
                <div className="text-[16px] font-extrabold tracking-[-0.02em] text-foreground">monclub</div>
                <div className="mt-[3px] text-[9px] font-extrabold uppercase tracking-[0.24em] text-muted-foreground">
                  Access
                </div>
              </div>
              <SideIconButton label="Réduire le menu" icon={ChevronLeft} onClick={() => setSidebarOpen(false)} side="right" />
            </>
          )}
        </div>
        {!sidebarOpen && (
          <div className="flex justify-center pb-1">
            <SideIconButton label="Déployer le menu" icon={Menu} onClick={() => setSidebarOpen(true)} side="right" />
          </div>
        )}

        {/* Grouped nav */}
        <ScrollArea className="min-h-0 flex-1">
          <nav aria-label="Navigation principale" className={cn("flex flex-col gap-3 py-1", sidebarOpen ? "px-2.5" : "px-2")}>
            {navGroups.map((group) => (
              <div key={group.label}>
                {sidebarOpen ? (
                  <div className="px-2.5 pb-1.5 text-[11px] font-bold uppercase tracking-[0.06em] text-muted-foreground">
                    {group.label}
                  </div>
                ) : (
                  <div className="mx-auto mb-2 h-px w-6 bg-sidebar-border" />
                )}
                <div className="flex flex-col gap-0.5">
                  {group.items.map(({ to, label, icon: Icon, live }) => {
                    const active = isRouteActive(to, location.pathname);
                    return (
                      <Tooltip key={to} delayDuration={0}>
                        <TooltipTrigger asChild>
                          <NavLink
                            to={to}
                            aria-current={active ? "page" : undefined}
                            className={cn(
                              "flex h-[38px] items-center gap-[11px] rounded-lg px-2.5 text-[14px] transition-colors",
                              active
                                ? "bg-primary/8 font-bold text-primary"
                                : "font-medium text-muted-foreground hover:bg-muted hover:text-foreground",
                              !sidebarOpen && "justify-center px-0",
                            )}
                          >
                            <Icon className="h-[19px] w-[19px] shrink-0" />
                            {sidebarOpen && <span className="flex-1 truncate">{label}</span>}
                            {live && sidebarOpen && (
                              <LiveDot className="ml-auto" tone={agentRunning ? "ok" : "off"} />
                            )}
                          </NavLink>
                        </TooltipTrigger>
                        {!sidebarOpen && <TooltipContent side="right">{label}</TooltipContent>}
                      </Tooltip>
                    );
                  })}
                </div>
              </div>
            ))}
          </nav>
        </ScrollArea>

        {/* Footer: warning pills, update card, account row */}
        <div className={cn("flex shrink-0 flex-col gap-2 pb-2.5 pt-2", sidebarOpen ? "px-2.5" : "px-2")}>
          {pills.map((p) => (
            <Tooltip key={p.key} delayDuration={0}>
              <TooltipTrigger asChild>
                <div
                  role="status"
                  className={cn(
                    "flex h-[30px] items-center gap-2 rounded-lg text-[12.5px] font-bold",
                    SOFT[p.tone],
                    sidebarOpen ? "px-2.5" : "justify-center",
                  )}
                >
                  <p.icon className="h-[15px] w-[15px] shrink-0" />
                  {sidebarOpen ? <span className="truncate">{p.label}</span> : <span className="sr-only">{p.label}</span>}
                </div>
              </TooltipTrigger>
              {(p.tip || !sidebarOpen) && (
                <TooltipContent side={tipSide} className="max-w-[260px]">
                  {sidebarOpen ? p.tip : `${p.label}${p.tip ? ` — ${p.tip}` : ""}`}
                </TooltipContent>
              )}
            </Tooltip>
          ))}

          {updateAvailable && (
            <Tooltip delayDuration={0}>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  onClick={() => navigate("/update")}
                  className={cn(
                    "flex w-full cursor-pointer items-center gap-2.5 rounded-[10px] bg-primary/8 text-left text-foreground transition-colors hover:bg-primary/12",
                    sidebarOpen ? "px-3 py-2.5" : "justify-center p-2",
                  )}
                >
                  <Download className={cn("h-5 w-5 shrink-0 text-primary", updateDownloading && "animate-pulse")} />
                  {sidebarOpen ? (
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[13px] font-bold">Mise à jour {latestVersion ?? ""}</span>
                      <span className="block truncate text-[12px] text-muted-foreground">{updateSubLabel}</span>
                    </span>
                  ) : (
                    <span className="sr-only">Mise à jour {latestVersion ?? ""} · {updateSubLabel}</span>
                  )}
                </button>
              </TooltipTrigger>
              {!sidebarOpen && (
                <TooltipContent side="right">
                  Mise à jour {latestVersion ?? ""} · {updateSubLabel}
                </TooltipContent>
              )}
            </Tooltip>
          )}

          <div
            className={cn(
              "flex items-center border-t border-dashed border-grey/24 pt-2",
              sidebarOpen ? "gap-2 px-1" : "flex-col gap-1",
            )}
          >
            <Tooltip delayDuration={0}>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  onClick={() => navigate("/profile")}
                  aria-label={`Profil — ${email || accountName}`}
                  className={cn(
                    "flex min-w-0 cursor-pointer items-center gap-2 rounded-lg bg-transparent p-0 text-left text-foreground",
                    sidebarOpen && "flex-1",
                  )}
                >
                  <span className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-success/16 text-[13px] font-extrabold text-success-ink">
                    {accountInitial}
                  </span>
                  {sidebarOpen && (
                    <span className="min-w-0">
                      <span className="block truncate text-[13px] font-bold">{accountName}</span>
                      <span className={cn("block truncate text-[11.5px] font-semibold", contractActive ? "text-success-ink" : "text-error-ink")}>
                        {contractActive ? "Contrat actif" : "Contrat inactif"}
                      </span>
                    </span>
                  )}
                </button>
              </TooltipTrigger>
              <TooltipContent side={tipSide}>{email || "Profil"}</TooltipContent>
            </Tooltip>

            <Tooltip delayDuration={0}>
              <TooltipTrigger asChild>
                <span className="shrink-0 [&_button]:h-7 [&_button]:w-7 [&_button]:rounded-lg [&_button]:text-muted-foreground">
                  <ThemeToggle />
                </span>
              </TooltipTrigger>
              <TooltipContent side={tipSide}>Thème</TooltipContent>
            </Tooltip>
            <SideIconButton label="Configuration" icon={Settings} onClick={() => navigate("/config")} side={tipSide} />
            <SideIconButton label="Déconnexion" icon={LogOut} onClick={() => setLogoutConfirm(true)} side={tipSide} />
          </div>
        </div>
      </aside>

      {/* ── Main column ─────────────────────────────────────────────────── */}
      <div className="flex min-w-0 flex-1 flex-col bg-background">
        <header className="flex h-[60px] shrink-0 items-center gap-2.5 border-b border-dashed border-grey/24 px-6">
          <div className="min-w-0 flex-1">
            <h1 className="m-0 truncate text-[19px] font-bold leading-[1.25] text-foreground">{pageTitle}</h1>
            {subtitle ? (
              <div className="truncate text-[13px] text-muted-foreground">{subtitle}</div>
            ) : status?.sync?.running ? (
              <div className="inline-flex items-center gap-1.5 text-[13px] text-primary">
                <LiveDot />
                Synchronisation…
              </div>
            ) : null}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2.5">{actions}</div>}
          {showHealth && (
            <Tooltip delayDuration={0}>
              <TooltipTrigger asChild>
                <span
                  role="status"
                  className={cn(
                    "inline-flex h-8 shrink-0 items-center gap-[7px] whitespace-nowrap rounded-lg px-[11px] text-[13px] font-bold",
                    SOFT[healthTone],
                  )}
                >
                  <span className={cn("h-2 w-2 rounded-full", healthTone === "success" ? "bg-success" : "bg-error")} />
                  {healthConnected} / {ultraWorkers.length} lecteurs connectés
                </span>
              </TooltipTrigger>
              <TooltipContent side="bottom">Appareils ULTRA connectés à ce poste</TooltipContent>
            </Tooltip>
          )}
        </header>

        <PcIdentityBanner />

        <main className={cn("min-h-0 flex-1", fill ? "overflow-hidden" : "overflow-auto")}>
          <div className={cn("px-6 pb-6 pt-3.5", fill && "h-full")}>
            <Outlet />
          </div>
        </main>
      </div>

      {/* Logout dialog */}
      <ConfirmDialog
        open={logoutConfirm}
        onOpenChange={setLogoutConfirm}
        title="Se déconnecter ?"
        description="Vous devrez vous reconnecter pour accéder à l'application."
        confirmLabel="Déconnexion"
        onConfirm={() => { void handleLogout(); }}
      />

      {/* Quit dialog (tray "Quitter") */}
      <ConfirmDialog
        open={quitRequested}
        onOpenChange={(open) => { if (!open) cancelQuit(); }}
        title="Quitter MonClub Access ?"
        description="L'application et tous les services seront arrêtés."
        confirmLabel="Quitter"
        onConfirm={() => { void confirmQuit(); }}
      />
    </div>
  );
}
