// App shell — sidebar + header, per the Claude Design "Access v3" refonte
// (`Access v3 - Partie 1 Pilotage.dc.html`).
//
// The design draws a fixed 216px white rail: a 56px brand row, nav grouped
// under three small caps labels (Pilotage / Membres / Diagnostic), and a footer
// holding the update card and the account row. The active item is a red-tinted
// pill with a 3px red bar bleeding off the left edge. The 54px header carries
// the page title, a muted subtitle, and per-page actions published through
// PageChromeContext.
//
// Kept beyond the design (dropping them would be a functional regression, not a
// restyle): the sidebar collapse toggle and the theme toggle. Both are folded
// into design-native positions — the collapse chevron sits in the brand row,
// the theme toggle joins settings/logout in the account row.

import { useState } from "react";
import { Outlet, NavLink, useLocation, useNavigate } from "react-router-dom";
import { useApp } from "@/context/AppContext";
import { useTrayIntegration } from "@/hooks/useTrayIntegration";
import { usePageChromeValue } from "@/context/PageChromeContext";
import { ThemeToggle } from "@/components/theme-toggle";
import PcIdentityBanner from "@/components/PcIdentityBanner";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard,
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
  ShieldCheck,
  DownloadCloud,
  type LucideIcon,
} from "lucide-react";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** Shows the breathing status dot on the right (the design marks Agent). */
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

/** The design's breathing status dot (a solid core under an expanding halo). */
export function LiveDot({ className, tone = "ok" }: { className?: string; tone?: "ok" | "off" }) {
  const color = tone === "ok" ? "bg-emerald-500" : "bg-muted-foreground/50";
  return (
    <span className={cn("relative inline-block h-[7px] w-[7px] shrink-0", className)}>
      {tone === "ok" && (
        <span className={cn("absolute inset-0 rounded-full animate-ping opacity-60", color)} />
      )}
      <span className={cn("absolute inset-0 rounded-full", color)} />
    </span>
  );
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
  const agentRunning = status?.agent?.running ?? false;

  // The design's account row shows a person's name and role. SessionBlock
  // carries neither — only `email` — so the address is the honest stand-in.
  const email = s?.email ?? "";
  const accountName = email ? email.split("@")[0] : "Compte";
  const accountInitial = (accountName[0] || "?").toUpperCase();

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

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* ── Sidebar ─────────────────────────────────────────────────────── */}
      <aside
        className={cn(
          // min-w-0 + overflow-hidden are load-bearing: as a flex item the rail
          // gets `min-width:auto`, which floors it at its content's min-content
          // width and would keep it at 216px when collapsed.
          "flex min-w-0 shrink-0 flex-col overflow-hidden bg-sidebar border-r border-sidebar-border transition-[width] duration-200 ease-in-out",
          sidebarOpen ? "w-[216px]" : "w-[64px]",
        )}
      >
        {/* Brand row */}
        <div className="flex h-14 shrink-0 items-center gap-2.5 px-[18px]">
          <div className="flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-[18px] bg-primary text-primary-foreground">
            <ShieldCheck className="h-[18px] w-[18px]" />
          </div>
          {sidebarOpen && (
            <>
              <div className="min-w-0 leading-none">
                <div className="font-display text-[15px] font-extrabold tracking-[-0.03em] text-foreground">
                  monclub
                </div>
                <div className="mt-[3px] text-[8.5px] font-extrabold uppercase tracking-[0.24em] text-muted-foreground">
                  Access
                </div>
              </div>
              <Button
                variant="ghost"
                size="icon"
                className="ml-auto h-6 w-6 shrink-0 rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
                onClick={() => setSidebarOpen(false)}
                title="Réduire le menu"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
              </Button>
            </>
          )}
        </div>
        {!sidebarOpen && (
          <div className="flex justify-center pb-1">
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6 rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
              onClick={() => setSidebarOpen(true)}
              title="Déployer le menu"
            >
              <Menu className="h-3.5 w-3.5" />
            </Button>
          </div>
        )}

        {/* Grouped nav */}
        <ScrollArea className="min-h-0 flex-1">
          <nav className={cn("flex flex-col gap-[18px] py-2", sidebarOpen ? "px-3" : "px-2")}>
            {NAV_GROUPS.map((group) => (
              <div key={group.label}>
                {sidebarOpen ? (
                  <div className="px-2.5 pb-[9px] text-[8.5px] font-extrabold uppercase tracking-[0.2em] text-muted-foreground">
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
                            className={cn(
                              "relative flex h-10 items-center gap-[11px] rounded-xl px-[11px] text-[13.5px] transition-colors",
                              active
                                ? "bg-primary/[0.08] font-bold text-foreground"
                                : "font-medium text-muted-foreground hover:bg-muted",
                              !sidebarOpen && "justify-center px-0",
                            )}
                          >
                            {active && (
                              <span className="absolute left-0 top-[9px] bottom-[9px] w-[3px] rounded-r-full bg-primary" />
                            )}
                            <Icon
                              className={cn(
                                "h-[19px] w-[19px] shrink-0",
                                active ? "text-primary" : "text-muted-foreground",
                              )}
                            />
                            {sidebarOpen && <span className="truncate">{label}</span>}
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

        {/* Footer: expiry warnings, update card, account row */}
        <div className="flex shrink-0 flex-col gap-2 p-3">
          {sidebarOpen && hasLoginWarning && (
            <div className="flex items-center gap-1.5 rounded-xl bg-amber-500/10 px-2.5 py-1.5">
              <AlertTriangle className="h-3 w-3 shrink-0 text-amber-600 dark:text-amber-400" />
              <span className="text-[11px] font-semibold text-amber-700 dark:text-amber-400">
                Session : {s!.loginDaysRemaining} j
              </span>
            </div>
          )}
          {sidebarOpen && hasContractWarning && (
            <div className="flex items-center gap-1.5 rounded-xl bg-primary/10 px-2.5 py-1.5">
              <AlertTriangle className="h-3 w-3 shrink-0 text-primary" />
              <span className="text-[11px] font-semibold text-primary">
                Contrat : {s!.contractDaysRemaining} j
              </span>
            </div>
          )}

          {updateAvailable && (
            <Tooltip delayDuration={0}>
              <TooltipTrigger asChild>
                <button
                  onClick={() => navigate("/update")}
                  className={cn(
                    "flex items-center gap-[9px] rounded-[18px] bg-primary/[0.06] text-left transition-colors hover:bg-primary/[0.1]",
                    sidebarOpen ? "px-[11px] py-[9px]" : "justify-center p-2",
                  )}
                >
                  <DownloadCloud
                    className={cn("h-[17px] w-[17px] shrink-0 text-primary", updateDownloading && "animate-pulse")}
                  />
                  {sidebarOpen && (
                    <span className="min-w-0 flex-1 leading-[1.3]">
                      <span className="block truncate text-[12px] font-bold text-foreground">
                        Mise à jour {latestVersion ?? ""}
                      </span>
                      <span className="block truncate text-[11px] text-muted-foreground">
                        {updateSubLabel}
                      </span>
                    </span>
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
              "flex items-center rounded-[18px] bg-muted",
              sidebarOpen ? "gap-1.5 px-2.5 py-2" : "flex-col gap-1 p-1.5",
            )}
          >
            <Tooltip delayDuration={0}>
              <TooltipTrigger asChild>
                <button
                  onClick={() => navigate("/profile")}
                  className="flex h-[26px] w-[26px] shrink-0 items-center justify-center rounded-[18px] bg-primary/10 text-[12px] font-bold text-primary"
                >
                  {accountInitial}
                </button>
              </TooltipTrigger>
              <TooltipContent side={sidebarOpen ? "top" : "right"}>{email || "Profil"}</TooltipContent>
            </Tooltip>

            {sidebarOpen && (
              <div className="min-w-0 flex-1 leading-[1.25]">
                <div className="truncate text-[12px] font-semibold text-foreground">{accountName}</div>
                <div className="truncate text-[10.5px] text-muted-foreground">
                  {s?.contractStatus ? "Contrat actif" : "Contrat inactif"}
                </div>
              </div>
            )}

            <Tooltip delayDuration={0}>
              <TooltipTrigger asChild>
                <span className="shrink-0">
                  <ThemeToggle />
                </span>
              </TooltipTrigger>
              <TooltipContent side={sidebarOpen ? "top" : "right"}>Thème</TooltipContent>
            </Tooltip>

            <Tooltip delayDuration={0}>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6 shrink-0 text-muted-foreground hover:text-foreground"
                  onClick={() => navigate("/config")}
                >
                  <Settings className="h-[17px] w-[17px]" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side={sidebarOpen ? "top" : "right"}>Configuration</TooltipContent>
            </Tooltip>

            <Tooltip delayDuration={0}>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6 shrink-0 text-muted-foreground hover:text-primary"
                  onClick={() => setLogoutConfirm(true)}
                >
                  <LogOut className="h-[17px] w-[17px]" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side={sidebarOpen ? "top" : "right"}>Déconnexion</TooltipContent>
            </Tooltip>
          </div>
        </div>
      </aside>

      {/* ── Main column ─────────────────────────────────────────────────── */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-[54px] shrink-0 items-center justify-between gap-4 border-b border-border bg-card px-6">
          <div className="flex min-w-0 items-baseline gap-[11px]">
            <span className="font-display text-[17px] font-extrabold tracking-[-0.02em] text-foreground">
              {pageTitle}
            </span>
            {subtitle && (
              <span className="truncate text-[12.5px] text-muted-foreground">{subtitle}</span>
            )}
            {status?.sync?.running && !subtitle && (
              <span className="inline-flex items-center gap-1.5 text-[12.5px] text-primary">
                <LiveDot />
                Synchronisation…
              </span>
            )}
          </div>
          <div className="flex shrink-0 items-center gap-[9px]">{actions}</div>
        </header>

        <PcIdentityBanner />

        <main className={cn("min-h-0 flex-1 bg-background", fill ? "overflow-hidden" : "overflow-auto")}>
          <div className={cn("px-6 py-5", fill && "h-full")}>
            <Outlet />
          </div>
        </main>
      </div>

      {/* Logout dialog */}
      <Dialog open={logoutConfirm} onOpenChange={setLogoutConfirm}>
        <DialogContent className="max-w-sm rounded-3xl">
          <DialogHeader>
            <DialogTitle className="font-display text-[19px] font-extrabold tracking-[-0.02em]">Se déconnecter ?</DialogTitle>
            <DialogDescription>Vous devrez vous reconnecter pour accéder à l'application.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setLogoutConfirm(false)}>Annuler</Button>
            <Button variant="destructive" onClick={handleLogout}>Déconnexion</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Quit dialog */}
      <Dialog open={quitRequested} onOpenChange={(open: boolean) => { if (!open) cancelQuit(); }}>
        <DialogContent className="max-w-sm rounded-3xl">
          <DialogHeader>
            <DialogTitle className="font-display text-[19px] font-extrabold tracking-[-0.02em]">Quitter MonClub Access ?</DialogTitle>
            <DialogDescription>L'application et tous les services seront arrêtés.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={cancelQuit}>Annuler</Button>
            <Button variant="destructive" onClick={confirmQuit}>Quitter</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
