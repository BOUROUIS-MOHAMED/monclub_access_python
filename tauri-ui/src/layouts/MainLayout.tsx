import { useState } from "react";
import { Outlet, NavLink, useLocation, useNavigate } from "react-router-dom";
import { useApp } from "@/context/AppContext";
import { useTrayIntegration } from "@/hooks/useTrayIntegration";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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
  FileText,
  Settings,
  Database,
  LogOut,
  ChevronLeft,
  Menu,
  AlertTriangle,
  ShieldCheck,
  User,
} from "lucide-react";
import { SidebarUpdateCard } from "@/components/SidebarUpdateCard";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/devices", label: "Appareils", icon: Router },
  { to: "/users", label: "Utilisateurs", icon: Users },
  { to: "/enroll", label: "Enrôlement", icon: Fingerprint },
  { to: "/agent", label: "Agent", icon: Bot },
  { to: "/logs", label: "Logs", icon: FileText },
  { to: "/local-db", label: "Base locale", icon: Database },
] as const;

const ALL_ROUTES = [
  ...NAV,
  { to: "/profile", label: "Profil" },
  { to: "/config", label: "Configuration" },
  { to: "/update", label: "Mise à jour" },
] as const;

export default function MainLayout() {
  const { status, logout } = useApp();
  const { quitRequested, confirmQuit, cancelQuit } = useTrayIntegration(8788);
  const location = useLocation();
  const navigate = useNavigate();

  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [logoutConfirm, setLogoutConfirm] = useState(false);

  const updateAvailable = status?.updates?.updateAvailable ?? false;
  const latestVersion = (status?.updates as { latestVersion?: string | null })?.latestVersion ?? null;
  const latestCodename = (status?.updates as { latestCodename?: string | null })?.latestCodename ?? null;

  const s = status?.session;
  const hasLoginWarning = s?.loginWarning && (s?.loginDaysRemaining ?? 99) > 0;
  const hasContractWarning = s?.contractWarning && (s?.contractDaysRemaining ?? 99) > 0;

  const pageTitle =
    ALL_ROUTES.find(({ to }) =>
      to === "/" ? location.pathname === "/" : location.pathname.startsWith(to)
    )?.label ?? "MonClub Access";

  const handleLogout = async () => {
    setLogoutConfirm(false);
    await logout();
  };

  const bottomIcons = [
    {
      icon: User,
      label: "Profil",
      action: () => navigate("/profile"),
      active: location.pathname.startsWith("/profile"),
    },
    {
      icon: Settings,
      label: "Configuration",
      action: () => navigate("/config"),
      active: location.pathname.startsWith("/config"),
    },
  ];

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* Sidebar */}
      <aside
        className={cn(
          "flex flex-col border-r border-border bg-sidebar transition-all duration-200 ease-in-out shrink-0",
          sidebarOpen ? "w-56" : "w-14",
        )}
      >
        {/* Logo row */}
        <div
          className={cn(
            "flex items-center h-14 border-b border-border px-3 shrink-0",
            sidebarOpen ? "justify-between gap-2" : "justify-center",
          )}
        >
          {sidebarOpen && (
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-sm">
                <ShieldCheck className="h-4 w-4" />
              </div>
              <div className="min-w-0 leading-none">
                <div className="truncate text-[13px] font-bold text-foreground tracking-tight">
                  MonClub
                </div>
                <div className="truncate text-[10px] font-semibold text-primary tracking-[0.15em] uppercase">
                  Access
                </div>
              </div>
            </div>
          )}
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 shrink-0 rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
            onClick={() => setSidebarOpen(!sidebarOpen)}
          >
            {sidebarOpen ? <ChevronLeft className="h-3.5 w-3.5" /> : <Menu className="h-3.5 w-3.5" />}
          </Button>
        </div>

        {/* Nav */}
        <ScrollArea className="flex-1 py-3">
          <nav className={cn("space-y-0.5", sidebarOpen ? "px-2" : "px-1.5")}>
            {NAV.map(({ to, label, icon: Icon }) => {
              const isActive = to === "/" ? location.pathname === "/" : location.pathname.startsWith(to);
              return (
                <Tooltip key={to} delayDuration={0}>
                  <TooltipTrigger asChild>
                    <NavLink
                      to={to}
                      className={cn(
                        "relative group flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] font-medium transition-colors duration-100",
                        isActive
                          ? "bg-primary/10 text-primary"
                          : "text-muted-foreground hover:bg-muted/60 hover:text-foreground",
                        !sidebarOpen && "justify-center px-0 py-2",
                      )}
                    >
                      {isActive && (
                        <span className="absolute left-0 top-1 bottom-1 w-[2px] rounded-r-full bg-primary" />
                      )}
                      <Icon
                        className={cn(
                          "h-4 w-4 shrink-0 transition-colors",
                          isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground",
                        )}
                      />
                      {sidebarOpen && <span className="truncate">{label}</span>}
                    </NavLink>
                  </TooltipTrigger>
                  {!sidebarOpen && (
                    <TooltipContent side="right">{label}</TooltipContent>
                  )}
                </Tooltip>
              );
            })}
          </nav>
        </ScrollArea>

        {/* Update notification card */}
        <SidebarUpdateCard
          updateAvailable={updateAvailable}
          latestVersion={latestVersion}
          latestCodename={latestCodename}
          sidebarOpen={sidebarOpen}
          onClick={() => navigate("/update")}
        />

        {/* Warning badges */}
        {sidebarOpen && (hasLoginWarning || hasContractWarning) && (
          <div className="shrink-0 px-2 pb-1 space-y-1">
            {hasLoginWarning && (
              <div className="flex items-center gap-1.5 rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-1">
                <AlertTriangle className="h-3 w-3 shrink-0 text-amber-400" />
                <span className="text-[11px] text-amber-400">Session: {s!.loginDaysRemaining}j</span>
              </div>
            )}
            {hasContractWarning && (
              <div className="flex items-center gap-1.5 rounded-md border border-red-500/30 bg-red-500/10 px-2 py-1">
                <AlertTriangle className="h-3 w-3 shrink-0 text-red-400" />
                <span className="text-[11px] text-red-400">Contrat: {s!.contractDaysRemaining}j</span>
              </div>
            )}
          </div>
        )}

        {/* Bottom icon bar */}
        <div className={cn("border-t border-border px-2 py-2 shrink-0", sidebarOpen ? "" : "")}>
          <div className={cn("flex gap-1", sidebarOpen ? "items-center justify-between" : "flex-col items-center")}>
            {bottomIcons.map(({ icon: Icon, label, action, active }) => (
              <Tooltip key={label} delayDuration={0}>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className={cn(
                      "h-8 w-8 text-muted-foreground hover:text-foreground hover:bg-muted",
                      active && "bg-primary/10 text-primary hover:text-primary",
                    )}
                    onClick={action}
                  >
                    <Icon className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side={sidebarOpen ? "top" : "right"}>{label}</TooltipContent>
              </Tooltip>
            ))}

            <Tooltip delayDuration={0}>
              <TooltipTrigger asChild>
                <span>
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
                  className="h-8 w-8 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                  onClick={() => setLogoutConfirm(true)}
                >
                  <LogOut className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent side={sidebarOpen ? "top" : "right"}>Déconnexion</TooltipContent>
            </Tooltip>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex flex-col flex-1 min-w-0">
        {/* Top bar */}
        <header className="flex items-center justify-between h-12 border-b border-border px-5 bg-background shrink-0">
          <div className="flex items-center gap-3">
            <h1 className="text-[13px] font-semibold text-foreground">{pageTitle}</h1>
            {status?.sync?.running && (
              <span className="inline-flex items-center gap-1.5 text-[11px] text-primary">
                <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
                Synchronisation…
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {!sidebarOpen && (hasLoginWarning || hasContractWarning) && (
              <>
                {hasLoginWarning && (
                  <Badge className="border-amber-500/30 bg-amber-500/10 text-amber-400 gap-1 text-[11px]">
                    <AlertTriangle className="h-3 w-3" />
                    Session: {s!.loginDaysRemaining}j
                  </Badge>
                )}
                {hasContractWarning && (
                  <Badge className="border-red-500/30 bg-red-500/10 text-red-400 gap-1 text-[11px]">
                    <AlertTriangle className="h-3 w-3" />
                    Contrat: {s!.contractDaysRemaining}j
                  </Badge>
                )}
              </>
            )}
          </div>
        </header>

        <main className="flex-1 overflow-auto">
          <div className="p-6 max-w-[1600px] mx-auto">
            <Outlet />
          </div>
        </main>
      </div>

      {/* Logout dialog */}
      <Dialog open={logoutConfirm} onOpenChange={setLogoutConfirm}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Se déconnecter ?</DialogTitle>
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
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Quitter MonClub Access ?</DialogTitle>
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
