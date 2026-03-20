import { useState } from "react";
import { Outlet, NavLink, useLocation } from "react-router-dom";
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
  Menu,
  ChevronLeft,
  AlertTriangle,
  ShieldCheck,
} from "lucide-react";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/devices", label: "Appareils", icon: Router },
  { to: "/users", label: "Utilisateurs", icon: Users },
  { to: "/enroll", label: "Enrolement", icon: Fingerprint },
  { to: "/agent", label: "Agent", icon: Bot },
  { to: "/logs", label: "Logs", icon: FileText },
  { to: "/config", label: "Configuration", icon: Settings },
  { to: "/local-db", label: "Base locale", icon: Database },
] as const;

export default function MainLayout() {
  const { status, logout } = useApp();
  const { quitRequested, confirmQuit, cancelQuit } = useTrayIntegration(8788);
  const location = useLocation();

  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [logoutConfirm, setLogoutConfirm] = useState(false);

  const s = status?.session;
  const hasLoginWarning = s?.loginWarning && (s?.loginDaysRemaining ?? 99) > 0;
  const hasContractWarning = s?.contractWarning && (s?.contractDaysRemaining ?? 99) > 0;

  const handleLogout = async () => {
    setLogoutConfirm(false);
    await logout();
  };

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
            <div className="flex items-center gap-2 min-w-0">
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary">
                <ShieldCheck className="h-4 w-4" />
              </div>
              <div className="min-w-0">
                <div className="truncate text-[13px] font-semibold text-foreground tracking-wide">
                  MonClub Access
                </div>
                <div className="truncate text-[11px] text-muted-foreground">
                  {s?.email ?? "Contrôle d'accès"}
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
                <NavLink
                  key={to}
                  to={to}
                  className={cn(
                    "group flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] font-medium transition-colors duration-100",
                    isActive
                      ? "bg-primary/12 text-primary"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground",
                    !sidebarOpen && "justify-center px-0 py-2",
                  )}
                >
                  <Icon
                    className={cn(
                      "h-4 w-4 shrink-0",
                      isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground",
                    )}
                  />
                  {sidebarOpen && <span className="truncate">{label}</span>}
                </NavLink>
              );
            })}
          </nav>
        </ScrollArea>

        {/* Bottom: warning badges + logout */}
        <div className="border-t border-border px-2 py-2 space-y-1 shrink-0">
          {sidebarOpen && (hasLoginWarning || hasContractWarning) && (
            <div className="space-y-1 mb-1">
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
          <Button
            variant="ghost"
            size={sidebarOpen ? "sm" : "icon"}
            className={cn(
              "w-full text-muted-foreground hover:text-foreground hover:bg-muted",
              sidebarOpen ? "justify-start gap-2 px-2.5" : "h-9 w-full",
            )}
            onClick={() => setLogoutConfirm(true)}
          >
            <LogOut className="h-3.5 w-3.5 shrink-0" />
            {sidebarOpen && <span className="text-[13px]">Deconnexion</span>}
          </Button>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex flex-col flex-1 min-w-0">
        {/* Top bar */}
        <header className="flex items-center justify-between h-14 border-b border-border px-5 bg-background shrink-0">
          <div className="flex items-center gap-2">
            {s?.email && (
              <span className="text-[13px] text-muted-foreground hidden sm:inline">{s.email}</span>
            )}
            {status?.sync?.running && (
              <Badge className="border-primary/25 bg-primary/10 text-primary text-[11px] gap-1">
                <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
                Synchronisation…
              </Badge>
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
            <ThemeToggle />
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
            <DialogTitle>Se deconnecter ?</DialogTitle>
            <DialogDescription>Vous devrez vous reconnecter pour acceder a l'application.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setLogoutConfirm(false)}>Annuler</Button>
            <Button variant="destructive" onClick={handleLogout}>Deconnexion</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Quit dialog */}
      <Dialog open={quitRequested} onOpenChange={(open: boolean) => { if (!open) cancelQuit(); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Quitter MonClub Access ?</DialogTitle>
            <DialogDescription>L'application et tous les services seront arretes.</DialogDescription>
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
