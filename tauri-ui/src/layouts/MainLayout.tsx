import { useEffect, useState } from "react";
import { Outlet, NavLink, useLocation } from "react-router-dom";
import { useApp } from "@/context/AppContext";
import { useTrayIntegration } from "@/hooks/useTrayIntegration";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
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
import { getTvHostBindings, postTvHostBindingRuntimeEvent, refreshTvHostMonitors } from "@/api/tv";
import { closeBindingWindow, detectHostMonitors, openBindingWindow } from "@/lib/tv-host-orchestrator";
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
  Monitor,
} from "lucide-react";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/tv/overview", label: "TV Overview", icon: Monitor },
  { to: "/tv/fleet-health", label: "TV Fleet Health", icon: Monitor },
  { to: "/tv/proof", label: "TV Proof / Stats", icon: FileText },
  { to: "/tv/runtime", label: "TV Runtime", icon: FileText },
  { to: "/tv/cache", label: "TV Cache", icon: Database },
  { to: "/tv/snapshots", label: "TV Snapshots", icon: FileText },
  { to: "/tv/ad-tasks", label: "TV Ad Tasks", icon: FileText },
  { to: "/devices", label: "Appareils", icon: Router },
  { to: "/users", label: "Utilisateurs", icon: Users },
  { to: "/enroll", label: "Enrôlement", icon: Fingerprint },
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

  useEffect(() => {
    let cancelled = false;

    const runHostOrchestration = async () => {
      try {
        const monitors = await detectHostMonitors();
        if (cancelled) return;
        await refreshTvHostMonitors(monitors);
        const res = await getTvHostBindings();
        const rows = (res.rows || []) as Array<Record<string, any>>;

        for (const row of rows) {
          const id = Number(row.id || 0);
          if (!(id > 0)) continue;
          const enabled = !!row.enabled;
          const autostart = !!row.autostart;
          const desired = String(row.desired_state || "").toUpperCase();
          const runtime = String(row.runtime_state || "").toUpperCase();

          if (enabled && autostart && desired === "RUNNING" && runtime !== "RUNNING") {
            const opened = await openBindingWindow(row as any, monitors.find((m) => m.monitorId === String(row.monitor_id || "")) || null);
            if (opened.ok) {
              await postTvHostBindingRuntimeEvent(id, { eventType: "WINDOW_LAUNCHED", windowId: opened.windowId });
            } else {
              await postTvHostBindingRuntimeEvent(id, {
                eventType: "WINDOW_LAUNCH_FAILED",
                errorCode: opened.error === "MONITOR_NOT_FOUND" ? "MONITOR_NOT_FOUND" : "WINDOW_LAUNCH_FAILED",
                errorMessage: opened.error || "WINDOW_LAUNCH_FAILED",
              });
            }
            continue;
          }

          if ((!enabled || desired === "STOPPED") && !!row.window_exists) {
            const closed = await closeBindingWindow(row as any);
            if (closed.ok) {
              await postTvHostBindingRuntimeEvent(id, { eventType: "WINDOW_CLOSED", windowId: closed.windowId });
            }
          }
        }
      } catch {
        // host orchestration is best-effort here
      }
    };

    void runHostOrchestration();
    const timerId = window.setInterval(() => {
      void runHostOrchestration();
    }, 15000);

    return () => {
      cancelled = true;
      window.clearInterval(timerId);
    };
  }, []);

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
      <aside className={cn(
        "flex flex-col border-r bg-card transition-all duration-300 ease-in-out shrink-0",
        sidebarOpen ? "w-56" : "w-14"
      )}>
        {/* Logo area */}
        <div className={cn("flex items-center gap-2 px-3 h-14 border-b shrink-0", sidebarOpen ? "justify-between" : "justify-center")}>
          {sidebarOpen && <span className="font-bold text-sm text-primary tracking-tight">MonClub Access</span>}
          <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => setSidebarOpen(!sidebarOpen)}>
            {sidebarOpen ? <ChevronLeft className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </Button>
        </div>

        {/* Navigation */}
        <ScrollArea className="flex-1 py-2">
          <nav className="flex flex-col gap-1 px-2">
            {NAV.map(({ to, label, icon: Icon }) => {
              const isActive = to === "/" ? location.pathname === "/" : location.pathname.startsWith(to);
              return (
                <NavLink key={to} to={to} className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-primary/10 text-primary"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground",
                  !sidebarOpen && "justify-center px-0"
                )}>
                  <Icon className="h-4 w-4 shrink-0" />
                  {sidebarOpen && <span>{label}</span>}
                </NavLink>
              );
            })}
          </nav>
        </ScrollArea>

        {/* Bottom actions */}
        <div className="border-t p-2 space-y-1">
          <Button variant="ghost" size={sidebarOpen ? "sm" : "icon"} className={cn("w-full", sidebarOpen ? "justify-start gap-2" : "h-9 w-full")} onClick={() => setLogoutConfirm(true)}>
            <LogOut className="h-4 w-4 shrink-0" />
            {sidebarOpen && <span className="text-sm">Déconnexion</span>}
          </Button>
        </div>
      </aside>

      {/* Main content area */}
      <div className="flex flex-col flex-1 min-w-0">
        {/* Top bar */}
        <header className="flex items-center justify-between h-14 border-b px-4 bg-card/50 backdrop-blur shrink-0">
          <div className="flex items-center gap-2">
            {s?.email && <span className="text-sm text-muted-foreground hidden sm:inline">{s.email}</span>}
          </div>
          <div className="flex items-center gap-1.5">
            {/* Expiry warnings */}
            {hasLoginWarning && (
              <Badge variant="warning" className="gap-1 text-xs">
                <AlertTriangle className="h-3 w-3" />
                Session: {s!.loginDaysRemaining}j
              </Badge>
            )}
            {hasContractWarning && (
              <Badge variant="destructive" className="gap-1 text-xs">
                <AlertTriangle className="h-3 w-3" />
                Contrat: {s!.contractDaysRemaining}j
              </Badge>
            )}
            <Separator orientation="vertical" className="h-5 mx-1" />
            <ThemeToggle />
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-auto">
          <div className="p-6 max-w-[1600px] mx-auto">
            <Outlet />
          </div>
        </main>
      </div>

      {/* Logout confirm */}
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

      {/* Quit confirm (from tray) */}
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









