import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { ArrowRight, ChevronLeft, Download, LogOut, Menu, Settings, User } from "lucide-react";

import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { ThemeToggle } from "@/components/theme-toggle";
import { cn } from "@/lib/utils";
import { TV_NAV_ITEMS } from "@/tv/navigation";
import { useTvAuth } from "@/tv/context/TvAuthContext";
import { getTvUpdateStatus } from "@/tv/api/runtime";
import tvLogo from "@/tv/assets/monclub_tv.png";
import { SidebarUpdateCard } from "@/components/SidebarUpdateCard";

export default function TvDashboardShell() {
  const location = useLocation();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [logoutConfirm, setLogoutConfirm] = useState(false);
  const { status, logout } = useTvAuth();

  // Update status polling
  const [updateAvailable, setUpdateAvailable] = useState(false);
  const [latestVersion, setLatestVersion] = useState<string | null>(null);
  const [latestCodename, setLatestCodename] = useState<string | null>(null);
  const updatePollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchUpdateStatus = useCallback(async () => {
    try {
      const s = await getTvUpdateStatus();
      setUpdateAvailable(s.updateAvailable ?? false);
      setLatestVersion(s.latestVersion ?? null);
      setLatestCodename(s.latestCodename ?? null);
    } catch {
      // silent — update check should never break the shell
    }
  }, []);

  useEffect(() => {
    fetchUpdateStatus();
    updatePollRef.current = setInterval(fetchUpdateStatus, 30_000);
    return () => {
      if (updatePollRef.current) clearInterval(updatePollRef.current);
    };
  }, [fetchUpdateStatus]);

  // Refresh TV tray on mount so screens are populated
  useEffect(() => {
    (async () => {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        await invoke("refresh_tv_tray_menu").catch(() => {});
      } catch { /* not in Tauri */ }
    })();
  }, []);

  const handleLogout = async () => {
    setLogoutConfirm(false);
    await logout();
  };

  const activeItem = useMemo(
    () => TV_NAV_ITEMS.find((item) => location.pathname.startsWith(item.to)) ?? TV_NAV_ITEMS[0],
    [location.pathname],
  );

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground">

      {/* Sidebar */}
      <aside
        className={cn(
          "relative z-10 flex shrink-0 flex-col border-r border-border bg-sidebar transition-all duration-200 ease-in-out",
          sidebarOpen ? "w-64" : "w-14",
        )}
      >
        {/* Logo row */}
        <div
          className={cn(
            "flex h-14 shrink-0 items-center border-b border-border",
            sidebarOpen ? "justify-between px-3" : "justify-between px-1.5",
          )}
        >
          {sidebarOpen && (
            <div className="flex items-center gap-2.5 min-w-0">
              <img
                src={tvLogo}
                alt="MonClub TV"
                className="h-7 w-7 shrink-0 rounded-md object-cover shadow-sm ring-1 ring-border"
              />
              <div className="min-w-0">
                <div className="truncate text-[13px] font-semibold tracking-wide text-foreground">
                  MonClub TV
                </div>
                <div className="truncate text-[11px] text-muted-foreground">
                  Host console
                </div>
              </div>
            </div>
          )}
          {!sidebarOpen && (
            <img
              src={tvLogo}
              alt="MonClub TV"
              className="h-7 w-7 shrink-0 rounded-md object-cover shadow-sm ring-1 ring-border"
            />
          )}

          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 shrink-0 rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
            onClick={() => setSidebarOpen((open) => !open)}
          >
            {sidebarOpen ? <ChevronLeft className="h-3.5 w-3.5" /> : <Menu className="h-3.5 w-3.5" />}
          </Button>
        </div>

        {/* Nav */}
        <ScrollArea className="flex-1 py-3">
          <nav className={cn("space-y-0.5", sidebarOpen ? "px-2" : "px-1.5")}>
            {TV_NAV_ITEMS.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  cn(
                    "group flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] font-medium transition-colors duration-100",
                    isActive
                      ? "bg-primary/12 text-primary"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground",
                    !sidebarOpen && "justify-center px-0 py-2",
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    <Icon
                      className={cn(
                        "h-4 w-4 shrink-0",
                        isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground",
                      )}
                    />
                    {sidebarOpen && <span className="truncate">{label}</span>}
                  </>
                )}
              </NavLink>
            ))}
          </nav>
        </ScrollArea>

        {/* Update notification card */}
        <SidebarUpdateCard
          updateAvailable={updateAvailable}
          latestVersion={latestVersion}
          latestCodename={latestCodename}
          sidebarOpen={sidebarOpen}
          onClick={() => navigate("/tv-updates")}
        />

        {/* Bottom icon bar: Profile, Settings, Theme, Logout */}
        <div className="border-t border-border px-2 py-2 shrink-0">
          {sidebarOpen ? (
            <div className="flex items-center justify-between gap-1">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className={cn(
                      "h-8 w-8 text-muted-foreground hover:text-foreground hover:bg-muted",
                      location.pathname.startsWith("/tv-profile") && "bg-primary/10 text-primary",
                    )}
                    onClick={() => navigate("/tv-profile")}
                  >
                    <User className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="top">Profil</TooltipContent>
              </Tooltip>

              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className={cn(
                      "h-8 w-8 text-muted-foreground hover:text-foreground hover:bg-muted",
                      location.pathname.startsWith("/tv-settings") && "bg-primary/10 text-primary",
                    )}
                    onClick={() => navigate("/tv-settings")}
                  >
                    <Settings className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="top">Paramètres</TooltipContent>
              </Tooltip>

              <Tooltip>
                <TooltipTrigger asChild>
                  <span>
                    <ThemeToggle />
                  </span>
                </TooltipTrigger>
                <TooltipContent side="top">Thème</TooltipContent>
              </Tooltip>

              <Tooltip>
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
                <TooltipContent side="top">Déconnexion</TooltipContent>
              </Tooltip>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-1">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className={cn(
                      "h-8 w-8 text-muted-foreground hover:text-foreground hover:bg-muted",
                      location.pathname.startsWith("/tv-profile") && "bg-primary/10 text-primary",
                    )}
                    onClick={() => navigate("/tv-profile")}
                  >
                    <User className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="right">Profil</TooltipContent>
              </Tooltip>

              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className={cn(
                      "h-8 w-8 text-muted-foreground hover:text-foreground hover:bg-muted",
                      location.pathname.startsWith("/tv-settings") && "bg-primary/10 text-primary",
                    )}
                    onClick={() => navigate("/tv-settings")}
                  >
                    <Settings className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="right">Paramètres</TooltipContent>
              </Tooltip>

              <Tooltip>
                <TooltipTrigger asChild>
                  <span>
                    <ThemeToggle />
                  </span>
                </TooltipTrigger>
                <TooltipContent side="right">Thème</TooltipContent>
              </Tooltip>

              <Tooltip>
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
                <TooltipContent side="right">Déconnexion</TooltipContent>
              </Tooltip>
            </div>
          )}
        </div>
      </aside>

      {/* Logout confirmation dialog */}
      <Dialog open={logoutConfirm} onOpenChange={setLogoutConfirm}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Se déconnecter ?</DialogTitle>
            <DialogDescription>
              Vous devrez vous reconnecter pour accéder à l'application.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setLogoutConfirm(false)}>
              Annuler
            </Button>
            <Button variant="destructive" onClick={handleLogout}>
              Déconnexion
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Main content */}
      <div className="relative z-10 flex min-w-0 flex-1 flex-col">
        {/* Header */}
        <header className="shrink-0 border-b border-border bg-background px-6 py-4">
          <div className="mx-auto flex max-w-[1680px] items-center justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-0.5">
                <span className="inline-flex items-center gap-1.5 rounded-md border border-primary/25 bg-primary/10 px-2 py-0.5 text-[11px] font-medium text-primary">
                  <img
                    src={tvLogo}
                    alt=""
                    className="h-3.5 w-3.5 rounded-sm object-cover"
                  />
                  MonClub TV
                </span>
                <span className="text-[11px] text-muted-foreground">
                  {activeItem.label}
                </span>
              </div>
              <h1 className="text-lg font-semibold tracking-tight text-foreground truncate">
                {activeItem.title}
              </h1>
              <p className="mt-0.5 text-[13px] text-muted-foreground leading-5 max-w-2xl truncate">
                {activeItem.description}
              </p>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="min-h-0 flex-1 overflow-y-auto overscroll-contain">
          <div className="mx-auto max-w-[1680px] px-6 py-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
