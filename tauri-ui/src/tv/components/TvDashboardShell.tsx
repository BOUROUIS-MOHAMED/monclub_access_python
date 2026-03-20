import { useMemo, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { ChevronLeft, Menu } from "lucide-react";

import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { TV_NAV_ITEMS } from "@/tv/navigation";
import tvLogo from "@/tv/assets/monclub_tv.png";

export default function TvDashboardShell() {
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(true);

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

        {/* Version tag at bottom */}
        {sidebarOpen && (
          <div className="shrink-0 border-t border-border px-4 py-3">
            <div className="text-[11px] text-muted-foreground">
              Standalone signage runtime
            </div>
          </div>
        )}
      </aside>

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

            <div className="shrink-0 hidden sm:flex items-center gap-2">
              <div className="rounded-md border border-border bg-muted/60 px-3 py-1.5 text-right">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-medium">
                  Runtime
                </div>
                <div className="text-[12px] font-medium text-foreground">
                  Independent desktop
                </div>
              </div>
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
