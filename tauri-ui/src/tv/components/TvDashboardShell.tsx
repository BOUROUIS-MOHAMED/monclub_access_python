import { useMemo, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { ChevronLeft, Menu, MonitorPlay, Sparkles } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { TV_NAV_ITEMS } from "@/tv/navigation";

export default function TvDashboardShell() {
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const activeItem = useMemo(
    () => TV_NAV_ITEMS.find((item) => location.pathname.startsWith(item.to)) ?? TV_NAV_ITEMS[0],
    [location.pathname],
  );

  return (
    <div className="flex h-screen overflow-hidden bg-transparent text-slate-50">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(14,165,233,0.14),transparent_32%),radial-gradient(circle_at_85%_12%,rgba(245,158,11,0.14),transparent_24%),linear-gradient(180deg,rgba(7,17,31,0.94)_0%,rgba(12,18,28,0.96)_100%)]" />

      <aside
        className={cn(
          "relative z-10 flex shrink-0 flex-col border-r border-white/10 bg-slate-950/70 backdrop-blur-xl transition-all duration-300 ease-out",
          sidebarOpen ? "w-72" : "w-20",
        )}
      >
        <div className={cn("flex h-[4.5rem] items-center border-b border-white/10 px-4", sidebarOpen ? "justify-between" : "justify-center")}>
          {sidebarOpen && (
            <div className="min-w-0">
              <div className="flex items-center gap-3">
                <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-cyan-400/15 text-cyan-200 shadow-[0_0_40px_rgba(34,211,238,0.12)]">
                  <MonitorPlay className="h-5 w-5" />
                </div>
                <div className="min-w-0">
                  <div className="truncate text-sm font-semibold tracking-[0.2em] text-cyan-200/90 uppercase">MonClub TV</div>
                  <div className="truncate text-xs text-slate-400">Standalone signage runtime</div>
                </div>
              </div>
            </div>
          )}

          <Button
            variant="ghost"
            size="icon"
            className="h-9 w-9 rounded-xl text-slate-300 hover:bg-white/10 hover:text-white"
            onClick={() => setSidebarOpen((open) => !open)}
          >
            {sidebarOpen ? <ChevronLeft className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </Button>
        </div>

        <ScrollArea className="flex-1 px-3 py-4">
          <nav className="space-y-2">
            {TV_NAV_ITEMS.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  cn(
                    "group flex items-center gap-3 rounded-2xl border px-3 py-3 text-sm transition-all duration-200",
                    isActive
                      ? "border-cyan-300/30 bg-cyan-300/12 text-white shadow-[0_10px_30px_rgba(6,182,212,0.14)]"
                      : "border-transparent text-slate-300 hover:border-white/10 hover:bg-white/[0.06] hover:text-white",
                    !sidebarOpen && "justify-center px-0",
                  )
                }
              >
                <Icon className="h-4 w-4 shrink-0" />
                {sidebarOpen && <span className="truncate font-medium">{label}</span>}
              </NavLink>
            ))}
          </nav>

          {sidebarOpen && (
            <div className="mt-6 space-y-3 rounded-[1.5rem] border border-white/10 bg-white/[0.05] p-4">
              <div className="flex items-center gap-2 text-sm font-medium text-white">
                <Sparkles className="h-4 w-4 text-amber-300" />
                TV Operator Focus
              </div>
              <div className="space-y-2 text-xs leading-5 text-slate-300">
                <p>Use the left rail to jump between startup safety, screen bindings, update status, and recovery tools.</p>
                <p>The player window remains isolated on `/tv-player`; this shell is for host supervision and support only.</p>
              </div>
            </div>
          )}
        </ScrollArea>
      </aside>

      <div className="relative z-10 flex min-w-0 flex-1 flex-col">
        <header className="shrink-0 border-b border-white/10 bg-slate-950/40 px-5 py-5 backdrop-blur-xl md:px-8">
          <div className="mx-auto flex max-w-[1680px] flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <Badge className="border-cyan-300/30 bg-cyan-300/12 text-cyan-100 hover:bg-cyan-300/12">MonClub TV</Badge>
                <Badge className="border-white/[0.12] bg-white/[0.06] text-slate-200 hover:bg-white/[0.06]">Standalone host console</Badge>
              </div>
              <div>
                <h1 className="text-2xl font-semibold tracking-tight text-white md:text-3xl">{activeItem.title}</h1>
                <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300 md:text-base">{activeItem.description}</p>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2 xl:w-[420px]">
              <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.06] p-4 shadow-[0_20px_60px_rgba(15,23,42,0.35)]">
                <div className="text-[11px] font-medium uppercase tracking-[0.22em] text-slate-400">Runtime Mode</div>
                <div className="mt-2 text-sm font-semibold text-white">Independent TV desktop process</div>
                <div className="mt-1 text-xs text-slate-400">Own API, own DB, own config, own updater.</div>
              </div>
              <div className="rounded-[1.5rem] border border-amber-300/15 bg-amber-400/10 p-4 shadow-[0_20px_60px_rgba(15,23,42,0.25)]">
                <div className="text-[11px] font-medium uppercase tracking-[0.22em] text-amber-100/70">Operator Hint</div>
                <div className="mt-2 text-sm font-semibold text-white">Use the left rail to change pages</div>
                <div className="mt-1 text-xs text-slate-300">Bindings now include a Preview action so you can inspect each screen layout without starting the live player.</div>
              </div>
            </div>
          </div>
        </header>

        <main className="min-h-0 flex-1 overflow-y-auto overscroll-contain">
          <div className="mx-auto max-w-[1680px] px-5 py-5 md:px-8 md:py-8">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
