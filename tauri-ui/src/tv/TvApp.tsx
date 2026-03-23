import { useEffect } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import { ThemeProvider } from "@/components/theme-provider";
import { TooltipProvider } from "@/components/ui/tooltip";
import { getTvConfig } from "@/tv/api";
import TvDashboardShell from "@/tv/components/TvDashboardShell";
import { TvOrchestrator } from "@/tv/components/TvOrchestrator";
import { TvAuthProvider } from "@/tv/context/TvAuthContext";
import { TV_NAV_ITEMS, type TvDashboardNavItem, type TvOverviewSectionId } from "@/tv/navigation";
import TvLogsPage from "@/tv/pages/TvLogsPage";
import TvOverviewPage from "@/tv/pages/TvOverviewPage";
import TvPlayerWindowPage from "@/tv/pages/TvPlayerWindowPage";
import TvSendMessagePage from "@/tv/pages/TvSendMessagePage";
import TvProfilePage from "@/tv/pages/TvProfilePage";
import TvSettingsPage from "@/tv/pages/TvSettingsPage";
import TvUpdatePage from "@/tv/pages/TvUpdatePage";
import { setTvKeepBackgroundOnClose } from "@/tv/runtime/native";

function TvOverviewRoute({ focusSection }: { focusSection: TvOverviewSectionId }) {
  return <TvOverviewPage focusSection={focusSection} />;
}

function renderTvRoute(item: TvDashboardNavItem) {
  if (item.view === "logs") {
    return <TvLogsPage />;
  }
  if (item.view === "settings") {
    return <TvSettingsPage />;
  }
  if (item.view === "profile") {
    return <TvProfilePage />;
  }
  if (item.view === "update") {
    return <TvUpdatePage />;
  }
  return <TvOverviewRoute focusSection={item.focusSection ?? "overview"} />;
}

export default function TvApp() {
  useEffect(() => {
    let disposed = false;

    void (async () => {
      try {
        const cfg = await getTvConfig();
        if (!disposed) {
          await setTvKeepBackgroundOnClose(Boolean(cfg.minimize_to_tray_on_close ?? true));
        }
      } catch {
        if (!disposed) {
          await setTvKeepBackgroundOnClose(true);
        }
      }
    })();

    return () => {
      disposed = true;
    };
  }, []);

  return (
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false} storageKey="monclub-theme">
      <TooltipProvider>
        {/* TvAuthProvider polls the TV backend (port 8789) for session state */}
        <TvAuthProvider>
          <BrowserRouter>
            <Routes>
              {/* TV player window — not guarded, just a renderer */}
              <Route path="/tv-player" element={<TvPlayerWindowPage />} />

              {/* Send message standalone window — opened from tray */}
              <Route path="/tv-send-message" element={<TvSendMessagePage />} />

              {/* All TV dashboard routes */}
              <Route
                element={(
                  <>
                    <TvOrchestrator />
                    <TvDashboardShell />
                  </>
                )}
              >
                {TV_NAV_ITEMS.map((item) => (
                  <Route
                    key={item.to}
                    path={item.to}
                    element={renderTvRoute(item)}
                  />
                ))}
                {/* Settings and Profile are not in the nav list but still need routes */}
                <Route path="/tv-settings" element={<TvSettingsPage />} />
                <Route path="/tv-profile" element={<TvProfilePage />} />
                <Route path="/" element={<Navigate to="/tv-overview" replace />} />
                <Route path="*" element={<Navigate to="/tv-overview" replace />} />
              </Route>
            </Routes>
          </BrowserRouter>
        </TvAuthProvider>
      </TooltipProvider>
    </ThemeProvider>
  );
}
