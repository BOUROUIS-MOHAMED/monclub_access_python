import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import { ThemeProvider } from "@/components/theme-provider";
import { TooltipProvider } from "@/components/ui/tooltip";
import TvDashboardShell from "@/tv/components/TvDashboardShell";
import { TvOrchestrator } from "@/tv/components/TvOrchestrator";
import { TV_NAV_ITEMS, type TvOverviewSectionId } from "@/tv/navigation";
import TvOverviewPage from "@/tv/pages/TvOverviewPage";
import TvPlayerWindowPage from "@/tv/pages/TvPlayerWindowPage";

function TvOverviewRoute({ focusSection }: { focusSection: TvOverviewSectionId }) {
  return <TvOverviewPage focusSection={focusSection} />;
}

export default function TvApp() {
  return (
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false} storageKey="monclub-theme">
      <TooltipProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/tv-player" element={<TvPlayerWindowPage />} />
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
                  element={<TvOverviewRoute focusSection={item.focusSection} />}
                />
              ))}
              <Route path="/" element={<Navigate to="/tv-overview" replace />} />
              <Route path="*" element={<Navigate to="/tv-overview" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </ThemeProvider>
  );
}
