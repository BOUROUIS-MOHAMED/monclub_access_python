import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { ThemeProvider } from "@/components/theme-provider";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AccessFeedbackProvider } from "@/components/AccessFeedbackProvider";
import { AppProvider, useApp } from "./context/AppContext";
import { EnrollmentProvider } from "./context/EnrollmentContext";
import { useEnrollmentListener } from "./hooks/useEnrollmentListener";
import { Loader2 } from "lucide-react";
import MainLayout from "./layouts/MainLayout";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import DevicesPage from "./pages/DevicesPage";
import UsersPage from "./pages/UsersPage";
import EnrollPage from "./pages/EnrollPage";
import AgentPage from "./pages/AgentPage";
import LogsPage from "./pages/LogsPage";
import SyncHistoryPage from "./pages/SyncHistoryPage";
import PushHistoryPage from "./pages/PushHistoryPage";
import ConfigPage from "./pages/ConfigPage";
import LocalDbPage from "./pages/LocalDbPage";
import ProfilePage from "./pages/ProfilePage";
import UpdatePage from "./pages/UpdatePage";
import RestrictedPage from "./pages/RestrictedPage";
import PopupWindow from "./pages/PopupWindow";
import TrayPanelPage from "./pages/TrayPanelPage";

function AppRoutes() {
  const { status, loading, error } = useApp();
  const loggedIn = status?.session?.loggedIn ?? false;
  const restricted = status?.session?.restricted ?? false;
  useEnrollmentListener();

  if (loading && !status) {
    return (
      <div className="flex flex-col items-center justify-center h-screen bg-background text-foreground gap-4">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Connexion au serveur local…</p>
        {error && <p className="text-xs text-destructive max-w-sm text-center">{error}</p>}
        <p className="text-xs text-muted-foreground">Assurez-vous que l'application Python est lancée (port 8788)</p>
      </div>
    );
  }

  if (!loggedIn) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  if (restricted) {
    return (
      <Routes>
        <Route path="/restricted" element={<RestrictedPage />} />
        <Route path="*" element={<Navigate to="/restricted" replace />} />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route element={<MainLayout />}>
        <Route index element={<DashboardPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="users" element={<UsersPage />} />
        <Route path="enroll" element={<EnrollPage />} />
        <Route path="agent" element={<AgentPage />} />
        <Route path="sync-history" element={<SyncHistoryPage />} />
        <Route path="push-history" element={<PushHistoryPage />} />
        <Route path="logs" element={<LogsPage />} />
        <Route path="config" element={<ConfigPage />} />
        <Route path="local-db" element={<LocalDbPage />} />
        <Route path="profile" element={<ProfilePage />} />
        <Route path="update" element={<UpdatePage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false} storageKey="monclub-theme">
      <TooltipProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/popup" element={<PopupWindow />} />
            <Route path="/tray-panel" element={<AppProvider><TrayPanelPage /></AppProvider>} />
            <Route
              path="*"
              element={(
                <AppProvider>
                  <AccessFeedbackProvider>
                    <EnrollmentProvider>
                      <AppRoutes />
                    </EnrollmentProvider>
                  </AccessFeedbackProvider>
                </AppProvider>
              )}
            />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </ThemeProvider>
  );
}









