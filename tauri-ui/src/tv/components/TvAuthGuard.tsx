/**
 * TvAuthGuard — protects TV pages behind TV authentication.
 *
 * Uses TvAuthContext which polls the TV backend (port 8789) for session state.
 * MonClub Access is NOT required. Shows the TV login page if not authenticated,
 * or a restricted screen if the session is restricted.
 */
import type { ReactNode } from "react";
import { Loader2, ShieldAlert } from "lucide-react";

import { useTvAuth } from "@/tv/context/TvAuthContext";
import TvLoginPage from "@/tv/pages/TvLoginPage";

interface Props {
  children: ReactNode;
}

export function TvAuthGuard({ children }: Props) {
  const { status, coreReady, loading } = useTvAuth();

  // Still connecting to TV backend — show splash
  if (loading && !status) {
    return (
      <div className="flex flex-col items-center justify-center h-screen bg-background text-foreground gap-4">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Connexion au serveur MonClub TV…</p>
        <p className="text-xs text-muted-foreground">
          Assurez-vous que le service MonClub TV est lancé (port 8789)
        </p>
      </div>
    );
  }

  // Core server reachable but not yet confirmed ready — still show splash
  if (!coreReady) {
    return (
      <div className="flex flex-col items-center justify-center h-screen bg-background text-foreground gap-4">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Connexion…</p>
      </div>
    );
  }

  // Not logged in — show the TV login page (same login as Access side)
  if (!status?.session?.loggedIn) {
    return <TvLoginPage />;
  }

  // Logged in but restricted — show restricted message
  if (status?.session?.restricted) {
    return (
      <div className="flex flex-col items-center justify-center h-screen bg-background text-foreground gap-4">
        <ShieldAlert className="h-10 w-10 text-destructive" />
        <h2 className="text-lg font-semibold">Accès restreint</h2>
        <p className="text-sm text-muted-foreground max-w-sm text-center">
          {status.session.reasons?.join(", ") || "Votre compte est actuellement restreint."}
        </p>
      </div>
    );
  }

  // Authenticated and not restricted — render TV shell
  return <>{children}</>;
}
