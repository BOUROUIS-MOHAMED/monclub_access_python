import { useState } from "react";
import { LogOut, User } from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useTvAuth } from "@/tv/context/TvAuthContext";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmtDate(value: string | null | undefined): string {
  if (!value) return "—";
  try {
    return new Intl.DateTimeFormat("fr-FR", {
      day: "2-digit",
      month: "long",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function fmtDateShort(value: string | null | undefined): string {
  if (!value) return "—";
  try {
    return new Intl.DateTimeFormat("fr-FR", {
      day: "2-digit",
      month: "long",
      year: "numeric",
    }).format(new Date(value));
  } catch {
    return value;
  }
}


// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

interface InfoRowProps {
  label: string;
  children: React.ReactNode;
}

function InfoRow({ label, children }: InfoRowProps) {
  return (
    <div className="flex items-center justify-between gap-4 py-2.5 border-b border-border/50 last:border-0">
      <span className="text-[13px] text-muted-foreground shrink-0">{label}</span>
      <span className="text-[13px] text-foreground text-right">{children}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function TvProfilePage() {
  const { status, logout } = useTvAuth();
  const [logoutOpen, setLogoutOpen] = useState(false);

  const session = status?.session;

  const handleLogout = async () => {
    setLogoutOpen(false);
    await logout();
  };

  const avatarLetter = session?.email
    ? session.email[0].toUpperCase()
    : "?";

  return (
    <div className="space-y-6">
      {/* Page header tag — matches TvSettingsPage pattern */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">

        {/* ── Section 1 — Account ── */}
        <Card className="border-border/70 bg-card/80 shadow-sm lg:col-span-2">
          <CardContent className="p-6">
            <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
              {/* Avatar */}
              <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-full bg-primary/15 ring-2 ring-primary/30 text-2xl font-bold text-primary select-none">
                {avatarLetter}
              </div>

              <div className="flex-1 min-w-0 space-y-2 text-center sm:text-left">
                <div className="text-xl font-semibold text-foreground truncate">
                  {session?.email ?? "—"}
                </div>

                <div className="flex flex-wrap items-center gap-2 justify-center sm:justify-start">
                  {session?.restricted ? (
                    <Badge variant="destructive" className="text-[11px]">
                      Accès restreint
                    </Badge>
                  ) : (
                    <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20 text-[11px]">
                      Connecté
                    </Badge>
                  )}
                  {session?.restricted && session.reasons.map((reason) => (
                    <Badge
                      key={reason}
                      variant="outline"
                      className="text-[11px] text-amber-400 border-amber-500/40"
                    >
                      {reason}
                    </Badge>
                  ))}
                </div>

                <div className="text-[12px] text-muted-foreground">
                  Dernière connexion : {fmtDate(session?.lastLoginAt)}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* ── Section 2 — Session ── */}
        <Card className="border-border/70 bg-card/80 shadow-sm">
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold">Session</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-5">
            {session?.loginWarning && (
              <Alert className="mb-4 border-amber-500/40 bg-amber-500/10 text-amber-400">
                <AlertDescription className="text-[13px]">
                  Votre session expire bientôt. Veuillez vous reconnecter.
                </AlertDescription>
              </Alert>
            )}
            <InfoRow label="Expire dans">
              <span className={session?.loginWarning ? "text-amber-400 font-medium" : undefined}>
                {session?.loginDaysRemaining != null
                  ? `${session.loginDaysRemaining} jour${session.loginDaysRemaining !== 1 ? "s" : ""}`
                  : "—"}
              </span>
            </InfoRow>
            <InfoRow label="Dernière connexion">
              {fmtDate(session?.lastLoginAt)}
            </InfoRow>
          </CardContent>
        </Card>

        {/* ── Section 3 — Contract ── */}
        <Card className="border-border/70 bg-card/80 shadow-sm">
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold">Contrat</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-5">
            {session?.contractWarning && (
              <Alert className="mb-4 border-amber-500/40 bg-amber-500/10 text-amber-400">
                <AlertDescription className="text-[13px]">
                  Votre contrat expire bientôt. Contactez MonClub pour le renouveler.
                </AlertDescription>
              </Alert>
            )}
            <InfoRow label="Statut">
              {session?.contractStatus ? (
                <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20 text-[11px]">
                  Actif
                </Badge>
              ) : (
                <Badge variant="destructive" className="text-[11px]">
                  Inactif
                </Badge>
              )}
            </InfoRow>
            <InfoRow label="Date de fin">
              {fmtDateShort(session?.contractEndDate)}
            </InfoRow>
            <InfoRow label="Jours restants">
              <span className={session?.contractWarning ? "text-amber-400 font-medium" : undefined}>
                {session?.contractDaysRemaining != null
                  ? `${session.contractDaysRemaining} jour${session.contractDaysRemaining !== 1 ? "s" : ""}`
                  : "—"}
              </span>
            </InfoRow>
          </CardContent>
        </Card>

        {/* ── Section 4 — System ── */}
        <Card className="border-border/70 bg-card/80 shadow-sm">
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold">Système</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-5">
            <InfoRow label="Appareils (DEVICE)">
              {status?.mode?.DEVICE ?? 0}
            </InfoRow>
            <InfoRow label="Appareils (AGENT)">
              {status?.mode?.AGENT ?? 0}
            </InfoRow>
            <InfoRow label="Dernière synchronisation">
              {fmtDate(status?.sync?.lastSyncAt)}
            </InfoRow>
            <InfoRow label="Appareil connecté">
              {status?.pullsdk?.connected ? (
                <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20 text-[11px]">
                  Oui
                </Badge>
              ) : (
                <Badge variant="outline" className="text-[11px] text-muted-foreground">
                  Non
                </Badge>
              )}
            </InfoRow>
          </CardContent>
        </Card>

        {/* ── Section 5 — Actions ── */}
        <Card className="border-border/70 bg-card/80 shadow-sm">
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-semibold">Actions</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-5">
            <Button
              variant="destructive"
              className="gap-2"
              onClick={() => setLogoutOpen(true)}
            >
              <LogOut className="h-4 w-4" />
              Se déconnecter
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Logout confirmation dialog */}
      <Dialog open={logoutOpen} onOpenChange={setLogoutOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <User className="h-4 w-4" />
              Se déconnecter ?
            </DialogTitle>
            <DialogDescription>
              Êtes-vous sûr de vouloir vous déconnecter ?
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setLogoutOpen(false)}>
              Annuler
            </Button>
            <Button variant="destructive" onClick={() => void handleLogout()}>
              <LogOut className="h-4 w-4 mr-2" />
              Déconnexion
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
