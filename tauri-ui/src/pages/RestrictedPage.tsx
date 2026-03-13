import { useApp } from "@/context/AppContext";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { ShieldX, LogIn } from "lucide-react";

export default function RestrictedPage() {
  const { status, logout } = useApp();
  const reasons = status?.session?.reasons ?? [];
  const s = status?.session;

  return (
    <div className="flex items-center justify-center min-h-screen bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-2 flex h-14 w-14 items-center justify-center rounded-full bg-destructive/10">
            <ShieldX className="h-7 w-7 text-destructive" />
          </div>
          <CardTitle className="text-xl">Accès restreint</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <Alert variant="destructive">
            <AlertTitle>Accès refusé</AlertTitle>
            <AlertDescription>Vous ne pouvez pas utiliser l'application pour le moment.</AlertDescription>
          </Alert>

          {reasons.length > 0 && (
            <div className="space-y-1.5">
              {reasons.map((r, i) => (
                <p key={i} className="text-sm text-muted-foreground">• {r}</p>
              ))}
            </div>
          )}

          {s && s.loginDaysRemaining != null && s.loginDaysRemaining <= 0 && (
            <>
              <Separator />
              <p className="text-sm text-muted-foreground">Votre session a expiré. Veuillez vous reconnecter.</p>
            </>
          )}

          {s && s.contractEndDate && s.contractDaysRemaining != null && s.contractDaysRemaining <= 0 && (
            <>
              <Separator />
              <p className="text-sm text-muted-foreground">
                Contrat expiré le <strong>{s.contractEndDate}</strong>. Contactez l'équipe MonClub.
              </p>
            </>
          )}

          <div className="flex justify-center pt-2">
            <Button onClick={logout}>
              <LogIn className="h-4 w-4" /> Se reconnecter
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
