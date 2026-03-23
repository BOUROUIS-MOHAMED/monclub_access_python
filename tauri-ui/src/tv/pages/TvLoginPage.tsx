/**
 * TvLoginPage — Login page displayed in the TV window when the user is not
 * authenticated. Calls the TV backend (port 8789) directly — MonClub Access
 * is not required. If Access is co-installed, the Python layer mirrors the
 * token to it automatically (SSO).
 */
import { useState } from "react";
import { Loader2, AlertCircle, Tv } from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useTvAuth } from "@/tv/context/TvAuthContext";

export default function TvLoginPage() {
  const { login } = useTvAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await login({ email, password });
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-background p-4">
      <div className="w-full max-w-sm">
        {/* Brand header */}
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-primary/15 text-primary">
            <Tv className="h-6 w-6" />
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">MonClub TV</h1>
          <p className="mt-1 text-[13px] text-muted-foreground">
            Connectez-vous pour accéder à la console TV
          </p>
        </div>

        {/* Form card */}
        <div className="rounded-xl border border-border bg-card p-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <Alert variant="destructive" className="py-2">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription className="text-[13px]">{error}</AlertDescription>
              </Alert>
            )}
            <div className="space-y-1.5">
              <Label htmlFor="tv-email" className="text-[13px]">
                Email
              </Label>
              <Input
                id="tv-email"
                type="email"
                placeholder="admin@monclub.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
                className="h-9 text-[13px]"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="tv-password" className="text-[13px]">
                Mot de passe
              </Label>
              <Input
                id="tv-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="h-9 text-[13px]"
              />
            </div>
            <Button type="submit" className="w-full h-9 text-[13px]" disabled={loading}>
              {loading ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Connexion…
                </>
              ) : (
                "Se connecter"
              )}
            </Button>
          </form>
        </div>

        <p className="mt-4 text-center text-[11px] text-muted-foreground">
          Assurez-vous que le service MonClub TV est lancé sur le port 8789
        </p>
      </div>
    </div>
  );
}
