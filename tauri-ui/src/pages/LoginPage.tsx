import { useState } from "react";
import { useApp } from "@/context/AppContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, AlertCircle, ShieldCheck } from "lucide-react";

export default function LoginPage() {
  const { login } = useApp();
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
    } catch (err: any) {
      setError(err?.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center h-screen bg-background">
      <div className="w-full max-w-[300px]">
        {/* Brand */}
        <div className="mb-10 flex flex-col items-center">
          <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-2xl bg-primary text-primary-foreground shadow-lg shadow-primary/25">
            <ShieldCheck className="h-7 w-7" />
          </div>
          <div className="text-center leading-none">
            <div className="text-2xl font-bold tracking-tight text-foreground">MonClub</div>
            <div className="mt-0.5 text-[11px] font-semibold text-primary tracking-[0.22em] uppercase">
              Access
            </div>
          </div>
        </div>

        {/* Form — bare, no card wrapper */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <Alert variant="destructive" className="py-2">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription className="text-[13px]">{error}</AlertDescription>
            </Alert>
          )}

          <div className="space-y-1">
            <Label htmlFor="email" className="text-[11px] text-muted-foreground font-medium tracking-wide">
              EMAIL
            </Label>
            <Input
              id="email"
              type="email"
              placeholder="admin@monclub.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoFocus
              className="h-10 text-[13px] font-mono"
            />
          </div>

          <div className="space-y-1">
            <Label htmlFor="password" className="text-[11px] text-muted-foreground font-medium tracking-wide">
              MOT DE PASSE
            </Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="h-10 text-[13px]"
            />
          </div>

          <Button
            type="submit"
            className="w-full h-10 text-[13px] font-semibold mt-2"
            disabled={loading}
          >
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

        <p className="mt-8 text-center text-[11px] text-muted-foreground/50">
          Service Python requis · port 8788
        </p>
      </div>
    </div>
  );
}
