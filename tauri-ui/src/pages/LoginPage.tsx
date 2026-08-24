// Connexion — Access v3, screen 09. No sidebar, no rail: the only task is to
// sign in. The card sits on the design system's topographic field, and the
// service line at the foot is a real indicator — if /status answered, the local
// Python service is up, which is exactly what that line claims.

import { useState } from "react";
import { useApp } from "@/context/AppContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { TOPO_BACKGROUND_IMAGE } from "@/lib/topo";
import { cn } from "@/lib/utils";
import { Loader2, AlertCircle, ShieldCheck, Mail, Key, Eye, EyeOff } from "lucide-react";

const LOCAL_SERVICE_PORT = 8788;

export default function LoginPage() {
  const { login, status } = useApp();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // A non-null status means the local API answered this process at least once.
  const serviceUp = !!status;

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
    <div className="relative flex h-screen items-center justify-center overflow-hidden bg-background">
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.06] dark:opacity-[0.09] dark:invert"
        style={{ backgroundImage: TOPO_BACKGROUND_IMAGE, backgroundSize: "cover", backgroundPosition: "center" }}
      />

      <form
        onSubmit={handleSubmit}
        className="relative w-[392px] rounded-3xl bg-card px-10 pb-8 pt-[38px] shadow-[0_8px_20px_rgba(0,0,0,0.08)]"
      >
        <div className="mb-[30px] flex flex-col items-center">
          <div className="mb-[18px] flex h-14 w-14 items-center justify-center rounded-3xl bg-primary text-primary-foreground shadow-[0_8px_20px_rgba(226,32,63,0.28)]">
            <ShieldCheck className="h-7 w-7" />
          </div>
          <div className="font-display text-[22px] font-extrabold leading-none tracking-[-0.03em] text-foreground">
            monclub
          </div>
          <div className="mt-2 text-[10px] font-extrabold uppercase tracking-[0.24em] text-muted-foreground">
            Access
          </div>
        </div>

        <div className="mb-3.5 flex flex-col gap-1.5">
          <label htmlFor="email" className="text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground">
            Email
          </label>
          <div className="relative">
            <Mail className="pointer-events-none absolute left-[13px] top-1/2 h-[18px] w-[18px] -translate-y-1/2 text-muted-foreground" />
            <Input
              id="email"
              type="email"
              placeholder="prenom.nom@monclub.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoFocus
              className="h-11 rounded-xl border-[1.5px] pl-[42px] font-mono text-[13px]"
            />
          </div>
        </div>

        <div className="mb-4 flex flex-col gap-1.5">
          <label htmlFor="password" className="text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground">
            Mot de passe
          </label>
          <div className="relative">
            <Key className="pointer-events-none absolute left-[13px] top-1/2 h-[18px] w-[18px] -translate-y-1/2 text-muted-foreground" />
            <Input
              id="password"
              type={showPwd ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              placeholder="••••••••"
              className={cn(
                "h-11 rounded-xl border-[1.5px] pl-[42px] pr-[42px] text-[14px] tracking-[0.1em]",
                error ? "border-primary" : "focus-visible:border-primary",
              )}
            />
            <button
              type="button"
              tabIndex={-1}
              onClick={() => setShowPwd((v) => !v)}
              className="absolute right-[13px] top-1/2 -translate-y-1/2 text-muted-foreground transition-colors hover:text-foreground"
            >
              {showPwd ? <EyeOff className="h-[18px] w-[18px]" /> : <Eye className="h-[18px] w-[18px]" />}
            </button>
          </div>
        </div>

        {error && (
          <div className="mb-5 flex items-start gap-[9px] rounded-xl border border-primary/20 bg-primary/[0.05] px-[13px] py-2.5">
            <AlertCircle className="mt-px h-4 w-4 shrink-0 text-primary" />
            <span className="text-[12px] leading-[1.5] text-primary">{error}</span>
          </div>
        )}

        <Button
          type="submit"
          disabled={loading}
          className="h-[46px] w-full justify-center gap-2 rounded-full text-[14px] font-bold shadow-[0_8px_20px_rgba(226,32,63,0.22)]"
        >
          {loading && <Loader2 className="h-[18px] w-[18px] animate-spin" />}
          {loading ? "Connexion…" : "Se connecter"}
        </Button>

        <div className="mt-[26px] flex items-center gap-[9px] border-t border-border pt-[18px]">
          <span className="relative inline-block h-2 w-2 shrink-0">
            {serviceUp && <span className="absolute inset-0 animate-ping rounded-full bg-emerald-500 opacity-60" />}
            <span className={cn("absolute inset-0 rounded-full", serviceUp ? "bg-emerald-500" : "bg-primary")} />
          </span>
          <span className="flex-1 text-[11.5px] text-muted-foreground">
            {serviceUp ? "Service local actif" : "Service local injoignable"}
          </span>
          <span className="font-mono text-[11px] text-muted-foreground">port {LOCAL_SERVICE_PORT}</span>
        </div>
      </form>
    </div>
  );
}
