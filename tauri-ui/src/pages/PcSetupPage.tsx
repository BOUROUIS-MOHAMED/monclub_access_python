import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Loader2,
  Monitor,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { usePcIdentity } from "@/context/PcIdentityContext";
import { setupFailureFromError, type PcSetupFailure } from "@/lib/pcIdentityState";
import { TOPO_BACKGROUND_IMAGE } from "@/lib/topo";
import { cn } from "@/lib/utils";

type SetupView = "choice" | "new" | "takeover";

function stateMessage(state: string | undefined): string {
  if (state === "revoked") {
    return "L’identité de ce poste a été révoquée. Enregistrez-le de nouveau ou remplacez un poste existant.";
  }
  if (state === "invalid_credentials" || state === "invalid_token") {
    return "Les identifiants de ce poste ne sont plus valides. Une nouvelle association est nécessaire.";
  }
  return "Associez ce poste à votre salle pour activer son suivi dans MonClub.";
}

function formatLastSeen(value: string | null | undefined): string {
  if (!value) return "Jamais vu";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return new Intl.DateTimeFormat("fr-FR", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(parsed);
}

export default function PcSetupPage() {
  const {
    status,
    pcs,
    pcsLoading,
    error,
    loadPcs,
    register,
    adopt,
    continueWithoutRegistration,
  } = usePcIdentity();
  const [view, setView] = useState<SetupView>("choice");
  const [name, setName] = useState("");
  const [selectedPcId, setSelectedPcId] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<PcSetupFailure | null>(null);

  useEffect(() => {
    void loadPcs().catch(() => undefined);
  }, [loadPcs]);

  const selectedPc = useMemo(
    () => pcs?.pcs.find((pc) => pc.id === selectedPcId) ?? null,
    [pcs, selectedPcId],
  );

  const handleRegister = async (event: React.FormEvent) => {
    event.preventDefault();
    const trimmedName = name.trim();
    if (!trimmedName) return;
    setBusy(true);
    setFailure(null);
    try {
      await register(trimmedName);
    } catch (requestError) {
      const nextFailure = setupFailureFromError(requestError);
      setFailure(nextFailure);
      setView(nextFailure.mode);
      if (nextFailure.mode === "takeover") {
        void loadPcs().catch(() => undefined);
      }
    } finally {
      setBusy(false);
    }
  };

  const handleAdopt = async () => {
    if (!selectedPcId) return;
    setBusy(true);
    setFailure(null);
    try {
      await adopt(selectedPcId);
    } catch (requestError) {
      setFailure(setupFailureFromError(requestError));
    } finally {
      setBusy(false);
    }
  };

  const chooseView = (nextView: SetupView) => {
    setFailure(null);
    setView(nextView);
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-auto bg-background px-6 py-10">
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.06] dark:opacity-[0.09] dark:invert"
        style={{ backgroundImage: TOPO_BACKGROUND_IMAGE, backgroundPosition: "center", backgroundSize: "cover" }}
      />

      <section className="relative w-full max-w-[720px] rounded-3xl bg-card px-8 py-8 shadow-[0_8px_28px_rgba(0,0,0,0.09)] sm:px-10">
        <div className="mb-7 flex items-start gap-4">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-primary text-primary-foreground shadow-[0_8px_20px_rgba(226,32,63,0.24)]">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div className="min-w-0">
            <p className="text-[10px] font-extrabold uppercase tracking-[0.2em] text-primary">Identité du poste</p>
            <h1 className="mt-1 font-display text-[24px] font-extrabold tracking-[-0.03em] text-foreground">
              Configurer ce PC
            </h1>
            <p className="mt-1.5 text-[13px] leading-5 text-muted-foreground">
              {stateMessage(status?.state)}
            </p>
          </div>
        </div>

        {(failure || (error && !pcs)) && (
          <div className="mb-5 flex items-start gap-2.5 rounded-2xl border border-amber-500/25 bg-amber-500/[0.07] px-4 py-3">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
            <p className="text-[12.5px] leading-5 text-amber-800 dark:text-amber-300">
              {failure?.message ?? "Impossible de charger la liste des PC pour le moment."}
            </p>
          </div>
        )}

        {view === "choice" && (
          <div className="grid gap-3 sm:grid-cols-2">
            <button
              type="button"
              onClick={() => chooseView("new")}
              className="group rounded-2xl border border-border bg-background p-5 text-left transition-colors hover:border-primary/50 hover:bg-primary/[0.03]"
            >
              <Monitor className="mb-4 h-6 w-6 text-primary" />
              <span className="block text-[14px] font-bold text-foreground">C’est un nouveau PC</span>
              <span className="mt-1.5 block text-[12px] leading-5 text-muted-foreground">
                Créer une identité distincte pour ce poste.
              </span>
            </button>
            <button
              type="button"
              onClick={() => chooseView("takeover")}
              className="group rounded-2xl border border-border bg-background p-5 text-left transition-colors hover:border-primary/50 hover:bg-primary/[0.03]"
            >
              <RefreshCw className="mb-4 h-6 w-6 text-primary" />
              <span className="block text-[14px] font-bold text-foreground">Ce PC remplace un ancien poste</span>
              <span className="mt-1.5 block text-[12px] leading-5 text-muted-foreground">
                Reprendre son identité et son historique.
              </span>
            </button>
          </div>
        )}

        {view === "new" && (
          <form onSubmit={handleRegister}>
            <button
              type="button"
              onClick={() => chooseView("choice")}
              className="mb-5 inline-flex items-center gap-1.5 text-[12px] font-semibold text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="h-3.5 w-3.5" /> Retour
            </button>
            <label htmlFor="pc-name" className="text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground">
              Nom du PC
            </label>
            <Input
              id="pc-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Ex. Accueil principal"
              maxLength={100}
              autoFocus
              className="mt-2 h-11 rounded-xl border-[1.5px]"
            />
            <p className="mt-2 text-[11.5px] leading-5 text-muted-foreground">
              Choisissez un nom qui permet de reconnaître facilement l’emplacement du poste.
            </p>
            <Button type="submit" disabled={busy || !name.trim()} className="mt-6 h-11 rounded-full px-6 font-bold">
              {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Enregistrer ce PC
            </Button>
          </form>
        )}

        {view === "takeover" && (
          <div>
            <button
              type="button"
              onClick={() => chooseView("choice")}
              className="mb-4 inline-flex items-center gap-1.5 text-[12px] font-semibold text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="h-3.5 w-3.5" /> Retour
            </button>
            <div className="mb-4 flex items-start gap-2.5 rounded-2xl bg-muted px-4 py-3">
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
              <p className="text-[12px] leading-5 text-muted-foreground">
                Le remplacement conserve l’identité et l’historique du poste sélectionné. Son secret est renouvelé : l’ancien PC ne pourra plus envoyer de télémétrie.
              </p>
            </div>

            <div className="mb-3 flex items-center justify-between">
              <div>
                <h2 className="text-[14px] font-bold text-foreground">Choisir le poste remplacé</h2>
                {pcs && (
                  <p className="mt-0.5 text-[11.5px] text-muted-foreground">
                    {pcs.activeCount} actif{pcs.activeCount > 1 ? "s" : ""} sur {pcs.cap} autorisé{pcs.cap > 1 ? "s" : ""}
                  </p>
                )}
              </div>
              <Button variant="ghost" size="sm" onClick={() => void loadPcs().catch(() => undefined)} disabled={pcsLoading}>
                <RefreshCw className={cn("mr-1.5 h-3.5 w-3.5", pcsLoading && "animate-spin")} />
                Actualiser
              </Button>
            </div>

            <div className="max-h-[290px] space-y-2 overflow-auto pr-1">
              {pcsLoading && !pcs && (
                <div className="flex items-center justify-center gap-2 py-10 text-[12px] text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" /> Chargement des postes…
                </div>
              )}
              {pcs?.pcs.map((pc) => {
                const selected = pc.id === selectedPcId;
                const stale = pc.stale ?? pc.isStale ?? false;
                return (
                  <button
                    key={pc.id}
                    type="button"
                    onClick={() => setSelectedPcId(pc.id)}
                    className={cn(
                      "flex w-full items-center gap-3 rounded-2xl border px-4 py-3 text-left transition-colors",
                      selected ? "border-primary bg-primary/[0.05]" : "border-border bg-background hover:bg-muted/60",
                    )}
                  >
                    <span className={cn(
                      "flex h-9 w-9 shrink-0 items-center justify-center rounded-xl",
                      selected ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground",
                    )}>
                      <Monitor className="h-4 w-4" />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[13px] font-bold text-foreground">{pc.name}</span>
                      <span className="mt-0.5 block text-[11px] text-muted-foreground">
                        Dernière activité : {formatLastSeen(pc.lastSeenAt ?? pc.lastHeartbeatAt ?? pc.lastSeen)}
                      </span>
                    </span>
                    <span className={cn(
                      "rounded-full px-2 py-1 text-[9.5px] font-bold uppercase tracking-wide",
                      stale ? "bg-amber-500/10 text-amber-700 dark:text-amber-300" : "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
                    )}>
                      {stale ? "Inactif" : pc.status || "Actif"}
                    </span>
                  </button>
                );
              })}
              {pcs && pcs.pcs.length === 0 && (
                <p className="py-8 text-center text-[12px] text-muted-foreground">Aucun poste enregistré.</p>
              )}
            </div>

            <Button onClick={handleAdopt} disabled={busy || !selectedPc} className="mt-5 h-11 rounded-full px-6 font-bold">
              {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {selectedPc ? `Ce PC remplace « ${selectedPc.name} »` : "Sélectionner un poste"}
            </Button>
          </div>
        )}

        <div className="mt-7 border-t border-border pt-5 text-center">
          <button
            type="button"
            onClick={continueWithoutRegistration}
            disabled={busy}
            className="text-[12px] font-semibold text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
          >
            Configurer plus tard
          </button>
          <p className="mt-1.5 text-[10.5px] text-muted-foreground">
            Le contrôle d’accès et l’ouverture des portes restent opérationnels sans cette configuration.
          </p>
        </div>
      </section>
    </div>
  );
}
