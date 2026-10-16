import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import {
  Fingerprint,
  CheckCircle2,
  XCircle,
  Loader2,
  Upload,
  AlertTriangle,
  User,
} from "lucide-react";
import { ActionButton } from "@/components/ui/action-button";
import { cn } from "@/lib/utils";
import LottiePhaseVisual from "./LottiePhaseVisual";

export type EnrollPhase =
  | "idle"
  | "connecting"       // Checking login / resolving membership
  | "device_init"      // Initializing / opening ZK9500
  | "wait_finger"      // Waiting for finger placement
  | "lift_finger"      // Sample captured — lift finger
  | "sample_rejected"  // Bad quality scan
  | "processing"       // Merging / encoding template
  | "push"             // Saving to backend
  | "success"
  | "failed"
  | "cancelled";

type Props = {
  open: boolean;
  phase: EnrollPhase;
  /** 0–3 samples captured so far */
  scanProgress: number;
  fullName?: string;
  fingerId?: number;
  errorMsg?: string;
  timedOut?: boolean;
  retryAvailable?: boolean;
  onCancel: () => void;
  onDismiss: () => void;
  onRetryPush?: () => void;
};

const CANCELLABLE: Set<EnrollPhase> = new Set([
  "connecting",
  "device_init",
  "wait_finger",
  "sample_rejected",
]);

export default function EnrollOverlay({
  open,
  phase,
  scanProgress,
  fullName,
  fingerId,
  errorMsg,
  timedOut,
  retryAvailable,
  onCancel,
  onDismiss,
  onRetryPush,
}: Props) {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Auto-dismiss 3 s after success
  useEffect(() => {
    if (phase === "success" && open) {
      timerRef.current = setTimeout(onDismiss, 3000);
    }
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [phase, open, onDismiss]);

  if (!open) return null;

  const canCancel = CANCELLABLE.has(phase);
  const showScanDots = ["wait_finger", "lift_finger", "sample_rejected"].includes(phase);

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
      <div
        role="dialog"
        aria-modal="true"
        className="mx-4 flex w-full max-w-sm flex-col items-center gap-5 rounded-2xl bg-card p-8 text-card-foreground shadow-[var(--shadow-dialog)]"
      >
        {/* Member strip — the design keeps the same silhouette on every phase:
            initials, name, and the finger number in mono on the right. */}
        {(fullName || fingerId !== undefined) && (
          <div className="flex w-full items-center gap-2.5 rounded-xl bg-muted px-2.5 py-2">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary/16 text-[12px] font-bold text-primary-ink">
              {fullName
                ? (fullName.trim().split(/\s+/).map((w) => w[0]).slice(0, 2).join("") || "?").toUpperCase()
                : <User className="h-3.5 w-3.5" />}
            </span>
            <div className="min-w-0 flex-1 text-left">
              <div className="truncate text-[13.5px] font-semibold text-foreground">{fullName ?? "—"}</div>
            </div>
            {fingerId !== undefined && (
              <span className="shrink-0 font-mono text-[12.5px] text-muted-foreground">doigt #{fingerId}</span>
            )}
          </div>
        )}

        {/* Animated visual — Lottie if available, CSS fallback */}
        <AnimationWithFallback phase={phase} />

        {/* Title + instruction */}
        <PhaseText phase={phase} errorMsg={errorMsg} />

        {/* Timeout warning */}
        {timedOut && (
          <p className="animate-pulse text-[13px] font-semibold text-warning-ink">
            Cette étape prend plus de temps que prévu…
          </p>
        )}

        {/* Scan progress dots */}
        {showScanDots && <ScanDots progress={scanProgress} />}

        {/* Actions */}
        {canCancel && (
          <ActionButton kind="outline" onClick={onCancel} className="w-full">
            Annuler
          </ActionButton>
        )}
        {phase === "failed" && (
          <div className="flex w-full flex-col gap-2">
            {retryAvailable && onRetryPush && (
              <ActionButton kind="primary" onClick={onRetryPush} className="w-full">
                Réessayer la sauvegarde
              </ActionButton>
            )}
            <ActionButton kind="outline" onClick={onDismiss} className="w-full">
              Fermer
            </ActionButton>
          </div>
        )}
        {phase === "success" && (
          <p className="text-[12.5px] text-muted-foreground">Fermeture automatique…</p>
        )}
      </div>
    </div>,
    document.body,
  );
}

// ── Animation with fallback ──────────────────────────────────────────────────

function AnimationWithFallback({ phase }: { phase: EnrollPhase }) {
  const lottie = LottiePhaseVisual({ phase });
  if (lottie) return lottie;
  return <PhaseVisual phase={phase} />;
}

// ── Animated visual per phase (CSS fallback) ─────────────────────────────────

function PhaseVisual({ phase }: { phase: EnrollPhase }) {
  switch (phase) {
    case "wait_finger":
      return (
        <div className="relative flex items-center justify-center w-40 h-40">
          <span
            className="absolute w-40 h-40 rounded-full bg-primary/16 animate-ping"
            style={{ animationDuration: "1.8s" }}
          />
          <span
            className="absolute w-28 h-28 rounded-full bg-primary/24 animate-ping"
            style={{ animationDuration: "1.8s", animationDelay: "0.45s" }}
          />
          <div className="relative z-10 w-20 h-20 rounded-full bg-primary/8 border-2 border-primary flex items-center justify-center">
            <Fingerprint className="w-10 h-10 text-primary" />
          </div>
        </div>
      );

    case "lift_finger":
      return (
        <div className="relative flex items-center justify-center w-40 h-40">
          <span className="absolute w-32 h-32 rounded-full bg-success/16 animate-ping" style={{ animationDuration: "1s" }} />
          <div className="relative z-10 w-20 h-20 rounded-full bg-success/8 border-2 border-success flex items-center justify-center animate-bounce">
            <CheckCircle2 className="w-10 h-10 text-success-ink" />
          </div>
        </div>
      );

    case "sample_rejected":
      return (
        <div className="relative flex items-center justify-center w-40 h-40">
          <div className="w-20 h-20 rounded-full bg-warning/8 border-2 border-warning flex items-center justify-center animate-pulse">
            <AlertTriangle className="w-10 h-10 text-warning-ink" />
          </div>
        </div>
      );

    case "device_init":
      return (
        <div className="relative flex items-center justify-center w-40 h-40">
          <span className="absolute w-32 h-32 rounded-full bg-primary/16 animate-ping" style={{ animationDuration: "2s" }} />
          <div className="relative z-10 w-20 h-20 rounded-full bg-primary/8 border-2 border-primary flex items-center justify-center animate-pulse">
            <Fingerprint className="w-10 h-10 text-primary" />
          </div>
        </div>
      );

    case "push":
      return (
        <div className="flex items-center justify-center w-40 h-40">
          <div className="w-20 h-20 rounded-full bg-info/8 border-2 border-info flex items-center justify-center">
            <Upload className="w-10 h-10 text-info-ink animate-bounce" />
          </div>
        </div>
      );

    case "success":
      return (
        <div className="relative flex items-center justify-center w-40 h-40">
          <span className="absolute w-36 h-36 rounded-full bg-success/16 animate-ping" style={{ animationDuration: "2s" }} />
          <div className="relative z-10 w-24 h-24 rounded-full bg-success/8 border-4 border-success flex items-center justify-center">
            <CheckCircle2 className="w-14 h-14 text-success-ink" />
          </div>
        </div>
      );

    case "failed":
      return (
        <div className="flex items-center justify-center w-40 h-40">
          <div className="w-20 h-20 rounded-full bg-error/8 border-2 border-error flex items-center justify-center">
            <XCircle className="w-10 h-10 text-error-ink" />
          </div>
        </div>
      );

    // connecting / processing / idle / cancelled → spinner
    default:
      return (
        <div className="flex items-center justify-center w-40 h-40">
          <div className="w-20 h-20 rounded-full bg-primary/8 border-2 border-primary flex items-center justify-center">
            <Loader2 className="w-10 h-10 text-primary animate-spin" />
          </div>
        </div>
      );
  }
}

// ── Title + instruction text per phase ───────────────────────────────────────

const PHASE_COPY: Record<EnrollPhase, { title: string; instruction: string }> = {
  idle:            { title: "",                       instruction: "" },
  connecting:      { title: "Connexion...",            instruction: "Vérification des informations..." },
  device_init:     { title: "Initialisation scanner", instruction: "Connexion au ZK9500..." },
  wait_finger:     { title: "Posez votre doigt",       instruction: "Appuyez fermement sur le scanner ZK9500" },
  lift_finger:     { title: "Levez le doigt !",        instruction: "Décollez puis reposez votre doigt" },
  sample_rejected: { title: "Réessayez",               instruction: "Même doigt — appuyez plus fermement" },
  processing:      { title: "Traitement...",           instruction: "Fusion des empreintes en cours..." },
  push:            { title: "Sauvegarde...",           instruction: "Enregistrement sur le serveur..." },
  // "enregistrée" = saved on the SERVER. Delivery to the terminal is a separate
  // step (a targeted member sync is requested right after the save), so do not
  // let this read as "the finger works now" -- it does not until the push lands.
  success:         { title: "Empreinte enregistrée",   instruction: "Envoi vers le lecteur demandé — vérifiez le doigt sur le terminal" },
  failed:          { title: "Échec de l'enrôlement",   instruction: "" },
  cancelled:       { title: "Annulé",                  instruction: "" },
};

const TITLE_COLOR: Partial<Record<EnrollPhase, string>> = {
  success:         "text-success-ink",
  failed:          "text-error-ink",
  lift_finger:     "text-success-ink",
  sample_rejected: "text-warning-ink",
};

function PhaseText({
  phase,
  errorMsg,
}: {
  phase: EnrollPhase;
  errorMsg?: string;
}) {
  const { title, instruction } = PHASE_COPY[phase] ?? PHASE_COPY.idle;
  const effectiveInstruction =
    phase === "failed" ? errorMsg || "Une erreur est survenue" : instruction;

  return (
    <div className="text-center space-y-1 max-w-xs">
      <p className={cn("text-[20px] font-bold", TITLE_COLOR[phase] ?? "")}>
        {title}
      </p>
      {effectiveInstruction && (
        <p className="text-[14px] text-muted-foreground">{effectiveInstruction}</p>
      )}
    </div>
  );
}

// ── Scan progress dots ────────────────────────────────────────────────────────

function ScanDots({ progress }: { progress: number }) {
  return (
    <div className="flex items-center gap-2">
      {[1, 2, 3].map((i) => (
        <div
          key={i}
          className={cn(
            "w-3 h-3 rounded-full border-2 transition-all duration-500",
            i <= progress
              ? "bg-success border-success scale-110"
              : "bg-transparent border-border",
          )}
        />
      ))}
      <span className="ml-1 text-[12.5px] text-muted-foreground">échantillon {progress} sur 3</span>
    </div>
  );
}
