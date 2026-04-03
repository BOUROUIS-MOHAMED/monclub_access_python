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
import { Button } from "@/components/ui/button";
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
        className="bg-card border rounded-2xl p-8 max-w-sm w-full mx-4 shadow-2xl flex flex-col items-center gap-5"
      >
        {/* Member info strip */}
        {(fullName || fingerId !== undefined) && (
          <div className="flex items-center gap-3 w-full bg-muted/50 rounded-lg px-3 py-2">
            <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0">
              <User className="w-4 h-4 text-primary" />
            </div>
            <div className="flex-1 min-w-0">
              {fullName && (
                <p className="text-sm font-medium truncate">{fullName}</p>
              )}
              {fingerId !== undefined && (
                <p className="text-xs text-muted-foreground">
                  Doigt #{fingerId}
                </p>
              )}
            </div>
          </div>
        )}

        {/* Animated visual — Lottie if available, CSS fallback */}
        <AnimationWithFallback phase={phase} />

        {/* Title + instruction */}
        <PhaseText phase={phase} errorMsg={errorMsg} />

        {/* Timeout warning */}
        {timedOut && (
          <p className="text-xs text-orange-500 animate-pulse">
            Cette etape prend plus de temps que prevu...
          </p>
        )}

        {/* Scan progress dots */}
        {showScanDots && <ScanDots progress={scanProgress} />}

        {/* Actions */}
        {canCancel && (
          <Button
            variant="outline"
            size="sm"
            onClick={onCancel}
            className="w-full"
          >
            Annuler
          </Button>
        )}
        {phase === "failed" && (
          <div className="flex flex-col gap-2 w-full">
            {retryAvailable && onRetryPush && (
              <Button
                variant="default"
                size="sm"
                onClick={onRetryPush}
                className="w-full"
              >
                Reessayer la sauvegarde
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={onDismiss}
              className="w-full"
            >
              Fermer
            </Button>
          </div>
        )}
        {phase === "success" && (
          <p className="text-xs text-muted-foreground">
            Fermeture automatique...
          </p>
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
            className="absolute w-40 h-40 rounded-full bg-blue-500/20 animate-ping"
            style={{ animationDuration: "1.8s" }}
          />
          <span
            className="absolute w-28 h-28 rounded-full bg-blue-500/25 animate-ping"
            style={{ animationDuration: "1.8s", animationDelay: "0.45s" }}
          />
          <div className="relative z-10 w-20 h-20 rounded-full bg-blue-500/10 border-2 border-blue-500 flex items-center justify-center">
            <Fingerprint className="w-10 h-10 text-blue-500" />
          </div>
        </div>
      );

    case "lift_finger":
      return (
        <div className="relative flex items-center justify-center w-40 h-40">
          <span className="absolute w-32 h-32 rounded-full bg-green-500/20 animate-ping" style={{ animationDuration: "1s" }} />
          <div className="relative z-10 w-20 h-20 rounded-full bg-green-500/10 border-2 border-green-500 flex items-center justify-center animate-bounce">
            <CheckCircle2 className="w-10 h-10 text-green-500" />
          </div>
        </div>
      );

    case "sample_rejected":
      return (
        <div className="relative flex items-center justify-center w-40 h-40">
          <div className="w-20 h-20 rounded-full bg-orange-500/10 border-2 border-orange-500 flex items-center justify-center animate-pulse">
            <AlertTriangle className="w-10 h-10 text-orange-500" />
          </div>
        </div>
      );

    case "device_init":
      return (
        <div className="relative flex items-center justify-center w-40 h-40">
          <span className="absolute w-32 h-32 rounded-full bg-blue-500/15 animate-ping" style={{ animationDuration: "2s" }} />
          <div className="relative z-10 w-20 h-20 rounded-full bg-blue-500/10 border-2 border-blue-500 flex items-center justify-center animate-pulse">
            <Fingerprint className="w-10 h-10 text-blue-500" />
          </div>
        </div>
      );

    case "push":
      return (
        <div className="flex items-center justify-center w-40 h-40">
          <div className="w-20 h-20 rounded-full bg-purple-500/10 border-2 border-purple-500 flex items-center justify-center">
            <Upload className="w-10 h-10 text-purple-500 animate-bounce" />
          </div>
        </div>
      );

    case "success":
      return (
        <div className="relative flex items-center justify-center w-40 h-40">
          <span className="absolute w-36 h-36 rounded-full bg-green-500/20 animate-ping" style={{ animationDuration: "2s" }} />
          <div className="relative z-10 w-24 h-24 rounded-full bg-green-500/10 border-4 border-green-500 flex items-center justify-center">
            <CheckCircle2 className="w-14 h-14 text-green-500" />
          </div>
        </div>
      );

    case "failed":
      return (
        <div className="flex items-center justify-center w-40 h-40">
          <div className="w-20 h-20 rounded-full bg-red-500/10 border-2 border-red-500 flex items-center justify-center">
            <XCircle className="w-10 h-10 text-red-500" />
          </div>
        </div>
      );

    // connecting / processing / idle / cancelled → spinner
    default:
      return (
        <div className="flex items-center justify-center w-40 h-40">
          <div className="w-20 h-20 rounded-full bg-primary/10 border-2 border-primary flex items-center justify-center">
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
  lift_finger:     { title: "Levez le doigt !",        instruction: "Décolllez puis replacez votre doigt" },
  sample_rejected: { title: "Réessayez",               instruction: "Même doigt — appuyez plus fermement" },
  processing:      { title: "Traitement...",           instruction: "Fusion des empreintes en cours..." },
  push:            { title: "Sauvegarde...",           instruction: "Enregistrement sur le serveur..." },
  success:         { title: "Enrôlement réussi !",     instruction: "L'empreinte a été enregistrée avec succès" },
  failed:          { title: "Échec de l'enrôlement",   instruction: "" },
  cancelled:       { title: "Annulé",                  instruction: "" },
};

const TITLE_COLOR: Partial<Record<EnrollPhase, string>> = {
  success:         "text-green-600 dark:text-green-400",
  failed:          "text-red-600 dark:text-red-400",
  lift_finger:     "text-green-600 dark:text-green-400",
  sample_rejected: "text-orange-600 dark:text-orange-400",
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
      <p className={cn("text-lg font-semibold", TITLE_COLOR[phase] ?? "")}>
        {title}
      </p>
      {effectiveInstruction && (
        <p className="text-sm text-muted-foreground">{effectiveInstruction}</p>
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
              ? "bg-green-500 border-green-500 scale-110"
              : "bg-transparent border-border",
          )}
        />
      ))}
      <span className="text-xs text-muted-foreground ml-1">{progress}/3</span>
    </div>
  );
}
