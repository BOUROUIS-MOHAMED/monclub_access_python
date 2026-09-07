export type PcSetupMode = "new" | "takeover";

export interface PcSetupFailure {
  mode: PcSetupMode;
  message: string;
  cap: number | null;
  activeCount: number | null;
}

interface IdentityErrorLike {
  code?: unknown;
  message?: unknown;
  details?: unknown;
  cap?: unknown;
  activeCount?: unknown;
  takeoverRequired?: unknown;
}

interface IdentityStatusLike {
  state?: unknown;
}

const SETUP_STATES = new Set(["first_run", "revoked", "invalid_credentials", "invalid_token"]);

export function shouldShowPcSetup(status: IdentityStatusLike | null, bypassed: boolean): boolean {
  if (!status || bypassed) return false;
  return SETUP_STATES.has(String(status.state || ""));
}

function finiteNumber(value: unknown): number | null {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function setupFailureFromError(error: unknown): PcSetupFailure {
  const source = error && typeof error === "object" ? error as IdentityErrorLike : {};
  const details = source.details && typeof source.details === "object"
    ? source.details as Record<string, unknown>
    : {};
  const cap = finiteNumber(source.cap ?? details.cap);
  const activeCount = finiteNumber(source.activeCount ?? details.activeCount);
  const isCapReached = source.code === "ACCESS_PC_CAP_REACHED" || source.takeoverRequired === true;

  if (isCapReached) {
    const capacity = cap == null ? "autorisée" : `de ${cap} PC actifs`;
    return {
      mode: "takeover",
      message: `La limite ${capacity} est atteinte. Choisissez le poste que ce PC remplace.`,
      cap,
      activeCount,
    };
  }

  return {
    mode: "new",
    message: typeof source.message === "string" && source.message.trim()
      ? source.message
      : "Impossible d’enregistrer ce PC pour le moment.",
    cap,
    activeCount,
  };
}
