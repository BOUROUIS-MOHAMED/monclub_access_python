// French copy for the sync / push history pages. Display only: the filters
// still send the raw backend values (SUCCESS, PERIODIC, …).
import type { Tone } from "@/components/ui/tone";

export const RUN_STATUS: Record<string, { l: string; tone: Tone }> = {
  SUCCESS: { l: "Réussi", tone: "success" },
  PARTIAL: { l: "Partiel", tone: "warning" },
  FAILED: { l: "Échec", tone: "error" },
  IN_PROGRESS: { l: "En cours", tone: "info" },
};
export function runStatus(s: string | null | undefined): { l: string; tone: Tone } {
  const k = String(s || "").toUpperCase();
  return RUN_STATUS[k] ?? { l: s || "—", tone: "grey" };
}

export const STATUS_FILTER_OPTIONS = [
  { value: "__all", label: "tous" },
  { value: "SUCCESS", label: "Réussi" },
  { value: "PARTIAL", label: "Partiel" },
  { value: "FAILED", label: "Échec" },
  { value: "IN_PROGRESS", label: "En cours" },
];

/** sync_run_history.run_type */
export const RUN_TYPE: Record<string, string> = {
  PERIODIC: "Périodique",
  TRIGGERED: "Déclenché",
  HARD_RESET: "Réinitialisation",
};

/** sync_run_history.trigger_source — the raw code is always shown next to it. */
export const TRIGGER_SOURCE: Record<string, string> = {
  TIMER: "Minuteur",
  STARTUP: "Démarrage",
  CHANGE_DETECTOR: "Changement détecté",
  REMOTE_COMMAND: "Commande du tableau de bord",
  SYNC_NOW_API: "Synchroniser maintenant",
  DATE_FLIP: "Changement de date",
  FAST_PATCH_BUNDLE: "Mise à jour rapide",
  MISSING_MEMBERS: "Membres manquants",
  MANUAL: "Manuel",
};

/** push_batch_history.policy */
export const PUSH_POLICY: Record<string, string> = {
  PRESERVE: "Conserver",
  MIRROR: "Miroir",
  INCREMENTAL: "Incrémental",
  FULL_REPLACE: "Remplacement complet",
  ADDITIVE_ONLY: "Ajout seul",
};

/** push_pin_history.operation */
export const PIN_OPERATION: Record<string, string> = {
  UPSERT: "Ajout / mise à jour",
  DELETE: "Suppression",
};

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const dt = new Date(value);
  return Number.isNaN(dt.getTime()) ? value : dt.toLocaleString("fr-FR");
}

/** « 850 ms » / « 1,8 s » (same thresholds as before, French decimal comma). */
export function formatDuration(ms: number | null | undefined): string {
  const value = Number(ms || 0);
  if (!value) return "—";
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(1).replace(".", ",")} s`;
}
