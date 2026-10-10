// The watchdog card's logic and texts (design section 12, owner decision O7). Pure TypeScript
// so node:test can run it. The rest of the Access UI is French only; this card carries its
// own small French / English dictionary, like the Erase-content wizard (eraseWizardText.ts).

export type Lang = "fr" | "en";

export type WatchdogLastResult = "ok" | "running" | "not_run_yet" | "failed" | null;

export interface WatchdogLogEntry {
  at: string | null;
  rawAt: string | null;
  level: string | null;
  message: string;
  fromLastCheck: boolean;
}

// GET /api/v2/watchdog -> { ok, watchdog } (access/watchdog_control.py).
export interface WatchdogStatus {
  taskName: string;
  registered: boolean | null; // null = the task could not be read (lastError)
  enabled: boolean | null;
  state: string | null;
  lastRunAt: string | null;
  lastResult: WatchdogLastResult;
  lastResultCode: number | null;
  nextRunAt: string | null;
  intervalMinutes: number | null;
  restartsLastHour: number;
  stoodDown: boolean;
  stoodDownReason: string | null;
  scriptPath: string | null;
  lastLogEntry: WatchdogLogEntry | null;
  lastError: string | null;
  available: boolean; // an installed build: the switch may change the task
  installRoot: string | null;
  checkedAt: string | null;
}

export type WatchdogChip = "loading" | "on" | "off" | "notInstalled" | "error" | "stoodDown";

// A failed read shows Error even when an older status is on screen (that status may be stale).
export function watchdogChip(status: WatchdogStatus | null, fetchError: string | null): WatchdogChip {
  if (fetchError) return "error";
  if (!status) return "loading";
  if (status.lastError || status.registered === null) return "error";
  if (!status.registered) return "notInstalled";
  if (!status.enabled) return "off";
  if (status.stoodDown) return "stoodDown";
  if (status.lastResult === "failed") return "error";
  return "on";
}

export function chipVariant(chip: WatchdogChip): "success" | "secondary" | "warning" | "destructive" | "outline" {
  switch (chip) {
    case "on": return "success";
    case "off": return "secondary";
    case "notInstalled": return "outline";
    case "stoodDown": return "warning";
    case "error": return "destructive";
    default: return "outline";
  }
}

// Turning it OFF asks first; turning it on does not.
export function needsConfirm(nextEnabled: boolean): boolean {
  return !nextEnabled;
}

export function switchDisabled(status: WatchdogStatus | null, busy: boolean, fetchError: string | null = null): boolean {
  return busy || !!fetchError || !status || !status.available || status.registered === null;
}

const fr = {
  title: "Garder MonClub Access en marche (watchdog)",
  explain: (minutes: number) =>
    `Toutes les ${minutes} minutes, Windows vérifie que MonClub Access tourne et le relance tout seul s'il s'est arrêté (plantage, mise à jour interrompue, coupure de courant).`,
  chip: {
    loading: "Lecture…",
    on: "Activé",
    off: "Désactivé",
    notInstalled: "Non installé",
    error: "Erreur",
    stoodDown: "En pause après des plantages répétés",
  } as Record<WatchdogChip, string>,
  switchLabel: "Relancer MonClub Access automatiquement",
  lastCheck: "Dernière vérification",
  never: "jamais",
  result: {
    ok: "OK",
    running: "vérification en cours",
    not_run_yet: "pas encore faite",
    failed: (code: string) => `échec (code ${code})`,
  },
  lastEvent: "Dernier message du watchdog",
  restarts: (n: number) => `Relances dans la dernière heure : ${n}`,
  stoodDown: (n: number) =>
    n >= 5
      ? `MonClub Access a été relancé ${n} fois dans la dernière heure : le watchdog ne le relancera plus avant la fin de cette heure. Il faut regarder pourquoi il s'arrête.`
      : "Le watchdog a refusé de relancer MonClub Access après des plantages répétés. Il faut regarder pourquoi il s'arrête.",
  notInstalled: "La tâche du watchdog n'existe pas sur ce PC. L'activer la crée.",
  offHint: "Désactivé : MonClub Access ne redémarre pas tout seul. Les mises à jour le laissent désactivé.",
  unavailable: "Ce réglage ne peut être changé que dans MonClub Access installé (pas en mode développement).",
  readError: "Impossible de lire l'état du watchdog :",
  changeError: "Le changement n'a pas pu être fait :",
  confirmTitle: "Désactiver le watchdog ?",
  confirmBody:
    "MonClub Access ne redémarrera plus tout seul après un plantage ou une mise à jour interrompue.",
  confirmOk: "Désactiver",
  cancel: "Annuler",
  refresh: "Actualiser",
  saving: "Modification…",
  langSwitch: "EN",
};

type Texts = typeof fr;

const en: Texts = {
  title: "Keep MonClub Access running (watchdog)",
  explain: (minutes: number) =>
    `Every ${minutes} minutes Windows checks that MonClub Access is running and starts it again by itself if it stopped (crash, interrupted update, power cut).`,
  chip: {
    loading: "Reading…",
    on: "On",
    off: "Off",
    notInstalled: "Not installed",
    error: "Error",
    stoodDown: "Stood down after repeated crashes",
  },
  switchLabel: "Restart MonClub Access automatically",
  lastCheck: "Last check",
  never: "never",
  result: {
    ok: "OK",
    running: "check running",
    not_run_yet: "not done yet",
    failed: (code: string) => `failed (code ${code})`,
  },
  lastEvent: "Last watchdog message",
  restarts: (n: number) => `Restarts in the last hour: ${n}`,
  stoodDown: (n: number) =>
    n >= 5
      ? `MonClub Access was restarted ${n} times in the last hour: the watchdog will not restart it again before that hour is over. Someone needs to look at why it stops.`
      : "The watchdog refused to restart MonClub Access after repeated crashes. Someone needs to look at why it stops.",
  notInstalled: "The watchdog task does not exist on this PC. Turning it on creates it.",
  offHint: "Off: MonClub Access does not restart by itself. Updates leave it off.",
  unavailable: "This setting can only be changed in an installed MonClub Access (not in development mode).",
  readError: "Could not read the watchdog status:",
  changeError: "The change could not be made:",
  confirmTitle: "Turn the watchdog off?",
  confirmBody: "Access will not restart by itself after a crash or an interrupted update.",
  confirmOk: "Turn off",
  cancel: "Cancel",
  refresh: "Refresh",
  saving: "Saving…",
  langSwitch: "FR",
};

export function watchdogTexts(lang: Lang): Texts {
  return lang === "en" ? en : fr;
}

export function hexCode(code: number | null): string {
  if (code === null || !Number.isFinite(code)) return "?";
  return "0x" + (code >>> 0).toString(16).toUpperCase();
}

export function formatWhen(iso: string | null, lang: Lang): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleString(lang === "fr" ? "fr-FR" : "en-GB", {
    day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit",
  });
}

// "Last check: <time> — <result>". When the last check wrote a watchdog log line, that line
// IS its result (the healthy path logs nothing, so a plain "OK" means Access was running).
export function lastCheckText(status: WatchdogStatus, lang: Lang): string {
  const t = watchdogTexts(lang);
  const when = formatWhen(status.lastRunAt, lang) ?? t.never;
  let result = "";
  if (status.lastRunAt) {
    if (status.lastLogEntry?.fromLastCheck) result = status.lastLogEntry.message;
    else if (status.lastResult === "failed") result = t.result.failed(hexCode(status.lastResultCode));
    else if (status.lastResult) result = t.result[status.lastResult];
  }
  const sep = lang === "fr" ? " : " : ": ";
  return result ? `${t.lastCheck}${sep}${when} — ${result}` : `${t.lastCheck}${sep}${when}`;
}

export const WATCHDOG_LANG_KEY = "monclub:watchdog-card-lang";

export function loadLang(): Lang {
  try {
    return localStorage.getItem(WATCHDOG_LANG_KEY) === "en" ? "en" : "fr";
  } catch {
    return "fr";
  }
}

export function saveLang(lang: Lang): void {
  try {
    localStorage.setItem(WATCHDOG_LANG_KEY, lang);
  } catch {
    // per-viewer convenience only
  }
}
