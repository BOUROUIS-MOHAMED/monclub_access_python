// Erase-content wizard texts, French and English. The rest of the Access UI is French only;
// the owner asked for both languages on this page (2026-09-27), so it carries its own small
// dictionary and a FR/EN switch rather than a new app-wide i18n layer.

export type Lang = "fr" | "en";

const fr = {
  colon: " :",
  title: "Effacer le contenu",
  steps: ["Contenu", "Choix", "Options", "Confirmer", "Exécution"],
  lockTitle: "Réservé à l'administrateur",
  lockText:
    "Saisissez le mot de passe administrateur de la salle. Le serveur le vérifie de nouveau au moment d'effacer.",
  password: "Mot de passe administrateur",
  unlock: "Déverrouiller",
  checking: "Vérification…",
  table: "Table",
  rows: "Lignes",
  readOnly: "Lecture seule : rien n'est modifié à cette étape.",
  reread: "Relire",
  chooseHelp: "Cochez les tables à effacer. Une table grisée ne peut pas être effacée ici.",
  admins: "Administrateurs du terminal (toujours conservés)",
  faces: "Visages enregistrés",
  forgetTitle: "Oublier les enregistrements de MonClub pour ce tourniquet ?",
  forgetYes:
    "Oui — MonClub oublie les membres qu'il avait écrits sur ce tourniquet (à choisir quand on efface les utilisateurs, par exemple pour passer en « Par personne »).",
  forgetNo: "Non — MonClub garde ses enregistrements et réécrit tout le monde au remplissage.",
  forgetNeedsUsers: "« Oui » n'est possible que si les utilisateurs sont effacés aussi.",
  refillTitle: "Remplissage",
  refillNow: "Remplir maintenant",
  refillAuto: "Remplir automatiquement (prochaine synchronisation)",
  refillHold: "Attendre que j'appuie sur « Remplir »",
  refillHoldHelp:
    "Pour la nuit de bascule : effacer, passer le tourniquet en « Par personne », redémarrer Access, puis « Remplir ».",
  refillAutoHelp: "En synchronisation manuelle, le remplissage attend le prochain « Synchroniser ».",
  acceptFaces: (n: number) =>
    `J'accepte la perte de ${n} visage(s) : aucune sauvegarde n'existe pour un visage.`,
  backupOnly: "Sauvegarde seule (répétition) : rien n'est effacé",
  rulesTitle: "Règles de sécurité",
  rules: [
    "Une sauvegarde des tables choisies est écrite dans un fichier et relue avant tout effacement. Si elle échoue, rien n'est effacé.",
    "Pendant l'opération, MonClub n'écrit plus rien sur ce tourniquet. La porte et les lectures continuent.",
    "Seules les tables cochées sont effacées — jamais les paramètres, les fuseaux horaires ni les jours fériés.",
    "Chaque étape est journalisée avec les nombres avant et après.",
  ],
  ruleAdmins: "Les administrateurs du terminal sont conservés.",
  typeName: "Pour confirmer, tapez le nom du tourniquet :",
  summary: "Résumé",
  willErase: "Tables effacées",
  willForget: "Enregistrements de MonClub",
  forgotten: "oubliés",
  kept: "gardés",
  willRefill: "Remplissage",
  erase: "Effacer",
  backupButton: "Sauvegarder",
  back: "Retour",
  next: "Suivant",
  close: "Fermer",
  states: {
    RUNNING: "En cours…",
    DONE: "Terminé",
    FAILED: "Échec — rien n'a été effacé",
    INCOMPLETE: "Incomplet — le tourniquet reste en attente",
  } as Record<string, string>,
  stepLabels: {
    start: "Démarrage",
    hold: "Tourniquet mis en attente (plus aucune écriture de MonClub)",
    idle: "Aucune synchronisation en cours",
    counts_before: "Comptage avant",
    backup: "Sauvegarde écrite, relue et vérifiée",
    erase: "Effacement",
    erase_users: "Utilisateurs effacés (administrateurs conservés)",
    erase_fingerprints: "Empreintes effacées (administrateurs conservés)",
    counts_after: "Comptage après et vérification",
    forget: "Enregistrements de MonClub oubliés",
    keep_records: "Enregistrements gardés : tout sera réécrit",
    wipe_reported: "Effacement noté pour le serveur",
    refill: "Remplissage demandé",
    finish: "Fin",
  } as Record<string, string>,
  eraseOf: (t: string) => `Table ${t} effacée`,
  before: "Avant",
  after: "Après",
  backupFile: "Fichier de sauvegarde",
  holdBanner: "En attente : MonClub n'écrit rien sur ce tourniquet jusqu'à « Remplir ».",
  refillButton: "Remplir maintenant",
  schemeNote: (s: string) =>
    `Le remplissage écrira les membres selon le schéma enregistré maintenant : ${s}.`,
  schemes: { ACCOUNT: "Par personne", MEMBERSHIP: "Par abonnement" } as Record<string, string>,
  mbPasses: (n: number) =>
    `Un terminal autonome reçoit au plus ${n} membres par passage : le remplissage se fait en plusieurs passages.`,
  incompleteHelp:
    "Vérifiez les nombres ci-dessous, puis relancez l'assistant ou appuyez sur « Remplir ». Rien n'a été oublié.",
  refilled: "Remplissage lancé.",
  notOnHold: "Ce tourniquet n'est plus en attente.",
  progress: (d: number, t: number) => `${d} / ${t}`,
  tableLabels: {
    user: "Utilisateurs et cartes (user)",
    userauthorize: "Droits d'accès aux portes (userauthorize)",
    templatev10: "Empreintes v10 (templatev10)",
    template: "Empreintes v9 (template)",
    transaction: "Journal des passages (transaction)",
    users: "Utilisateurs : cartes, mots de passe, empreintes (sauf administrateurs)",
    fingerprints: "Empreintes (sauf administrateurs)",
    attendance: "Journal des passages",
  } as Record<string, string>,
  reasons: {
    DOOR_LOG_NOT_SUPPORTED:
      "Ne peut pas être effacé ici : le PC ne sait pas encore prouver quels passages de ce journal ont déjà été envoyés au serveur.",
    UNREADABLE: "Le terminal n'a pas répondu pour cette table.",
  } as Record<string, string>,
  unknown: "—",
};

const en: typeof fr = {
  colon: ":",
  title: "Erase content",
  steps: ["Content", "Choose", "Options", "Confirm", "Run"],
  lockTitle: "Administrator only",
  lockText:
    "Enter the gym's administrator password. The server checks it again when the erase starts.",
  password: "Administrator password",
  unlock: "Unlock",
  checking: "Checking…",
  table: "Table",
  rows: "Rows",
  readOnly: "Read-only: nothing is changed at this step.",
  reread: "Read again",
  chooseHelp: "Tick the tables to erase. A greyed-out table cannot be erased here.",
  admins: "Terminal administrators (always kept)",
  faces: "Enrolled faces",
  forgetTitle: "Forget MonClub's records for this turnstile?",
  forgetYes:
    "Yes — MonClub forgets the members it had written to this turnstile (choose it when the users are erased, for example to switch to 'Par personne').",
  forgetNo: "No — MonClub keeps its records and writes everyone again at the refill.",
  forgetNeedsUsers: "'Yes' needs the users erased too.",
  refillTitle: "Refill",
  refillNow: "Refill now",
  refillAuto: "Refill automatically (next sync)",
  refillHold: "Hold until I press Refill",
  refillHoldHelp:
    "For the cutover night: erase, switch the turnstile to 'Par personne', restart Access, then Refill.",
  refillAutoHelp: "With manual sync, the refill waits for the next 'Synchronize'.",
  acceptFaces: (n: number) =>
    `I accept the loss of ${n} face template(s): no backup exists for a face.`,
  backupOnly: "Backup only (rehearsal): nothing is erased",
  rulesTitle: "Safety rules",
  rules: [
    "A backup of the chosen tables is written to a file and read back before anything is erased. If it fails, nothing is erased.",
    "During the run MonClub writes nothing to this turnstile. The door and the scans keep working.",
    "Only the ticked tables are erased — never the parameters, time zones or holidays.",
    "Every step is logged with the counts before and after.",
  ],
  ruleAdmins: "The terminal's administrators are kept.",
  typeName: "To confirm, type the turnstile's name:",
  summary: "Summary",
  willErase: "Tables erased",
  willForget: "MonClub's records",
  forgotten: "forgotten",
  kept: "kept",
  willRefill: "Refill",
  erase: "Erase",
  backupButton: "Back up",
  back: "Back",
  next: "Next",
  close: "Close",
  states: {
    RUNNING: "Running…",
    DONE: "Done",
    FAILED: "Failed — nothing was erased",
    INCOMPLETE: "Incomplete — the turnstile stays on hold",
  },
  stepLabels: {
    start: "Start",
    hold: "Turnstile on hold (no more writes from MonClub)",
    idle: "No sync running",
    counts_before: "Counts before",
    backup: "Backup written, read back and checked",
    erase: "Erase",
    erase_users: "Users erased (administrators kept)",
    erase_fingerprints: "Fingerprints erased (administrators kept)",
    counts_after: "Counts after, and check",
    forget: "MonClub's records forgotten",
    keep_records: "Records kept: everyone will be written again",
    wipe_reported: "Erase noted for the server",
    refill: "Refill requested",
    finish: "End",
  },
  eraseOf: (t: string) => `Table ${t} erased`,
  before: "Before",
  after: "After",
  backupFile: "Backup file",
  holdBanner: "On hold: MonClub writes nothing to this turnstile until Refill.",
  refillButton: "Refill now",
  schemeNote: (s: string) => `The refill writes the members under the scheme recorded now: ${s}.`,
  schemes: { ACCOUNT: "Par personne (per person)", MEMBERSHIP: "Par abonnement (per membership)" },
  mbPasses: (n: number) =>
    `A standalone terminal receives at most ${n} members per pass: the refill takes several passes.`,
  incompleteHelp:
    "Check the counts below, then run the wizard again or press Refill. Nothing was forgotten.",
  refilled: "Refill started.",
  notOnHold: "This turnstile is no longer on hold.",
  progress: (d: number, t: number) => `${d} / ${t}`,
  tableLabels: {
    user: "Users and cards (user)",
    userauthorize: "Door rights (userauthorize)",
    templatev10: "Fingerprints v10 (templatev10)",
    template: "Fingerprints v9 (template)",
    transaction: "Door log (transaction)",
    users: "Users: cards, passwords, fingerprints (administrators kept)",
    fingerprints: "Fingerprints (administrators kept)",
    attendance: "Attendance log",
  },
  reasons: {
    DOOR_LOG_NOT_SUPPORTED:
      "Cannot be erased here: the PC cannot yet prove which events of this log were already sent to the server.",
    UNREADABLE: "The terminal did not answer for this table.",
  },
  unknown: "—",
};

export const ERASE_TEXT: Record<Lang, typeof fr> = { fr, en };

const LANG_KEY = "monclub:erase-wizard-lang";

export function loadLang(): Lang {
  try {
    const v = localStorage.getItem(LANG_KEY);
    return v === "en" ? "en" : "fr";
  } catch {
    return "fr";
  }
}

export function saveLang(lang: Lang): void {
  try {
    localStorage.setItem(LANG_KEY, lang);
  } catch {
    /* a private window: the choice lasts for this page only */
  }
}
