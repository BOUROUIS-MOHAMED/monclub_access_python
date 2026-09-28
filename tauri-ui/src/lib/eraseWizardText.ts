// Erase-content wizard texts, French and English. The rest of the Access UI is French only;
// the owner asked for both languages on this page (2026-09-27), so it carries its own small
// dictionary and a FR/EN switch rather than a new app-wide i18n layer.

export type Lang = "fr" | "en";

// What an erase takes from the people the refill does not put back (lane 1d, review nit): the
// user itself, or only door rights and / or fingerprints -- their user and card then stay.
export type NotRefilledWhat = "users" | "rights" | "fingers" | "rightsFingers";

const fr = {
  colon: " :",
  title: "Effacer le contenu",
  steps: ["Contenu", "Choix", "Options", "Confirmer", "Exécution"],
  lockTitle: "Réservé à l'administrateur",
  lockText:
    "Saisissez le mot de passe administrateur de la salle. Le serveur MonClub le vérifie ici, puis de nouveau au moment d'effacer et pour « Remplir » : l'effacement comme le remplissage demandent Internet.",
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
  forgetForcedMb:
    "Obligatoire quand on efface les utilisateurs d'un terminal autonome : sinon MonClub tenterait de supprimer des membres déjà partis.",
  requiredByUser:
    "Effacée avec les utilisateurs : sinon les droits et les empreintes restent et passent au prochain membre qui reçoit le même numéro.",
  refillTitle: "Remplissage",
  refillNow: "Remplir maintenant",
  refillAuto: "Remplir automatiquement (prochaine synchronisation)",
  refillHold: "Attendre que j'appuie sur « Remplir »",
  refillHoldHelp:
    "Pour la nuit de bascule : effacer, passer le tourniquet en « Par personne », redémarrer Access, puis « Remplir ».",
  heldAlready:
    "Ce tourniquet est déjà en attente depuis un effacement : seul le bouton « Remplir » le libère. Choisissez « Attendre que j'appuie sur « Remplir » ».",
  refillWillWrite: (n: number, s: string) => `Le remplissage écrira ${n} membre(s) sur ce tourniquet (schéma ${s}).`,
  // The list's time, in the refill line (lane 1c): the last SUCCESSFUL sync, and the limit.
  listAge: (ageSec: number | null | undefined, maxSec: number | null | undefined) =>
    (ageSec === null || ageSec === undefined
      ? "Liste des membres : aucune synchronisation réussie depuis le démarrage d'Access."
      : `Liste des membres reçue de MonClub ${ageSec < 60 ? "il y a moins d'une minute" : `il y a ${Math.floor(ageSec / 60)} min`}`
        + (maxSec ? ` (elle doit dater de moins de ${Math.round(maxSec / 60)} min).` : ".")),
  stale: {
    TOO_OLD: (ageSec: number | null | undefined, maxSec: number | null | undefined) =>
      `La liste des membres n'est pas récente : la dernière synchronisation réussie date de ${Math.floor((ageSec ?? 0) / 60)} min (limite ${Math.round((maxSec ?? 600) / 60)} min). Attendez la prochaine synchronisation, puis relisez : rien n'est effacé.`,
    LAST_SYNC_FAILED: () =>
      "La dernière synchronisation avec MonClub n'a pas réussi : la liste des membres peut être incomplète. Attendez la prochaine synchronisation réussie, puis relisez : rien n'est effacé.",
    NO_SYNC_YET: () =>
      "Aucune synchronisation avec MonClub n'a encore réussi depuis le démarrage d'Access : la liste des membres peut être incomplète. Attendez la prochaine synchronisation, puis relisez : rien n'est effacé.",
  } as Record<string, (ageSec: number | null | undefined, maxSec: number | null | undefined) => string>,
  refillIfAccount: (n: number, w: number) =>
    w > 0
      ? `En « Par personne » : ${n} membre(s), et ${w} sans numéro de compte, qui ne seraient pas écrits.`
      : `En « Par personne » : ${n} membre(s).`,
  refillCacheAt: (s: string) => `Liste des membres de ce PC enregistrée le ${s}.`,
  withheldOnlyIfAccount:
    "Ce blocage ne concerne que « Attendre que j'appuie sur « Remplir » » (prévu pour passer en « Par personne ») : sans changement de schéma, « Remplir maintenant » écrit tout le monde.",
  lockoutHold:
    "Après cet effacement, AUCUN membre ne passe au tourniquet par carte ou par empreinte tant que « Remplir » n'est pas fait (Internet requis).",
  lockoutRefill:
    "Pendant l'effacement et jusqu'à la fin du remplissage, les membres ne passent pas au tourniquet par carte ou par empreinte.",
  // Fingerprints only (lane 1c, review nit): the cards keep working.
  lockoutFingersHold:
    "Après cet effacement, les membres qui passent par empreinte ne passent plus tant que « Remplir » n'est pas fait (Internet requis). Les cartes continuent de fonctionner.",
  lockoutFingersRefill:
    "Pendant l'effacement et jusqu'à la fin du remplissage, les membres qui passent par empreinte ne passent pas. Les cartes continuent de fonctionner.",
  // Why a finished run kept its hold (the run's finish note, lane 1c review nit).
  finishNotes: {
    HELD_BEFORE: "Le tourniquet était déjà en attente depuis un effacement précédent : il le reste. Appuyez sur « Remplir ».",
    PIN_SCHEME_CHANGED: "Le schéma de numérotation a changé pendant l'effacement : le tourniquet reste en attente. Vérifiez le schéma, puis appuyez sur « Remplir ».",
    PIN_SCHEME_UNREADABLE: "Le schéma de numérotation n'a pas pu être relu à la fin : le tourniquet reste en attente. Appuyez sur « Remplir ».",
    // Lane 1e (master review C0): « Remplir » is refused on these holds until the scheme is the
    // terminal's again -- the server checks it from the hold row, which a restart keeps.
    HELD_SCHEME_MOVED:
      "Le schéma de numérotation a changé pendant l'opération, avant tout effacement : le tourniquet reste en attente, même après un redémarrage d'Access, car il porte encore tous les numéros de l'ancien schéma. « Remplir » est refusé tant que le schéma enregistré n'est pas revenu à l'ancien. Pour continuer : remettez l'ancien schéma dans le tableau de bord, puis effacez-le à nouveau avec « Attendre que j'appuie sur « Remplir » » (ou « Remplir » pour le libérer sans rien effacer).",
    HELD_SCHEME_UNREADABLE:
      "Le schéma de numérotation n'a pas pu être relu après l'arrêt : le tourniquet reste en attente par prudence, même après un redémarrage d'Access (rien n'a été effacé). « Remplir » n'est accepté que sous le schéma de l'étape 1 : vérifiez le schéma dans le tableau de bord ; inchangé, « Remplir » remet tout le monde ; changé, remettez-le, ou effacez à nouveau avec « Attendre… ».",
    // The same holds, not recorded as kept (lane 1d; "may not" since lane 1e: the next start
    // still keeps the row when the scheme then differs).
    HELD_SCHEME_MOVED_SESSION:
      "Le schéma de numérotation a changé pendant l'opération, avant tout effacement : le tourniquet reste en attente, mais cette attente n'a pas pu être enregistrée et risque de ne PAS tenir après un redémarrage d'Access. Ne redémarrez pas Access : remettez l'ancien schéma dans le tableau de bord, puis effacez-le à nouveau avec « Attendre que j'appuie sur « Remplir » » (ou « Remplir » pour le libérer sans rien effacer).",
    HELD_SCHEME_UNREADABLE_SESSION:
      "Le schéma de numérotation n'a pas pu être relu après l'arrêt : le tourniquet reste en attente par prudence (rien n'a été effacé), mais cette attente n'a pas pu être enregistrée et risque de ne PAS tenir après un redémarrage d'Access. Vérifiez le schéma dans le tableau de bord avant tout redémarrage, puis « Remplir » (ou effacez à nouveau avec « Attendre… » s'il a changé).",
    // Lane 1e (master review nit): the turnstile deleted in MonClub during the run.
    HELD_DEVICE_GONE:
      "Ce tourniquet a été supprimé dans MonClub pendant l'opération, avant tout effacement : rien n'a été effacé. Il reste en attente jusqu'au prochain redémarrage d'Access ; rien à faire.",
  } as Record<string, string>,
  // The people the refill will NOT put back (lane 1c, review C0).
  notRefilledTitle: (n: number, s: string, what: NotRefilledWhat) =>
    `${n} personne(s) de ce tourniquet ${{
      users: "ne seront PAS remises par le remplissage",
      rights: "perdront leurs droits d'accès, et le remplissage ne les leur rendra PAS",
      fingers: "perdront leurs empreintes, et le remplissage ne les leur rendra PAS",
      rightsFingers: "perdront leurs droits d'accès et leurs empreintes, et le remplissage ne les leur rendra PAS",
    }[what]} : elles ne sont pas dans la liste des membres de MonClub pour ce tourniquet (schéma ${s}) — personnel ou agents d'entretien enregistrés sur le tourniquet, utilisateurs d'un autre système, membres qui n'y ont plus droit. ${what === "users" ? "Ce que l'effacement leur retire (utilisateur, carte, droits, empreintes) ne revient pas." : "Leur utilisateur et leur carte restent sur le tourniquet."}`,
  notRefilledBackup:
    "Leur seule copie est la sauvegarde de cet effacement : elle est gardée sans limite de durée (jamais supprimée après 30 jours).",
  notRefilledTick: (n: number) =>
    `J'ai lu la liste : le remplissage ne rendra pas à ces ${n} personne(s) ce que l'effacement leur retire.`,
  notRefilledNone: "Chaque personne de ce tourniquet est dans la liste du remplissage.",
  notRefilledUnknown:
    "La liste des utilisateurs du tourniquet n'a pas pu être lue : on ne sait pas qui le remplissage ne remettrait pas. Relisez l'étape 1.",
  notRefilledKept: (n: number) =>
    `${n} personne(s) hors de la liste du remplissage ont perdu ce que cet effacement leur a retiré : la sauvegarde de cet effacement est gardée sans limite de durée.`,
  otherPcsTitle:
    "Fermez MonClub Access sur tous les autres PC de cette salle et gardez-le fermé jusqu'au remplissage (« Remplir ») : la mise en attente ne vaut que pour CE PC, les autres continueraient d'écrire sur ce tourniquet. Quitter ne suffit pas : le watchdog d'Access le relance en quelques minutes, et le démarrage avec Windows à la prochaine ouverture de session.",
  otherPcsTick:
    "MonClub Access est fermé sur tous les autres PC de cette salle — sur chacun : « Ouvrir MonClub Access avec Windows » décoché, watchdog désactivé (Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'), puis Quitter — et le restera jusqu'au remplissage.",
  deviceLine: (name: string, ip: string, port: string, sdk: string) =>
    `Tourniquet : ${name} — adresse ${ip}:${port} — ${sdk}. L'effacement est lié à cette adresse.`,
  sdkNames: { ZK_PULLSDK: "PullSDK (contrôleur C3)", ZK_STANDALONE: "zkemkeeper (terminal autonome)" } as Record<string, string>,
  phases: {
    backup_fingers: "Sauvegarde des empreintes",
    erase_users: "Effacement des utilisateurs",
    erase_fingers: "Effacement des empreintes",
  } as Record<string, string>,
  errorDetail: "Détail",
  noAnswerYet: "Pas de réponse à temps : lecture de l'état de l'effacement…",
  refillAutoHelp: "En synchronisation manuelle, le remplissage attend le prochain « Synchroniser ».",
  acceptFaces: (n: number) =>
    `J'accepte la perte de ${n} visage(s) : aucune sauvegarde n'existe pour un visage.`,
  acceptFacesUnknown:
    "Le terminal n'a pas donné son nombre de visages : j'accepte la perte des visages éventuels (aucune sauvegarde n'existe pour un visage).",
  backupOnly: "Sauvegarde seule (répétition) : rien n'est effacé",
  rulesTitle: "Règles de sécurité",
  rules: [
    "Une sauvegarde des tables choisies est écrite dans un fichier et relue avant tout effacement. Si elle échoue, rien n'est effacé.",
    "Pendant l'opération, MonClub n'écrit plus aucun membre sur ce tourniquet. La porte et les lectures continuent.",
    "Seules les tables cochées sont effacées — jamais les paramètres, les fuseaux horaires ni les jours fériés.",
    "Si l'effacement ne se termine pas vérifié, le tourniquet reste en attente, rien n'est oublié et tout sera réécrit au remplissage.",
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
    erase_recorded: "Effacement enregistré : le dernier résultat d'écriture de chaque membre devient « inconnu »",
    not_refilled: "Personnes hors de la liste du remplissage vérifiées sur la sauvegarde",
    forget: "Enregistrements de MonClub oubliés",
    keep_records: "Enregistrements gardés : tout sera réécrit",
    records_invalidated: "Enregistrements gardés, marqués à réécrire",
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
  schemeChanged: (s: string) =>
    `Le schéma a changé depuis l'affichage : c'est maintenant ${s}. Vérifiez-le, puis appuyez de nouveau sur « Remplir ».`,
  // A hold kept because the scheme moved before any delete (lane 1e, master review C0): read from
  // the hold row (/erase/holds: reason, terminalScheme), so it shows after a restart too.
  schemeMovedHold: (terminal: string | null, now: string) =>
    (terminal
      ? `Rien n'a été effacé sur ce tourniquet : le schéma de numérotation a changé pendant un effacement, avant toute suppression. Il porte encore les numéros « ${terminal} », et le schéma enregistré maintenant est « ${now} ». « Remplir » est refusé tant que le schéma n'est pas revenu à « ${terminal} » : remettez-le dans le tableau de bord, ou effacez à nouveau le tourniquet avec « Attendre que j'appuie sur « Remplir » ».`
      : "Rien n'a été effacé sur ce tourniquet, et le schéma avec lequel ses numéros ont été écrits n'est pas enregistré : « Remplir » est refusé. Effacez-le à nouveau avec « Attendre que j'appuie sur « Remplir » »."),
  schemeMovedBack: (terminal: string) =>
    `Rien n'a été effacé sur ce tourniquet : le schéma avait changé pendant un effacement, avant toute suppression. Il est revenu à « ${terminal} », celui de ses numéros : « Remplir » le libère et remet tout le monde, sans rien effacer. Pour continuer la bascule, effacez-le plutôt à nouveau avec « Attendre que j'appuie sur « Remplir » ».`,
  holdsUnknown:
    "Access n'a pas pu relire les mises en attente : tous les tourniquets restent en attente jusqu'à la prochaine lecture réussie.",
  refillNeedsInternet: "Le remplissage demande Internet : le serveur vérifie le mot de passe.",
  handoverWaits:
    "Tant qu'il est en attente, ce tourniquet n'est pas cédé à un autre PC : un changement de PC pilote attend « Remplir ».",
  codes: {
    ADDRESS_CHANGED:
      "Le terminal est encore connecté à son ancienne adresse IP : attendez qu'Access se reconnecte (jusqu'à 30 min) ou redémarrez Access, puis relisez.",
    ADDRESS_UNKNOWN: "Access ne connaît pas l'adresse de la connexion ouverte avec ce terminal : relisez dans un instant.",
    REFILL_IN_PROGRESS: "Un remplissage de ce tourniquet est en cours : réessayez dans un instant.",
    RUN_IN_PROGRESS: "Un effacement est déjà en cours.",
    HOLD_CHANGED: "La mise en attente de ce tourniquet a changé entre-temps : fermez et rouvrez la fenêtre.",
    HOLDS_UNKNOWN: "Access n'a pas pu relire les mises en attente : rien n'est effacé ni rempli pour l'instant.",
    ADMIN_PASSWORD_UNCHECKABLE:
      "Pas d'Internet : le serveur MonClub doit vérifier le mot de passe (pour effacer comme pour « Remplir »). Rétablissez la connexion, puis réessayez.",
    ADMIN_PASSWORD: "Mot de passe incorrect.",
    ADMIN_PASSWORD_REQUIRED: "Saisissez le mot de passe administrateur.",
    PC_NOT_SIGNED_IN: "Ce PC n'est pas connecté à MonClub : le mot de passe ne peut pas être vérifié. Reconnectez ce PC, puis réessayez.",
    ADMIN_PASSWORD_CHECK_FAILED: "Le serveur MonClub n'a pas pu vérifier le mot de passe : réessayez dans un instant.",
    PREVIEW_EXPIRED: "La lecture de l'étape 1 date de plus de 15 minutes : revenez à l'étape 1 et relisez.",
    WRONG_DEVICE: "Cette lecture concerne un autre tourniquet : relisez l'étape 1.",
    DEVICE_CHANGED: "Le nom, l'adresse ou le SDK du tourniquet a changé depuis l'étape 1 : relisez.",
    NO_DEVICE: "Tourniquet inconnu.",
    NO_DEVICE_NAME: "Ce tourniquet n'a pas de nom dans MonClub : nommez-le avant d'effacer.",
    NAME_MISMATCH: "Le nom tapé n'est pas celui de ce tourniquet.",
    NO_TABLES: "Choisissez au moins une table.",
    UNKNOWN_TABLE: "Table inconnue.",
    NOT_ERASABLE: "Cette table ne peut pas être effacée par l'assistant.",
    DOOR_LOG_NOT_SUPPORTED: "Le journal des passages ne peut pas être effacé ici.",
    UNREADABLE: "Le terminal n'a pas répondu pour cette table : relisez l'étape 1.",
    FORGET_REQUIRED: "Choisissez si MonClub oublie ses enregistrements.",
    FORGET_NEEDS_USERS: "« Oublier » demande que les utilisateurs soient effacés aussi.",
    USER_NEEDS_RIGHTS_AND_FINGERS: "Effacer les utilisateurs demande d'effacer aussi les droits et les empreintes lisibles.",
    USERS_ERASE_NEEDS_FORGET: "Effacer les utilisateurs d'un terminal autonome demande « Oublier ».",
    REFILL_REQUIRED: "Choisissez quand le tourniquet est rempli.",
    FACES_UNKNOWN: "Le terminal n'a pas donné son nombre de visages : acceptez leur perte éventuelle (étape 3).",
    FACES_PRESENT: "Des visages sont enregistrés et ne peuvent pas être sauvegardés : acceptez leur perte (étape 3).",
    NOT_DRIVER: "Ce PC ne pilote pas ce tourniquet.",
    HANDOVER_IN_PROGRESS: "Ce tourniquet est en cours de passage à un autre PC.",
    ADD_ONLY: "Ce tourniquet n'accepte que des ajouts pour l'instant (changement de PC pilote non terminé) : aucun effacement.",
    NO_WORKER: "Aucune connexion Access en cours avec ce tourniquet sur ce PC.",
    NOT_CONNECTED: "Le tourniquet n'est pas connecté.",
    UNSUPPORTED_PROTOCOL: "Le SDK de ce tourniquet n'est pas pris en charge par l'assistant.",
    STATUS_UNREADABLE: "Le terminal n'a pas donné ses compteurs : relisez dans un instant.",
    PIN_SCHEME_UNREADABLE: "Le schéma de numérotation de ce tourniquet n'a pas pu être lu : réessayez.",
    PIN_SCHEME_REQUIRED: "Relisez la fenêtre : le schéma affiché manque.",
    RUN_NOT_STARTED: "L'effacement n'a pas pu démarrer : rien n'a été effacé. Réessayez.",
    NOT_ON_HOLD: "Ce tourniquet n'est plus en attente.",
    RECORDS_NOT_RESET: "Les enregistrements de MonClub n'ont pas pu être remis à zéro : le tourniquet reste en attente. Réessayez.",
    OTHER_PCS_NOT_CONFIRMED:
      "Confirmez que MonClub Access est fermé sur tous les autres PC de cette salle (watchdog désactivé, « Ouvrir MonClub Access avec Windows » décoché).",
    HELD_USE_REFILL:
      "Ce tourniquet est déjà en attente depuis un effacement : choisissez « Attendre que j'appuie sur « Remplir » », puis appuyez sur « Remplir ».",
    REFILL_SOURCE_MISSING:
      "Ce PC n'a pas de liste des membres pour remplir le tourniquet : rien n'est effacé. Synchronisez, puis relisez.",
    REFILL_SOURCE_STALE:
      "La liste des membres de ce PC n'est pas récente (dernière synchronisation en échec, trop ancienne, ou aucune depuis le démarrage d'Access) : attendez la prochaine synchronisation, puis relisez. Rien n'est effacé.",
    REFILL_SOURCE_EMPTY: "Le remplissage n'écrirait aucun membre sur ce tourniquet : rien n'est effacé.",
    REFILL_WITHHELD:
      "Des membres n'ont pas de numéro de compte dans la liste de ce PC : en « Par personne », le remplissage ne les écrirait pas. La liste des membres doit d'abord être relue en entier.",
    BUSY: "Une synchronisation en cours ne s'est pas terminée à temps : rien n'a été effacé. Réessayez.",
    BACKUP_INCOMPLETE: "La sauvegarde ne correspond pas aux compteurs du terminal : rien n'a été effacé.",
    BACKUP_UNVERIFIABLE: "Le terminal n'a pas donné tous ses compteurs : la sauvegarde ne peut pas être vérifiée, rien n'a été effacé.",
    BACKUP_UNTRUSTED: "La liste lue sur le terminal n'est pas fiable : rien n'a été effacé.",
    BACKUP_WRITE: "Le fichier de sauvegarde n'a pas pu être écrit ou relu : rien n'a été effacé.",
    RESULTS_NOT_RESET: "L'effacement n'a pas pu être enregistré avant la première suppression : rien n'a été effacé.",
    ADMIN_PIN_IN_ROSTER:
      "Un administrateur du terminal a le même numéro qu'un membre : le remplissage l'écraserait. Changez le numéro de cet administrateur sur le terminal : rien n'a été effacé.",
    NOT_REFILLED_UNKNOWN:
      "La liste des utilisateurs du tourniquet n'a pas pu être lue : on ne sait pas qui le remplissage ne remettrait pas. Relisez l'étape 1 : rien n'est effacé.",
    NOT_REFILLED_UNCONFIRMED:
      "Des personnes de ce tourniquet ne seront pas remises par le remplissage : cochez la case qui le confirme (étape 4).",
    NOT_REFILLED_CHANGED:
      "Au moment d'effacer, le tourniquet portait des personnes hors de la liste du remplissage qui n'étaient pas affichées à l'étape 1 : rien n'a été effacé. Relisez l'étape 1.",
    KEEP_MARK_NOT_WRITTEN:
      "La marque qui garde la sauvegarde sans limite de durée n'a pas pu être écrite : rien n'a été effacé. L'effacement était déjà enregistré : le tourniquet reste en attente, et « Remplir » réécrit tout le monde.",
    HELD_SCHEME_MOVED:
      "« Remplir » refusé : rien n'a été effacé sur ce tourniquet, et il porte encore les numéros d'un autre schéma que celui enregistré maintenant. Remettez ce schéma dans le tableau de bord, puis réessayez ; ou effacez-le à nouveau avec « Attendre que j'appuie sur « Remplir » ».",
    TLS_CLOCK:
      "Le serveur MonClub a refusé la connexion sécurisée : la date ou l'heure de ce PC est sans doute fausse (ou le certificat du serveur a expiré). Vérifiez la date et l'heure de Windows ; si elles sont justes, appelez le développeur. Rien n'a été modifié.",
    PIN_SCHEME_CHANGED:
      "Le schéma de numérotation du tourniquet a changé depuis l'étape 1 : rien n'a été effacé. Relisez l'étape 1.",
    NOT_VERIFIED: "L'effacement n'a pas pu être vérifié : des lignes restent, ou un comptage ou une liste n'a pas répondu.",
    ERASE_FAILED: "Une commande d'effacement a échoué : une partie a peut-être été effacée.",
    NO_ANSWER: "Une commande a été envoyée sans réponse : elle a peut-être agi.",
    NOT_SENT: "Une commande n'a pas été envoyée (délai ou connexion perdue).",
    DEVICE_ERROR: "Une commande au terminal a échoué.",
    UNEXPECTED: "Erreur inattendue d'Access.",
    ERASE_NOT_ENABLED:
      "L'effacement n'est pas activé pour cette salle — le propriétaire peut l'activer dans le tableau de bord (page PC d'accès).",
    ERASE_SWITCH_UNCHECKED:
      "L'activation de l'effacement pour cette salle n'a pas pu être vérifiée : le serveur MonClub a répondu autre chose que prévu. Rien n'est effacé.",
    ERASE_SWITCH_MISSING:
      "Le serveur MonClub ne propose pas encore l'activation de l'effacement : l'effacement n'est pas disponible avant sa mise à jour. Rien n'est effacé ; réessayer ne change rien d'ici là.",
    ERASE_SWITCH_UNREACHABLE:
      "Le serveur MonClub n'a pas répondu à la vérification de l'activation : vérifiez Internet, puis réessayez. Rien n'est effacé.",
  } as Record<string, string>,
  schemes: { ACCOUNT: "Par personne", MEMBERSHIP: "Par abonnement" } as Record<string, string>,
  mbPasses: (n: number) =>
    `Un terminal autonome reçoit au plus ${n} membres par passage : le remplissage se fait en plusieurs passages.`,
  incompleteHelp:
    "Vérifiez les nombres ci-dessous, puis relancez l'assistant ou appuyez sur « Remplir » : MonClub réécrira tous ses membres. Rien n'a été oublié.",
  refilled: "Remplissage lancé.",
  refilledWith: (s: string) => `Remplissage lancé, schéma ${s}.`,
  backupsNotMarked:
    "Attention : la date du remplissage n'a pas pu être notée dans les sauvegardes ; elles seront supprimées 30 jours après l'effacement.",
  // What « Remplir » reports (lane 1c, review F1): warnings, never a refusal.
  refillWarn: {
    REFILL_WITHHELD: (n: number, s: string) =>
      `Attention : ${n} membre(s) n'ont pas de numéro de compte dans la liste de ce PC : en « ${s} », ils ne sont pas écrits sur le tourniquet.`,
    REFILL_SOURCE_STALE: () =>
      "Attention : la liste des membres de ce PC n'est pas récente : le remplissage écrit la liste qu'il a ; la prochaine synchronisation réussie apportera les changements.",
    REFILL_SOURCE_MISSING: () =>
      "Attention : ce PC n'a pas de liste des membres : le tourniquet reste vide jusqu'à ce qu'une synchronisation en apporte une.",
    REFILL_SOURCE_EMPTY: () =>
      "Attention : la liste des membres de ce PC ne contient aucun membre pour ce tourniquet : rien n'y est écrit.",
  } as Record<string, (n: number, s: string) => string>,
  adminClash: (pins: string[], s: string) =>
    `D'après la sauvegarde de l'effacement, ${pins.length} administrateur(s) du terminal ont le même numéro qu'un membre en « ${s} » (${pins.join(", ")}) : le remplissage écrirait ces membres à leur place, sans droits d'administrateur. « Remplir » ne relit pas le terminal : changez leur numéro sur le terminal puis confirmez ci-dessous, ou confirmez pour qu'ils soient remplacés.`,
  confirmAdminOverwrite: (pins: string[]) =>
    `Je confirme pour les administrateurs ${pins.join(", ")} : leur numéro a été changé sur le terminal, ou ils seront remplacés par les membres du même numéro.`,
  refillWarnAdmins: (pins: string[]) =>
    `Administrateurs confirmés (numéro changé sur le terminal, ou remplacés par le membre du même numéro) : ${pins.join(", ")}.`,
  refillWarnAdminsUnchecked:
    "Les administrateurs du terminal n'ont pas pu être vérifiés (sauvegarde illisible) : un administrateur qui a le numéro d'un membre sera remplacé par ce membre.",
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
    UNREADABLE:
      "Table absente ou illisible sur ce terminal (le terminal n'a pas donné de nombre). Sur un C3, c'est souvent la table v9 « template » : les empreintes sont dans « templatev10 ».",
  } as Record<string, string>,
  unknown: "—",
};

const en: typeof fr = {
  colon: ":",
  title: "Erase content",
  steps: ["Content", "Choose", "Options", "Confirm", "Run"],
  lockTitle: "Administrator only",
  lockText:
    "Enter the gym's administrator password. The MonClub server checks it here, then again when the erase starts and for Refill: the erase and the refill both need the internet.",
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
  forgetForcedMb:
    "Required when a standalone terminal's users are erased: otherwise MonClub would try to delete members who are already gone.",
  requiredByUser:
    "Erased with the users: otherwise the rights and fingerprints stay and pass to the next member who gets the same number.",
  refillTitle: "Refill",
  refillNow: "Refill now",
  refillAuto: "Refill automatically (next sync)",
  refillHold: "Hold until I press Refill",
  refillHoldHelp:
    "For the cutover night: erase, switch the turnstile to 'Par personne', restart Access, then Refill.",
  heldAlready:
    "This turnstile is already on hold after an erase: only the Refill button releases it. Choose 'Hold until I press Refill'.",
  refillWillWrite: (n: number, s: string) => `The refill will write ${n} member(s) to this turnstile (scheme ${s}).`,
  listAge: (ageSec: number | null | undefined, maxSec: number | null | undefined) =>
    (ageSec === null || ageSec === undefined
      ? "Member list: no successful sync since Access started."
      : `Member list received from MonClub ${ageSec < 60 ? "less than a minute ago" : `${Math.floor(ageSec / 60)} min ago`}`
        + (maxSec ? ` (it must be less than ${Math.round(maxSec / 60)} min old).` : ".")),
  stale: {
    TOO_OLD: (ageSec: number | null | undefined, maxSec: number | null | undefined) =>
      `The member list is not recent: the last successful sync was ${Math.floor((ageSec ?? 0) / 60)} min ago (limit ${Math.round((maxSec ?? 600) / 60)} min). Wait for the next sync, then read again: nothing is erased.`,
    LAST_SYNC_FAILED: () =>
      "The last sync with MonClub did not succeed: the member list may be incomplete. Wait for the next successful sync, then read again: nothing is erased.",
    NO_SYNC_YET: () =>
      "No sync with MonClub has succeeded since Access started: the member list may be incomplete. Wait for the next sync, then read again: nothing is erased.",
  },
  refillIfAccount: (n: number, w: number) =>
    w > 0
      ? `Under 'Par personne': ${n} member(s), and ${w} without an account number, who would not be written.`
      : `Under 'Par personne': ${n} member(s).`,
  refillCacheAt: (s: string) => `This PC's member list was saved on ${s}.`,
  withheldOnlyIfAccount:
    "This refusal concerns 'Hold until I press Refill' only (meant for a switch to 'Par personne'): with no scheme change, 'Refill now' writes everyone.",
  lockoutHold:
    "After this erase NO member gets through the turnstile by card or fingerprint until Refill is pressed (the internet is needed).",
  lockoutRefill:
    "During the erase and until the refill has finished, members do not get through the turnstile by card or fingerprint.",
  lockoutFingersHold:
    "After this erase, members who pass by fingerprint do not get through until Refill is pressed (the internet is needed). Cards keep working.",
  lockoutFingersRefill:
    "During the erase and until the refill has finished, members who pass by fingerprint do not get through. Cards keep working.",
  finishNotes: {
    HELD_BEFORE: "The turnstile was already on hold after an earlier erase: it stays on hold. Press Refill.",
    PIN_SCHEME_CHANGED: "The pin scheme changed during the erase: the turnstile stays on hold. Check the scheme, then press Refill.",
    PIN_SCHEME_UNREADABLE: "The pin scheme could not be read again at the end: the turnstile stays on hold. Press Refill.",
    HELD_SCHEME_MOVED:
      "The pin scheme changed during the run, before anything was erased: the turnstile stays on hold, even after Access restarts, because it still holds every number of the old scheme. Refill is refused until the recorded scheme is the old one again. To go on: set the old scheme back in the dashboard, then erase it again with 'Hold until I press Refill' (or Refill to release it without erasing anything).",
    HELD_SCHEME_UNREADABLE:
      "The pin scheme could not be read after the stop: the turnstile stays on hold as a precaution, even after Access restarts (nothing was erased). Refill is accepted only under step 1's scheme: check the scheme in the dashboard; unchanged, Refill puts everyone back; changed, set it back, or erase again with 'Hold…'.",
    HELD_SCHEME_MOVED_SESSION:
      "The pin scheme changed during the run, before anything was erased: the turnstile stays on hold, but this hold could not be recorded and may NOT last through a restart of Access. Do not restart Access: set the old scheme back in the dashboard, then erase it again with 'Hold until I press Refill' (or Refill to release it without erasing anything).",
    HELD_SCHEME_UNREADABLE_SESSION:
      "The pin scheme could not be read after the stop: the turnstile stays on hold as a precaution (nothing was erased), but this hold could not be recorded and may NOT last through a restart of Access. Check the scheme in the dashboard before any restart, then Refill (or erase again with 'Hold…' if it changed).",
    HELD_DEVICE_GONE:
      "This turnstile was deleted in MonClub during the run, before anything was erased: nothing was erased. It stays on hold until Access restarts; nothing to do.",
  },
  notRefilledTitle: (n: number, s: string, what: NotRefilledWhat) =>
    `${n} person(s) on this turnstile ${{
      users: "will NOT be put back by the refill",
      rights: "will lose their door rights, and the refill will NOT give them back",
      fingers: "will lose their fingerprints, and the refill will NOT give them back",
      rightsFingers: "will lose their door rights and fingerprints, and the refill will NOT give them back",
    }[what]}: they are not in MonClub's member list for this turnstile (scheme ${s}) — staff or cleaners enrolled on the turnstile, another system's users, members no longer allowed there. ${what === "users" ? "What the erase takes from them (user, card, door rights, fingerprints) does not come back." : "Their user and card stay on the turnstile."}`,
  notRefilledBackup:
    "Their only copy is this erase's backup: it is kept with no time limit (never deleted after 30 days).",
  notRefilledTick: (n: number) =>
    `I have read the list: the refill will not give these ${n} person(s) back what the erase takes from them.`,
  notRefilledNone: "Everyone on this turnstile is in the refill's list.",
  notRefilledUnknown:
    "The turnstile's user list could not be read: who the refill would not put back is unknown. Read step 1 again.",
  notRefilledKept: (n: number) =>
    `${n} person(s) outside the refill's list lost what this erase took from them: this erase's backup is kept with no time limit.`,
  otherPcsTitle:
    "Close MonClub Access on every other PC of this gym and keep it closed until Refill: the hold binds THIS PC only, the others would keep writing to this turnstile. Quitting is not enough: Access's watchdog starts it again within minutes, and the start with Windows at the next logon.",
  otherPcsTick:
    "MonClub Access is closed on every other PC of this gym — on each: 'Ouvrir MonClub Access avec Windows' unticked, the watchdog switched off (Disable-ScheduledTask -TaskName 'MonClub Access Watchdog'), then Quit — and stays closed until the refill.",
  deviceLine: (name: string, ip: string, port: string, sdk: string) =>
    `Turnstile: ${name} — address ${ip}:${port} — ${sdk}. The erase is tied to this address.`,
  sdkNames: { ZK_PULLSDK: "PullSDK (C3 controller)", ZK_STANDALONE: "zkemkeeper (standalone terminal)" },
  phases: {
    backup_fingers: "Backing up fingerprints",
    erase_users: "Erasing users",
    erase_fingers: "Erasing fingerprints",
  },
  errorDetail: "Detail",
  noAnswerYet: "No answer in time: reading the erase status…",
  refillAutoHelp: "With manual sync, the refill waits for the next 'Synchronize'.",
  acceptFaces: (n: number) =>
    `I accept the loss of ${n} face template(s): no backup exists for a face.`,
  acceptFacesUnknown:
    "The terminal did not report its face count: I accept the loss of any faces (no backup exists for a face).",
  backupOnly: "Backup only (rehearsal): nothing is erased",
  rulesTitle: "Safety rules",
  rules: [
    "A backup of the chosen tables is written to a file and read back before anything is erased. If it fails, nothing is erased.",
    "During the run MonClub writes no member to this turnstile. The door and the scans keep working.",
    "Only the ticked tables are erased — never the parameters, time zones or holidays.",
    "If the erase does not end verified, the turnstile stays on hold, nothing is forgotten and everyone is written again at the refill.",
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
    erase_recorded: "Erase recorded: each member's last write result becomes 'unknown'",
    not_refilled: "People outside the refill's list checked against the backup",
    forget: "MonClub's records forgotten",
    keep_records: "Records kept: everyone will be written again",
    records_invalidated: "Records kept, marked to be written again",
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
  schemeChanged: (s: string) =>
    `The scheme changed since it was shown: it is now ${s}. Check it, then press Refill again.`,
  schemeMovedHold: (terminal: string | null, now: string) =>
    (terminal
      ? `Nothing was erased on this turnstile: the pin scheme changed during an erase, before any delete. It still holds '${terminal}' numbers, and the scheme recorded now is '${now}'. Refill is refused until the scheme is '${terminal}' again: set it back in the dashboard, or erase the turnstile again with 'Hold until I press Refill'.`
      : "Nothing was erased on this turnstile, and the scheme its numbers were written under is not recorded: Refill is refused. Erase it again with 'Hold until I press Refill'."),
  schemeMovedBack: (terminal: string) =>
    `Nothing was erased on this turnstile: the scheme changed during an erase, before any delete. It is back to '${terminal}', the scheme of its numbers: Refill releases it and puts everyone back, without erasing anything. To go on with the switch, erase it again with 'Hold until I press Refill' instead.`,
  holdsUnknown:
    "Access could not read the holds back: every turnstile stays on hold until the next successful read.",
  refillNeedsInternet: "Refill needs the internet: the server checks the password.",
  handoverWaits:
    "While it is on hold, this turnstile is not handed to another PC: a change of driving PC waits for Refill.",
  codes: {
    ADDRESS_CHANGED:
      "The terminal is still connected at its old IP address: wait for Access to reconnect (up to 30 min) or restart Access, then read again.",
    ADDRESS_UNKNOWN: "Access does not know the address of its open connection to this terminal: read again in a moment.",
    REFILL_IN_PROGRESS: "A refill of this turnstile is running: try again in a moment.",
    RUN_IN_PROGRESS: "An erase is already running.",
    HOLD_CHANGED: "This turnstile's hold changed meanwhile: close and reopen the dialog.",
    HOLDS_UNKNOWN: "Access could not read the holds back: nothing is erased or refilled for now.",
    ADMIN_PASSWORD_UNCHECKABLE:
      "No internet: the MonClub server must check the password (to erase and to Refill). Restore the connection, then try again.",
    ADMIN_PASSWORD: "Wrong password.",
    ADMIN_PASSWORD_REQUIRED: "Enter the administrator password.",
    PC_NOT_SIGNED_IN: "This PC is not signed in to MonClub: the password cannot be checked. Sign this PC in again, then try again.",
    ADMIN_PASSWORD_CHECK_FAILED: "The MonClub server could not check the password: try again in a moment.",
    PREVIEW_EXPIRED: "Step 1 was read more than 15 minutes ago: go back to step 1 and read again.",
    WRONG_DEVICE: "This reading is of another turnstile: read step 1 again.",
    DEVICE_CHANGED: "The turnstile's name, address or SDK changed since step 1: read again.",
    NO_DEVICE: "Unknown turnstile.",
    NO_DEVICE_NAME: "This turnstile has no name in MonClub: name it before erasing.",
    NAME_MISMATCH: "The typed name is not this turnstile's name.",
    NO_TABLES: "Choose at least one table.",
    UNKNOWN_TABLE: "Unknown table.",
    NOT_ERASABLE: "This table cannot be erased by the wizard.",
    DOOR_LOG_NOT_SUPPORTED: "The door log cannot be erased here.",
    UNREADABLE: "The terminal did not answer for this table: read step 1 again.",
    FORGET_REQUIRED: "Choose whether MonClub forgets its records.",
    FORGET_NEEDS_USERS: "'Forget' needs the users erased too.",
    USER_NEEDS_RIGHTS_AND_FINGERS: "Erasing the users needs every readable rights and fingerprint table erased too.",
    USERS_ERASE_NEEDS_FORGET: "Erasing a standalone terminal's users needs 'Forget'.",
    REFILL_REQUIRED: "Choose when the turnstile is refilled.",
    FACES_UNKNOWN: "The terminal did not report its face count: accept the possible loss of faces (step 3).",
    FACES_PRESENT: "Faces are enrolled and cannot be backed up: accept their loss (step 3).",
    NOT_DRIVER: "This PC does not drive this turnstile.",
    HANDOVER_IN_PROGRESS: "This turnstile is being handed over to another PC.",
    ADD_ONLY: "This turnstile accepts additions only for now (a change of driving PC is not finished): no erase.",
    NO_WORKER: "Access has no running connection to this turnstile on this PC.",
    NOT_CONNECTED: "The turnstile is not connected.",
    UNSUPPORTED_PROTOCOL: "This turnstile's SDK is not supported by the wizard.",
    STATUS_UNREADABLE: "The terminal did not report its counters: read again in a moment.",
    PIN_SCHEME_UNREADABLE: "This turnstile's pin scheme could not be read: try again.",
    PIN_SCHEME_REQUIRED: "Read the dialog again: the scheme shown is missing.",
    RUN_NOT_STARTED: "The erase could not start: nothing was erased. Try again.",
    NOT_ON_HOLD: "This turnstile is no longer on hold.",
    RECORDS_NOT_RESET: "MonClub's records could not be reset: the turnstile stays on hold. Try again.",
    OTHER_PCS_NOT_CONFIRMED:
      "Confirm that MonClub Access is closed on every other PC of this gym (watchdog switched off, 'Ouvrir MonClub Access avec Windows' unticked).",
    HELD_USE_REFILL:
      "This turnstile is already on hold after an erase: choose 'Hold until I press Refill', then press Refill.",
    REFILL_SOURCE_MISSING:
      "This PC has no member list to refill the turnstile from: nothing is erased. Synchronize, then read again.",
    REFILL_SOURCE_STALE:
      "This PC's member list is not recent (the last sync failed, is too old, or none succeeded since Access started): wait for the next sync, then read again. Nothing is erased.",
    REFILL_SOURCE_EMPTY: "The refill would write no member to this turnstile: nothing is erased.",
    REFILL_WITHHELD:
      "Some members have no account number in this PC's list: under 'Par personne' the refill would not write them. The member list must be read again in full first.",
    BUSY: "A sync in progress did not end in time: nothing was erased. Try again.",
    BACKUP_INCOMPLETE: "The backup does not match the terminal's counters: nothing was erased.",
    BACKUP_UNVERIFIABLE: "The terminal did not report all its counters: the backup cannot be checked, nothing was erased.",
    BACKUP_UNTRUSTED: "The list read from the terminal cannot be trusted: nothing was erased.",
    BACKUP_WRITE: "The backup file could not be written or read back: nothing was erased.",
    RESULTS_NOT_RESET: "The erase could not be recorded before its first delete: nothing was erased.",
    ADMIN_PIN_IN_ROSTER:
      "A terminal administrator has the same number as a member: the refill would overwrite it. Change that administrator's number on the terminal: nothing was erased.",
    NOT_REFILLED_UNKNOWN:
      "The turnstile's user list could not be read: who the refill would not put back is unknown. Read step 1 again: nothing is erased.",
    NOT_REFILLED_UNCONFIRMED:
      "Some people on this turnstile will not be put back by the refill: tick the box that confirms it (step 4).",
    NOT_REFILLED_CHANGED:
      "When the erase was about to start, the turnstile held people outside the refill's list who were not shown at step 1: nothing was erased. Read step 1 again.",
    KEEP_MARK_NOT_WRITTEN:
      "The mark that keeps the backup with no time limit could not be written: nothing was erased. The erase was already recorded: the turnstile stays on hold, and Refill writes everyone again.",
    HELD_SCHEME_MOVED:
      "Refill refused: nothing was erased on this turnstile, and it still holds the numbers of another scheme than the one recorded now. Set that scheme back in the dashboard, then try again; or erase it again with 'Hold until I press Refill'.",
    TLS_CLOCK:
      "The MonClub server refused the secure connection: this PC's date or time is probably wrong (or the server's certificate has expired). Check Windows' date and time; if they are right, call the developer. Nothing was changed.",
    PIN_SCHEME_CHANGED:
      "The turnstile's pin scheme changed since step 1: nothing was erased. Read step 1 again.",
    NOT_VERIFIED: "The erase could not be verified: rows remain, or a count or a listing did not answer.",
    ERASE_FAILED: "An erase command failed: part of it may have been erased.",
    NO_ANSWER: "A command was sent and got no answer: it may have acted.",
    NOT_SENT: "A command was not sent (timeout or connection lost).",
    DEVICE_ERROR: "A command to the terminal failed.",
    UNEXPECTED: "Unexpected Access error.",
    ERASE_NOT_ENABLED:
      "Erasing is not enabled for this gym — the owner can enable it in the dashboard (access PCs page).",
    ERASE_SWITCH_UNCHECKED:
      "Whether erasing is enabled for this gym could not be checked: the MonClub server answered something unexpected. Nothing is erased.",
    ERASE_SWITCH_MISSING:
      "The MonClub server does not offer the erase switch yet: erasing is not available until the server is updated. Nothing is erased; trying again changes nothing until then.",
    ERASE_SWITCH_UNREACHABLE:
      "The MonClub server did not answer the switch check: check the internet, then try again. Nothing is erased.",
  },
  schemes: { ACCOUNT: "Par personne (per person)", MEMBERSHIP: "Par abonnement (per membership)" },
  mbPasses: (n: number) =>
    `A standalone terminal receives at most ${n} members per pass: the refill takes several passes.`,
  incompleteHelp:
    "Check the counts below, then run the wizard again or press Refill: MonClub writes all its members again. Nothing was forgotten.",
  refilled: "Refill started.",
  refilledWith: (s: string) => `Refill started, scheme ${s}.`,
  backupsNotMarked:
    "Warning: the refill date could not be noted in the backups; they will be deleted 30 days after the erase.",
  refillWarn: {
    REFILL_WITHHELD: (n: number, s: string) =>
      `Warning: ${n} member(s) have no account number in this PC's list: under ${s} they are not written to the turnstile.`,
    REFILL_SOURCE_STALE: () =>
      "Warning: this PC's member list is not recent: the refill writes the list it has; the next successful sync brings the changes.",
    REFILL_SOURCE_MISSING: () =>
      "Warning: this PC has no member list: the turnstile stays empty until a sync brings one.",
    REFILL_SOURCE_EMPTY: () =>
      "Warning: this PC's member list holds no member for this turnstile: nothing is written to it.",
  },
  adminClash: (pins: string[], s: string) =>
    `According to the erase's backup, ${pins.length} terminal administrator(s) have the same number as a member under '${s}' (${pins.join(", ")}): the refill would write those members over them, without administrator rights. Refill does not read the terminal again: change their number on the terminal then confirm below, or confirm to have them replaced.`,
  confirmAdminOverwrite: (pins: string[]) =>
    `I confirm for administrators ${pins.join(", ")}: their number was changed on the terminal, or they will be replaced by the members with the same number.`,
  refillWarnAdmins: (pins: string[]) =>
    `Administrators confirmed (number changed on the terminal, or replaced by the member with the same number): ${pins.join(", ")}.`,
  refillWarnAdminsUnchecked:
    "The terminal's administrators could not be checked (backup unreadable): an administrator who has a member's number will be replaced by that member.",
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
    UNREADABLE:
      "Table missing or unreadable on this terminal (it gave no count). On a C3 this is often the v9 'template' table: the fingerprints are in 'templatev10'.",
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
