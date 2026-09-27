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
  refillIfAccount: (n: number, w: number) =>
    w > 0
      ? `En « Par personne » : ${n} membre(s), et ${w} sans numéro de compte, qui ne seraient pas écrits.`
      : `En « Par personne » : ${n} membre(s).`,
  refillCacheAt: (s: string) => `Liste des membres de ce PC enregistrée le ${s}.`,
  lockoutHold:
    "Après cet effacement, AUCUN membre ne passe au tourniquet par carte ou par empreinte tant que « Remplir » n'est pas fait (Internet requis).",
  lockoutRefill:
    "Pendant l'effacement et jusqu'à la fin du remplissage, les membres ne passent pas au tourniquet par carte ou par empreinte.",
  otherPcsTitle:
    "Fermez MonClub Access sur tous les autres PC de cette salle et gardez-le fermé jusqu'au remplissage (« Remplir ») : la mise en attente ne vaut que pour CE PC, les autres continueraient d'écrire sur ce tourniquet.",
  otherPcsTick:
    "MonClub Access est fermé sur tous les autres PC de cette salle, et le restera jusqu'au remplissage.",
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
    OTHER_PCS_NOT_CONFIRMED: "Confirmez que MonClub Access est fermé sur tous les autres PC de cette salle.",
    HELD_USE_REFILL:
      "Ce tourniquet est déjà en attente depuis un effacement : choisissez « Attendre que j'appuie sur « Remplir » », puis appuyez sur « Remplir ».",
    REFILL_SOURCE_MISSING:
      "Ce PC n'a pas de liste des membres pour remplir le tourniquet : rien n'est effacé. Synchronisez, puis relisez.",
    REFILL_SOURCE_STALE:
      "La dernière synchronisation avec MonClub n'a pas réussi (ou aucune depuis le démarrage d'Access) : la liste des membres peut être incomplète. Synchronisez, puis relisez.",
    REFILL_SOURCE_EMPTY: "Le remplissage n'écrirait aucun membre sur ce tourniquet : rien n'est effacé.",
    REFILL_WITHHELD:
      "Des membres n'ont pas de numéro de compte dans la liste de ce PC : en « Par personne », le remplissage ne les écrirait pas. La liste des membres doit d'abord être relue en entier ; sans changement de schéma, choisissez « Remplir maintenant ».",
    BUSY: "Une synchronisation en cours ne s'est pas terminée à temps : rien n'a été effacé. Réessayez.",
    BACKUP_INCOMPLETE: "La sauvegarde ne correspond pas aux compteurs du terminal : rien n'a été effacé.",
    BACKUP_UNVERIFIABLE: "Le terminal n'a pas donné tous ses compteurs : la sauvegarde ne peut pas être vérifiée, rien n'a été effacé.",
    BACKUP_UNTRUSTED: "La liste lue sur le terminal n'est pas fiable : rien n'a été effacé.",
    BACKUP_WRITE: "Le fichier de sauvegarde n'a pas pu être écrit ou relu : rien n'a été effacé.",
    RESULTS_NOT_RESET: "L'effacement n'a pas pu être enregistré avant la première suppression : rien n'a été effacé.",
    ADMIN_PIN_IN_ROSTER:
      "Un administrateur du terminal a le même numéro qu'un membre : le remplissage l'écraserait. Changez le numéro de cet administrateur sur le terminal : rien n'a été effacé.",
    NOT_VERIFIED: "L'effacement n'a pas pu être vérifié : des lignes restent sur le terminal.",
    ERASE_FAILED: "Une commande d'effacement a échoué : une partie a peut-être été effacée.",
    NO_ANSWER: "Une commande a été envoyée sans réponse : elle a peut-être agi.",
    NOT_SENT: "Une commande n'a pas été envoyée (délai ou connexion perdue).",
    DEVICE_ERROR: "Le terminal a refusé une commande.",
    UNEXPECTED: "Erreur inattendue d'Access.",
    ERASE_NOT_ENABLED:
      "L'effacement n'est pas activé pour cette salle — le propriétaire peut l'activer dans le tableau de bord (page PC d'accès).",
    ERASE_SWITCH_UNCHECKED:
      "L'activation de l'effacement pour cette salle n'a pas pu être vérifiée : rien n'est effacé. Réessayez (Internet requis).",
  } as Record<string, string>,
  schemes: { ACCOUNT: "Par personne", MEMBERSHIP: "Par abonnement" } as Record<string, string>,
  mbPasses: (n: number) =>
    `Un terminal autonome reçoit au plus ${n} membres par passage : le remplissage se fait en plusieurs passages.`,
  incompleteHelp:
    "Vérifiez les nombres ci-dessous, puis relancez l'assistant ou appuyez sur « Remplir » : MonClub réécrira tous ses membres. Rien n'a été oublié.",
  refilled: "Remplissage lancé.",
  refilledWith: (s: string) => `Remplissage lancé, schéma ${s}.`,
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
  refillIfAccount: (n: number, w: number) =>
    w > 0
      ? `Under 'Par personne': ${n} member(s), and ${w} without an account number, who would not be written.`
      : `Under 'Par personne': ${n} member(s).`,
  refillCacheAt: (s: string) => `This PC's member list was saved on ${s}.`,
  lockoutHold:
    "After this erase NO member gets through the turnstile by card or fingerprint until Refill is pressed (the internet is needed).",
  lockoutRefill:
    "During the erase and until the refill has finished, members do not get through the turnstile by card or fingerprint.",
  otherPcsTitle:
    "Close MonClub Access on every other PC of this gym and keep it closed until Refill: the hold binds THIS PC only, the others would keep writing to this turnstile.",
  otherPcsTick:
    "MonClub Access is closed on every other PC of this gym, and stays closed until the refill.",
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
    OTHER_PCS_NOT_CONFIRMED: "Confirm that MonClub Access is closed on every other PC of this gym.",
    HELD_USE_REFILL:
      "This turnstile is already on hold after an erase: choose 'Hold until I press Refill', then press Refill.",
    REFILL_SOURCE_MISSING:
      "This PC has no member list to refill the turnstile from: nothing is erased. Synchronize, then read again.",
    REFILL_SOURCE_STALE:
      "The last sync with MonClub did not succeed (or none ran since Access started): the member list may be incomplete. Synchronize, then read again.",
    REFILL_SOURCE_EMPTY: "The refill would write no member to this turnstile: nothing is erased.",
    REFILL_WITHHELD:
      "Some members have no account number in this PC's list: under 'Par personne' the refill would not write them. The member list must be read again in full first; with no scheme change, choose 'Refill now'.",
    BUSY: "A sync in progress did not end in time: nothing was erased. Try again.",
    BACKUP_INCOMPLETE: "The backup does not match the terminal's counters: nothing was erased.",
    BACKUP_UNVERIFIABLE: "The terminal did not report all its counters: the backup cannot be checked, nothing was erased.",
    BACKUP_UNTRUSTED: "The list read from the terminal cannot be trusted: nothing was erased.",
    BACKUP_WRITE: "The backup file could not be written or read back: nothing was erased.",
    RESULTS_NOT_RESET: "The erase could not be recorded before its first delete: nothing was erased.",
    ADMIN_PIN_IN_ROSTER:
      "A terminal administrator has the same number as a member: the refill would overwrite it. Change that administrator's number on the terminal: nothing was erased.",
    NOT_VERIFIED: "The erase could not be verified: rows remain on the terminal.",
    ERASE_FAILED: "An erase command failed: part of it may have been erased.",
    NO_ANSWER: "A command was sent and got no answer: it may have acted.",
    NOT_SENT: "A command was not sent (timeout or connection lost).",
    DEVICE_ERROR: "The terminal refused a command.",
    UNEXPECTED: "Unexpected Access error.",
    ERASE_NOT_ENABLED:
      "Erasing is not enabled for this gym — the owner can enable it in the dashboard (access PCs page).",
    ERASE_SWITCH_UNCHECKED:
      "Whether erasing is enabled for this gym could not be checked: nothing is erased. Try again (the internet is needed).",
  },
  schemes: { ACCOUNT: "Par personne (per person)", MEMBERSHIP: "Par abonnement (per membership)" },
  mbPasses: (n: number) =>
    `A standalone terminal receives at most ${n} members per pass: the refill takes several passes.`,
  incompleteHelp:
    "Check the counts below, then run the wizard again or press Refill: MonClub writes all its members again. Nothing was forgotten.",
  refilled: "Refill started.",
  refilledWith: (s: string) => `Refill started, scheme ${s}.`,
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
