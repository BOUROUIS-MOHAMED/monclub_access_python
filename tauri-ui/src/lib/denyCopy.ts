// Refusal copy shared by the entry screen (PopupWindow) and the Dashboard feed.
// Moved verbatim out of pages/PopupWindow.tsx (v5 redesign, step 1) so the
// Dashboard can show the same short French text instead of the raw engine code.
// Pure module: no React, no "@/" imports — node-tested (denyCopy.test.ts).

// ── Rule 5: a refusal always says what to do ────────────────────────────────
// The engines emit SCREAMING_SNAKE codes (app/core/access_verification.py,
// realtime_agent.py, ultra_engine.py). Each becomes a sentence plus an action.
export interface DenyCopy { title: string; action: string; short: string }
export const A_DENY_FALLBACK: DenyCopy = {
  title: "Cet accès n'a pas pu être validé",
  action: "Présentez-vous à l'accueil — nous réglons ça tout de suite.",
  short: "Accès refusé",
};
export const A_DENY: Record<string, DenyCopy> = {
  DENY_NO_CARD_MATCH: { title: "Cette carte n'est pas reconnue", action: "Présentez-vous à l'accueil — nous la réassocierons en un instant.", short: "Carte non reconnue" },
  DENY_NO_MATCH: { title: "Ce badge n'est pas reconnu", action: "Présentez-vous à l'accueil — nous le réassocierons en un instant.", short: "Badge non reconnu" },
  INVALID_CARD_FORMAT: { title: "Carte illisible", action: "Représentez-la bien à plat sur le lecteur.", short: "Carte illisible" },
  INVALID_CARD_LENGTH: { title: "Carte illisible", action: "Représentez-la bien à plat sur le lecteur.", short: "Carte illisible" },
  INVALID_FORMAT: { title: "Lecture illisible", action: "Représentez votre carte ou votre code.", short: "Lecture illisible" },
  DENY_CARD_COLLISION: { title: "Cette carte est associée à plusieurs comptes", action: "Présentez-vous à l'accueil pour la régulariser.", short: "Carte en double" },
  DENY_COLLISION: { title: "Ce code correspond à plusieurs comptes", action: "Présentez-vous à l'accueil pour le régulariser.", short: "Code en double" },
  DENY_EXPIRED: { title: "Ce code QR a expiré", action: "Régénérez-le dans l'application MonClub, puis représentez-le.", short: "Code QR expiré" },
  DENY_NOT_IN_LOCAL_ROSTER: { title: "Aucun abonnement actif trouvé pour ce code", action: "Présentez-vous à l'accueil pour vérifier votre abonnement.", short: "Abonnement non trouvé" },
  DENY_NOT_ALLOWED_TODAY: { title: "Abonnement non valable aujourd'hui", action: "Présentez-vous à l'accueil pour vérifier votre abonnement.", short: "Abonnement non valable aujourd'hui" },
  DENY_TOTP_FAILED: { title: "Ce code QR n'est pas valide", action: "Régénérez-le dans l'application MonClub, puis représentez-le.", short: "Code QR invalide" },
  DENY_AMBIGUOUS_COUNTER: { title: "Ce code QR a déjà été utilisé", action: "Régénérez-le dans l'application MonClub.", short: "Code QR déjà utilisé" },
  DENY_FUTURE_SKEW: { title: "L'heure de votre téléphone est décalée", action: "Activez l'heure automatique, puis représentez votre code.", short: "Heure du téléphone décalée" },
  DENY_ANTI_FRAUD_CARD: { title: "Vous venez déjà de passer", action: "Patientez un instant avant de représenter votre carte.", short: "Passage déjà enregistré" },
  DENY_ANTI_FRAUD_QR: { title: "Vous venez déjà de passer", action: "Patientez un instant avant de représenter votre code.", short: "Passage déjà enregistré" },
  DENY_RFID_DISABLED: { title: "Le badge n'est pas activé sur cette entrée", action: "Utilisez votre code QR, ou présentez-vous à l'accueil.", short: "Badge désactivé ici" },
  DENY_HANDLE_SLOW: { title: "Le tourniquet n'a pas répondu à temps", action: "Représentez votre carte — si cela persiste, voyez l'accueil.", short: "Tourniquet sans réponse" },
  DOOR_CMD_FAILED: { title: "Le tourniquet n'a pas répondu", action: "Représentez votre carte — si cela persiste, voyez l'accueil.", short: "Tourniquet sans réponse" },
};
export function aDenyCopy(raw: string): DenyCopy {
  const trimmed = String(raw || "").trim();
  if (!trimmed) return A_DENY_FALLBACK;
  const hit = A_DENY[trimmed.toUpperCase()];
  if (hit) return hit;
  // Some paths already emit a human sentence rather than a code — show it, but
  // still append an action so rule 5 holds.
  if (/\s/.test(trimmed) && trimmed !== trimmed.toUpperCase()) {
    return { title: trimmed, action: A_DENY_FALLBACK.action, short: trimmed };
  }
  return A_DENY_FALLBACK;
}

/** The one-line refusal text for a feed row ("Carte non reconnue", fallback
 *  "Accès refusé"). ULTRA device refusals carry `DEVICE_DENIED` (no "why"), which
 *  has no entry and therefore reads "Accès refusé". */
export function denyShort(raw: string | null | undefined): string {
  return aDenyCopy(String(raw ?? "")).short;
}
