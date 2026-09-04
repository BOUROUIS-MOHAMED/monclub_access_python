// Multi-lane TV popup for the gym entry display — "Écran d'entrée", direction A.
//
// Renders up to N concurrent member cards (default 3, configurable from
// backend via /status → popup.lanes). Each lane lives for its full
// popup_duration_sec regardless of other arrivals. New events fill the
// first free lane; when all lanes are busy the oldest entry is evicted so
// the freshest scan is always visible. There is no global MIN_SHOW lock
// and no per-person dedupe — duplicate events are already filtered
// upstream by the access_history INSERT-OR-IGNORE constraint, so this UI
// trusts the backend stream.
//
// The presentation layer is the "Écran d'entrée — direction A" design: one
// screen-level component (EntryScreen) that shows an idle standby, a single
// full-field verdict (1 scan), or a wall of verdict fields (2+ scans).
// All data/lifecycle plumbing below the SOURCE banner is unchanged.

import { useState, useEffect, useLayoutEffect, useRef, useCallback, useMemo, type CSSProperties, type ReactNode } from "react";
import { getApiBaseUrl, openSSE, get } from "@/api/client";
import type { PopupEvent } from "@/api/types";
import { LOCAL_API_PREFIX } from "@/config/appConst";
import { buildPopupImageCandidates, toPopupCachedImageUrl } from "@/lib/popupImages";
// Self-hosted Hanken Grotesk (the entry screen's display face) — bundled by Vite so the
// gym TVs render correctly offline, no Google Fonts request at runtime.
import "@fontsource/hanken-grotesk/400.css";
import "@fontsource/hanken-grotesk/500.css";
import "@fontsource/hanken-grotesk/600.css";
import "@fontsource/hanken-grotesk/700.css";
import "@fontsource/hanken-grotesk/800.css";

// ── Defaults (overridable from backend /status payload) ───────────────────
const DEFAULT_LANES = 3;
const MAX_LANES = 5;
const DEFAULT_DURATION_SEC = 5; // TV-friendly default; backend overrides
const MIN_DURATION_MS = 2500;
const FADE_OUT_MS = 350;

// Direction A draws the refusal states in full (section 01 of the design calls
// "Autorisé · Refusé" the two states that are 99% of the day, and rules 1 and 5
// are both about the refusal). The popup wall nevertheless still shows GRANTED
// entries for identified members only — unchanged behaviour. Flip this to true
// to actually surface refusals on the entry screen; nothing else needs editing.
const SHOW_DENIED_ENTRIES = false;

// ── Types ─────────────────────────────────────────────────────────────────
interface ActiveLane {
  laneId: string;        // stable per-lane id; survives event swaps in this slot
  event: PopupEvent;
  arrivedAt: number;     // Date.now() at insertion
  expiresAt: number;     // arrivedAt + durationMs
  fadingOut: boolean;
  imgUrl: string | null; // current image src (data: or /image-cache?…)
  imgFallbacks: string[]; // remaining candidates to try on <img onError>
}

// ── Helpers ───────────────────────────────────────────────────────────────
function toPopupEvent(raw: any): PopupEvent {
  const eventId = String(raw?.eventId ?? raw?.id ?? `evt-${Date.now()}-${Math.random()}`);
  const popupDurationSec = Number(raw?.popupDurationSec ?? raw?.durationSec ?? raw?.duration ?? DEFAULT_DURATION_SEC);
  return {
    eventId,
    title: String(raw?.title ?? "Acces"),
    message: String(raw?.message ?? ""),
    imagePath: String(raw?.imagePath ?? raw?.image ?? ""),
    popupShowImage: raw?.popupShowImage !== false,
    userFullName: String(raw?.userFullName ?? raw?.fullName ?? ""),
    userImage: String(raw?.userImage ?? raw?.image ?? ""),
    userValidFrom: String(raw?.userValidFrom ?? raw?.validFrom ?? ""),
    userValidTo: String(raw?.userValidTo ?? raw?.validTo ?? ""),
    userMembershipId: raw?.userMembershipId != null ? Number(raw.userMembershipId) : null,
    userMembershipTitle: raw?.userMembershipTitle ? String(raw.userMembershipTitle) : undefined,
    userMembersType: raw?.userMembersType ? String(raw.userMembersType) : undefined,
    userPhone: String(raw?.userPhone ?? raw?.phone ?? ""),
    deviceId: Number(raw?.deviceId ?? 0),
    deviceName: String(raw?.deviceName ?? ""),
    allowed: Boolean(raw?.allowed),
    reason: String(raw?.reason ?? ""),
    scanMode: String(raw?.scanMode ?? ""),
    popupDurationSec: Number.isFinite(popupDurationSec) && popupDurationSec > 0 ? popupDurationSec : DEFAULT_DURATION_SEC,
    popupEnabled: raw?.popupEnabled !== false,
    winNotifyEnabled: raw?.winNotifyEnabled !== false,
    receivedAt: Number(raw?.receivedAt ?? Date.now()),
    userBirthday: raw?.userBirthday ? String(raw.userBirthday) : undefined,
    imageSource: raw?.imageSource ? String(raw.imageSource) : undefined,
    userImageStatus: raw?.userImageStatus ? String(raw.userImageStatus) : undefined,
    userProfileImage: String(raw?.userProfileImage ?? ""),
    // Frequent-pass VISUAL alert. Absent/0 on every normal scan, which keeps the
    // screen on its usual granted layout.
    repeatCount: Number(raw?.repeatCount ?? 0) || 0,
    repeatLimit: Number(raw?.repeatLimit ?? 0) || 0,
    repeatWindowMin: Number(raw?.repeatWindowMin ?? 0) || 0,
    previousEntryAt: raw?.previousEntryAt ? String(raw.previousEntryAt) : undefined,
  };
}

function laneIdFor(eventId: string): string {
  return `lane-${eventId.slice(0, 24)}-${Math.floor(Math.random() * 1e6)}`;
}

/* ══════════════════════════════════════════════════════════════════════════
   ▼▼▼ ÉCRAN D'ENTRÉE — DIRECTION A
   Ported from the Claude Design export `Ecran d'entree - A.dc.html`.

   The rule of the direction: THE VERDICT IS THE SCREEN. A turnstile has a
   green light or a red one — not a label. So the whole field is green / red /
   gold / dark, never a badge floating on neutral. Its five rules, which the
   code below follows literally:
     1. the background carries the decision;
     2. hierarchy comes from solid colours, never from opacity (on a saturated
        field, lowering opacity drags text toward the background and kills it);
     3. the first name first, enormous — the only word that matters to the member;
     4. the photo is a verification, not the subject — a white-ringed medallion;
     5. a refusal always says what to do (the technical code becomes a sentence
        followed by an action).

   The design is drawn on a fixed 1280×720 frame and deploys at 1920×1080 —
   same ratio — so it renders on a 1280×720 stage scaled uniformly to whatever
   size the popup window happens to be. Every measurement below is therefore
   the design's own pixel value, unmodified.

   Glyphs are inline SVG rather than the design's Material Symbols web font:
   this window is deliberately offline-safe (Hanken Grotesk is self-hosted via
   @fontsource) and must not acquire a Google Fonts dependency.
   ════════════════════════════════════════════════════════════════════════ */

const STAGE_W = 1280;
const STAGE_H = 720;

// Design-system tokens. The design rebases the old oklch accents onto the real
// tokens so this screen belongs to the rest of the product.
const A_GREEN = "#10B981";
const A_GREEN_INK = "#0A2E22";
const A_GREEN_DOT = "#114A38";
const A_RED = "#E2203F";
const A_RED_SUB = "#FFD9DF";
// --wigo-orange. The design uses it for "deuxieme passage" instead of red on
// purpose: red means "you are not a member", and treating a paid-up member like
// an expired one is a mistake of tone. Orange says "a verifier", not "refuse".
const A_ORANGE = "#E24A24";
const A_ORANGE_SUB = "#FFD9CF";
const A_ORANGE_INK_DEEP = "#A8320F";
const A_GOLD = "#E7BB4E";
const A_GOLD_INK = "#3A2A05";
const A_GOLD_INK_SOFT = "#5A4108";
const A_DARK = "#181818";
const A_DARK_SUB = "#C9CED2";
const A_DARK_FAINT = "#4A5056";

const A_MONTHS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"];
const A_DAYS = ["dimanche", "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi"];

type ScanCategory = "standard" | "staff" | "kids" | "coach" | "vip";

/** Wire members_type (backend MembersType enum) -> popup badge category. */
const A_MEMBERS_TYPE_CAT: Record<string, ScanCategory> = {
  STAFF: "staff",
  KIDS: "kids",
  COACH: "coach",
  VIP: "vip",
};

/** Badge wording. "standard" never renders a badge. */
const A_CATEGORY_LABEL: Record<ScanCategory, string> = {
  standard: "",
  staff: "Équipe",
  kids: "Kids Club",
  coach: "Coach",
  vip: "VIP",
};

type ScanMethod = "card" | "qr" | "fingerprint";
type GlyphName = "check" | "cancel" | "cake" | "sparkle" | "schedule" | "card" | "qr" | "fingerprint" | "history";

interface EntryScan {
  laneId: string;
  fullName: string;
  firstName: string;
  lastName: string;
  imgUrl: string | null;
  granted: boolean;
  reason: string;
  plan: string | null;
  memberNo: string | null;
  category: ScanCategory;
  validTo: Date | null;
  birthday: Date | null;
  device: string;
  method: ScanMethod;
  at: Date;
  // Frequent-pass VISUAL alert, set by the engine only when it fired. 0 = inert.
  repeatCount: number;
  repeatLimit: number;
  repeatWindowMin: number;
  previousEntryAt: Date | null;
}

// ── Formatting ──────────────────────────────────────────────────────────────
function aPad2(n: number): string { return n < 10 ? "0" + n : String(n); }
function aClock(d: Date): string { return aPad2(d.getHours()) + ":" + aPad2(d.getMinutes()); }
function aDayNum(d: Date): string { return d.getDate() === 1 ? "1er" : String(d.getDate()); }
function aLongDate(d: Date): string { return A_DAYS[d.getDay()] + " " + aDayNum(d) + " " + A_MONTHS[d.getMonth()]; }
function aFullDate(d: Date): string { return aDayNum(d) + " " + A_MONTHS[d.getMonth()] + " " + d.getFullYear(); }
function aSameDay(a: Date, b: Date): boolean { return a.getDate() === b.getDate() && a.getMonth() === b.getMonth(); }
function aMethodLabel(m: ScanMethod): string { return m === "qr" ? "QR Code" : (m === "fingerprint" ? "Empreinte" : "Carte"); }
function aPlural(n: number, one: string, many: string): string { return n > 1 ? many : one; }
function aInitials(name: string): string {
  const p = (name || "").trim().split(/\s+/).filter(Boolean);
  if (!p.length) return "—";
  const a = p[0][0] || "";
  const b = p.length > 1 ? p[p.length - 1][0] : "";
  return (a + b).toUpperCase();
}
function aParseDate(s: string | undefined | null): Date | null {
  if (!s) return null;
  const p = String(s).slice(0, 10).split("-");
  if (p.length < 3) return null;
  const y = Number(p[0]), mo = Number(p[1]), da = Number(p[2]);
  if (!y || !mo || !da) return null;
  return new Date(y, mo - 1, da);
}
// Age only when the stored birth year is plausible — placeholder years (1900,
// 1970) would otherwise render an absurd "126 ans aujourd'hui".
function aAgeToday(bd: Date | null, now: Date): number | null {
  if (!bd) return null;
  let age = now.getFullYear() - bd.getFullYear();
  const dm = now.getMonth() - bd.getMonth();
  if (dm < 0 || (dm === 0 && now.getDate() < bd.getDate())) age -= 1;
  return age >= 3 && age <= 100 ? age : null;
}
function aDaysLeft(validTo: Date | null, now: Date): number | null {
  if (!validTo) return null;
  // validTo is a date at local midnight; the membership is good through that day.
  const end = new Date(validTo.getFullYear(), validTo.getMonth(), validTo.getDate(), 23, 59, 59);
  return Math.ceil((end.getTime() - now.getTime()) / 86400000);
}

// Real scanMode values from the access engine look like "RFID_CARD" / "QR_TOTP" /
// "RFID_DIRECT" / "RFID_ONLY" — NOT "QR"/"FP". Classify the same way the backend's
// _credential_type_from_raw does (QR/TOTP → QR, FP/FINGER/BIO → fingerprint, else card).
function aMethodFor(scanMode: string | undefined): ScanMethod {
  const sm = String(scanMode || "").toUpperCase();
  if (sm.includes("QR") || sm.includes("TOTP")) return "qr";
  if (sm.includes("FP") || sm.includes("FINGER") || sm.includes("BIO")) return "fingerprint";
  return "card";
}

function aSplitName(full: string): { first: string; last: string } {
  const parts = String(full || "").trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return { first: "Membre", last: "" };
  if (parts.length === 1) return { first: parts[0], last: "" };
  return { first: parts[0], last: parts.slice(1).join(" ") };
}

function mapLaneToScan(lane: ActiveLane): EntryScan {
  const e = lane.event;
  const title = e.userMembershipTitle && String(e.userMembershipTitle).trim() ? String(e.userMembershipTitle) : null;
  const cat: ScanCategory = A_MEMBERS_TYPE_CAT[String(e.userMembersType || "").toUpperCase()] ?? "standard";
  const full = e.userFullName || "Membre";
  const { first, last } = aSplitName(full);
  return {
    laneId: lane.laneId,
    fullName: full,
    firstName: first,
    lastName: last,
    imgUrl: lane.imgUrl,
    granted: !!e.allowed,
    reason: e.reason || "",
    plan: title,
    memberNo: e.userMembershipId != null ? String(e.userMembershipId) : null,
    category: cat,
    validTo: aParseDate(e.userValidTo),
    birthday: e.userBirthday ? aParseDate(e.userBirthday) : null,
    device: e.deviceName || "Entrée",
    method: aMethodFor(e.scanMode),
    at: new Date(lane.arrivedAt),
    repeatCount: Number(e.repeatCount ?? 0) || 0,
    repeatLimit: Number(e.repeatLimit ?? 0) || 0,
    repeatWindowMin: Number(e.repeatWindowMin ?? 0) || 0,
    previousEntryAt: aParseDateTime(e.previousEntryAt),
  };
}

/** "YYYY-MM-DD HH:MM:SS" (local wall-clock, no zone) -> Date. */
function aParseDateTime(s: string | undefined | null): Date | null {
  const t = String(s || "").trim();
  if (!t) return null;
  const m = t.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/);
  if (!m) return null;
  const d = new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  return isNaN(d.getTime()) ? null : d;
}

/** True when the refusal is the pre-existing re-entry block (not a real refusal). */
function aIsReentryDeny(reason: string): boolean {
  const r = String(reason || "").trim().toUpperCase();
  return r === "DENY_ANTI_FRAUD_CARD" || r === "DENY_ANTI_FRAUD_QR";
}

// ── Rule 5: a refusal always says what to do ────────────────────────────────
// The engines emit SCREAMING_SNAKE codes (app/core/access_verification.py,
// realtime_agent.py, ultra_engine.py). Each becomes a sentence plus an action.
interface DenyCopy { title: string; action: string; short: string }
const A_DENY_FALLBACK: DenyCopy = {
  title: "Cet accès n'a pas pu être validé",
  action: "Présentez-vous à l'accueil — nous réglons ça tout de suite.",
  short: "Accès refusé",
};
const A_DENY: Record<string, DenyCopy> = {
  DENY_NO_CARD_MATCH: { title: "Cette carte n'est pas reconnue", action: "Présentez-vous à l'accueil — nous la réassocierons en un instant.", short: "Carte non reconnue" },
  DENY_NO_MATCH: { title: "Ce badge n'est pas reconnu", action: "Présentez-vous à l'accueil — nous le réassocierons en un instant.", short: "Badge non reconnu" },
  INVALID_CARD_FORMAT: { title: "Carte illisible", action: "Représentez-la bien à plat sur le lecteur.", short: "Carte illisible" },
  INVALID_CARD_LENGTH: { title: "Carte illisible", action: "Représentez-la bien à plat sur le lecteur.", short: "Carte illisible" },
  INVALID_FORMAT: { title: "Lecture illisible", action: "Représentez votre carte ou votre code.", short: "Lecture illisible" },
  DENY_CARD_COLLISION: { title: "Cette carte est associée à plusieurs comptes", action: "Présentez-vous à l'accueil pour la régulariser.", short: "Carte en double" },
  DENY_COLLISION: { title: "Ce code correspond à plusieurs comptes", action: "Présentez-vous à l'accueil pour le régulariser.", short: "Code en double" },
  DENY_EXPIRED: { title: "Ce code QR a expiré", action: "Régénérez-le dans l'application MonClub, puis représentez-le.", short: "Code QR expiré" },
  DENY_TOTP_FAILED: { title: "Ce code QR n'est pas valide", action: "Régénérez-le dans l'application MonClub, puis représentez-le.", short: "Code QR invalide" },
  DENY_AMBIGUOUS_COUNTER: { title: "Ce code QR a déjà été utilisé", action: "Régénérez-le dans l'application MonClub.", short: "Code QR déjà utilisé" },
  DENY_FUTURE_SKEW: { title: "L'heure de votre téléphone est décalée", action: "Activez l'heure automatique, puis représentez votre code.", short: "Heure du téléphone décalée" },
  DENY_ANTI_FRAUD_CARD: { title: "Vous venez déjà de passer", action: "Patientez un instant avant de représenter votre carte.", short: "Passage déjà enregistré" },
  DENY_ANTI_FRAUD_QR: { title: "Vous venez déjà de passer", action: "Patientez un instant avant de représenter votre code.", short: "Passage déjà enregistré" },
  DENY_RFID_DISABLED: { title: "Le badge n'est pas activé sur cette entrée", action: "Utilisez votre code QR, ou présentez-vous à l'accueil.", short: "Badge désactivé ici" },
  DENY_HANDLE_SLOW: { title: "Le tourniquet n'a pas répondu à temps", action: "Représentez votre carte — si cela persiste, voyez l'accueil.", short: "Tourniquet sans réponse" },
  DOOR_CMD_FAILED: { title: "Le tourniquet n'a pas répondu", action: "Représentez votre carte — si cela persiste, voyez l'accueil.", short: "Tourniquet sans réponse" },
};
function aDenyCopy(raw: string): DenyCopy {
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

// ── The colour field ────────────────────────────────────────────────────────
interface Field {
  bg: string;
  ink: string;       // primary text
  soft: string;      // secondary text (device name, eyebrow)
  sub: string;       // surname
  dot: string;       // footer separator — a SOLID darker tint, never an alpha
                     // of the ink (rule 2: on a saturated field, opacity drags
                     // a mark toward the background and kills it)
  glyph: GlyphName;  // the giant watermark
  glyphOpacity: number;
  ring: string;      // photo medallion ring
  markColor: string; // wordmark colour
  markOpacity: number;
}
function aFieldFor(scan: EntryScan, now: Date): Field {
  if (!scan.granted && aIsReentryDeny(scan.reason)) {
    // Re-entry block (anti_fraude_duration). The member IS paid up — the door just
    // stayed shut because they passed seconds ago. Orange, not red.
    return { bg: A_ORANGE, ink: "#fff", soft: "#fff", sub: A_ORANGE_SUB, dot: A_ORANGE_SUB, glyph: "history", glyphOpacity: 0.1, ring: "rgba(255,255,255,.5)", markColor: "#fff", markOpacity: 0.6 };
  }
  if (!scan.granted) {
    return { bg: A_RED, ink: "#fff", soft: "#fff", sub: A_RED_SUB, dot: A_RED_SUB, glyph: "cancel", glyphOpacity: 0.1, ring: "rgba(255,255,255,.45)", markColor: "#fff", markOpacity: 0.6 };
  }
  if (scan.birthday && aSameDay(scan.birthday, now)) {
    return { bg: A_GOLD, ink: A_GOLD_INK, soft: A_GOLD_INK_SOFT, sub: A_GOLD_INK_SOFT, dot: A_GOLD_INK, glyph: "cake", glyphOpacity: 0.1, ring: "rgba(255,255,255,.6)", markColor: A_GOLD_INK, markOpacity: 1 };
  }
  return { bg: A_GREEN, ink: A_GREEN_INK, soft: A_GREEN_INK, sub: A_GREEN_INK, dot: A_GREEN_DOT, glyph: "check", glyphOpacity: 0.09, ring: "rgba(255,255,255,.55)", markColor: A_GREEN_INK, markOpacity: 1 };
}

// ── Glyphs (inline SVG — no web-font dependency) ────────────────────────────
// The filled disc glyphs use fillRule="evenodd" so the mark is a true hole in
// the disc, exactly as a Material Symbols filled icon knocks out.
const A_PATHS: Partial<Record<GlyphName, string>> = {
  check: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm-1.4 14.9L5.2 11.5l1.6-1.6 3.8 3.8 6.6-6.6 1.6 1.6z",
  cancel: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm4.2 4.4L12 10.6 7.8 6.4 6.4 7.8 10.6 12l-4.2 4.2 1.4 1.4L12 13.4l4.2 4.2 1.4-1.4L13.4 12z",
  cake: "M12 6c1.11 0 2-.9 2-2 0-.38-.1-.73-.29-1.03L12 0l-1.71 2.97c-.19.3-.29.65-.29 1.03 0 1.1.9 2 2 2zm4.6 9.99-1.07-1.07-1.08 1.07c-1.3 1.3-3.58 1.31-4.89 0l-1.07-1.07-1.09 1.07C6.75 16.64 5.88 17 4.96 17c-.73 0-1.4-.23-1.96-.61V21c0 .55.45 1 1 1h16c.55 0 1-.45 1-1v-4.61c-.56.38-1.23.61-1.96.61-.92 0-1.79-.36-2.44-1.01zM18 9h-5V7h-2v2H6c-1.66 0-3 1.34-3 3v1.54c0 1.08.88 1.96 1.96 1.96.52 0 1.02-.2 1.38-.57l2.14-2.13 2.13 2.13c.74.74 2.03.74 2.77 0l2.14-2.13 2.13 2.13c.37.37.86.57 1.38.57 1.08 0 1.96-.88 1.96-1.96V12c0-1.66-1.34-3-3-3z",
  sparkle: "M12 2.2l1.95 6.15 6.15 1.95-6.15 1.95L12 18.4l-1.95-6.15L3.9 10.3l6.15-1.95z",
  history: "M13 3a9 9 0 0 0-9 9H1l3.89 3.89.07.14L9 12H6a7 7 0 1 1 2.05 4.95l-1.42 1.42A9 9 0 1 0 13 3zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8z",
  schedule: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm-.9 4.4h1.8v5.35l4.15 2.47-.9 1.48-5.05-3.02z",
  card: "M20 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2Zm0 14H4v-6h16zM20 8H4V6h16z",
};

function AGlyph({ name, size, color, opacity, style }: { name: GlyphName; size: number; color?: string; opacity?: number; style?: CSSProperties }) {
  const common: CSSProperties = { width: size + "px", height: size + "px", display: "block", flex: "none", color: color || "currentColor", opacity, ...style };
  if (name === "fingerprint") {
    return (
      <svg viewBox="0 0 24 24" style={common} fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" aria-hidden="true">
        <path d="M6 10.5a6 6 0 0 1 12 0v1.7" />
        <path d="M9 10.6a3 3 0 0 1 6 0v5.6" />
        <path d="M12 10.9v7.3" />
        <path d="M6.2 14.2v-1.1" />
        <path d="M6.9 18.4c.5-.9.8-1.9.9-2.9" />
        <path d="M17.4 18.8c.4-.9.6-1.8.6-2.8" />
      </svg>
    );
  }
  if (name === "qr") {
    return (
      <svg viewBox="0 0 24 24" style={common} fill="currentColor" aria-hidden="true">
        <path fillRule="evenodd" d="M3 3h7.5v7.5H3zm2 2v3.5h3.5V5z" />
        <path fillRule="evenodd" d="M13.5 3H21v7.5h-7.5zm2 2v3.5H19V5z" />
        <path fillRule="evenodd" d="M3 13.5h7.5V21H3zm2 2V19h3.5v-3.5z" />
        <path d="M13.5 13.5h3v3h-3zm4.5 0h3v3h-3zm-4.5 4.5h3v3h-3zm4.5 0h3v3h-3z" />
      </svg>
    );
  }
  return (
    <svg viewBox="0 0 24 24" style={common} fill="currentColor" aria-hidden="true">
      <path fillRule="evenodd" d={A_PATHS[name]} />
    </svg>
  );
}

function AMethodGlyph({ m, size }: { m: ScanMethod; size: number }) {
  return <AGlyph name={m === "qr" ? "qr" : (m === "fingerprint" ? "fingerprint" : "card")} size={size} />;
}

// The design ships `assets/monclub-wordmark.png`, but that export is a broken
// placeholder (two solid red blocks, no lettering), so the mark is set
// typographically in the screen's own display face. Drop a real wordmark in
// src/assets/ and swap this component's body to an <img> when one exists.
function AWordmark({ size, color, opacity }: { size: number; color: string; opacity?: number }) {
  return (
    <span style={{ fontFamily: "'Hanken Grotesk',sans-serif", fontWeight: 800, fontSize: size + "px", lineHeight: 1, letterSpacing: "-.045em", color, opacity, display: "block", whiteSpace: "nowrap" }}>monclub</span>
  );
}

// ── Rule 4: the photo is a verification, not the subject ────────────────────
// A white-ringed medallion. The design crops with `cover` at 22% from the top
// (faces sit high in a portrait); this replaces the previous `contain` fit,
// which cannot look right inside a circle.
function APhoto({ scan, field, size, ring, onImageError }: { scan: EntryScan; field: Field; size: number; ring: number; onImageError: (laneId: string) => void }) {
  return (
    <div style={{ position: "relative", width: size + "px", height: size + "px", flex: "none", borderRadius: "50%", overflow: "hidden", background: "#101010", boxShadow: "0 0 0 " + ring + "px " + field.ring }}>
      {scan.imgUrl ? (
        <img
          src={scan.imgUrl}
          alt=""
          onError={() => onImageError(scan.laneId)}
          style={{ position: "absolute", inset: 0, width: "100%", height: "100%", objectFit: "cover", objectPosition: "center 22%", filter: scan.granted ? "none" : "grayscale(1) contrast(1.05)" }}
        />
      ) : (
        <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", color: "rgba(255,255,255,.92)", fontWeight: 800, fontSize: Math.round(size * 0.34) + "px", letterSpacing: "-.03em" }}>
          {aInitials(scan.fullName)}
        </div>
      )}
    </div>
  );
}

// ── Shared type styles ──────────────────────────────────────────────────────
const A_EYEBROW: CSSProperties = { fontWeight: 700, letterSpacing: ".26em", textTransform: "uppercase" };
const A_NAME: CSSProperties = { fontWeight: 800, letterSpacing: "-.045em", lineHeight: 0.93, overflowWrap: "break-word" };
const A_TABULAR: CSSProperties = { fontWeight: 700, letterSpacing: "-.02em", fontVariantNumeric: "tabular-nums" };

// Rule 3: the first name is enormous — but it still has to fit the frame.
function aFirstSize(s: string, base: number): number {
  const n = s.length;
  if (n <= 5) return base;
  if (n <= 7) return Math.round(base * 0.89);
  if (n <= 9) return Math.round(base * 0.76);
  if (n <= 12) return Math.round(base * 0.63);
  if (n <= 16) return Math.round(base * 0.5);
  return Math.round(base * 0.4);
}
function aLastSize(first: number, s: string): number {
  const base = Math.round(first * 0.455);
  const n = s.length;
  if (n <= 11) return base;
  if (n <= 17) return Math.round(base * 0.78);
  return Math.round(base * 0.62);
}

function APill({ children, bg, color }: { children: ReactNode; bg: string; color: string }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: "10px", height: "44px", padding: "0 20px", borderRadius: "999px", background: bg, color, fontWeight: 700, whiteSpace: "nowrap" }}>
      {children}
    </span>
  );
}

// ── 01 · The verdict screen (one scan) ──────────────────────────────────────
function AVerdict({ scan, now, onImageError }: { scan: EntryScan; now: Date; onImageError: (laneId: string) => void }) {
  const f = aFieldFor(scan, now);
  const birthday = f.glyph === "cake";
  const age = birthday ? aAgeToday(scan.birthday, now) : null;
  const daysLeft = scan.granted ? aDaysLeft(scan.validTo, now) : null;
  const expiring = !birthday && daysLeft != null && daysLeft > 0 && daysLeft <= 7;

  const firstSize = aFirstSize(scan.firstName, 132);
  const lastSize = aLastSize(firstSize, scan.lastName);
  // Frequent-pass VISUAL alert. `repeatCount` is only ever non-zero when the
  // engine actually crossed the threshold, so this is inert on a normal scan.
  const repeat = scan.repeatCount > 1;
  const reentryDeny = !scan.granted && aIsReentryDeny(scan.reason);
  const showBadge = repeat || reentryDeny;

  const eyebrow = reentryDeny
    ? "Deuxième passage"
    : scan.granted
      ? (birthday ? "Joyeux anniversaire" : "Accès autorisé")
      : "Accès refusé";
  const deny = scan.granted ? null : aDenyCopy(scan.reason);

  return (
    <div style={{ position: "absolute", inset: 0, background: f.bg, color: f.ink, display: "flex", overflow: "hidden" }}>
      <AGlyph
        name={f.glyph}
        size={birthday ? 560 : 620}
        color={f.ink}
        opacity={f.glyphOpacity}
        style={{ position: "absolute", right: (birthday ? -70 : -90) + "px", top: "50%", transform: "translateY(-50%)" }}
      />

      <div style={{ position: "relative", flex: 1, minWidth: 0, display: "flex", flexDirection: "column", padding: "34px 46px" }}>
        {/* header */}
        <div style={{ flex: "none", display: "flex", alignItems: "center", justifyContent: "space-between", gap: "20px" }}>
          <AWordmark size={23} color={f.markColor} opacity={f.markOpacity} />
          <div style={{ display: "flex", alignItems: "center", gap: "18px" }}>
            <span style={{ fontSize: "18px", fontWeight: 600, color: f.soft }}>{scan.device}</span>
            <span style={{ ...A_TABULAR, fontSize: "32px", color: f.ink }}>{aClock(now)}</span>
          </div>
        </div>

        {/* rule 3 + rule 4 */}
        <div style={{ flex: 1, minHeight: 0, display: "flex", alignItems: "center", gap: "46px", animation: "aRise .32s cubic-bezier(.4,0,.2,1)" }}>
          <div style={{ position: "relative", flex: "none" }}>
            <APhoto scan={scan} field={f} size={268} ring={8} onImageError={onImageError} />
            {showBadge && (
              <div style={{ position: "absolute", right: "-6px", bottom: "2px", height: "44px", padding: "0 16px", borderRadius: "999px", background: "#fff", color: A_ORANGE_INK_DEEP, fontSize: "19px", fontWeight: 800, display: "flex", alignItems: "center", gap: "8px", boxShadow: "0 4px 14px rgba(0,0,0,.2)" }}>
                <AGlyph name="history" size={22} />
                {scan.repeatCount > 1 ? scan.repeatCount : 2}
                <sup style={{ fontSize: "12px", lineHeight: 1 }}>e</sup>
              </div>
            )}
          </div>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ ...A_EYEBROW, fontSize: "19px", color: f.soft, marginBottom: "18px", display: "flex", alignItems: "center", gap: "12px" }}>
              {birthday && <AGlyph name="sparkle" size={24} />}
              {eyebrow}
            </div>
            <div style={{ ...A_NAME, fontSize: firstSize + "px", marginBottom: "2px", color: f.ink }}>{scan.firstName}</div>
            {!!scan.lastName && <div style={{ ...A_NAME, fontSize: lastSize + "px", color: f.sub }}>{scan.lastName}</div>}
          </div>
        </div>

        {/* footer — one of four states */}
        {deny ? (
          <div style={{ flex: "none", display: "flex", alignItems: "stretch", gap: "20px", padding: "22px 26px", borderRadius: "18px", background: "rgba(0,0,0,.26)" }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: "27px", fontWeight: 700, marginBottom: "6px", color: "#fff" }}>{deny.title}</div>
              <div style={{ fontSize: "20px", fontWeight: 500, color: "#fff" }}>{deny.action}</div>
            </div>
            {/* The two-line timeline only renders when the engine actually gave us a
                previous passage — never fabricated from the current time. */}
            {reentryDeny && scan.previousEntryAt && (
              <>
                <div style={{ width: "1px", flex: "none", background: "rgba(255,255,255,.28)" }} />
                <div style={{ flex: "none", display: "flex", flexDirection: "column", justifyContent: "center", gap: "9px", minWidth: "190px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "11px" }}>
                    <span style={{ ...A_TABULAR, fontSize: "21px", color: "#fff", width: "58px" }}>{aClock(scan.previousEntryAt)}</span>
                    <span style={{ width: "9px", height: "9px", borderRadius: "50%", background: "#fff", flex: "none" }} />
                    <span style={{ fontSize: "17px", fontWeight: 600, color: A_ORANGE_SUB }}>1<sup style={{ fontSize: "10px" }}>er</sup> passage</span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "11px" }}>
                    <span style={{ ...A_TABULAR, fontSize: "21px", color: "#fff", width: "58px" }}>{aClock(scan.at)}</span>
                    <span style={{ width: "9px", height: "9px", borderRadius: "50%", background: "#fff", flex: "none" }} />
                    <span style={{ fontSize: "17px", fontWeight: 700, color: "#fff" }}>maintenant</span>
                  </div>
                </div>
              </>
            )}
          </div>
        ) : repeat ? (
          /* Door opened normally — the passage is merely SIGNALLED to the front desk. */
          <div style={{ flex: "none", display: "flex", alignItems: "center", gap: "18px", padding: "20px 24px", borderRadius: "18px", background: "#fff" }}>
            <AGlyph name="history" size={34} color={A_ORANGE_INK_DEEP} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: "24px", fontWeight: 700, color: "#121A1C" }}>
                {scan.repeatCount}<sup style={{ fontSize: "13px" }}>e</sup> passage en {scan.repeatWindowMin} minute{scan.repeatWindowMin > 1 ? "s" : ""}
              </div>
              <div style={{ fontSize: "19px", fontWeight: 500, color: "#4A5056" }}>
                {scan.previousEntryAt
                  ? `Premier passage à ${aClock(scan.previousEntryAt)} — signalé au poste d'accueil.`
                  : "Signalé au poste d'accueil."}
              </div>
            </div>
            <span style={{ flex: "none", fontSize: "19px", fontWeight: 600, color: "#4A5056", whiteSpace: "nowrap" }}>
              {[scan.plan, scan.memberNo ? "nº " + scan.memberNo : null].filter(Boolean).join(" · ")}
            </span>
          </div>
        ) : expiring ? (
          <div style={{ flex: "none", display: "flex", alignItems: "center", gap: "18px", padding: "20px 24px", borderRadius: "18px", background: A_GOLD_INK }}>
            <AGlyph name="schedule" size={34} color={A_GOLD} />
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ fontSize: "24px", fontWeight: 700, color: "#fff", marginBottom: "4px" }}>
                {"Votre abonnement se termine dans " + daysLeft + " " + aPlural(daysLeft as number, "jour", "jours")}
              </div>
              <div style={{ fontSize: "19px", fontWeight: 500, color: A_GOLD }}>Passez à l'accueil quand vous voulez pour le renouveler.</div>
            </div>
            {!!scan.memberNo && <span style={{ flex: "none", fontSize: "18px", fontWeight: 600, color: A_GOLD }}>{"nº " + scan.memberNo}</span>}
          </div>
        ) : (
          <div style={{ flex: "none", display: "flex", alignItems: "center", gap: "14px", fontSize: "21px", fontWeight: 600, color: f.soft }}>
            {birthday && age != null && (
              <APill bg="rgba(58,42,5,.14)" color={A_GOLD_INK}>{age + " ans aujourd'hui"}</APill>
            )}
            {scan.category !== "standard" && (
              <APill bg="rgba(255,255,255,.22)" color={f.ink}>{A_CATEGORY_LABEL[scan.category]}</APill>
            )}
            {!!scan.plan && <span>{scan.plan}</span>}
            {!birthday && !!scan.plan && !!scan.validTo && (
              <span style={{ width: "5px", height: "5px", borderRadius: "50%", background: f.dot }} />
            )}
            {!birthday && !!scan.validTo && <span>{"valable jusqu'au " + aFullDate(scan.validTo)}</span>}
            <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: "9px", whiteSpace: "nowrap" }}>
              {birthday ? (
                <>
                  <AGlyph name="check" size={24} />
                  Accès autorisé · bonne séance&nbsp;!
                </>
              ) : (
                <>
                  <AMethodGlyph m={scan.method} size={24} />
                  {aMethodLabel(scan.method) + (scan.memberNo ? " · nº " + scan.memberNo : "")}
                </>
              )}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

// ── 03 · Simultaneous scans — every lane is its own full-height field ───────
// The design draws three. `popup_lanes` may be up to MAX_LANES (5), so 4-5
// wrap onto a second row (2×2, then 3+2) and the type steps down — five 256px
// columns cannot carry a 62px first name.
function aMultiGrid(n: number): { columns: string; rows: string; span: (i: number) => number } {
  if (n === 4) return { columns: "repeat(2,1fr)", rows: "repeat(2,1fr)", span: () => 1 };
  if (n >= 5) return { columns: "repeat(6,1fr)", rows: "repeat(2,1fr)", span: (i) => (i < 3 ? 2 : 3) };
  return { columns: "repeat(" + Math.max(1, n) + ",1fr)", rows: "1fr", span: () => 1 };
}

function AMulti({ scans, now, onImageError }: { scans: EntryScan[]; now: Date; onImageError: (laneId: string) => void }) {
  const n = scans.length;
  const grid = aMultiGrid(n);
  const dense = n > 3;
  const photo = dense ? 78 : 104;
  const photoRing = dense ? 4 : 5;
  const ebSize = dense ? 12 : 14;
  const firstBase = dense ? 44 : 62;
  const footSize = dense ? 15 : 17;
  const watermark = dense ? 200 : 280;

  return (
    <div style={{ position: "absolute", inset: 0, background: A_DARK, display: "flex", flexDirection: "column" }}>
      <div style={{ flex: "none", display: "flex", alignItems: "center", justifyContent: "space-between", gap: "20px", padding: "22px 30px 16px" }}>
        <AWordmark size={20} color="#fff" opacity={0.5} />
        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
          <span style={{ fontSize: "16px", fontWeight: 600, color: A_DARK_SUB }}>{n + " passages simultanés · " + scans[0].device}</span>
          <span style={{ ...A_TABULAR, fontSize: "28px", color: "#fff" }}>{aClock(now)}</span>
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: grid.columns, gridTemplateRows: grid.rows, gap: "14px", padding: "0 24px 24px" }}>
        {scans.map((scan, i) => {
          const f = aFieldFor(scan, now);
          const birthday = f.glyph === "cake";
          const deny = scan.granted ? null : aDenyCopy(scan.reason);
          const firstSize = aFirstSize(scan.firstName, firstBase);
          const lastSize = aLastSize(firstSize, scan.lastName);
          return (
            <div
              key={scan.laneId}
              style={{
                gridColumn: "span " + grid.span(i),
                minWidth: 0,
                position: "relative",
                overflow: "hidden",
                borderRadius: "24px",
                background: f.bg,
                color: f.ink,
                display: "flex",
                flexDirection: "column",
                padding: dense ? "20px 20px" : "26px 24px",
                animation: "aRise .3s cubic-bezier(.4,0,.2,1) " + (i * 0.06).toFixed(2) + "s both",
              }}
            >
              <AGlyph name={f.glyph} size={watermark} color={f.ink} opacity={f.glyphOpacity + 0.01} style={{ position: "absolute", right: "-52px", bottom: "-52px" }} />
              <div style={{ position: "relative", marginBottom: dense ? "16px" : "22px" }}>
                <APhoto scan={scan} field={f} size={photo} ring={photoRing} onImageError={onImageError} />
              </div>
              <div style={{ position: "relative", flex: 1, minHeight: 0 }}>
                <div style={{ ...A_EYEBROW, fontSize: ebSize + "px", color: f.soft, marginBottom: dense ? "9px" : "12px" }}>
                  {scan.granted ? (birthday ? "Anniversaire" : "Autorisé") : "Refusé"}
                </div>
                <div style={{ ...A_NAME, fontSize: firstSize + "px", marginBottom: "2px", color: f.ink }}>{scan.firstName}</div>
                {!!scan.lastName && (
                  <div style={{ ...A_NAME, fontSize: lastSize + "px", color: f.sub, display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{scan.lastName}</div>
                )}
              </div>
              {deny ? (
                <div style={{ position: "relative", flex: "none", padding: "14px 16px", borderRadius: "14px", background: "rgba(0,0,0,.26)" }}>
                  <div style={{ fontSize: (footSize + 1) + "px", fontWeight: 700, marginBottom: "3px", color: "#fff" }}>{deny.short}</div>
                  <div style={{ fontSize: (footSize - 2) + "px", fontWeight: 500, color: "#fff" }}>Voyez l'accueil</div>
                </div>
              ) : (
                <div style={{ position: "relative", flex: "none", fontSize: footSize + "px", fontWeight: 600, color: f.soft }}>
                  <div style={{ marginBottom: "5px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{scan.plan || (scan.memberNo ? "nº " + scan.memberNo : "Membre")}</div>
                  <div style={{ display: "flex", alignItems: "center", gap: "9px" }}>
                    <AMethodGlyph m={scan.method} size={footSize + 3} />
                    {aMethodLabel(scan.method) + " · " + aClock(scan.at)}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── 04 · Standby ────────────────────────────────────────────────────────────
// The only state with no verdict colour: the design-system dark means "no
// decision in progress", which is what makes the arrival of green or red so
// abrupt. The breathing dot says the reader is listening — without it, a
// frozen screen and a broken one look identical.
const A_TOPO_URL = (() => {
  const rings: string[] = [];
  const centres: Array<[number, number, number]> = [[190, 205, 1.35], [455, 445, 0.85]];
  for (const [cx, cy, k] of centres) {
    for (let i = 1; i <= 11; i++) {
      const r = i * 26 * k;
      rings.push('<ellipse cx="' + cx + '" cy="' + cy + '" rx="' + (r * 1.18).toFixed(1) + '" ry="' + r.toFixed(1) + '" transform="rotate(' + (i * 3 - 14) + ' ' + cx + ' ' + cy + ')"/>');
    }
  }
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="640" height="640" viewBox="0 0 640 640"><g fill="none" stroke="#ffffff" stroke-width="1.6">' + rings.join("") + "</g></svg>";
  return 'url("data:image/svg+xml,' + encodeURIComponent(svg) + '")';
})();

function ABreathDot({ color }: { color: string }) {
  return (
    <span style={{ position: "relative", display: "inline-block", width: "9px", height: "9px", flex: "none" }}>
      <i style={{ position: "absolute", inset: 0, borderRadius: "50%", background: color, animation: "aBreathe 2.6s ease-out infinite" }} />
      <i style={{ position: "absolute", inset: 0, borderRadius: "50%", background: color }} />
    </span>
  );
}

type ACreds = { rfid?: boolean; fingerprint?: boolean; qr?: boolean; face?: boolean } | null;

/** What the readers in THIS gym actually accept. Falls back to the historical
 *  card wording only when nothing is known -- never name a credential family the
 *  hardware does not have (the standalone terminal has no card reader at all). */
function aIdlePrompt(creds: ACreds): { glyph: "card" | "fingerprint" | "qr"; text: string } {
  if (!creds) return { glyph: "card", text: "Présentez votre carte" };
  const on = [
    creds.rfid ? "card" : null,
    creds.fingerprint ? "fingerprint" : null,
    creds.qr ? "qr" : null,
  ].filter(Boolean) as ("card" | "fingerprint" | "qr")[];
  if (on.length === 0) return { glyph: "card", text: "Présentez-vous au lecteur" };
  if (on.length > 1) return { glyph: on[0], text: "Présentez-vous au lecteur" };
  if (on[0] === "fingerprint") return { glyph: "fingerprint", text: "Posez votre doigt" };
  if (on[0] === "qr") return { glyph: "qr", text: "Présentez votre QR code" };
  return { glyph: "card", text: "Présentez votre carte" };
}

function AIdle({ place, now, linkUp, todayCount, readersUp, readersTotal, creds }: { place: string; now: Date; linkUp: boolean; todayCount: number; readersUp: number | null; readersTotal: number | null; creds: ACreds }) {
  const prompt = aIdlePrompt(creds);
  return (
    <div style={{ position: "absolute", inset: 0, background: A_DARK, color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", overflow: "hidden" }}>
      <div style={{ position: "absolute", inset: 0, backgroundImage: A_TOPO_URL, backgroundSize: "cover", backgroundPosition: "center", opacity: 0.06 }} />
      <div style={{ position: "absolute", top: "30px", left: "36px" }}><AWordmark size={20} color="#fff" opacity={0.5} /></div>
      <div style={{ position: "absolute", top: "30px", right: "36px", display: "inline-flex", alignItems: "center", gap: "11px", height: "38px", padding: "0 16px", borderRadius: "12px", background: "rgba(255,255,255,.08)" }}>
        <ABreathDot color={aReaderTone(linkUp, readersUp, readersTotal)} />
        <span style={{ fontSize: "16px", fontWeight: 600, color: A_DARK_SUB }}>{aReaderLabel(linkUp, readersUp, readersTotal)}</span>
      </div>

      <div style={{ position: "relative", display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center" }}>
        <div style={{ ...A_TABULAR, fontSize: "152px", lineHeight: 1, letterSpacing: "-.05em", color: "#fff", marginBottom: "12px" }}>{aClock(now)}</div>
        <div style={{ fontSize: "26px", fontWeight: 500, color: A_DARK_SUB, marginBottom: "54px" }}>{aLongDate(now)}</div>
        <div style={{ display: "flex", alignItems: "center", gap: "18px", padding: "20px 34px", borderRadius: "999px", background: A_RED, color: "#fff" }}>
          <AGlyph name={prompt.glyph} size={34} />
          <span style={{ fontSize: "28px", fontWeight: 700, letterSpacing: "-.01em" }}>{prompt.text}</span>
        </div>
      </div>

      <div style={{ position: "absolute", bottom: "32px", left: 0, right: 0, display: "flex", alignItems: "center", justifyContent: "center", gap: "24px", fontSize: "16px", color: A_DARK_SUB }}>
        <span>{place}</span>
        {todayCount > 0 && (
          <>
            <span style={{ width: "5px", height: "5px", borderRadius: "50%", background: A_DARK_FAINT }} />
            <span>{todayCount + " " + aPlural(todayCount, "passage", "passages") + " aujourd'hui"}</span>
          </>
        )}
      </div>
    </div>
  );
}

// ── The 1280×720 stage ──────────────────────────────────────────────────────
// Uniformly scaled to the window so the design's own pixel values hold at any
// size (1920×1080 is the same ratio). The window background is painted with
// the field colour too, so on a non-16:9 window the letterbox still reads as
// the verdict rather than as a black bar.
function AStage({ background, children }: { background: string; children: ReactNode }) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const [scale, setScale] = useState(1);

  const measure = useCallback(() => {
    const el = hostRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) return;
    const next = Math.min(r.width / STAGE_W, r.height / STAGE_H);
    // setState with an unchanged number bails out, so this never loops.
    if (next > 0) setScale(next);
  }, []);

  useLayoutEffect(() => {
    measure();
    window.addEventListener("resize", measure);
    let ro: ResizeObserver | undefined;
    if (typeof ResizeObserver !== "undefined") {
      ro = new ResizeObserver(measure);
      ro.observe(hostRef.current as Element);
    }
    return () => {
      window.removeEventListener("resize", measure);
      if (ro) ro.disconnect();
    };
  }, [measure]);

  // Self-heal: ResizeObserver notifications are delivered on the frame
  // lifecycle, so a webview that is resized while not compositing (moved to
  // another monitor, un-minimised, fullscreened) can come back with a stale
  // scale and a letterboxed or overflowing stage. This screen re-renders every
  // second from its own clock, so re-measuring on every render costs one
  // getBoundingClientRect per second and guarantees the stage corrects itself.
  useLayoutEffect(measure);

  return (
    <div ref={hostRef} style={{ position: "fixed", inset: 0, overflow: "hidden", background, transition: "background 280ms ease" }}>
      <div
        style={{
          position: "absolute",
          left: "50%",
          top: "50%",
          width: STAGE_W + "px",
          height: STAGE_H + "px",
          transform: "translate(-50%,-50%) scale(" + scale + ")",
          transformOrigin: "center center",
          overflow: "hidden",
          fontFamily: "'Hanken Grotesk',sans-serif",
          WebkitFontSmoothing: "antialiased",
        }}
      >
        {children}
      </div>
    </div>
  );
}

// Screen-level component: standby / verdict / wall from the active lanes.
function EntryScreen({ lanes, idle, gymName, linkUp, todayCount, onImageError }: {
  lanes: ActiveLane[];
  idle: boolean;
  gymName: string;
  linkUp: boolean;
  todayCount: number;
  onImageError: (laneId: string) => void;
}) {
  const [now, setNow] = useState<Date>(() => new Date());
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const scans = useMemo(() => lanes.map(mapLaneToScan), [lanes]);
  const single = !idle && scans.length === 1;
  const multi = !idle && scans.length > 1;

  // The standby screen has no event to name the door, so remember the last one.
  const [lastDevice, setLastDevice] = useState("");
  useEffect(() => {
    const d = scans.length ? scans[0].device : "";
    if (d) setLastDevice(d);
  }, [scans]);

  const stageBg = single ? aFieldFor(scans[0], now).bg : A_DARK;
  const sceneKey = idle ? "idle" : scans.map((s) => s.laneId).join("|");

  return (
    <AStage background={stageBg}>
      <div key={sceneKey} style={{ position: "absolute", inset: 0, animation: "aScene 420ms cubic-bezier(.16,.84,.3,1) both" }}>
        {idle && <AIdle place={lastDevice || gymName || "MonClub Access"} now={now} linkUp={linkUp} todayCount={todayCount} readersUp={readersUp} readersTotal={readersTotal} creds={creds} />}
        {single && <AVerdict scan={scans[0]} now={now} onImageError={onImageError} />}
        {multi && <AMulti scans={scans} now={now} onImageError={onImageError} />}
      </div>
    </AStage>
  );
}

/* ▲▲▲ END DIRECTION A ▲▲▲ */

// ── Main component ────────────────────────────────────────────────────────
// ── Freeze telemetry beacon (popup → backend) ────────────────────────────────
// Posts a heartbeat / SSE-lifecycle beacon to the local API so a popup-window
// FREEZE is visible in the backend log: if these stop arriving the webview is
// hung; if they keep arriving while no popup shows, it's the data/render path.
// Hits an auth-exempt loopback endpoint; best-effort (never throws).
// Reader badge for the idle screen. Reports what is actually known:
// a partly-down fleet is amber with a count, never a single green light.
function aReaderTone(linkUp: boolean, up: number | null, total: number | null): string {
  if (total === null || up === null) return linkUp ? A_GREEN : A_RED;
  if (up === 0) return A_RED;
  return up < total ? A_GOLD : A_GREEN;
}
function aReaderLabel(linkUp: boolean, up: number | null, total: number | null): string {
  if (total === null || up === null) return linkUp ? "Lecteur actif" : "Lecteur hors ligne";
  if (up === 0) return total > 1 ? "Lecteurs hors ligne" : "Lecteur hors ligne";
  if (up < total) return `${up}/${total} lecteurs actifs`;
  return total > 1 ? `${total} lecteurs actifs` : "Lecteur actif";
}

function postPopupTelemetry(body: Record<string, unknown>): void {
  try {
    void fetch(`${getApiBaseUrl()}${LOCAL_API_PREFIX}/popup/telemetry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      keepalive: true,
    }).catch(() => {});
  } catch { /* ignore */ }
}

export default function PopupWindow() {
  const [lanes, setLanes] = useState<ActiveLane[]>([]);
  const [gymName, setGymName] = useState<string>("");
  const [maxLanes, setMaxLanes] = useState<number>(DEFAULT_LANES);
  const [defaultDurationSec, setDefaultDurationSec] = useState<number>(DEFAULT_DURATION_SEC);
  // Standby-screen chrome. `linkUp` starts optimistic so opening the window
  // never flashes "hors ligne" before the first poll lands.
  const [linkUp, setLinkUp] = useState<boolean>(true);
  // Counts so a partly-down fleet is not hidden behind one green light.
  const [readersUp, setReadersUp] = useState<number | null>(null);
  const [readersTotal, setReadersTotal] = useState<number | null>(null);
  const [creds, setCreds] = useState<ACreds>(null);
  const [todayCount, setTodayCount] = useState<number>(0);

  const lanesRef = useRef<ActiveLane[]>([]);
  const seenEventIdsRef = useRef<Map<string, number>>(new Map()); // event_id → seen-at, for cheap cross-channel dedupe
  const lastLocalRawRef = useRef<string>("");
  const tickHandleRef = useRef<number | null>(null);

  // ── Freeze telemetry state (popup heartbeat + SSE lifecycle) ──
  const lastSseAtRef = useRef<number>(0);     // last SSE message that reached JS (incl 15s ping)
  const lastShownAtRef = useRef<number>(0);   // last lane-state change (a render update)
  const sseStateRef = useRef<string>("init"); // init | open | error
  const sseReconnectsRef = useRef<number>(0);
  const mountedAtRef = useRef<number>(Date.now());
  // Bumping this tears down + rebuilds the SSE EventSource. The watchdog uses it
  // to recover from a SILENTLY-dead stream (readyState OPEN but no data/ping for
  // >45s — native EventSource fires no onerror on a half-open socket, so it never
  // auto-reconnects → the popup was stuck until a manual right-click→Refresh).
  const [sseEpoch, setSseEpoch] = useState(0);
  const lastForcedReconnectRef = useRef<number>(0);

  // keep refs in sync with state; a lanes change == the popup re-rendered new content
  useEffect(() => { lanesRef.current = lanes; lastShownAtRef.current = Date.now(); }, [lanes]);

  // Fetch popup config (lane count, default duration) once on mount
  useEffect(() => {
    fetch(`${getApiBaseUrl()}${LOCAL_API_PREFIX}/status`)
      .then((r) => r.json())
      .then((d) => {
        const name =
          d?.session?.gymName ||
          d?.gymName ||
          d?.session?.organizationName ||
          "";
        if (name) setGymName(String(name));
        const lanesRaw = Number(d?.popup?.lanes);
        if (Number.isFinite(lanesRaw) && lanesRaw > 0) {
          setMaxLanes(Math.min(MAX_LANES, Math.max(1, Math.floor(lanesRaw))));
        }
        const durRaw = Number(d?.popup?.durationSec);
        if (Number.isFinite(durRaw) && durRaw > 0) {
          setDefaultDurationSec(Math.max(1, Math.floor(durRaw)));
        }
      })
      .catch(() => {});
  }, []);

  // Image source resolution
  const resolveImageForLane = useCallback((evt: PopupEvent): { imgUrl: string | null; imgFallbacks: string[] } => {
    if (!evt.popupShowImage) return { imgUrl: null, imgFallbacks: [] };
    const chain = buildPopupImageCandidates(evt);
    const first = chain[0];
    if (!first) return { imgUrl: null, imgFallbacks: [] };
    return {
      imgUrl: toPopupCachedImageUrl(first),
      imgFallbacks: chain.slice(1),
    };
  }, []);

  // Lane image error → advance the fallback chain
  const handleImageError = useCallback((laneId: string) => {
    setLanes((current) => {
      const next: ActiveLane[] = [];
      let mutated = false;
      for (const lane of current) {
        if (lane.laneId !== laneId) {
          next.push(lane);
          continue;
        }
        const remaining = [...lane.imgFallbacks];
        const candidate = remaining.shift();
        if (!candidate) {
          // give up — switch to initial avatar
          next.push({ ...lane, imgUrl: null, imgFallbacks: [] });
          mutated = true;
          continue;
        }
        next.push({
          ...lane,
          imgUrl: toPopupCachedImageUrl(candidate),
          imgFallbacks: remaining,
        });
        mutated = true;
      }
      return mutated ? next : current;
    });
  }, []);

  // Add a new event into the lane grid (latest-N policy)
  const enqueue = useCallback(
    (evt: PopupEvent) => {
      // Show ONLY granted entries for identified members. Denied scans and
      // unidentified ("Inconnu") cards are not surfaced on the popup wall.
      // (History/audit still records everything via the drawer — this filter is
      // popup-display only.) See SHOW_DENIED_ENTRIES.
      const knownUser = !!evt.userFullName && evt.userFullName.trim().length > 0;
      if ((!evt.allowed && !SHOW_DENIED_ENTRIES) || !knownUser) {
        console.debug("[popup] skip (not a granted+known entry)", {
          eventId: evt.eventId, allowed: evt.allowed,
          user: evt.userFullName, reason: evt.reason,
        });
        return;
      }

      // Cross-channel dedupe: SSE + Tauri + localStorage may all deliver the
      // same event in the same window. We keep a small Map of recently-seen
      // event IDs and drop duplicates. 30s window matches the backend's
      // anti-fraud cooldown and is much shorter than the old per-person 8s
      // dedupe (which was actually blocking distinct rapid entries).
      const now = Date.now();
      const seenAt = seenEventIdsRef.current.get(evt.eventId);
      if (seenAt && now - seenAt < 30_000) return;
      seenEventIdsRef.current.set(evt.eventId, now);
      // periodic cleanup of the dedupe map
      if (seenEventIdsRef.current.size > 200) {
        const cutoff = now - 60_000;
        for (const [eid, ts] of seenEventIdsRef.current) {
          if (ts < cutoff) seenEventIdsRef.current.delete(eid);
        }
      }

      console.info("[popup] SHOW", { eventId: evt.eventId, user: evt.userFullName, device: evt.deviceName });
      const durationSec = evt.popupDurationSec || defaultDurationSec;
      const durationMs = Math.max(MIN_DURATION_MS, durationSec * 1000);
      const expiresAt = now + durationMs;
      const { imgUrl, imgFallbacks } = resolveImageForLane(evt);
      const newLane: ActiveLane = {
        laneId: laneIdFor(evt.eventId),
        event: evt,
        arrivedAt: now,
        expiresAt,
        fadingOut: false,
        imgUrl,
        imgFallbacks,
      };

      setLanes((current) => {
        // already showing this exact event? (defensive — dedupe above
        // catches the common case; this guards an SSE replay race)
        if (current.some((l) => l.event.eventId === evt.eventId && !l.fadingOut)) {
          return current;
        }
        if (current.length < maxLanes) {
          return [...current, newLane];
        }
        // evict the oldest lane (the one with the earliest arrivedAt) so
        // the freshest scan is always visible. This is what the user asked
        // for: at peak hours, show the three latest entries.
        let oldestIdx = 0;
        let oldestArrived = current[0].arrivedAt;
        for (let i = 1; i < current.length; i++) {
          if (current[i].arrivedAt < oldestArrived) {
            oldestArrived = current[i].arrivedAt;
            oldestIdx = i;
          }
        }
        const next = current.slice();
        next[oldestIdx] = newLane;
        return next;
      });
    },
    [maxLanes, defaultDurationSec, resolveImageForLane],
  );

  // Expiration tick: every 200ms re-check expiries. Uses a single setInterval
  // for the whole grid (one timer, N lanes) — far cheaper than per-lane
  // setTimeout that we'd have to track/clean on every state change.
  useEffect(() => {
    const tick = () => {
      const now = Date.now();
      const current = lanesRef.current;
      if (current.length === 0) return;
      let mutated = false;
      const next: ActiveLane[] = [];
      for (const lane of current) {
        if (lane.fadingOut) {
          // already fading; drop after FADE_OUT_MS
          if (now - lane.expiresAt > FADE_OUT_MS) {
            mutated = true;
            continue; // drop this lane entirely
          }
          next.push(lane);
        } else if (now >= lane.expiresAt) {
          next.push({ ...lane, fadingOut: true });
          mutated = true;
        } else {
          next.push(lane);
        }
      }
      if (mutated) setLanes(next);
    };
    tickHandleRef.current = window.setInterval(tick, 200);
    return () => {
      if (tickHandleRef.current != null) {
        window.clearInterval(tickHandleRef.current);
        tickHandleRef.current = null;
      }
    };
  }, []);

  // ── Channel 1: SSE from local API ────────────────────────────────────────
  useEffect(() => {
    // replayLast=0: do NOT replay the last popup on connect. The popup wall
    // must show only LIVE scans. replayLast=1 caused the window to re-show an
    // old ("ancient") member on every open and on every silent reconnect
    // (the SSE force-closes every 30 min and EventSource auto-reconnects).
    console.info("[popup] SSE connecting /agent/events (replayLast=0)");
    // Stamp now so a stream that never delivers a single message/ping is still
    // detectable by the watchdog from t0 (not just after the first message).
    lastSseAtRef.current = Date.now();
    const es = openSSE("/agent/events?replayLast=0&client=popup", (type, data) => {
      // ANY SSE message (including the 15s ping) proves data is reaching the
      // popup's JS event loop — used by the freeze heartbeat to localise stalls.
      lastSseAtRef.current = Date.now();
      if (type !== "popup" && type !== "notification") return;
      try {
        const parsed = typeof data === "string" ? JSON.parse(data) : data;
        console.debug("[popup] SSE event recv", {
          eventId: parsed?.eventId, allowed: parsed?.allowed,
          user: parsed?.userFullName ?? parsed?.fullName, reason: parsed?.reason,
        });
        enqueue(toPopupEvent(parsed));
      } catch (err) {
        console.warn("[popup] SSE parse failed", err);
      }
    }, {
      onOpen: () => { sseStateRef.current = "open"; lastSseAtRef.current = Date.now(); },
      onError: () => { sseStateRef.current = "error"; },
      onReconnect: () => { sseReconnectsRef.current += 1; },
    });
    // Watchdog for SILENT SSE death: native EventSource fires NO onerror on a
    // half-open socket, so it never auto-reconnects (POPUP_HB showed reconns stuck
    // at 0 while the popup froze until a manual refresh). If the stream is OPEN but
    // no message/ping has arrived for >45s (3 missed 15s server pings), force a
    // fresh connection. At most one forced reconnect per 20s so a genuinely-down
    // backend can't cause a reconnect storm. Keeps replayLast=0 (live-only) on the
    // rebuild — must NOT reintroduce replayLast>0 (the "ancient user on open" bug).
    const wd = window.setInterval(() => {
      if (es.readyState !== EventSource.OPEN) return; // CONNECTING/CLOSED: native path handles it
      const now = Date.now();
      if (now - lastSseAtRef.current <= 45000) return;
      if (now - lastForcedReconnectRef.current < 20000) return;
      lastForcedReconnectRef.current = now;
      sseStateRef.current = "error";
      sseReconnectsRef.current += 1;
      console.warn("[popup] SSE watchdog: stream silent >45s while OPEN — forcing reconnect");
      try { es.close(); } catch { /* noop */ }
      setSseEpoch((e) => e + 1); // triggers this effect's cleanup + rebuild
    }, 10000);
    return () => { window.clearInterval(wd); es.close(); };
  }, [enqueue, sseEpoch]);

  // ── Channel 2: Tauri IPC ────────────────────────────────────────────────
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    import("@tauri-apps/api/event")
      .then(({ listen }) => listen<any>("popup-notification", (e) => {
        try { enqueue(toPopupEvent(e.payload)); } catch { /* ignore */ }
      }))
      .then((fn) => { unlisten = fn; })
      .catch(() => { /* browser dev mode */ });
    return () => { if (unlisten) unlisten(); };
  }, [enqueue]);

  // ── Channel 3: localStorage polling (cross-window fallback) ─────────────
  useEffect(() => {
    const read = () => {
      try {
        const raw = localStorage.getItem("popupEvent");
        if (!raw || raw === lastLocalRawRef.current) return;
        lastLocalRawRef.current = raw;
        const parsed = JSON.parse(raw);
        // Drop a STALE stored event (this fallback can hold an old value on
        // mount — another "ancient user on open" source). receivedAt is stamped
        // by the writer; ignore anything older than 10s.
        const ts = Number(parsed?.receivedAt ?? 0);
        if (ts && Date.now() - ts > 10_000) {
          console.debug("[popup] skip stale localStorage event", { ageMs: Date.now() - ts });
          return;
        }
        enqueue(toPopupEvent(parsed));
      } catch { /* ignore */ }
    };
    const onStorage = (e: StorageEvent) => { if (e.key === "popupEvent") read(); };
    read();
    window.addEventListener("storage", onStorage);
    const id = window.setInterval(read, 500);
    return () => {
      window.removeEventListener("storage", onStorage);
      window.clearInterval(id);
    };
  }, [enqueue]);

  // ── Channel 4: sequence-cursor polling (guaranteed self-healing floor) ─────
  // The SSE (Ch.1) and the main window's re-broadcast (Ch.2/3) all depend on a
  // long-lived connection that can SILENTLY half-die (no onerror), leaving the
  // popup stuck until a manual refresh. This channel does NOT depend on any
  // connection staying alive: each poll is an independent HTTP request, so a
  // dead socket just means one poll fails and the next succeeds. It guarantees
  // the popup catches up within the poll interval regardless of SSE state.
  // First poll (cursor -1) starts at the server's HEAD => no backlog/ancient
  // events; thereafter only NEW events per the per-engine seq cursors. Overlap
  // with the SSE is removed by the eventId dedupe in enqueue().
  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    let sinceAgent = -1; // -1 => first poll pins the cursor at HEAD (live-only)
    let sinceUltra = -1;
    let misses = 0;
    const poll = async () => {
      try {
        const res = await get<any>("/popup/poll", {
          since_agent: String(sinceAgent),
          since_ultra: String(sinceUltra),
        });
        if (cancelled) return;
        // This poll is the popup's only connection-independent link to the
        // backend, so it also drives the standby screen's "Lecteur actif"
        // indicator. Both setState calls are no-ops when the value is
        // unchanged, so the 1.5s cadence costs no re-renders.
        misses = 0;
        // readersUp/readersTotal are the REAL per-device link state from the ULTRA
        // worker. HTTP success only proves the local server answered -- on a
        // standalone terminal the reader link lives inside the worker, so a dead
        // MB2000 used to breathe green here all day. Absent (AGENT gyms, older
        // backend) => keep the previous optimistic behaviour rather than lie red.
        if (typeof res?.readersTotal === "number" && res.readersTotal > 0) {
          setReadersUp(typeof res?.readersUp === "number" ? res.readersUp : null);
          setReadersTotal(res.readersTotal);
          setLinkUp((res.readersUp ?? 0) > 0);
        } else {
          setReadersUp(null);
          setReadersTotal(null);
          setLinkUp(true);
        }
        if (typeof res?.todayCount === "number") setTodayCount(res.todayCount);
        setCreds(res?.credentials && typeof res.credentials === "object" ? res.credentials : null);
        if (typeof res?.seqAgent === "number") sinceAgent = res.seqAgent;
        if (typeof res?.seqUltra === "number") sinceUltra = res.seqUltra;
        const evs = Array.isArray(res?.events) ? res.events : [];
        for (const ev of evs) {
          try { enqueue(toPopupEvent(ev)); } catch { /* ignore one bad event */ }
        }
      } catch {
        // transient (stall/offline) — the next tick just retries. Only call the
        // reader offline after two consecutive misses so a single blip on a
        // busy backend does not flicker the standby badge.
        misses += 1;
        if (!cancelled && misses >= 2) setLinkUp(false);
      }
      finally {
        if (!cancelled) timer = window.setTimeout(poll, 1500);
      }
    };
    timer = window.setTimeout(poll, 1500);
    return () => { cancelled = true; if (timer) window.clearTimeout(timer); };
  }, [enqueue]);

  // ── Freeze telemetry: heartbeat beacon to the backend (POPUP_HB) ──────────
  // Fires every 10s from the popup's OWN event loop. If the webview hangs these
  // stop → a gap in POPUP_HB pinpoints a popup-window freeze (vs backend/data).
  useEffect(() => {
    const beat = () => {
      const now = Date.now();
      postPopupTelemetry({
        kind: "hb",
        window: "popup",
        lanes: lanesRef.current.length,
        sse: sseStateRef.current,
        sseReconnects: sseReconnectsRef.current,
        lastSseAgeMs: lastSseAtRef.current ? now - lastSseAtRef.current : -1,
        lastShownAgeMs: lastShownAtRef.current ? now - lastShownAtRef.current : -1,
        uptimeMs: now - mountedAtRef.current,
      });
    };
    beat(); // initial beacon on mount
    const id = window.setInterval(beat, 10_000);
    return () => window.clearInterval(id);
  }, []);

  // Active lanes → entry screen (standby when none, verdict for 1, wall for 2+)
  const visibleLanes = useMemo(() => lanes, [lanes]);
  const laneCount = visibleLanes.length;

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <>
      <EntryScreen
        lanes={visibleLanes}
        idle={laneCount === 0}
        gymName={gymName}
        linkUp={linkUp}
        todayCount={todayCount}
        onImageError={handleImageError}
      />
      <style>{globalKeyframes}</style>
    </>
  );
}

// ── Keyframes shared across the window (Hanken Grotesk is bundled via @fontsource) ─
const globalKeyframes = `
  @keyframes aRise{from{opacity:0;transform:translateY(16px);}to{opacity:1;transform:none;}}
  @keyframes aBreathe{0%,100%{transform:scale(1);opacity:.5;}50%{transform:scale(1.7);opacity:0;}}
  @keyframes aScene{from{opacity:0;}to{opacity:1;}}
`;
