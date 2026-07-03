// Multi-lane TV popup for the gym entry display — MÉRIDIEN design.
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
// The presentation layer is the MÉRIDIEN "Borne d'accueil" design: one
// screen-level component (MeridienScreen) that shows an idle standby, a
// single hero card (1 scan), or a "simultaneous scans" wall (2-3 scans).
// All data/lifecycle plumbing below the SOURCE banner is unchanged.

import { useState, useEffect, useRef, useCallback, useMemo, type CSSProperties } from "react";
import { getApiBaseUrl, openSSE, get } from "@/api/client";
import type { PopupEvent } from "@/api/types";
import { LOCAL_API_PREFIX } from "@/config/appConst";
import { buildPopupImageCandidates, toPopupCachedImageUrl } from "@/lib/popupImages";
// Self-hosted Hanken Grotesk (the MÉRIDIEN display font) — bundled by Vite so the
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
  };
}

function laneIdFor(eventId: string): string {
  return `lane-${eventId.slice(0, 24)}-${Math.floor(Math.random() * 1e6)}`;
}

/* ══════════════════════════════════════════════════════════════════════════
   ▼▼▼ MÉRIDIEN design — ported from the Claude Design "Borne d'accueil" export.
   Pure presentation: takes the active lanes and renders idle / single / multi.
   ════════════════════════════════════════════════════════════════════════ */

// Parse an inline CSS string into a React style object (keeps the design's
// exact inline styles verbatim, incl. custom props like --accent).
function css(s: string): CSSProperties {
  const o: Record<string, string> = {};
  for (const decl of String(s).split(";")) {
    const d = decl.trim();
    if (!d) continue;
    const i = d.indexOf(":");
    if (i < 0) continue;
    const prop = d.slice(0, i).trim();
    const val = d.slice(i + 1).trim();
    if (prop.indexOf("--") === 0) { o[prop] = val; continue; }
    o[prop.replace(/-([a-z])/g, (_m, c: string) => c.toUpperCase())] = val;
  }
  return o as CSSProperties;
}

const M_GREEN = "oklch(0.82 0.18 142)";
const M_RED = "oklch(0.62 0.21 25)";
const M_GOLD = "oklch(0.82 0.14 85)";
const M_MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
const M_MONTHS_SHORT = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const M_DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

type ScanCategory = "standard" | "staff" | "kids";
type ScanMethod = "card" | "qr" | "fingerprint";

interface MeridienScan {
  laneId: string;
  name: string;
  imgUrl: string | null;
  granted: boolean;
  denyReason: string;
  plan: string | null;
  memberNo: string | null;
  category: ScanCategory;
  validFrom: Date | null;
  validTo: Date | null;
  birthday: Date | null;
  device: string;
  method: ScanMethod;
}

function mSameDay(a: Date, b: Date): boolean { return a.getDate() === b.getDate() && a.getMonth() === b.getMonth(); }
function mClock(d: Date): string { return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }); }
function mLongDate(d: Date): string { return M_DAYS[d.getDay()] + " " + d.getDate() + " " + M_MONTHS[d.getMonth()] + " " + d.getFullYear(); }
function mShortDate(d: Date): string { return d.getDate() + " " + M_MONTHS_SHORT[d.getMonth()] + " " + d.getFullYear(); }
function mMonthYear(d: Date): string { return M_MONTHS_SHORT[d.getMonth()] + " " + d.getFullYear(); }
function mMethodLabel(m: ScanMethod): string { return m === "qr" ? "QR Code" : (m === "fingerprint" ? "Fingerprint" : "Card"); }
function mPlanLabel(scan: MeridienScan): string { return scan.plan || (scan.memberNo ? ("No. " + scan.memberNo) : "Member"); }
function mInitials(name: string): string {
  const p = (name || "").trim().split(/\s+/).filter(Boolean);
  if (!p.length) return "—";
  const a = p[0][0] || "";
  const b = p.length > 1 ? p[p.length - 1][0] : "";
  return (a + b).toUpperCase();
}
function mAccent(scan: MeridienScan, now: Date): string {
  const bd = !!(scan.birthday && mSameDay(scan.birthday, now));
  return scan.granted ? (bd ? M_GOLD : M_GREEN) : M_RED;
}
function mParseDate(s: string | undefined | null): Date | null {
  if (!s) return null;
  const p = String(s).slice(0, 10).split("-");
  if (p.length < 3) return null;
  const y = Number(p[0]), mo = Number(p[1]), da = Number(p[2]);
  if (!y || !mo || !da) return null;
  return new Date(y, mo - 1, da);
}

// Real scanMode values from the access engine look like "RFID_CARD" / "QR_TOTP" /
// "RFID_DIRECT" / "RFID_ONLY" — NOT "QR"/"FP". Classify the same way the backend's
// _credential_type_from_raw does (QR/TOTP → QR, FP/FINGER/BIO → fingerprint, else card).
function mMethodFor(scanMode: string | undefined): ScanMethod {
  const sm = String(scanMode || "").toUpperCase();
  if (sm.includes("QR") || sm.includes("TOTP")) return "qr";
  if (sm.includes("FP") || sm.includes("FINGER") || sm.includes("BIO")) return "fingerprint";
  return "card";
}

function mapLaneToScan(lane: ActiveLane): MeridienScan {
  const e = lane.event;
  const title = e.userMembershipTitle && String(e.userMembershipTitle).trim() ? String(e.userMembershipTitle) : null;
  const cat: ScanCategory = e.userMembersType === "STAFF" ? "staff" : (e.userMembersType === "KIDS" ? "kids" : "standard");
  return {
    laneId: lane.laneId,
    name: e.userFullName || "Member",
    imgUrl: lane.imgUrl,
    granted: !!e.allowed,
    denyReason: e.reason || "Access denied",
    plan: title,
    memberNo: (!title && e.userMembershipId != null) ? String(e.userMembershipId) : null,
    category: cat,
    validFrom: mParseDate(e.userValidFrom),
    validTo: mParseDate(e.userValidTo),
    birthday: e.userBirthday ? mParseDate(e.userBirthday) : null,
    device: e.deviceName || "Turnstile",
    method: mMethodFor(e.scanMode),
  };
}

// ── icon glyphs ─────────────────────────────────────────────────────────────
function MMark({ granted, color, size }: { granted: boolean; color: string; size: number }) {
  if (granted) {
    return <span style={{ display: "block", width: Math.round(size * 0.5) + "px", height: size + "px", borderRight: "3px solid " + color, borderBottom: "3px solid " + color, transform: "rotate(45deg)", marginTop: -Math.round(size * 0.18) + "px", boxSizing: "border-box" }} />;
  }
  return (
    <span style={{ position: "relative", width: size + "px", height: size + "px", display: "block" }}>
      <span style={{ position: "absolute", top: "50%", left: 0, right: 0, height: "3px", marginTop: "-1.5px", background: color, borderRadius: "2px", transform: "rotate(45deg)" }} />
      <span style={{ position: "absolute", top: "50%", left: 0, right: 0, height: "3px", marginTop: "-1.5px", background: color, borderRadius: "2px", transform: "rotate(-45deg)" }} />
    </span>
  );
}
function MDisc({ granted, accent }: { granted: boolean; accent: string }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", flex: "0 0 auto", width: "clamp(44px,3.4vw,64px)", height: "clamp(44px,3.4vw,64px)", borderRadius: "50%", background: accent }}>
      <MMark granted={granted} color="#070809" size={22} />
    </span>
  );
}
function MMethodIcon({ m }: { m: ScanMethod }) {
  const wrapStyle: CSSProperties = { display: "inline-flex", alignItems: "center", justifyContent: "center", width: "1.05em", height: "1.05em", color: "currentColor" };
  if (m === "qr") {
    const cells = [1, 1, 0, 1, 0, 1, 0, 1, 1];
    return (
      <span style={wrapStyle}>
        <span style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gridTemplateRows: "repeat(3,1fr)", gap: "1.5px", width: "1em", height: "1em" }}>
          {cells.map((v, i) => <span key={i} style={{ background: v ? "currentColor" : "transparent", borderRadius: ".5px" }} />)}
        </span>
      </span>
    );
  }
  if (m === "fingerprint") {
    return (
      <span style={wrapStyle}>
        <span style={{ position: "relative", width: "1em", height: "1em", display: "block" }}>
          <span style={{ position: "absolute", inset: 0, borderRadius: "50%", border: "1.5px solid currentColor" }} />
          <span style={{ position: "absolute", inset: "26%", borderRadius: "50%", border: "1.5px solid currentColor" }} />
          <span style={{ position: "absolute", inset: "44%", borderRadius: "50%", background: "currentColor" }} />
        </span>
      </span>
    );
  }
  return (
    <span style={wrapStyle}>
      <span style={{ position: "relative", display: "block", width: "1.05em", height: ".72em", border: "1.5px solid currentColor", borderRadius: "3px" }}>
        <span style={{ position: "absolute", top: "2px", left: "-1px", right: "-1px", height: "2.5px", background: "currentColor" }} />
      </span>
    </span>
  );
}
function MConfetti() {
  const cols = [M_GOLD, "#f3f4f2", M_GREEN];
  const arr = [];
  for (let i = 0; i < 26; i++) {
    const left = Math.random() * 100;
    const dur = 4.5 + Math.random() * 3;
    const delay = -Math.random() * 7;
    const sz = 5 + Math.random() * 7;
    const round = Math.random() > 0.5;
    arr.push(<span key={i} style={{ position: "absolute", top: "-14vh", left: left + "%", width: sz + "px", height: (round ? sz : sz * 0.45) + "px", background: cols[i % cols.length], borderRadius: round ? "50%" : "1px", opacity: 0.8, animation: "confettiFall " + dur + "s linear " + delay + "s infinite" }} />);
  }
  return <>{arr}</>;
}
function mCategoryStyle(cat: ScanCategory): CSSProperties {
  const c = cat === "staff" ? "oklch(0.7 0.12 250)" : "oklch(0.78 0.12 195)";
  return { display: "inline-flex", alignItems: "center", gap: "10px", padding: "11px 20px", borderRadius: "999px", fontFamily: "'Hanken Grotesk',sans-serif", fontWeight: 600, fontSize: "clamp(15px,1.35vw,21px)", color: c, background: "color-mix(in oklch," + c + ",transparent 90%)", border: "1px solid color-mix(in oklch," + c + ",transparent 62%)" };
}

// ── Idle standby ────────────────────────────────────────────────────────────
function MeridienIdle({ gymName, now }: { gymName: string; now: Date }) {
  return (
    <div style={css("position:absolute;inset:0;display:flex;flex-direction:column;justify-content:space-between;padding:clamp(48px,5vw,104px);")}>
      <div style={css("display:flex;justify-content:space-between;align-items:flex-start;gap:24px;")}>
        <div>
          <div style={css("font-weight:800;font-size:clamp(28px,2.9vw,52px);letter-spacing:-.01em;line-height:.95;")}>{gymName || "MonClub Access"}</div>
        </div>
        <div style={css("display:flex;align-items:center;gap:11px;")}>
          <span style={css("width:10px;height:10px;border-radius:50%;background:var(--accent);box-shadow:0 0 14px var(--accent);animation:pulseDot 2.6s ease-in-out infinite;")} />
          <span style={css("text-transform:uppercase;letter-spacing:.24em;font-size:clamp(11px,1vw,15px);color:var(--accent);font-weight:700;")}>Open</span>
        </div>
      </div>
      <div style={css("text-align:center;")}>
        <div style={css("font-weight:700;font-size:clamp(108px,22vw,340px);line-height:.8;letter-spacing:-.04em;font-variant-numeric:tabular-nums;")}>{mClock(now)}</div>
        <div style={css("margin-top:clamp(16px,1.6vw,30px);color:var(--muted);text-transform:uppercase;letter-spacing:.3em;font-size:clamp(13px,1.3vw,21px);font-weight:600;")}>{mLongDate(now)}</div>
        <div style={css("margin-top:clamp(10px,1vw,18px);text-transform:uppercase;letter-spacing:.34em;font-size:clamp(10px,.95vw,14px);font-weight:600;color:var(--faint);")}>powered by <span style={css("color:var(--accent);font-weight:800;")}>monclub</span></div>
      </div>
      <div style={css("display:flex;flex-direction:column;align-items:center;gap:22px;")}>
        <div style={css("position:relative;width:clamp(56px,5.6vw,80px);height:clamp(56px,5.6vw,80px);")}>
          <div style={css("position:absolute;inset:0;border-radius:50%;border:2px dashed color-mix(in oklch,var(--accent),transparent 40%);animation:ringspin 11s linear infinite;")} />
          <div style={css("position:absolute;inset:38%;border-radius:50%;background:var(--accent);box-shadow:0 0 20px var(--accent);")} />
        </div>
        <div style={css("text-transform:uppercase;letter-spacing:.2em;font-size:clamp(13px,1.35vw,22px);font-weight:600;color:rgba(243,244,242,.82);animation:breathe 3.8s ease-in-out infinite;")}>Present your card, QR code or fingerprint</div>
      </div>
    </div>
  );
}

// ── Single hero card ────────────────────────────────────────────────────────
function MeridienSingle({ scan, now, onImageError }: { scan: MeridienScan; now: Date; onImageError: (laneId: string) => void }) {
  const granted = scan.granted;
  const bd = !!(scan.birthday && mSameDay(scan.birthday, now));
  const accent = granted ? (bd ? M_GOLD : M_GREEN) : M_RED;
  const name = scan.name;
  const fn = name.split(/\s+/)[0];
  const len = name.length;
  const nameSize = len > 34 ? "clamp(28px,3vw,56px)" : (len > 22 ? "clamp(38px,4.6vw,84px)" : "clamp(50px,6.6vw,116px)");
  const showValidity = granted && !!scan.validFrom && !!scan.validTo;

  let memberSince = "", validToLabel = "", expiringLabel = "", pct = 0;
  let showExpiring = false;
  if (showValidity && scan.validFrom && scan.validTo) {
    pct = Math.max(4, Math.min(100, Math.round((now.getTime() - scan.validFrom.getTime()) / (scan.validTo.getTime() - scan.validFrom.getTime()) * 100)));
    memberSince = "Member since " + mMonthYear(scan.validFrom);
    validToLabel = "Valid until " + mShortDate(scan.validTo);
    const dleft = Math.ceil((scan.validTo.getTime() - now.getTime()) / 86400000);
    showExpiring = dleft <= 14 && dleft > 0;
    expiringLabel = "Expires in " + dleft + " day" + (dleft > 1 ? "s" : "");
  }

  const photoImgStyle: CSSProperties = { ...css("position:absolute;inset:0;width:100%;height:100%;object-fit:contain;object-position:center;"), filter: granted ? "none" : "grayscale(.75) brightness(.7) contrast(1.05)" };

  return (
    <div style={css("position:absolute;inset:0;display:flex;align-items:center;padding:clamp(44px,4.5vw,96px);gap:clamp(40px,4.5vw,88px);")}>
      <div style={css("flex:0 0 33%;max-width:470px;align-self:stretch;display:flex;padding:clamp(28px,3vw,64px) 0;")}>
        <div style={css("position:relative;flex:1;border-radius:26px;overflow:hidden;background:linear-gradient(165deg,#181a20,#0c0d11);border:1px solid var(--line);box-shadow:0 50px 100px -40px rgba(0,0,0,.8);")}>
          {scan.imgUrl ? (
            <img src={scan.imgUrl} alt="" style={photoImgStyle} onError={() => onImageError(scan.laneId)} />
          ) : (
            <div style={css("position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;background:radial-gradient(80% 70% at 50% 40%,color-mix(in oklch,var(--accent),transparent 82%),transparent 70%);")}>
              <span style={css("font-weight:800;font-size:clamp(76px,11vw,176px);color:var(--accent);line-height:1;letter-spacing:-.02em;")}>{mInitials(name)}</span>
              <span style={css("text-transform:uppercase;letter-spacing:.24em;font-size:clamp(10px,.95vw,14px);font-weight:600;color:var(--muted);")}>No photo</span>
            </div>
          )}
          <div style={css("position:absolute;left:0;right:0;bottom:0;height:34%;background:linear-gradient(to top,rgba(7,8,9,.65),transparent);pointer-events:none;")} />
          <div style={css("position:absolute;inset:0;border-radius:26px;box-shadow:inset 0 0 0 2px color-mix(in oklch,var(--accent),transparent 58%);pointer-events:none;")} />
        </div>
      </div>

      <div style={css("flex:1;min-width:0;display:flex;flex-direction:column;justify-content:center;")}>
        <div style={css("display:flex;align-items:center;gap:13px;color:var(--faint);text-transform:uppercase;letter-spacing:.2em;font-size:clamp(12px,1.05vw,16px);font-weight:600;")}>
          <span>{scan.device}</span>
          <span style={css("width:4px;height:4px;border-radius:50%;background:currentColor;")} />
          <span style={css("display:inline-flex;align-items:center;gap:9px;")}><MMethodIcon m={scan.method} /><span>{mMethodLabel(scan.method)}</span></span>
        </div>

        <div style={css("display:flex;align-items:center;gap:clamp(14px,1.3vw,22px);margin-top:clamp(22px,2.2vw,40px);")}>
          <MDisc granted={granted} accent={accent} />
          <span style={css("font-size:clamp(27px,3.1vw,54px);font-weight:700;letter-spacing:-.015em;color:var(--accent);white-space:nowrap;line-height:1;")}>{granted ? "ACCESS GRANTED" : "ACCESS DENIED"}</span>
        </div>

        <div style={{ fontFamily: "'Hanken Grotesk',sans-serif", fontWeight: 800, lineHeight: 0.95, letterSpacing: "-.02em", marginTop: "clamp(14px,1.4vw,26px)", fontSize: nameSize, color: "var(--ink)", overflowWrap: "break-word", hyphens: "auto", maxWidth: "15ch" }}>{name}</div>

        {bd && (
          <div style={css("margin-top:clamp(16px,1.6vw,26px);display:inline-flex;align-self:flex-start;align-items:center;gap:12px;padding:11px 20px;border-radius:999px;background:color-mix(in oklch,var(--accent),transparent 88%);border:1px solid color-mix(in oklch,var(--accent),transparent 60%);white-space:nowrap;")}>
            <span style={css("width:11px;height:11px;background:var(--accent);transform:rotate(45deg);box-shadow:0 0 12px var(--accent);")} />
            <span style={css("font-weight:700;font-size:clamp(16px,1.5vw,27px);color:var(--accent);")}>{"Happy birthday, " + fn + "!"}</span>
          </div>
        )}

        <div style={css("margin-top:clamp(22px,2.2vw,38px);display:flex;flex-wrap:wrap;gap:12px;align-items:center;")}>
          <span style={css("display:inline-flex;align-items:center;gap:10px;padding:11px 20px;border-radius:999px;border:1px solid var(--line);background:var(--surface);font-weight:600;font-size:clamp(15px,1.35vw,21px);color:var(--ink);white-space:nowrap;")}>
            <span style={css("width:8px;height:8px;border-radius:50%;background:var(--accent);")} />{mPlanLabel(scan)}
          </span>
          {scan.category !== "standard" && <span style={mCategoryStyle(scan.category)}>{scan.category === "staff" ? "Staff" : "Kids Club"}</span>}
        </div>

        {!granted && (
          <div style={css("margin-top:clamp(24px,2.4vw,40px);padding:clamp(20px,1.8vw,30px) clamp(22px,2vw,34px);border-radius:20px;background:color-mix(in oklch,var(--accent),transparent 91%);max-width:48ch;")}>
            <div style={css("text-transform:uppercase;letter-spacing:.2em;font-size:clamp(12px,1vw,15px);font-weight:700;color:var(--accent);margin-bottom:10px;")}>Reason</div>
            <div style={css("font-size:clamp(20px,2vw,32px);font-weight:700;color:var(--ink);line-height:1.15;")}>{scan.denyReason}</div>
            <div style={css("margin-top:12px;color:var(--muted);font-size:clamp(14px,1.2vw,19px);font-weight:500;")}>Please see the front desk.</div>
          </div>
        )}

        {showValidity && (
          <div style={css("margin-top:clamp(24px,2.4vw,40px);max-width:46ch;")}>
            <div style={css("display:flex;justify-content:space-between;gap:16px;color:var(--muted);font-size:clamp(13px,1.05vw,17px);font-weight:500;margin-bottom:12px;")}>
              <span>{memberSince}</span>
              <span>{validToLabel}</span>
            </div>
            <div style={css("height:5px;border-radius:999px;background:var(--surface);overflow:hidden;")}>
              <div style={{ width: pct + "%", height: "100%", borderRadius: "999px", background: accent }} />
            </div>
            {showExpiring && <div style={css("margin-top:12px;color:var(--accent);font-weight:600;font-size:clamp(13px,1.1vw,18px);")}>{expiringLabel}</div>}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Simultaneous-scans wall (2-3) ───────────────────────────────────────────
function MeridienMulti({ scans, now, onImageError }: { scans: MeridienScan[]; now: Date; onImageError: (laneId: string) => void }) {
  return (
    <div style={css("position:absolute;inset:0;display:flex;flex-direction:column;padding:clamp(44px,4.5vw,84px);")}>
      <div style={css("display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:clamp(28px,2.8vw,48px);gap:24px;")}>
        <div>
          <div style={css("font-weight:800;font-size:clamp(44px,6vw,112px);line-height:.85;letter-spacing:-.03em;")}><span style={css("color:var(--accent);")}>{String(scans.length)}</span> members</div>
          <div style={css("margin-top:14px;color:var(--muted);text-transform:uppercase;letter-spacing:.22em;font-size:clamp(12px,1.1vw,18px);font-weight:600;")}>Simultaneous scans</div>
        </div>
        <div style={css("text-align:right;color:var(--muted);text-transform:uppercase;letter-spacing:.16em;font-size:clamp(12px,1.05vw,17px);font-weight:600;")}>
          <div>{scans[0].device}</div>
          <div style={css("margin-top:9px;font-size:clamp(20px,1.8vw,30px);letter-spacing:0;color:var(--ink);font-weight:700;")}>{mClock(now)}</div>
        </div>
      </div>
      <div style={css("flex:1;display:grid;grid-auto-flow:column;grid-auto-columns:1fr;gap:clamp(18px,1.8vw,30px);min-height:0;")}>
        {scans.map((scan) => {
          const granted = scan.granted;
          const bd = !!(scan.birthday && mSameDay(scan.birthday, now));
          const accent = granted ? (bd ? M_GOLD : M_GREEN) : M_RED;
          const cardStyle: CSSProperties = { position: "relative", display: "flex", flexDirection: "column", borderRadius: "22px", overflow: "hidden", background: "#0c0d11", border: "1px solid var(--line)", boxShadow: "0 30px 70px -30px rgba(0,0,0,.7)", "--card-accent": accent } as CSSProperties;
          const imgStyle: CSSProperties = { ...css("position:absolute;inset:0;width:100%;height:100%;object-fit:contain;object-position:center;"), filter: granted ? "none" : "grayscale(.75) brightness(.7)" };
          return (
            <div key={scan.laneId} style={cardStyle}>
              <div style={css("position:relative;flex:1;min-height:0;background:linear-gradient(165deg,#181a20,#0c0d11);")}>
                {scan.imgUrl ? (
                  <img src={scan.imgUrl} alt="" style={imgStyle} onError={() => onImageError(scan.laneId)} />
                ) : (
                  <div style={css("position:absolute;inset:0;display:flex;align-items:center;justify-content:center;background:radial-gradient(80% 70% at 50% 40%,color-mix(in oklch,var(--card-accent),transparent 82%),transparent 70%);")}>
                    <span style={css("font-weight:800;font-size:clamp(50px,6vw,108px);color:var(--card-accent);line-height:1;letter-spacing:-.02em;")}>{mInitials(scan.name)}</span>
                  </div>
                )}
                <div style={css("position:absolute;left:0;right:0;bottom:0;height:58%;background:linear-gradient(to top,#0c0d11 8%,rgba(12,13,17,.35) 55%,transparent);pointer-events:none;")} />
                <div style={css("position:absolute;top:16px;left:16px;display:inline-flex;align-items:center;gap:8px;padding:8px 15px;border-radius:999px;background:var(--card-accent);")}>
                  <MMark granted={granted} color="#070809" size={13} />
                  <span style={css("font-weight:700;color:#070809;font-size:clamp(13px,1.05vw,18px);letter-spacing:.02em;")}>{granted ? "GRANTED" : "DENIED"}</span>
                </div>
              </div>
              <div style={css("padding:clamp(18px,1.5vw,26px);")}>
                <div style={css("font-weight:800;font-size:clamp(21px,1.9vw,36px);line-height:1.04;letter-spacing:-.01em;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;")}>{scan.name}</div>
                <div style={{ marginTop: "9px", fontSize: "clamp(15px,1.3vw,22px)", fontWeight: granted ? 500 : 600, color: granted ? "var(--muted)" : "var(--card-accent)" }}>{granted ? mPlanLabel(scan) : scan.denyReason}</div>
                <div style={css("margin-top:14px;color:var(--faint);text-transform:uppercase;letter-spacing:.16em;font-size:clamp(11px,.92vw,15px);font-weight:600;")}>{mMethodLabel(scan.method)}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

const M_ROOT_STYLE = "position:fixed;inset:0;font-family:'Hanken Grotesk',sans-serif;color:#f3f4f2;background:radial-gradient(140% 120% at 50% -8%,#15171c 0%,#0b0c10 52%,#070809 100%);overflow:hidden;--ink:#f3f4f2;--muted:rgba(243,244,242,.46);--faint:rgba(243,244,242,.3);--line:rgba(243,244,242,.12);--surface:rgba(243,244,242,.045);";

// Screen-level component: idle / single / multi from the active lanes.
function MeridienScreen({ lanes, idle, gymName, onImageError }: { lanes: ActiveLane[]; idle: boolean; gymName: string; onImageError: (laneId: string) => void }) {
  const [now, setNow] = useState<Date>(() => new Date());
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const scans = useMemo(() => lanes.map(mapLaneToScan), [lanes]);
  const single = !idle && scans.length === 1;
  const multi = !idle && scans.length > 1;
  const accent = idle ? M_GREEN : (single ? mAccent(scans[0], now) : M_GREEN);
  const rootStyle: CSSProperties = { ...css(M_ROOT_STYLE), "--accent": accent } as CSSProperties;
  const showConfetti = single && !!(scans[0].birthday && mSameDay(scans[0].birthday, now));
  const sceneKey = idle ? "idle" : scans.map((s) => s.laneId).join("|");

  return (
    <div style={rootStyle}>
      <div style={css("position:absolute;inset:0;background:radial-gradient(72% 62% at 24% 28%,color-mix(in oklch,var(--accent),transparent 89%),transparent 64%);pointer-events:none;z-index:0;animation:drift 38s ease-in-out infinite;")} />
      <div style={css("position:absolute;top:0;left:0;right:0;height:3px;background:var(--accent);box-shadow:0 0 22px color-mix(in oklch,var(--accent),transparent 45%);z-index:7;")} />

      <div key={sceneKey} style={{ ...css("position:absolute;inset:0;z-index:2;"), animation: "meridienEnter 600ms cubic-bezier(.16,.84,.3,1) both" }}>
        {idle && <MeridienIdle gymName={gymName} now={now} />}
        {single && <MeridienSingle scan={scans[0]} now={now} onImageError={onImageError} />}
        {multi && <MeridienMulti scans={scans} now={now} onImageError={onImageError} />}
      </div>

      {showConfetti && <div style={css("position:absolute;inset:0;z-index:3;pointer-events:none;overflow:hidden;")}><MConfetti /></div>}
    </div>
  );
}

/* ▲▲▲ END MÉRIDIEN design ▲▲▲ */

// ── Main component ────────────────────────────────────────────────────────
// ── Freeze telemetry beacon (popup → backend) ────────────────────────────────
// Posts a heartbeat / SSE-lifecycle beacon to the local API so a popup-window
// FREEZE is visible in the backend log: if these stop arriving the webview is
// hung; if they keep arriving while no popup shows, it's the data/render path.
// Hits an auth-exempt loopback endpoint; best-effort (never throws).
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
      // popup-display only.)
      const knownUser = !!evt.userFullName && evt.userFullName.trim().length > 0;
      if (!evt.allowed || !knownUser) {
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
    const poll = async () => {
      try {
        const res = await get<any>("/popup/poll", {
          since_agent: String(sinceAgent),
          since_ultra: String(sinceUltra),
        });
        if (cancelled) return;
        if (typeof res?.seqAgent === "number") sinceAgent = res.seqAgent;
        if (typeof res?.seqUltra === "number") sinceUltra = res.seqUltra;
        const evs = Array.isArray(res?.events) ? res.events : [];
        for (const ev of evs) {
          try { enqueue(toPopupEvent(ev)); } catch { /* ignore one bad event */ }
        }
      } catch { /* transient (stall/offline) — the next tick just retries */ }
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

  // Active lanes → MÉRIDIEN screen (idle when none, single for 1, multi for 2-3)
  const visibleLanes = useMemo(() => lanes, [lanes]);
  const laneCount = visibleLanes.length;

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <>
      <MeridienScreen
        lanes={visibleLanes}
        idle={laneCount === 0}
        gymName={gymName}
        onImageError={handleImageError}
      />
      <style>{globalKeyframes}</style>
    </>
  );
}

// ── Keyframes shared across the window (Hanken Grotesk is bundled via @fontsource) ─
const globalKeyframes = `
  @keyframes drift{0%{transform:translate3d(0,0,0) scale(1);}50%{transform:translate3d(3%,2%,0) scale(1.12);}100%{transform:translate3d(0,0,0) scale(1);}}
  @keyframes breathe{0%,100%{opacity:.55;}50%{opacity:1;}}
  @keyframes ringspin{to{transform:rotate(360deg);}}
  @keyframes pulseDot{0%,100%{opacity:1;transform:scale(1);}50%{opacity:.4;transform:scale(.8);}}
  @keyframes confettiFall{0%{transform:translateY(-14vh) rotate(0deg);}100%{transform:translateY(116vh) rotate(720deg);}}
  @keyframes meridienEnter{0%{transform:translateY(20px) scale(.99);}100%{transform:none;}}
`;
