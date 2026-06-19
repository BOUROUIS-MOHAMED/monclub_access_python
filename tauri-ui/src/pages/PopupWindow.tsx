// Multi-lane TV popup for the gym entry display.
//
// Renders up to N concurrent member cards (default 3, configurable from
// backend via /status → popup.lanes). Each lane lives for its full
// popup_duration_sec regardless of other arrivals. New events fill the
// first free lane; when all lanes are busy the oldest entry is evicted so
// the freshest scan is always visible. There is no global MIN_SHOW lock
// and no per-person dedupe — duplicate events are already filtered
// upstream by the access_history INSERT-OR-IGNORE constraint, so this UI
// trusts the backend stream.

import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { getApiBaseUrl, openSSE } from "@/api/client";
import type { PopupEvent } from "@/api/types";
import { LOCAL_API_PREFIX } from "@/config/appConst";
import { buildPopupImageCandidates, toPopupCachedImageUrl } from "@/lib/popupImages";

// ── Defaults (overridable from backend /status payload) ───────────────────
const DEFAULT_LANES = 3;
const MAX_LANES = 5;
const DEFAULT_DURATION_SEC = 5; // TV-friendly default; backend overrides
const MIN_DURATION_MS = 2500;
const FADE_OUT_MS = 350;

const CONFETTI_COLORS = ["#facc15", "#f472b6", "#a78bfa", "#34d399", "#fb923c", "#60a5fa"];

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

function isTodayBirthday(birthday: string | undefined): boolean {
  if (!birthday) return false;
  try {
    const t = new Date();
    const mm = String(t.getMonth() + 1).padStart(2, "0");
    const dd = String(t.getDate()).padStart(2, "0");
    const parts = birthday.slice(0, 10).split("-");
    if (parts.length < 3) return false;
    return `${parts[1]}-${parts[2]}` === `${mm}-${dd}`;
  } catch {
    return false;
  }
}

function laneIdFor(eventId: string): string {
  return `lane-${eventId.slice(0, 24)}-${Math.floor(Math.random() * 1e6)}`;
}

function paletteFor(allowed: boolean, birthday: boolean) {
  if (birthday) {
    return {
      accent: "#f59e0b",
      glow: "250,159,21",
      status: "Joyeux Anniversaire !",
      icon: "🎂",
      bgFrom: "#451a03",
    };
  }
  if (allowed) {
    return {
      accent: "#10b981",
      glow: "16,185,129",
      status: "Accès Autorisé",
      icon: "✓",
      bgFrom: "#022c22",
    };
  }
  return {
    accent: "#ef4444",
    glow: "239,68,68",
    status: "Accès Refusé",
    icon: "✕",
    bgFrom: "#450a0a",
  };
}

// ── Idle screen ───────────────────────────────────────────────────────────
function IdleScreen({ gymName }: { gymName: string }) {
  const name = gymName || "MonClub Access";
  return (
    <div
      className="h-screen w-screen flex flex-col items-center justify-center select-none relative overflow-hidden"
      style={{ background: "#080808" }}
    >
      <div
        className="absolute pointer-events-none"
        style={{
          width: "70vw",
          height: "70vw",
          borderRadius: "50%",
          background: "radial-gradient(circle, rgba(16,185,129,0.07) 0%, transparent 70%)",
          top: "50%",
          left: "50%",
          transform: "translate(-50%, -50%)",
        }}
      />
      <div
        style={{
          width: "clamp(3rem, 8vw, 6rem)",
          height: 2,
          background: "linear-gradient(90deg, transparent, #10b981, transparent)",
          marginBottom: "clamp(1.5rem, 4vh, 3rem)",
        }}
      />
      <h1
        className="font-black uppercase text-center"
        style={{
          margin: 0,
          letterSpacing: "0.18em",
          lineHeight: 1.1,
          fontSize: "clamp(3rem, 7vw, 6.5rem)",
          background: "linear-gradient(160deg, #ffffff 40%, #a1a1aa 100%)",
          WebkitBackgroundClip: "text",
          WebkitTextFillColor: "transparent",
        }}
      >
        {name}
      </h1>
      <div
        style={{
          width: "clamp(3rem, 8vw, 6rem)",
          height: 2,
          background: "linear-gradient(90deg, transparent, #10b981, transparent)",
          marginTop: "clamp(1.5rem, 4vh, 3rem)",
          marginBottom: "clamp(1rem, 3vh, 2rem)",
        }}
      />
      <p
        className="font-medium uppercase text-center"
        style={{
          margin: 0,
          letterSpacing: "0.45em",
          fontSize: "clamp(0.7rem, 1.2vw, 0.95rem)",
          color: "#52525b",
        }}
      >
        powered by&nbsp;
        <span style={{ color: "#10b981", fontWeight: 700 }}>monclub</span>
      </p>
    </div>
  );
}

// ── Single card (hero or split) ───────────────────────────────────────────
function LaneCard({
  lane,
  layout,
  onImageError,
}: {
  lane: ActiveLane;
  layout: "hero" | "split2" | "split3";
  onImageError: (laneId: string) => void;
}) {
  const n = lane.event;
  const birthday = n.allowed && isTodayBirthday(n.userBirthday);
  const p = paletteFor(n.allowed, birthday);
  const initial = (n.userFullName || "?")[0].toUpperCase();
  const durationMs = Math.max(MIN_DURATION_MS, n.popupDurationSec * 1000);
  const remainingRatio = Math.max(0, Math.min(1, (lane.expiresAt - Date.now()) / durationMs));
  const sizing = layout === "hero" ? "hero" : layout === "split2" ? "split2" : "split3";

  // Font scaling per layout — the TV is far away, so we keep names huge in
  // hero and just barely shrink in 3-up to keep them readable.
  const nameFontSize =
    sizing === "hero"
      ? "clamp(2.8rem, 5.5vw, 5rem)"
      : sizing === "split2"
      ? "clamp(2.2rem, 3.6vw, 3.6rem)"
      : "clamp(1.6rem, 2.4vw, 2.6rem)";

  const statusFontSize =
    sizing === "hero"
      ? "1.25rem"
      : sizing === "split2"
      ? "1rem"
      : "0.85rem";

  const heroLayout = sizing === "hero";

  return (
    <div
      className="relative h-full w-full overflow-hidden"
      style={{
        background: "#050505",
        opacity: lane.fadingOut ? 0 : 1,
        transition: `opacity ${FADE_OUT_MS}ms ease`,
        animation: lane.fadingOut ? undefined : "laneEnter 320ms cubic-bezier(0.16,1,0.3,1) both",
      }}
    >
      {/* Birthday confetti */}
      {birthday && (
        <div className="absolute inset-0 pointer-events-none overflow-hidden z-30">
          {[...Array(18)].map((_, i) => (
            <div
              key={i}
              style={{
                position: "absolute",
                width: i % 3 === 0 ? 12 : 8,
                height: i % 3 === 0 ? 20 : 8,
                borderRadius: i % 2 === 0 ? "50%" : 3,
                background: CONFETTI_COLORS[i % CONFETTI_COLORS.length],
                left: `${(i * 5.4) % 100}%`,
                top: -24,
                animation: `confettiFall ${1.6 + (i % 5) * 0.28}s ease-in ${i * 0.07}s forwards`,
              }}
            />
          ))}
        </div>
      )}

      <div
        className={heroLayout ? "flex h-full" : "flex flex-col h-full"}
        style={{ overflow: "hidden" }}
      >
        {/* Photo block */}
        <div
          className="relative flex-shrink-0"
          style={
            heroLayout
              ? { width: "44%", height: "100%" }
              : { width: "100%", height: "52%" }
          }
        >
          {lane.imgUrl ? (
            <img
              key={lane.imgUrl}
              src={lane.imgUrl}
              alt=""
              className="absolute inset-0 w-full h-full object-cover object-top"
              onError={() => onImageError(lane.laneId)}
            />
          ) : (
            <div
              className="absolute inset-0 flex items-center justify-center"
              style={{
                background: `linear-gradient(160deg, ${p.bgFrom}, #050505)`,
              }}
            >
              <span
                className="font-black leading-none select-none"
                style={{
                  fontSize: heroLayout ? "38vw" : "22vw",
                  color: p.accent,
                  opacity: 0.12,
                }}
              >
                {initial}
              </span>
            </div>
          )}
          {/* fade-to-info gradient */}
          <div
            className="absolute inset-0"
            style={{
              background: heroLayout
                ? "linear-gradient(to right, transparent 55%, #050505 100%)"
                : "linear-gradient(to bottom, transparent 60%, #050505 100%)",
            }}
          />
          {/* accent edge */}
          <div
            className="absolute"
            style={
              heroLayout
                ? { top: 0, bottom: 0, right: 0, width: 4, background: p.accent, opacity: 0.6 }
                : { left: 0, right: 0, bottom: 0, height: 4, background: p.accent, opacity: 0.6 }
            }
          />
        </div>

        {/* Info block */}
        <div
          className="flex-1 flex flex-col relative overflow-hidden"
          style={{
            background: "#050505",
            padding: heroLayout ? "5vh 4vw" : "1.5vh 1.5vw",
            justifyContent: heroLayout ? "center" : "flex-start",
          }}
        >
          {/* glow */}
          <div
            className="absolute pointer-events-none"
            style={{
              right: "-10vw",
              top: "50%",
              transform: "translateY(-50%)",
              width: "60vw",
              height: "60vw",
              borderRadius: "50%",
              background: `radial-gradient(circle, rgba(${p.glow},0.18) 0%, transparent 70%)`,
            }}
          />

          {/* status badge */}
          <div className="flex items-center gap-3 relative" style={{ marginBottom: heroLayout ? "1.5rem" : "0.5rem" }}>
            <span style={{ color: p.accent, fontWeight: 900, fontSize: statusFontSize }}>
              {p.icon}
            </span>
            <span
              className="font-black uppercase"
              style={{
                color: p.accent,
                letterSpacing: "0.22em",
                fontSize: statusFontSize,
              }}
            >
              {p.status}
            </span>
            {n.scanMode && !birthday && (
              <span className="text-zinc-600 font-normal lowercase" style={{ fontSize: "0.7em" }}>
                · {n.scanMode}
              </span>
            )}
          </div>

          {/* name */}
          <h1
            className="font-black text-white relative z-10 leading-none"
            style={{
              fontSize: nameFontSize,
              letterSpacing: "-0.02em",
              wordBreak: "break-word",
              marginBottom: heroLayout ? "1rem" : "0.4rem",
              maxHeight: heroLayout ? undefined : "26%",
              overflow: "hidden",
            }}
          >
            {n.userFullName || "Inconnu"}
          </h1>

          {/* membership id pill */}
          {n.userMembershipId != null && (
            <div style={{ marginBottom: heroLayout ? "2rem" : "0.5rem" }}>
              <span
                className="inline-flex items-center gap-2 rounded-full font-bold"
                style={{
                  background: `rgba(${p.glow},0.12)`,
                  border: `1px solid rgba(${p.glow},0.3)`,
                  color: p.accent,
                  padding: heroLayout ? "0.4rem 1rem" : "0.18rem 0.6rem",
                  fontSize: heroLayout ? "1.05rem" : "0.8rem",
                }}
              >
                # {n.userMembershipId}
              </span>
            </div>
          )}

          {/* image flags (only in hero — saves vertical space in splits) */}
          {heroLayout && (n.imageSource === "PROFILE_BORROWED" || n.userImageStatus === "REQUIRED_CHANGE") && (
            <div className="flex flex-wrap gap-2 mb-4">
              {n.imageSource === "PROFILE_BORROWED" && (
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium"
                      style={{ background: "rgba(255,255,255,0.08)", color: "#a1a1aa" }}>
                  👤 Profile photo — no gym image set
                </span>
              )}
              {n.userImageStatus === "REQUIRED_CHANGE" && (
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium"
                      style={{ background: "rgba(251,146,60,0.15)", color: "#fb923c", border: "1px solid rgba(251,146,60,0.3)" }}>
                  ⚠ Image change required
                </span>
              )}
            </div>
          )}

          {/* validity row (hero only — too cramped in 3-up) */}
          {heroLayout && (n.userValidFrom || n.userValidTo) && (
            <div className="grid grid-cols-2 gap-x-10 gap-y-4 mb-6 relative z-10">
              {n.userValidFrom && (
                <div>
                  <p className="text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 mb-1">Début</p>
                  <p className="text-2xl font-bold text-zinc-100">{n.userValidFrom.slice(0, 10)}</p>
                </div>
              )}
              {n.userValidTo && (
                <div>
                  <p className="text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 mb-1">Fin</p>
                  <p className="text-2xl font-bold text-zinc-100">{n.userValidTo.slice(0, 10)}</p>
                </div>
              )}
            </div>
          )}

          {/* deny reason (replaces validity row for denied entries) */}
          {!n.allowed && n.reason && (
            <div style={{ marginBottom: heroLayout ? "1.5rem" : "0.3rem" }}>
              <p className="text-xs font-bold uppercase tracking-[0.2em] text-zinc-500 mb-1">Raison</p>
              <p
                className="font-bold text-zinc-100 leading-tight"
                style={{ fontSize: heroLayout ? "1.4rem" : "0.95rem" }}
              >
                {n.reason}
              </p>
            </div>
          )}

          {/* birthday banner */}
          {birthday && heroLayout && (
            <div
              className="rounded-2xl mb-4"
              style={{
                padding: "1rem 1.5rem",
                background: "linear-gradient(135deg, rgba(120,53,15,0.6), rgba(88,28,135,0.6))",
                border: "1px solid rgba(250,204,21,0.25)",
              }}
            >
              <p
                className="font-extrabold text-xl text-center"
                style={{
                  background: "linear-gradient(90deg, #fde68a, #f9a8d4, #c4b5fd)",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                }}
              >
                🎉 Joyeux anniversaire ! 🎉
              </p>
            </div>
          )}

          {/* device footer */}
          {n.deviceName && (
            <div className="flex items-center gap-2 mt-auto">
              <div
                className="rounded-full flex-shrink-0"
                style={{ width: 8, height: 8, background: p.accent, opacity: 0.5 }}
              />
              <span
                className="text-zinc-600 truncate"
                style={{ fontSize: heroLayout ? "1rem" : "0.75rem" }}
              >
                {n.deviceName}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* progress bar — drains over the lane's lifetime */}
      <div
        className="absolute bottom-0 left-0 right-0"
        style={{ height: 4, background: "rgba(255,255,255,0.06)" }}
      >
        <div
          style={{
            height: "100%",
            width: `${remainingRatio * 100}%`,
            background: p.accent,
            opacity: 0.7,
            transition: "width 100ms linear",
          }}
        />
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────
export default function PopupWindow() {
  const [lanes, setLanes] = useState<ActiveLane[]>([]);
  const [gymName, setGymName] = useState<string>("");
  const [maxLanes, setMaxLanes] = useState<number>(DEFAULT_LANES);
  const [defaultDurationSec, setDefaultDurationSec] = useState<number>(DEFAULT_DURATION_SEC);

  const lanesRef = useRef<ActiveLane[]>([]);
  const seenEventIdsRef = useRef<Map<string, number>>(new Map()); // event_id → seen-at, for cheap cross-channel dedupe
  const lastLocalRawRef = useRef<string>("");
  const tickHandleRef = useRef<number | null>(null);

  // keep refs in sync with state
  useEffect(() => { lanesRef.current = lanes; }, [lanes]);

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
    const es = openSSE("/agent/events?replayLast=0", (type, data) => {
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
    });
    return () => { es.close(); };
  }, [enqueue]);

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

  // Decide layout from current lane count
  const visibleLanes = useMemo(() => lanes, [lanes]);
  const laneCount = visibleLanes.length;
  const layoutMode: "hero" | "split2" | "split3" =
    laneCount <= 1 ? "hero" : laneCount === 2 ? "split2" : "split3";

  // ── Render ─────────────────────────────────────────────────────────────
  if (laneCount === 0) {
    return (
      <>
        <IdleScreen gymName={gymName} />
        <style>{globalKeyframes}</style>
      </>
    );
  }

  return (
    <div className="h-screen w-screen flex overflow-hidden select-none" style={{ background: "#000" }}>
      {visibleLanes.map((lane) => (
        <div
          key={lane.laneId}
          className="h-full"
          style={{
            flex: "1 1 0",
            minWidth: 0,
            borderRight: "1px solid rgba(255,255,255,0.05)",
          }}
        >
          <LaneCard lane={lane} layout={layoutMode} onImageError={handleImageError} />
        </div>
      ))}
      <style>{globalKeyframes}</style>
    </div>
  );
}

// ── Keyframes shared across the window ────────────────────────────────────
const globalKeyframes = `
  @keyframes laneEnter {
    0%   { opacity: 0; transform: translateY(8px) scale(0.98); }
    100% { opacity: 1; transform: translateY(0)    scale(1);    }
  }
  @keyframes confettiFall {
    0%   { transform: translateY(0px)   rotate(0deg);    opacity: 0.9; }
    100% { transform: translateY(105vh) rotate(540deg);  opacity: 0;   }
  }
`;
