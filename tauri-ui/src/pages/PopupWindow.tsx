import { useState, useEffect, useRef, useCallback } from "react";
import { openSSE } from "@/api/client";
import type { PopupEvent } from "@/api/types";

const API_PORT = 8788;
const API_BASE = `http://127.0.0.1:${API_PORT}/api/v2`;

// ── Timing constants ──────────────────────────────────────────────────────────
const MIN_SHOW_MS = 2000;   // never interrupt a notification before this
const MAX_SHOW_MS = 8000;   // go idle this long after last event

// ── Helpers ───────────────────────────────────────────────────────────────────

function toPopupEvent(raw: any): PopupEvent {
  const eventId = String(raw?.eventId ?? raw?.id ?? `evt-${Date.now()}`);
  const userFullName = String(raw?.userFullName ?? raw?.fullName ?? "");
  const userImage = String(raw?.userImage ?? raw?.image ?? "");
  const userValidFrom = String(raw?.userValidFrom ?? raw?.validFrom ?? "");
  const userValidTo = String(raw?.userValidTo ?? raw?.validTo ?? "");
  const popupDurationSec = Number(raw?.popupDurationSec ?? raw?.durationSec ?? raw?.duration ?? 5);
  return {
    eventId,
    title: String(raw?.title ?? "Acces"),
    message: String(raw?.message ?? ""),
    imagePath: String(raw?.imagePath ?? raw?.image ?? ""),
    popupShowImage: raw?.popupShowImage !== false,
    userFullName,
    userImage,
    userValidFrom,
    userValidTo,
    userMembershipId: raw?.userMembershipId != null ? Number(raw.userMembershipId) : null,
    userPhone: String(raw?.userPhone ?? raw?.phone ?? ""),
    deviceId: Number(raw?.deviceId ?? 0),
    deviceName: String(raw?.deviceName ?? ""),
    allowed: Boolean(raw?.allowed),
    reason: String(raw?.reason ?? ""),
    scanMode: String(raw?.scanMode ?? ""),
    popupDurationSec: Number.isFinite(popupDurationSec) && popupDurationSec > 0 ? popupDurationSec : 5,
    popupEnabled: raw?.popupEnabled !== false,
    winNotifyEnabled: raw?.winNotifyEnabled !== false,
    receivedAt: Number(raw?.receivedAt ?? Date.now()),
    userBirthday: raw?.userBirthday ? String(raw.userBirthday) : undefined,
    imageSource: raw?.imageSource ? String(raw.imageSource) : undefined,
    userImageStatus: raw?.userImageStatus ? String(raw.userImageStatus) : undefined,
  };
}

function isTodayBirthday(birthday: string | undefined): boolean {
  if (!birthday) return false;
  try {
    const today = new Date();
    const mm = String(today.getMonth() + 1).padStart(2, "0");
    const dd = String(today.getDate()).padStart(2, "0");
    const parts = birthday.slice(0, 10).split("-");
    if (parts.length < 3) return false;
    return `${parts[1]}-${parts[2]}` === `${mm}-${dd}`;
  } catch {
    return false;
  }
}

function InfoCell({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-sm font-bold uppercase tracking-[0.2em] text-zinc-500 mb-1">{label}</p>
      <p className="text-[1.75rem] font-bold text-zinc-100 leading-tight">{value}</p>
    </div>
  );
}

const CONFETTI = ["#facc15", "#f472b6", "#a78bfa", "#34d399", "#fb923c", "#60a5fa"];

// ── Idle screen ───────────────────────────────────────────────────────────────

function IdleScreen({ gymName }: { gymName: string }) {
  const name = gymName || "MonClub Access";
  return (
    <div
      className="h-screen w-screen flex flex-col items-center justify-center select-none relative overflow-hidden"
      style={{ background: "#080808" }}
    >
      {/* ambient radial glow behind the text */}
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

      {/* top rule */}
      <div
        style={{
          width: "clamp(3rem, 8vw, 6rem)",
          height: 2,
          background: "linear-gradient(90deg, transparent, #10b981, transparent)",
          marginBottom: "clamp(1.5rem, 4vh, 3rem)",
        }}
      />

      {/* gym name */}
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

      {/* bottom rule */}
      <div
        style={{
          width: "clamp(3rem, 8vw, 6rem)",
          height: 2,
          background: "linear-gradient(90deg, transparent, #10b981, transparent)",
          marginTop: "clamp(1.5rem, 4vh, 3rem)",
          marginBottom: "clamp(1rem, 3vh, 2rem)",
        }}
      />

      {/* powered by */}
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

      <style>{`
        @keyframes idlePulse {
          0%, 100% { opacity: 0.07; }
          50%       { opacity: 0.13; }
        }
      `}</style>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function PopupWindow() {
  const [phase, setPhase] = useState<"idle" | "showing">("idle");
  const [current, setCurrent] = useState<PopupEvent | null>(null);
  const [imgSrc, setImgSrc] = useState<string | null>(null);
  const [gymName, setGymName] = useState<string>("");
  const [showKey, setShowKey] = useState(0);

  // Refs — used inside callbacks to avoid stale closures
  const phaseRef = useRef<"idle" | "showing">("idle");
  const showSinceRef = useRef<number>(0);
  const pendingRef = useRef<PopupEvent | null>(null);
  const idleTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const minTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const shownCooldownRef = useRef<Map<string, number>>(new Map());
  const lastLocalRawRef = useRef<string>("");
  const goIdleRef = useRef<() => void>(() => {});

  // Keep phaseRef in sync
  const setPhaseSync = useCallback((p: "idle" | "showing") => {
    phaseRef.current = p;
    setPhase(p);
  }, []);


  // Fetch gym name once on mount
  useEffect(() => {
    fetch(`${API_BASE}/status`)
      .then((r) => r.json())
      .then((d) => {
        const name =
          d?.session?.gymName ||
          d?.gymName ||
          d?.session?.organizationName ||
          "";
        if (name) setGymName(String(name));
      })
      .catch(() => {});
  }, []);

  const resolveImage = useCallback((evt: PopupEvent) => {
    if (!evt.popupShowImage) { setImgSrc(null); return; }
    const img = (evt.userImage || evt.imagePath || "").trim();
    if (!img) { setImgSrc(null); return; }
    if (img.startsWith("data:")) { setImgSrc(img); return; }
    setImgSrc(`${API_BASE}/image-cache?url=${encodeURIComponent(img)}`);
  }, []);

  // showEvent — transitions to "showing" state with proper timers
  const showEvent = useCallback((evt: PopupEvent) => {
    pendingRef.current = null;
    if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
    if (minTimerRef.current) clearTimeout(minTimerRef.current);

    // Record cooldown keyed by person — prevents dual-engine duplicate events
    const personKey = String(evt.userMembershipId ?? `${evt.userFullName}|${evt.deviceId}`);
    shownCooldownRef.current.set(personKey, Date.now());
    showSinceRef.current = Date.now();
    setCurrent(evt);
    setShowKey((k) => k + 1);
    setPhaseSync("showing");
    resolveImage(evt);

    // goIdleRef is called by BOTH the timer and onAnimationEnd on the progress bar
    goIdleRef.current = () => {
      if (phaseRef.current !== "showing") return;
      if (pendingRef.current) return; // minTimer will handle the pending event
      pendingRef.current = null;
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
      setPhaseSync("idle");
    };

    // After MAX_SHOW_MS with no new events → go idle (backup for onAnimationEnd)
    idleTimerRef.current = setTimeout(() => {
      goIdleRef.current();
    }, MAX_SHOW_MS);

    // After MIN_SHOW_MS → pick up any queued event
    minTimerRef.current = setTimeout(() => {
      const next = pendingRef.current;
      if (next) {
        pendingRef.current = null;
        showEvent(next);
      }
    }, MIN_SHOW_MS);
  }, [resolveImage, setPhaseSync]);

  // handleEvent — the single entry point for all incoming events
  const handleEvent = useCallback((evt: PopupEvent) => {
    // Deduplicate by person within MAX_SHOW_MS window — handles dual-engine duplicates
    const personKey = String(evt.userMembershipId ?? `${evt.userFullName}|${evt.deviceId}`);
    const lastAt = shownCooldownRef.current.get(personKey) ?? 0;
    if (Date.now() - lastAt < MAX_SHOW_MS) return;

    if (phaseRef.current === "idle") {
      // Screen is idle — show immediately
      showEvent(evt);
      return;
    }

    // Currently showing: respect MIN_SHOW_MS
    const elapsed = Date.now() - showSinceRef.current;
    if (elapsed >= MIN_SHOW_MS) {
      // Min time already served — switch now
      showEvent(evt);
    } else {
      // Too soon — queue it (only keep the latest incoming event)
      pendingRef.current = evt;
    }
  }, [showEvent]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
      if (minTimerRef.current) clearTimeout(minTimerRef.current);
    };
  }, []);

  // Channel 1 — Direct SSE from backend
  useEffect(() => {
    const es = openSSE("/agent/events?replayLast=1", (type, data) => {
      if (type !== "popup" && type !== "notification") return;
      try {
        handleEvent(toPopupEvent(typeof data === "string" ? JSON.parse(data) : data));
      } catch { /* ignore */ }
    });
    return () => { es.close(); };
  }, [handleEvent]);

  // Channel 2 — Tauri IPC
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    import("@tauri-apps/api/event")
      .then(({ listen }) => listen<any>("popup-notification", (e) => {
        try { handleEvent(toPopupEvent(e.payload)); } catch { /* ignore */ }
      }))
      .then((fn) => { unlisten = fn; })
      .catch(() => { /* browser mode */ });
    return () => { if (unlisten) unlisten(); };
  }, [handleEvent]);

  // Channel 3 — localStorage polling (fallback / cross-window)
  useEffect(() => {
    const read = () => {
      try {
        const raw = localStorage.getItem("popupEvent");
        if (!raw || raw === lastLocalRawRef.current) return;
        lastLocalRawRef.current = raw;
        handleEvent(toPopupEvent(JSON.parse(raw)));
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
  }, [handleEvent]);

  // ── Idle screen ────────────────────────────────────────────────────────────
  if (phase === "idle" || !current) {
    return <IdleScreen gymName={gymName} />;
  }

  // ── Notification screen ───────────────────────────────────────────────────
  const n = current;
  const allowed = Boolean(n.allowed);
  const isBirthday = allowed && isTodayBirthday(n.userBirthday);
  const initial = (n.userFullName || "?")[0].toUpperCase();

  const accentColor = isBirthday ? "#f59e0b" : allowed ? "#10b981" : "#ef4444";
  const glowHex     = isBirthday ? "250,159,21" : allowed ? "16,185,129" : "239,68,68";
  const statusLabel = isBirthday ? "Joyeux Anniversaire !" : allowed ? "Accès Autorisé" : "Accès Refusé";
  const statusIcon  = isBirthday ? "🎂" : allowed ? "✓" : "✕";
  const noBgFrom    = isBirthday ? "#451a03" : allowed ? "#022c22" : "#450a0a";
  const noBgTo      = "#050505";

  return (
    <div className="h-screen w-screen flex overflow-hidden select-none relative">
      {/* ── CONFETTI (birthday only) ── */}
      {isBirthday && (
        <div className="absolute inset-0 pointer-events-none overflow-hidden z-30">
          {[...Array(28)].map((_, i) => (
            <div
              key={i}
              style={{
                position: "absolute",
                width: i % 3 === 0 ? 14 : 9,
                height: i % 3 === 0 ? 22 : 9,
                borderRadius: i % 2 === 0 ? "50%" : 3,
                background: CONFETTI[i % CONFETTI.length],
                left: `${(i * 3.7) % 100}%`,
                top: -24,
                animation: `confettiFall ${1.6 + (i % 5) * 0.28}s ease-in ${i * 0.07}s forwards`,
              }}
            />
          ))}
        </div>
      )}

      {/* ── LEFT: photo / initial panel ── */}
      <div className="relative flex-shrink-0 h-full" style={{ width: "44%" }}>
        {imgSrc ? (
          <img
            src={imgSrc}
            alt=""
            className="absolute inset-0 w-full h-full object-cover object-top"
            onError={() => setImgSrc(null)}
          />
        ) : (
          <div
            className="absolute inset-0 flex items-center justify-center"
            style={{ background: `linear-gradient(160deg, ${noBgFrom}, ${noBgTo})` }}
          >
            <span
              className="font-black leading-none select-none"
              style={{ fontSize: "38vw", color: accentColor, opacity: 0.12 }}
            >
              {initial}
            </span>
          </div>
        )}
        <div
          className="absolute inset-0"
          style={{ background: "linear-gradient(to right, transparent 55%, #050505 100%)" }}
        />
        <div
          className="absolute inset-0"
          style={{ background: "linear-gradient(to top, #050505 0%, transparent 35%)" }}
        />
        <div
          className="absolute inset-0"
          style={{ background: "linear-gradient(to bottom, #050505 0%, transparent 20%)" }}
        />
        <div
          className="absolute top-0 bottom-0 right-0 w-1"
          style={{ background: accentColor, opacity: 0.6 }}
        />
      </div>

      {/* ── RIGHT: info panel ── */}
      <div
        className="flex-1 flex flex-col justify-center relative overflow-hidden"
        style={{ background: "#050505", padding: "5vh 6vw" }}
      >
        {/* ambient glow */}
        <div
          className="absolute pointer-events-none"
          style={{
            right: "-10vw",
            top: "50%",
            transform: "translateY(-50%)",
            width: "60vw",
            height: "60vw",
            borderRadius: "50%",
            background: `radial-gradient(circle, rgba(${glowHex},0.18) 0%, transparent 70%)`,
          }}
        />

        {/* status badge */}
        <div className="flex items-center gap-4 mb-6 relative">
          <span className="text-2xl font-black leading-none" style={{ color: accentColor }}>
            {statusIcon}
          </span>
          <span
            className="text-xl font-black uppercase tracking-[0.22em]"
            style={{ color: accentColor }}
          >
            {statusLabel}
          </span>
          {n.scanMode && !isBirthday && (
            <span className="text-base text-zinc-600 font-normal lowercase tracking-normal ml-1">
              · {n.scanMode}
            </span>
          )}
        </div>

        {/* name */}
        <h1
          className="font-black text-white relative z-10 leading-none mb-4"
          style={{
            fontSize: "clamp(2.8rem, 5.5vw, 5rem)",
            letterSpacing: "-0.02em",
            wordBreak: "break-word",
            maxWidth: "100%",
          }}
        >
          {n.userFullName || "Inconnu"}
        </h1>

        {/* membership id pill */}
        {n.userMembershipId != null && (
          <div className="flex items-center gap-2 mb-8">
            <div
              className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full text-lg font-bold"
              style={{
                background: `rgba(${glowHex},0.12)`,
                border: `1px solid rgba(${glowHex},0.3)`,
                color: accentColor,
              }}
            >
              # {n.userMembershipId}
            </div>
          </div>
        )}

        {/* image flags */}
        {(n.imageSource === 'PROFILE_BORROWED' || n.userImageStatus === 'REQUIRED_CHANGE') && (
          <div className="flex flex-wrap gap-2 mb-4">
            {n.imageSource === 'PROFILE_BORROWED' && (
              <span
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium"
                style={{ background: 'rgba(255,255,255,0.08)', color: '#a1a1aa' }}
              >
                👤 Profile photo — no gym image set
              </span>
            )}
            {n.userImageStatus === 'REQUIRED_CHANGE' && (
              <span
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium"
                style={{ background: 'rgba(251,146,60,0.15)', color: '#fb923c', border: '1px solid rgba(251,146,60,0.3)' }}
              >
                ⚠ Image change required
              </span>
            )}
          </div>
        )}

        {/* divider */}
        <div
          className="rounded-full mb-8"
          style={{ height: 3, width: "4rem", background: accentColor, opacity: 0.8 }}
        />

        {/* info grid */}
        <div className="grid grid-cols-2 gap-x-10 gap-y-7 mb-8 relative z-10">
          {n.userValidFrom ? <InfoCell label="Début" value={n.userValidFrom.slice(0, 10)} /> : null}
          {n.userValidTo ? <InfoCell label="Fin" value={n.userValidTo.slice(0, 10)} /> : null}
          {!n.userPhone && !n.userValidFrom && !n.userValidTo && n.reason ? (
            <div className="col-span-2">
              <p className="text-sm font-bold uppercase tracking-[0.2em] text-zinc-500 mb-1">Raison</p>
              <p className="text-[1.75rem] font-bold text-zinc-100 leading-tight">{n.reason}</p>
            </div>
          ) : null}
        </div>

        {/* birthday banner */}
        {isBirthday && (
          <div
            className="rounded-2xl px-6 py-4 mb-8"
            style={{
              background: "linear-gradient(135deg, rgba(120,53,15,0.6), rgba(88,28,135,0.6))",
              border: "1px solid rgba(250,204,21,0.25)",
            }}
          >
            <p
              className="font-extrabold text-2xl text-center"
              style={{
                background: "linear-gradient(90deg, #fde68a, #f9a8d4, #c4b5fd)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
              }}
            >
              🎉 Nous vous souhaitons un joyeux anniversaire ! 🎉
            </p>
          </div>
        )}

        {/* device footer */}
        {n.deviceName ? (
          <div className="flex items-center gap-3 mt-auto">
            <div
              className="w-2 h-2 rounded-full flex-shrink-0"
              style={{ background: accentColor, opacity: 0.5 }}
            />
            <span className="text-lg text-zinc-600 truncate">{n.deviceName}</span>
          </div>
        ) : null}
      </div>

      {/* ── PROGRESS BAR — time remaining until idle ── */}
      <div
        className="absolute bottom-0 left-0 right-0"
        style={{ height: 4, background: "rgba(255,255,255,0.06)" }}
      >
        <div
          key={showKey}
          onAnimationEnd={() => goIdleRef.current()}
          style={{
            height: "100%",
            width: "100%",
            background: accentColor,
            opacity: 0.7,
            transformOrigin: "left center",
            animation: `progressDrain ${MAX_SHOW_MS}ms linear forwards`,
          }}
        />
      </div>

      <style>{`
        @keyframes confettiFall {
          0%   { transform: translateY(0px) rotate(0deg);    opacity: 0.9; }
          100% { transform: translateY(105vh) rotate(540deg); opacity: 0;   }
        }
        @keyframes progressDrain {
          0%   { transform: scaleX(1); }
          100% { transform: scaleX(0); }
        }
      `}</style>
    </div>
  );
}
