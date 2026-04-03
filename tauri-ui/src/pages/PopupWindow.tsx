import { useState, useEffect, useRef, useCallback } from "react";
import { openSSE } from "@/api/client";
import type { PopupEvent } from "@/api/types";

const API_PORT = 8788;
const API_BASE = `http://127.0.0.1:${API_PORT}/api/v2`;

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

export default function PopupWindow() {
  const [notification, setNotification] = useState<PopupEvent | null>(null);
  const [imgSrc, setImgSrc] = useState<string | null>(null);
  const [showData, setShowData] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastLocalEventIdRef = useRef<string>("");
  const lastShownEventIdRef = useRef<string>("");

  const resolveImage = useCallback((evt: PopupEvent) => {
    if (!evt.popupShowImage) { setImgSrc(null); return; }
    const img = (evt.userImage || evt.imagePath || "").trim();
    if (!img) { setImgSrc(null); return; }
    if (img.startsWith("http") || img.startsWith("data:")) { setImgSrc(img); return; }
    setImgSrc(`${API_BASE}/image-cache?url=${encodeURIComponent(img)}`);
  }, []);

  const showNotification = useCallback((evt: PopupEvent) => {
    if (evt.eventId && evt.eventId === lastShownEventIdRef.current) return;
    lastShownEventIdRef.current = evt.eventId || "";
    setNotification(evt);
    setShowData(true);
    resolveImage(evt);
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(
      () => setShowData(false),
      Math.max(1, Number(evt.popupDurationSec || 5)) * 1000,
    );
  }, [resolveImage]);

  // Channel 1 — Direct SSE
  useEffect(() => {
    const es = openSSE("/agent/events?replayLast=1", (type, data) => {
      if (type !== "popup" && type !== "notification") return;
      try { showNotification(toPopupEvent(typeof data === "string" ? JSON.parse(data) : data)); }
      catch { /* ignore */ }
    });
    return () => { es.close(); if (timerRef.current) clearTimeout(timerRef.current); };
  }, [showNotification]);

  // Channel 2 — Tauri IPC
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    import("@tauri-apps/api/event")
      .then(({ listen }) => listen<any>("popup-notification", (e) => {
        try { showNotification(toPopupEvent(e.payload)); } catch { /* ignore */ }
      }))
      .then((fn) => { unlisten = fn; })
      .catch(() => { /* browser mode */ });
    return () => { if (unlisten) unlisten(); };
  }, [showNotification]);

  // Channel 3 — localStorage polling
  useEffect(() => {
    const read = () => {
      try {
        const raw = localStorage.getItem("popupEvent");
        if (!raw) return;
        const parsed = toPopupEvent(JSON.parse(raw));
        if (!parsed.eventId || parsed.eventId === lastLocalEventIdRef.current) return;
        lastLocalEventIdRef.current = parsed.eventId;
        showNotification(parsed);
      } catch { /* ignore */ }
    };
    const onStorage = (e: StorageEvent) => { if (e.key === "popupEvent") read(); };
    read();
    window.addEventListener("storage", onStorage);
    const id = window.setInterval(read, 500);
    return () => { window.removeEventListener("storage", onStorage); window.clearInterval(id); };
  }, [showNotification]);

  if (!notification) return <div className="h-screen w-screen bg-black" />;

  const n = notification;
  const isAllowed = Boolean(n.allowed);
  const isBirthday = isTodayBirthday(n.userBirthday);
  const initial = (n.userFullName || "?")[0].toUpperCase();

  // ── colour scheme ──
  const accentColor  = isBirthday ? "#f59e0b" : isAllowed ? "#10b981" : "#ef4444";
  const glowHex      = isBirthday ? "250,159,21"  : isAllowed ? "16,185,129" : "239,68,68";
  const statusLabel  = isBirthday ? "Joyeux Anniversaire !" : isAllowed ? "Accès Autorisé" : "Accès Refusé";
  const statusIcon   = isBirthday ? "🎂" : isAllowed ? "✓" : "✗";
  const noBgFrom     = isBirthday ? "#451a03" : isAllowed ? "#022c22" : "#2d0a0a";
  const noBgTo       = "#050505";

  return (
    <div
      className="h-screen w-screen flex overflow-hidden select-none relative"
      style={{ opacity: showData ? 1 : 0.18, transition: "opacity 0.6s ease" }}
    >
      {/* ── CONFETTI (birthday only) ── */}
      {isBirthday && showData && (
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
        {/* gradient fade to right → dark panel */}
        <div
          className="absolute inset-0"
          style={{ background: "linear-gradient(to right, transparent 55%, #050505 100%)" }}
        />
        {/* bottom vignette */}
        <div
          className="absolute inset-0"
          style={{ background: "linear-gradient(to top, #050505 0%, transparent 35%)" }}
        />
        {/* top vignette */}
        <div
          className="absolute inset-0"
          style={{ background: "linear-gradient(to bottom, #050505 0%, transparent 20%)" }}
        />
        {/* colored vertical stripe along right edge */}
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
          <span
            className="text-2xl font-black leading-none"
            style={{ color: accentColor }}
          >
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

        {/* ── NAME ── big and bold */}
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

        {/* divider */}
        <div
          className="rounded-full mb-8"
          style={{
            height: 3,
            width: "4rem",
            background: accentColor,
            opacity: 0.8,
          }}
        />

        {/* info grid */}
        <div className="grid grid-cols-2 gap-x-10 gap-y-7 mb-8 relative z-10">
          {n.userPhone ? <InfoCell label="Téléphone" value={n.userPhone} /> : null}
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

      <style>{`
        @keyframes confettiFall {
          0%   { transform: translateY(0px) rotate(0deg);    opacity: 0.9; }
          100% { transform: translateY(105vh) rotate(540deg); opacity: 0;   }
        }
      `}</style>
    </div>
  );
}
