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
  };
}

export default function PopupWindow() {
  const [notification, setNotification] = useState<PopupEvent | null>(null);
  const [imgSrc, setImgSrc] = useState<string | null>(null);
  const [showData, setShowData] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastLocalEventIdRef = useRef<string>("");
  // Deduplication across all delivery channels (SSE + Tauri IPC + localStorage)
  const lastShownEventIdRef = useRef<string>("");

  const resolveImage = useCallback((evt: PopupEvent) => {
    if (!evt.popupShowImage) {
      setImgSrc(null);
      return;
    }
    const img = (evt.userImage || evt.imagePath || "").trim();
    if (!img) {
      setImgSrc(null);
      return;
    }
    if (img.startsWith("http") || img.startsWith("data:")) {
      setImgSrc(img);
      return;
    }
    setImgSrc(`${API_BASE}/image-cache?url=${encodeURIComponent(img)}`);
  }, []);

  const showNotification = useCallback((evt: PopupEvent) => {
    // Deduplicate: skip if this exact event was already shown (can arrive via
    // multiple channels: direct SSE, Tauri IPC, and localStorage fallback).
    if (evt.eventId && evt.eventId === lastShownEventIdRef.current) return;
    lastShownEventIdRef.current = evt.eventId || "";

    setNotification(evt);
    setShowData(true);
    resolveImage(evt);

    if (timerRef.current) {
      clearTimeout(timerRef.current);
    }
    timerRef.current = setTimeout(
      () => setShowData(false),
      Math.max(1, Number(evt.popupDurationSec || 5)) * 1000,
    );
  }, [resolveImage]);

  // Channel 1 — Direct SSE from the backend.
  // The popup window connects independently so it receives events without
  // needing the main window to relay them.
  useEffect(() => {
    const es = openSSE("/agent/events", (type, data) => {
      if (type !== "popup" && type !== "notification") return;
      try {
        const parsed = toPopupEvent(typeof data === "string" ? JSON.parse(data) : data);
        showNotification(parsed);
      } catch {
        // ignore malformed events
      }
    });

    return () => {
      es.close();
      if (timerRef.current) {
        clearTimeout(timerRef.current);
      }
    };
  }, [showNotification]);

  // Channel 2 — Tauri cross-window IPC (primary relay from main window).
  // In Tauri, each WebviewWindow is a separate WebView2 process with
  // isolated localStorage — so we use Tauri's emit/listen instead.
  // The main window emits "popup-notification" via usePopupStream whenever
  // it receives an event from the backend SSE.
  useEffect(() => {
    let unlisten: (() => void) | undefined;

    import("@tauri-apps/api/event")
      .then(({ listen }) =>
        listen<any>("popup-notification", (event) => {
          try {
            const parsed = toPopupEvent(event.payload);
            showNotification(parsed);
          } catch {
            // ignore malformed payload
          }
        })
      )
      .then((fn) => { unlisten = fn; })
      .catch(() => { /* not running inside Tauri — no-op */ });

    return () => {
      if (unlisten) unlisten();
    };
  }, [showNotification]);

  // Channel 3 — localStorage polling (browser / same-context fallback).
  // Works when the app is opened as a regular browser tab (not Tauri).
  useEffect(() => {
    const readLocalPopup = () => {
      try {
        const raw = localStorage.getItem("popupEvent");
        if (!raw) return;
        const parsed = toPopupEvent(JSON.parse(raw));
        if (!parsed.eventId || parsed.eventId === lastLocalEventIdRef.current) return;
        lastLocalEventIdRef.current = parsed.eventId;
        showNotification(parsed);
      } catch {
        // ignore malformed localStorage payload
      }
    };

    const onStorage = (e: StorageEvent) => {
      if (e.key === "popupEvent") readLocalPopup();
    };

    readLocalPopup();
    window.addEventListener("storage", onStorage);
    const id = window.setInterval(readLocalPopup, 500);

    return () => {
      window.removeEventListener("storage", onStorage);
      window.clearInterval(id);
    };
  }, [showNotification]);

  if (!showData || !notification) {
    return <div className="h-screen w-screen bg-black" />;
  }

  const n = notification;
  return (
    <div className="h-screen w-screen bg-black text-white grid grid-rows-4 grid-cols-4 gap-0 overflow-hidden select-none">
      <div className="col-span-4 bg-black" />

      <div className="bg-black" />
      <div className="col-span-2 row-span-2 flex items-center justify-center bg-black p-2">
        {imgSrc ? (
          <img src={imgSrc} alt="" className="max-h-full max-w-full object-contain rounded-lg" onError={() => setImgSrc(null)} />
        ) : (
          <div className="flex items-center justify-center h-full w-full">
            <div className="h-32 w-32 rounded-full bg-zinc-800 flex items-center justify-center text-5xl font-bold text-zinc-500">
              {(n.userFullName || "?")[0]}
            </div>
          </div>
        )}
      </div>
      <div className="bg-black flex flex-col justify-center px-6 space-y-2">
        <p className="text-lg font-bold text-emerald-400 truncate">{n.userFullName || "Inconnu"}</p>
        {n.userMembershipId != null && <p className="text-sm text-zinc-400">Abonnement #{n.userMembershipId}</p>}
      </div>

      <div className="bg-black" />
      <div className="bg-black flex flex-col justify-center px-6 space-y-1">
        {n.userValidFrom && <p className="text-xs text-zinc-500">Du: <span className="text-zinc-300">{n.userValidFrom}</span></p>}
        {n.userValidTo && <p className="text-xs text-zinc-500">Au: <span className="text-zinc-300">{n.userValidTo}</span></p>}
        {n.deviceName && <p className="text-xs text-zinc-600 mt-2">{n.deviceName}</p>}
      </div>

      <div className="col-span-4 bg-black" />
    </div>
  );
}
