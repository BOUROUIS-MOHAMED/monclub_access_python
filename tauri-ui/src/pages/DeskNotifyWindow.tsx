import { useCallback, useEffect, useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { get, openSSE } from "@/api/client";
import type { PopupEvent } from "@/api/types";
import { buildPopupImageCandidates, toPopupCachedImageUrl } from "@/lib/popupImages";
import { feeLinesView, parseFees, feeDueSoonDays } from "@/lib/feeAlerts";
import { DESK_DEFAULTS, deskAccepts, deskAdvance, deskBirthday, deskDaysLeft, deskDuration, deskReentry, DeskTestInbox, deskScrollOffset,
  type DeskNotifySettings, type DeskNotifyAction } from "@/lib/deskNotify";
import { AGlyph, ARefusalGlyph, APhoto, aAgeToday, aClock, aDenyCopy, aFieldFor, aMethodFor, aMethodLabel,
  mapLaneToScan, toPopupEvent, A_GOLD, A_GOLD_INK, A_ORANGE_INK_DEEP } from "./PopupWindow";
import "./desk-notify.css";

interface Tile {
  id: string; event: PopupEvent; arrivedAt: number; remaining: number; duration: number;
  tickAt: number; paused: boolean; imgUrl: string | null; imgFallbacks: string[];
}

function staffCopy(e: PopupEvent) {
  const fallback = aDenyCopy(e.reason, e.reasonDate);
  const date = /^\d{4}-\d{2}-\d{2}$/.test(e.reasonDate || "") ? e.reasonDate!.split("-").reverse().join("/") : "";
  const copy: Record<string, [string, string]> = {
    MEMBERSHIP_EXPIRED: ["Abonnement expiré" + (date ? ` le ${date}` : ""), "Proposez-lui un renouvellement."],
    DEBT_DUE_PASSED: [date ? `Échéance du ${date} dépassée` : "Échéance dépassée", "Encaissez le reste pour rouvrir l'accès."],
    FEE_DUE_PASSED: ["Frais obligatoire échu" + (date ? ` depuis le ${date}` : ""), "À encaisser depuis le tableau de bord."],
    MEMBERSHIP_FROZEN: [date ? `Gelé, retour prévu le ${date}` : "Abonnement gelé", "Le gel peut être annulé depuis sa fiche."],
    MEMBERSHIP_NOT_STARTED: [date ? `Son abonnement commence le ${date}` : "Son abonnement n'a pas encore commencé", "Les dates se changent depuis sa fiche."],
    OFF_HOURS: ["Hors horaires de sa formule", "Il pourra entrer pendant les horaires de sa formule."],
    ENTRY_LIMIT: ["Limite d'entrées atteinte", "Un pack de séances ou une autre formule rouvre l'accès."],
    DENY_NO_CARD_MATCH: ["Cette carte n'est liée à aucun membre", "Associez-la, ou vérifiez la synchronisation."],
  };
  if (deskReentry(e)) {
    const previous = /[T ](\d{2}:\d{2})/.exec(e.previousEntryAt || "")?.[1];
    return { ...fallback, title: "Déjà passé" + (previous ? ` à ${previous}` : ""), action: "La porte reste fermée quelques secondes : rien à faire." };
  }
  const hit = copy[e.reason];
  return { ...fallback, title: hit?.[0] || fallback.title, action: hit?.[1] || "Ouvrez sa fiche pour voir pourquoi." };
}

function Close({ close }: { close: () => void }) {
  return <button className="desk-close" aria-label="Fermer" onClick={(e) => { e.stopPropagation(); close(); }}>
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true"><path d="M3 3l8 8M11 3l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></svg>
  </button>;
}

function DeskTile({ tile, full, settings, remove, pause, imageError, act }: {
  tile: Tile; full: boolean; settings: DeskNotifySettings; remove: () => void; pause: (paused: boolean) => void;
  imageError: () => void; act: (action: DeskNotifyAction["action"]) => void;
}) {
  const e = tile.event;
  const showIdentity = e.allowed || e.refusedDisplay === true;
  const unknown = e.reason === "DENY_NO_CARD_MATCH";
  const scan = mapLaneToScan({ laneId: tile.id, event: showIdentity ? e : { ...e, userFullName: "", userImage: "", userProfileImage: "" },
    arrivedAt: tile.arrivedAt, expiresAt: 0, fadingOut: false, imgUrl: showIdentity ? tile.imgUrl : null, imgFallbacks: [] });
  const now = new Date(tile.arrivedAt);
  const field = aFieldFor(scan, now);
  const birthday = e.allowed && deskBirthday(e, now);
  const reentry = deskReentry(e);
  const eyebrow = !e.allowed ? reentry ? "Deuxième passage" : "Accès refusé" : birthday ? "Joyeux anniversaire" : "Accès autorisé";
  const shortEyebrow = !e.allowed ? reentry ? "Deuxième passage" : "Refusé" : birthday ? "Anniversaire" : "Autorisé";
  const name = showIdentity && e.userFullName ? e.userFullName : unknown ? "Carte inconnue" : "Carte";
  const days = e.allowed ? deskDaysLeft(e.userValidTo, now) : null;
  const ending = days !== null && days >= 0 && days <= 7;
  const fees = e.allowed ? feeLinesView(parseFees(e.fees), now, feeDueSoonDays(e.feeDueSoonDays)) : null;
  const repeat = e.allowed && (e.repeatCount || 0) > 0;
  const hasPanel = !e.allowed || ending || !!fees?.shown.length || repeat;
  const copy = staffCopy(e);
  const size = full ? 108 : 46;
  const age = birthday ? aAgeToday(scan.birthday, now) : null;
  // An unknown card belongs to nobody: only its number is worth showing.
  const meta = unknown ? (e.refusedCardNo ? `Carte n° ${e.refusedCardNo}` : "")
    : [showIdentity ? e.userMembershipTitle : "", showIdentity && e.userValidTo ? `jusqu’au ${dateText(e.userValidTo)}` : "",
      showIdentity ? aMethodLabel(aMethodFor(e.scanMode)) : e.refusedCardNo ? `Carte n° ${e.refusedCardNo}` : ""].filter(Boolean).join(" · ");
  const medallion = <div className="desk-medallion" style={{ margin: full ? 5 : 0 }}>
    {!showIdentity || unknown ? <div className="desk-card-photo" style={{ width: size, height: size, boxShadow: `0 0 0 ${full ? 5 : 3}px ${field.ring}` }}><AGlyph name="card" size={size / 2} /></div>
      : <APhoto scan={scan} field={field} size={size} ring={full ? 5 : 3} onImageError={imageError} />}
    {full && repeat && <span className="desk-repeat"><AGlyph name="history" size={15} />{e.repeatCount}<sup>e</sup></span>}
  </div>;
  const panels: ReactNode[] = [];
  if (!e.allowed) panels.push(<div className="desk-panel desk-deny" key="deny">
    {reentry ? <AGlyph name="history" size={26} /> : <ARefusalGlyph name={copy.glyph} size={26} color="#FFFFFF" />}
    <div><strong>{copy.title}</strong><p>{copy.action}</p></div>
  </div>);
  if (ending) panels.push(<div className="desk-panel desk-ending" key="ending"><AGlyph name="schedule" size={24} color={A_GOLD} />
    <div><strong>Se termine dans {days} {days === 1 ? "jour" : "jours"} ({dateText(e.userValidTo, true)})</strong><p>Le bon moment pour lui proposer de renouveler.</p></div>
  </div>);
  for (const fee of fees?.shown || []) panels.push(<div className="desk-panel desk-fee" key={`fee-${fee.name}`}><ARefusalGlyph name="receiptLong" size={24} color="#B76E00" />
    <div><strong>{fee.title}</strong><p>{fee.dueDate ? `À régler ${fee.kind === "dueSoon" ? "avant le" : "depuis le"} ${dateText(fee.dueDate)}.` : "À encaisser depuis le tableau de bord."}</p></div>
  </div>);
  if (fees?.moreText) panels.push(<div className="desk-more-fees" key="more">{fees.moreText}</div>);
  if (repeat) panels.push(<div className="desk-panel desk-fee" key="repeat"><AGlyph name="history" size={24} color={A_ORANGE_INK_DEEP} />
    <div><strong>{e.repeatCount}<sup>e</sup> passage en {e.repeatWindowMin} minutes</strong><p>{scan.previousEntryAt ? `Premier passage à ${aClock(scan.previousEntryAt)}. ` : ""}La porte s’est ouverte.</p></div>
  </div>);
  const buttons: { label: string; action: DeskNotifyAction["action"]; primary?: boolean }[] = unknown
    ? [{ label: "Associer à un membre", action: "assignCard", primary: true }]
    : [{ label: "Ouvrir la fiche", action: "open" }];
  // Fees can only be managed on the dashboard: never offer a collection button here.
  if (!unknown && e.reason !== "FEE_DUE_PASSED" && !fees?.shown.length) {
    if (settings.renewButton && ((!e.allowed && e.reason === "MEMBERSHIP_EXPIRED") || ending)) buttons.push({ label: "Renouveler", action: "renew", primary: true });
    if (settings.payRestButton && !e.allowed && e.reason === "DEBT_DUE_PASSED") buttons.push({ label: "Payer le reste", action: "payRest", primary: true });
  }
  return <article className={`desk-tile ${full ? "desk-full" : "desk-strip"} ${tile.paused ? "desk-paused" : ""}`}
    style={{ background: field.bg, color: field.ink, "--desk-sub": !e.allowed ? field.sub : birthday ? field.sub : "#114A38",
      "--desk-button-bg": !e.allowed ? "rgba(255,255,255,.22)" : birthday ? "rgba(255,255,255,.36)" : "rgba(255,255,255,.32)",
      "--desk-button-ink": !e.allowed ? reentry ? "#A8320F" : "#B0122C" : birthday ? A_GOLD_INK : "#0A6B4C" } as CSSProperties}
    onMouseEnter={() => pause(true)} onMouseLeave={() => pause(false)} onClick={() => act("open")} role="button" tabIndex={0}
    onKeyDown={(key) => { if (key.target === key.currentTarget && (key.key === "Enter" || key.key === " ")) { key.preventDefault(); act("open"); } }}>
    <AGlyph name={field.glyph} size={full ? 250 : 90} opacity={full ? field.glyphOpacity : .12} style={{ position: "absolute", right: full ? -60 : 30, top: full ? "34%" : "50%", transform: "translateY(-50%)", pointerEvents: "none" }} />
    {full ? <>
      <header className="desk-header"><span className="desk-wordmark">monclub</span>
        {tile.paused ? <span className="desk-pause">En pause</span> : <><span className="desk-device">{e.deviceName || "Entrée"}</span><span className="desk-clock">{aClock(now)}</span></>}
        <Close close={remove} />
      </header>
      <div className="desk-person">{medallion}<div className="desk-names">
        <div className="desk-eyebrow">{eyebrow}</div>
        <div className="desk-first" style={{ fontSize: !showIdentity || unknown ? 28 : 36 }}>{showIdentity && !unknown ? scan.firstName : name}</div>
        {showIdentity && !unknown && <div className="desk-last" style={{ fontSize: hasPanel ? 24 : 26 }}>{scan.lastName}</div>}
        {hasPanel && meta && <div className="desk-meta">{meta}</div>}
      </div></div>
      {panels}
      {!hasPanel && <div className="desk-plan">{age !== null && <span className="desk-age">{age} ans aujourd’hui</span>}
        {birthday ? e.userMembershipTitle : [e.userMembershipTitle, e.userValidTo ? `jusqu’au ${dateText(e.userValidTo)}` : ""].filter(Boolean).join(" · ")}</div>}
      <div className="desk-buttons">{buttons.map((b) => <button key={b.action} className={b.primary ? "desk-primary" : ""}
        onClick={(click) => { click.stopPropagation(); act(b.action); }}>{b.label}</button>)}</div>
      <div className="desk-timer"><div style={{ width: `${tile.duration ? tile.remaining / tile.duration * 100 : 100}%`, background: field.ink }} /></div>
    </> : <>{medallion}<div className="desk-strip-name"><div className="desk-eyebrow">{tile.paused ? "En pause" : `${shortEyebrow} · ${aClock(now)}`}</div><div>{name}</div></div><Close close={remove} /></>}
  </article>;
}

function dateText(date: string, short = false): string {
  const [year, month, day] = date.slice(0, 10).split("-");
  return year && month && day ? `${day}/${month}${short ? "" : `/${year}`}` : "";
}

export default function DeskNotifyWindow() {
  const [settings, setSettings] = useState<DeskNotifySettings>(DESK_DEFAULTS);
  const settingsRef = useRef(settings);
  const [tiles, setTiles] = useState<Tile[]>([]);
  const stack = useRef<HTMLDivElement>(null);
  const viewport = useRef<HTMLDivElement>(null);
  const testInbox = useRef(new DeskTestInbox());
  const seen = useRef(new Map<string, number>());
  const enqueue = useCallback((raw: unknown) => {
    const e = toPopupEvent(raw);
    const s = settingsRef.current;
    const now = Date.now();
    if (!deskAccepts(e, s, new Date(now)) || seen.current.has(e.eventId)) return;
    for (const [id, at] of seen.current) if (now - at > 3600000) seen.current.delete(id);
    seen.current.set(e.eventId, now);
    const images = (e.allowed || e.refusedDisplay) && e.popupShowImage ? buildPopupImageCandidates(e) : [];
    const duration = deskDuration(e, s.durationSec);
    setTiles((old) => [{ id: e.eventId, event: e, arrivedAt: now, duration, remaining: duration, tickAt: now, paused: false,
      imgUrl: images[0] ? toPopupCachedImageUrl(images[0]) : null, imgFallbacks: images.slice(1) }, ...old]);
    if (s.sound && !e.allowed) void new Audio("/sounds/scan-rejected.mp3").play().catch(() => {});
  }, []);

  useEffect(() => {
    document.documentElement.classList.add("desk-notify-document");
    let stopped = false;
    let stream: EventSource | undefined;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const s = await get<DeskNotifySettings>("/desk-notify/settings");
        if (stopped) return;
        settingsRef.current = s;
        setSettings((old) => JSON.stringify(old) === JSON.stringify(s) ? old : s);
        if (!s.enabled) { setTiles([]); void invoke("hide_desk_notify_window").catch(() => {}); }
        for (const test of testInbox.current.drain(s)) enqueue(test);
        if (!stream) stream = openSSE("/agent/events?replayLast=0&client=desk", (type, data) => {
          if (type !== "popup") return;
          const event = toPopupEvent(data);
          if (!testInbox.current.receive(event)) enqueue(event);
        });
      } catch { /* Keep the last settings during a temporary API interruption. */ }
      if (!stopped) timer = window.setTimeout(poll, 2000);
    };
    void poll();
    return () => { stopped = true; stream?.close(); window.clearTimeout(timer); document.documentElement.classList.remove("desk-notify-document"); };
  }, [enqueue]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      const now = Date.now();
      setTiles((old) => old.length ? old.map((t) => ({ ...t, tickAt: now, remaining: t.duration ? deskAdvance(t.remaining, now - t.tickAt, t.paused) : 0 }))
        .filter((t) => !t.duration || t.remaining > 0) : old);
    }, 100);
    return () => window.clearInterval(timer);
  }, []);

  const count = tiles.length;
  const layoutKey = `${settings.screen}:${settings.position}:${settings.maxVisible}:${count}:${tiles[0]?.id || ""}`;
  useLayoutEffect(() => {
    let stopped = false;
    let serial = Promise.resolve();
    const pinToCorner = () => {
      const container = viewport.current;
      if (container) container.scrollTop = deskScrollOffset(container.scrollHeight, container.clientHeight, settings.position);
    };
    const resize = () => {
      serial = serial.catch(() => {}).then(async () => {
        if (stopped) return;
        if (!settings.enabled || !count) { await invoke("hide_desk_notify_window"); return; }
        const height = Math.ceil((stack.current?.getBoundingClientRect().height || 0) + 24);
        const scale = await invoke<number>("desk_notify_scale", { screen: settings.screen });
        if (stopped) return;
        await invoke("layout_desk_notify_window", { screen: settings.screen, position: settings.position, width: Math.round(424 * scale), height: Math.round(height * scale) });
        if (!stopped) { pinToCorner(); await invoke("show_desk_notify_window"); }
      }).catch(() => { /* Browser preview has no native window. */ });
    };
    resize();
    const observer = new ResizeObserver(() => { pinToCorner(); resize(); });
    if (stack.current) observer.observe(stack.current);
    if (viewport.current) observer.observe(viewport.current);
    return () => { stopped = true; observer.disconnect(); };
  }, [layoutKey, settings.enabled]);

  const remove = (id: string) => setTiles((old) => old.filter((t) => t.id !== id));
  const act = (tile: Tile, action: DeskNotifyAction["action"]) => {
    const payload: DeskNotifyAction = { action, ...(tile.event.userMembershipId ? { activeMembershipId: tile.event.userMembershipId } : {}),
      ...(tile.event.refusedCardNo ? { cardNo: tile.event.refusedCardNo } : {}) };
    void emit("desk-notify-action", payload).then(() => remove(tile.id)).catch(() => {});
  };
  const visible = tiles.slice(0, settings.maxVisible);
  const hidden = tiles.slice(settings.maxVisible);
  const top = settings.position.startsWith("TOP_");
  const overflow = hidden.length > 0 && <div className="desk-overflow" key="overflow"><span className="desk-wordmark">monclub</span><span>+{hidden.length} autres entrées depuis {aClock(new Date(hidden[hidden.length - 1].arrivedAt))}</span>
    <button onClick={() => { void emit("desk-notify-action", { action: "open" }).then(() => setTiles((old) => old.slice(0, settings.maxVisible))); }}>Voir dans Access</button></div>;
  const cards = visible.map((tile, index) => <DeskTile key={tile.id} tile={tile} full={index === 0} settings={settings} remove={() => remove(tile.id)} act={(action) => act(tile, action)}
    pause={(paused) => setTiles((old) => old.map((t) => t.id === tile.id ? { ...t, paused, tickAt: Date.now(), remaining: t.duration ? deskAdvance(t.remaining, Date.now() - t.tickAt, t.paused) : 0 } : t))}
    imageError={() => setTiles((old) => old.map((t) => t.id === tile.id ? { ...t, imgUrl: t.imgFallbacks[0] ? toPopupCachedImageUrl(t.imgFallbacks[0]) : null, imgFallbacks: t.imgFallbacks.slice(1) } : t))} />);
  return <div className="desk-window" ref={viewport}><div className="desk-stack" ref={stack}>{top ? <>{cards}{overflow}</> : <>{overflow}{cards.reverse()}</>}</div></div>;
}
