import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getTvScreenMessages } from "@/tv/api";

enum WeatherType {
  SUNNY = "Sunny",
  CLOUDY = "Cloudy",
  RAINY = "Rainy",
  STORMY = "Stormy",
}

enum AdDisplayMode {
  FULL_SCREEN = "FULL_SCREEN",
  ADS_1_4_H = "ADS_1_4_H",
  ADS_1_2_H = "ADS_1_2_H",
  ADS_3_4_H = "ADS_3_4_H",
  ADS_1_4_V = "ADS_1_4_V",
  ADS_1_2_V = "ADS_1_2_V",
  ADS_3_4_V = "ADS_3_4_V",
}

type TvNotification = {
  id: number;
  title: string;
  description: string;
  phase: "entering" | "visible" | "exiting";
};

type TvEvent = {
  id: number;
  title: string;
  description: string;
  room: string;
  coachName: string;
  startsAt: string;
  image: string;
  phase: "entering" | "visible" | "exiting";
};

type TvQuote = {
  id: number;
  text: string;
  author: string;
  phase: "entering" | "visible" | "exiting";
};

type TvAdPanel = {
  id: number;
  mode: AdDisplayMode;
  phase: "entering" | "visible" | "exiting";
};

const rand = (min: number, max: number) =>
  Math.floor(Math.random() * (max - min + 1) + min);

const formatSegment = (segment: number) => (segment < 10 ? `0${segment}` : `${segment}`);
const formatHours = (hours: number) => (hours % 12 === 0 ? 12 : hours % 12);
const formatTime = (date: Date) =>
  `${formatHours(date.getHours())}:${formatSegment(date.getMinutes())}`;

function getFutureDate(hoursFromNow: number, minutesFromNow: number) {
  const date = new Date();
  date.setHours(date.getHours() + hoursFromNow);
  date.setMinutes(date.getMinutes() + minutesFromNow);
  date.setSeconds(0);
  date.setMilliseconds(0);
  return date.toISOString();
}

function useCurrentTime() {
  const [date, setDate] = useState(new Date());

  useEffect(() => {
    const interval = window.setInterval(() => setDate(new Date()), 1000);
    return () => window.clearInterval(interval);
  }, []);

  return date;
}

function TimeInfo() {
  const date = useCurrentTime();
  return <span className="time-text">{formatTime(date)}</span>;
}

function WeatherSnap() {
  const temperature = useMemo(() => rand(65, 85), []);
  return (
    <span className="weather-snap">
      <span className="weather-icon">☀️</span>
      <span className="weather-temp">{temperature}</span>
      <span className="weather-unit">°F</span>
    </span>
  );
}

function Info({ id }: { id?: string }) {
  return (
    <div id={id} className="info-bar">
      <TimeInfo />
      <WeatherSnap />
    </div>
  );
}

function Reminder() {
  return (
    <div className="reminder">
      <span className="reminder-icon">🔔</span>
      <span className="reminder-text">
        Extra cool people meeting <span className="reminder-time">10AM</span>
      </span>
    </div>
  );
}

function QuickNav() {
  const items = ["Weather", "Events", "Notifications", "Ads"];

  return (
    <div id="quick-nav" className="static-row">
      {items.map((item) => (
        <div key={item} className="glass-pill quick-nav-item">
          {item}
        </div>
      ))}
    </div>
  );
}

function WeatherSection() {
  const days = useMemo(
    () => [
      { name: "Mon", temperature: rand(60, 80), weather: WeatherType.SUNNY },
      { name: "Tue", temperature: rand(60, 80), weather: WeatherType.SUNNY },
      { name: "Wed", temperature: rand(60, 80), weather: WeatherType.CLOUDY },
      { name: "Thu", temperature: rand(60, 80), weather: WeatherType.RAINY },
      { name: "Fri", temperature: rand(60, 80), weather: WeatherType.STORMY },
      { name: "Sat", temperature: rand(60, 80), weather: WeatherType.SUNNY },
      { name: "Sun", temperature: rand(60, 80), weather: WeatherType.CLOUDY },
    ],
    []
  );

  const getIcon = (type: WeatherType) => {
    switch (type) {
      case WeatherType.CLOUDY:
        return "☁️";
      case WeatherType.RAINY:
        return "🌦️";
      case WeatherType.STORMY:
        return "⛈️";
      default:
        return "☀️";
    }
  };

  return (
    <section id="weather-section" className="menu-section">
      <div className="weather-section-shell">
        <div className="menu-section-title">
          <span>☀️</span>
          <span className="menu-section-title-text">How&apos;s it look out there?</span>
        </div>

        <div className="weather-grid">
          {days.map((day) => (
            <div key={day.name} className="day-card">
              <div className="day-card-content">
                <span className="day-name">{day.name}</span>
                <span className={`day-weather-icon ${day.weather.toLowerCase()}`}>
                  {getIcon(day.weather)}
                </span>
                <span className="day-weather-temperature">
                  {day.temperature}
                  <span className="day-weather-temperature-unit">°F</span>
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function Background({ visualSrc, visualMimeType }: { visualSrc?: string | null; visualMimeType?: string | null }) {
  const isVideo =
    (visualMimeType ?? "").toUpperCase().startsWith("VIDEO") ||
    (visualMimeType ?? "").toUpperCase().includes("MP4") ||
    (visualMimeType ?? "").toUpperCase().includes("WEBM");

  return (
    <div id="app-background">
      {visualSrc ? (
        isVideo ? (
          <video
            key={visualSrc}
            src={visualSrc}
            autoPlay
            muted
            playsInline
            loop
            className="w-full h-full object-cover"
            style={{ width: "100%", height: "100%", objectFit: "cover" }}
          />
        ) : (
          <img
            key={visualSrc}
            src={visualSrc}
            alt=""
            style={{ width: "100%", height: "100%", objectFit: "cover" }}
          />
        )
      ) : (
        <div id="app-background-image" />
      )}
    </div>
  );
}

type NotificationToastProps = {
  notification: TvNotification | null;
  onClose: () => void;
};

function NotificationToast({ notification, onClose }: NotificationToastProps) {
  if (!notification) return null;

  return (
    <div className={`tv-notification tv-notification--${notification.phase}`}>
      <div className="tv-notification-glow" />
      <div className="tv-notification-icon-wrap">
        <div className="tv-notification-icon">🔔</div>
      </div>

      <div className="tv-notification-content">
        <div className="tv-notification-top-row">
          <span className="tv-notification-badge">Gym notification</span>
          <button
            type="button"
            className="tv-notification-close"
            onClick={onClose}
            aria-label="Close notification"
          >
            ✕
          </button>
        </div>

        <div className="tv-notification-title">{notification.title}</div>
        <div className="tv-notification-description">{notification.description}</div>

        <div className="tv-notification-progress">
          <div className="tv-notification-progress-bar" />
        </div>
      </div>
    </div>
  );
}

function formatTimeLeft(startsAt: string, now: Date) {
  const start = new Date(startsAt).getTime();
  const current = now.getTime();
  const diff = start - current;

  if (diff <= 0) return "Started";

  const totalMinutes = Math.floor(diff / 1000 / 60);
  const days = Math.floor(totalMinutes / (60 * 24));
  const hours = Math.floor((totalMinutes % (60 * 24)) / 60);
  const minutes = totalMinutes % 60;

  if (days > 0) return `${days}d ${hours}h left`;
  if (hours > 0) return `${hours}h ${minutes}m left`;
  return `${minutes}m left`;
}

type EventCardToastProps = {
  event: TvEvent | null;
  onClose: () => void;
};

function EventCardToast({ event, onClose }: EventCardToastProps) {
  const now = useCurrentTime();

  if (!event) return null;

  return (
    <div className={`tv-event-card tv-event-card--${event.phase}`}>
      <div className="tv-event-card-glow" />

      <div
        className="tv-event-card-image"
        style={{ backgroundImage: `url(${event.image})` }}
      />

      <div className="tv-event-card-content">
        <div className="tv-event-card-top-row">
          <span className="tv-event-card-badge">Next event</span>
          <button
            type="button"
            className="tv-event-card-close"
            onClick={onClose}
            aria-label="Close event card"
          >
            ✕
          </button>
        </div>

        <div className="tv-event-card-title">{event.title}</div>
        <div className="tv-event-card-description">{event.description}</div>

        <div className="tv-event-details">
          <div className="tv-event-detail-row">
            <div className="tv-event-detail-icon">⏳</div>
            <div className="tv-event-detail-body">
              <div className="tv-event-detail-label">Starts</div>
              <div className="tv-event-detail-value">{formatTimeLeft(event.startsAt, now)}</div>
            </div>
          </div>

          <div className="tv-event-detail-row">
            <div className="tv-event-detail-icon">📍</div>
            <div className="tv-event-detail-body">
              <div className="tv-event-detail-label">Room</div>
              <div className="tv-event-detail-value">{event.room}</div>
            </div>
          </div>

          <div className="tv-event-detail-row">
            <div className="tv-event-detail-icon">🧑‍🏫</div>
            <div className="tv-event-detail-body">
              <div className="tv-event-detail-label">Coach</div>
              <div className="tv-event-detail-value">{event.coachName}</div>
            </div>
          </div>
        </div>

        <div className="tv-event-card-progress">
          <div className="tv-event-card-progress-bar" />
        </div>
      </div>
    </div>
  );
}

type QuoteBannerProps = {
  quote: TvQuote | null;
  onClose: () => void;
};

function QuoteBanner({ quote, onClose }: QuoteBannerProps) {
  if (!quote) return null;

  return (
    <div className={`tv-quote-banner tv-quote-banner--${quote.phase}`}>
      <div className="tv-quote-banner-glow" />

      <div className="tv-quote-top-row">
        <span className="tv-quote-badge">Quote of the day</span>
        <button
          type="button"
          className="tv-quote-close"
          onClick={onClose}
          aria-label="Close quote"
        >
          ✕
        </button>
      </div>

      <div className="tv-quote-text">“{quote.text}”</div>
      <div className="tv-quote-author">— {quote.author}</div>
    </div>
  );
}

type AdPanelProps = {
  adPanel: TvAdPanel | null;
  onClose: () => void;
};

function AdPanel({ adPanel, onClose }: AdPanelProps) {
  if (!adPanel) return null;

  const isHorizontal =
    adPanel.mode === AdDisplayMode.ADS_1_4_H ||
    adPanel.mode === AdDisplayMode.ADS_1_2_H ||
    adPanel.mode === AdDisplayMode.ADS_3_4_H;

  const isFullScreen = adPanel.mode === AdDisplayMode.FULL_SCREEN;

  return (
    <div
      className={`tv-ad-panel tv-ad-panel--${adPanel.phase} ${
        isFullScreen
          ? "tv-ad-panel--full-screen"
          : isHorizontal
            ? "tv-ad-panel--horizontal"
            : "tv-ad-panel--vertical"
      } tv-ad-panel--${adPanel.mode.toLowerCase()}`}
    >
      <div className="tv-ad-panel-video-placeholder">
        <button
          type="button"
          className="tv-ad-close"
          onClick={onClose}
          aria-label="Close ad panel"
        >
          ✕
        </button>

        <div className="tv-ad-placeholder-center">
          <div className="tv-ad-placeholder-box">
            <div className="tv-ad-placeholder-label">VIDEO AD</div>
            <div className="tv-ad-placeholder-text">AD PLACEHOLDER</div>
          </div>
        </div>
      </div>
    </div>
  );
}

type SettingsPanelProps = {
  isOpen: boolean;
  onOpen: () => void;
  onClose: () => void;
  adMode: AdDisplayMode;
  onAdModeChange: (value: AdDisplayMode) => void;
  onShowNotification: () => void;
  onShowEvent: () => void;
  onShowQuote: () => void;
  onShowAd: (mode: AdDisplayMode) => void;
};

function SettingsPanel({
  isOpen,
  onOpen,
  onClose,
  adMode,
  onAdModeChange,
  onShowNotification,
  onShowEvent,
  onShowQuote,
  onShowAd,
}: SettingsPanelProps) {
  return (
    <>
      <button
        type="button"
        className="floating-settings-button"
        onClick={onOpen}
        aria-label="Open screen settings"
      >
        <span className="floating-settings-icon">⚙</span>
      </button>

      {isOpen && (
        <>
          <div className="settings-overlay" onClick={onClose} />
          <div className="settings-modal">
            <div className="settings-modal-header">
              <div>
                <div className="settings-modal-title">TV Screen Settings</div>
                <div className="settings-modal-subtitle">
                  Choose which state to display next.
                </div>
              </div>

              <button
                type="button"
                className="settings-close-button"
                onClick={onClose}
                aria-label="Close settings"
              >
                ✕
              </button>
            </div>

            <div className="settings-modal-content">
              <button
                type="button"
                className="settings-action-button"
                onClick={onShowEvent}
              >
                Show next event
              </button>

              <button
                type="button"
                className="settings-action-button"
                onClick={onShowNotification}
              >
                Send notification
              </button>

              <div className="settings-field">
                <label htmlFor="ad-mode" className="settings-field-label">
                  Send ad
                </label>
                <select
                  id="ad-mode"
                  className="settings-select"
                  value={adMode}
                  onChange={(e) => {
                    const value = e.target.value as AdDisplayMode;
                    onAdModeChange(value);
                    onShowAd(value);
                  }}
                >
                  <option value={AdDisplayMode.FULL_SCREEN}>FULL_SCREEN</option>
                  <option value={AdDisplayMode.ADS_1_4_H}>ADS_1_4_H</option>
                  <option value={AdDisplayMode.ADS_1_2_H}>ADS_1_2_H</option>
                  <option value={AdDisplayMode.ADS_3_4_H}>ADS_3_4_H</option>
                  <option value={AdDisplayMode.ADS_1_4_V}>ADS_1_4_V</option>
                  <option value={AdDisplayMode.ADS_1_2_V}>ADS_1_2_V</option>
                  <option value={AdDisplayMode.ADS_3_4_V}>ADS_3_4_V</option>
                </select>
              </div>

              <button
                type="button"
                className="settings-action-button"
                onClick={onShowQuote}
              >
                Show quote
              </button>
            </div>
          </div>
        </>
      )}
    </>
  );
}

export type SmartDashboardPageProps = {
  audioTitle?: string | null;
  audioProgressPercent?: number;
  visualSrc?: string | null;
  visualMimeType?: string | null;
  bindingId?: number;
};

export default function SmartDashboardPage({
  audioTitle,
  audioProgressPercent,
  visualSrc,
  visualMimeType,
  bindingId,
}: SmartDashboardPageProps = {}) {
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [adMode, setAdMode] = useState<AdDisplayMode>(AdDisplayMode.FULL_SCREEN);
  const [notification, setNotification] = useState<TvNotification | null>(null);
  const [eventCard, setEventCard] = useState<TvEvent | null>(null);
  const [quote, setQuote] = useState<TvQuote | null>(null);
  const [adPanel, setAdPanel] = useState<TvAdPanel | null>(null);

  const notificationAutoHideRef = useRef<number | null>(null);
  const notificationRemoveRef = useRef<number | null>(null);
  const eventAutoHideRef = useRef<number | null>(null);
  const eventRemoveRef = useRef<number | null>(null);
  const quoteAutoHideRef = useRef<number | null>(null);
  const quoteRemoveRef = useRef<number | null>(null);
  const adAutoHideRef = useRef<number | null>(null);
  const adRemoveRef = useRef<number | null>(null);
  const lastShownMessageIdRef = useRef<number | null>(null);

  const clearNotificationTimers = () => {
    if (notificationAutoHideRef.current) {
      window.clearTimeout(notificationAutoHideRef.current);
      notificationAutoHideRef.current = null;
    }
    if (notificationRemoveRef.current) {
      window.clearTimeout(notificationRemoveRef.current);
      notificationRemoveRef.current = null;
    }
  };

  const clearEventTimers = () => {
    if (eventAutoHideRef.current) {
      window.clearTimeout(eventAutoHideRef.current);
      eventAutoHideRef.current = null;
    }
    if (eventRemoveRef.current) {
      window.clearTimeout(eventRemoveRef.current);
      eventRemoveRef.current = null;
    }
  };

  const clearQuoteTimers = () => {
    if (quoteAutoHideRef.current) {
      window.clearTimeout(quoteAutoHideRef.current);
      quoteAutoHideRef.current = null;
    }
    if (quoteRemoveRef.current) {
      window.clearTimeout(quoteRemoveRef.current);
      quoteRemoveRef.current = null;
    }
  };

  const clearAdTimers = () => {
    if (adAutoHideRef.current) {
      window.clearTimeout(adAutoHideRef.current);
      adAutoHideRef.current = null;
    }
    if (adRemoveRef.current) {
      window.clearTimeout(adRemoveRef.current);
      adRemoveRef.current = null;
    }
  };

  const hideNotification = () => {
    clearNotificationTimers();
    setNotification((prev) => {
      if (!prev) return null;
      return { ...prev, phase: "exiting" };
    });

    notificationRemoveRef.current = window.setTimeout(() => {
      setNotification(null);
      notificationRemoveRef.current = null;
    }, 520);
  };

  const hideEventCard = () => {
    clearEventTimers();
    setEventCard((prev) => {
      if (!prev) return null;
      return { ...prev, phase: "exiting" };
    });

    eventRemoveRef.current = window.setTimeout(() => {
      setEventCard(null);
      eventRemoveRef.current = null;
    }, 560);
  };

  const hideQuote = () => {
    clearQuoteTimers();
    setQuote((prev) => {
      if (!prev) return null;
      return { ...prev, phase: "exiting" };
    });

    quoteRemoveRef.current = window.setTimeout(() => {
      setQuote(null);
      quoteRemoveRef.current = null;
    }, 500);
  };

  const hideAdPanel = () => {
    clearAdTimers();
    setAdPanel((prev) => {
      if (!prev) return null;
      return { ...prev, phase: "exiting" };
    });

    adRemoveRef.current = window.setTimeout(() => {
      setAdPanel(null);
      adRemoveRef.current = null;
    }, 700);
  };

  const showNotificationWithData = useCallback(
    (title: string, description: string, durationMs: number) => {
      clearNotificationTimers();
      clearEventTimers();
      setIsSettingsOpen(false);
      setEventCard(null);

      const nextNotification: TvNotification = {
        id: Date.now(),
        title,
        description,
        phase: "entering",
      };

      setNotification(nextNotification);

      window.setTimeout(() => {
        setNotification((prev) => {
          if (!prev || prev.id !== nextNotification.id) return prev;
          return { ...prev, phase: "visible" };
        });
      }, 30);

      notificationAutoHideRef.current = window.setTimeout(() => {
        hideNotification();
      }, Math.max(2000, durationMs - 500));
    },
    []
  );

  const showNotification = () => {
    showNotificationWithData(
      "Gym notification",
      "Tomorrow’s group class starts at 7:00 PM. Please arrive 15 minutes early for check-in.",
      4500
    );
  };

  useEffect(() => {
    if (!bindingId || bindingId <= 0) return;

    const poll = async () => {
      try {
        const result = await getTvScreenMessages(bindingId, 1);
        const msg = result.rows?.[0];
        if (msg && msg.id !== lastShownMessageIdRef.current) {
          lastShownMessageIdRef.current = msg.id;
          showNotificationWithData(
            msg.title,
            msg.description ?? "",
            (msg.displayDurationSec ?? 5) * 1000
          );
        }
      } catch {
        // ignore polling errors
      }
    };

    poll();
    const id = window.setInterval(poll, 3000);
    return () => window.clearInterval(id);
  }, [bindingId, showNotificationWithData]);

  const showEventCard = () => {
    clearEventTimers();
    clearNotificationTimers();

    setIsSettingsOpen(false);
    setNotification(null);

    const nextEvent: TvEvent = {
      id: Date.now(),
      title: "HIIT Full Body Blast",
      description:
        "A high-energy session mixing cardio intervals and strength rounds to boost endurance and burn calories fast.",
      room: "Studio B",
      coachName: "Coach Sarah",
      startsAt: getFutureDate(1, 25),
      image:
        "https://images.unsplash.com/photo-1517836357463-d25dfeac3438?auto=format&fit=crop&w=1200&q=80",
      phase: "entering",
    };

    setEventCard(nextEvent);

    window.setTimeout(() => {
      setEventCard((prev) => {
        if (!prev || prev.id !== nextEvent.id) return prev;
        return { ...prev, phase: "visible" };
      });
    }, 30);

    eventAutoHideRef.current = window.setTimeout(() => {
      hideEventCard();
    }, 6000);
  };

  const showQuote = () => {
    clearQuoteTimers();
    setIsSettingsOpen(false);

    const nextQuote: TvQuote = {
      id: Date.now(),
      text: "Discipline is choosing between what you want now and what you want most.",
      author: "Abraham Lincoln",
      phase: "entering",
    };

    setQuote(nextQuote);

    window.setTimeout(() => {
      setQuote((prev) => {
        if (!prev || prev.id !== nextQuote.id) return prev;
        return { ...prev, phase: "visible" };
      });
    }, 30);

    quoteAutoHideRef.current = window.setTimeout(() => {
      hideQuote();
    }, 6500);
  };

  const showAdPanel = (mode: AdDisplayMode) => {
    clearAdTimers();
    setIsSettingsOpen(false);

    const nextAd: TvAdPanel = {
      id: Date.now(),
      mode,
      phase: "entering",
    };

    setAdPanel(nextAd);

    window.setTimeout(() => {
      setAdPanel((prev) => {
        if (!prev || prev.id !== nextAd.id) return prev;
        return { ...prev, phase: "visible" };
      });
    }, 30);

    adAutoHideRef.current = window.setTimeout(() => {
      hideAdPanel();
    }, 6000);
  };

  useEffect(() => {
    return () => {
      clearNotificationTimers();
      clearEventTimers();
      clearQuoteTimers();
      clearAdTimers();
    };
  }, []);

  return (
    <>
      <style>{`
        :root {
          --bg: #1e1e1e;
          --text: #f5f5f5;
          --text-soft: rgba(255, 255, 255, 0.8);
          --muted: #d0d0d0;
          --shadow: 0 8px 30px rgba(0, 0, 0, 0.25);
          --background-image: url("https://images.unsplash.com/photo-1483728642387-6c3bdd6c93e5?auto=format&fit=crop&w=2076&q=80");
        }

        * {
          box-sizing: border-box;
          -webkit-tap-highlight-color: transparent;
        }

        html, body, #root {
          width: 100%;
          height: 100%;
          margin: 0;
          overflow: hidden;
        }

        body {
          background: var(--bg);
          font-family: "Rubik", sans-serif;
          user-select: none;
          touch-action: none;
        }

        #app {
          position: relative;
          width: 100vw;
          height: 100vh;
          overflow: hidden;
          background: var(--bg);
        }

        .glass-pill {
          backdrop-filter: blur(8px);
          background: rgba(255, 255, 255, 0.1);
          border: 1px solid rgba(255, 255, 255, 0.12);
          border-radius: 999px;
          box-shadow: var(--shadow);
          color: var(--text);
        }

        #app-background {
          position: absolute;
          inset: 0;
          overflow: hidden;
          z-index: 1;
        }

        #app-background-image {
          width: 100%;
          height: 100%;
          background-image: var(--background-image);
          background-position: center;
          background-repeat: no-repeat;
          background-size: cover;
          transform: scale(1.03);
        }

        #app-menu {
          position: relative;
          z-index: 2;
          width: 100%;
          height: 100%;
        }

        #app-menu-content-wrapper {
          width: 100%;
          height: 100%;
          padding: clamp(18px, 2vw, 30px) clamp(28px, 3vw, 56px);
          background: linear-gradient(
            to bottom,
            rgba(12, 12, 12, 0.1) 0%,
            rgba(18, 18, 18, 0.28) 45%,
            rgba(24, 24, 24, 0.7) 100%
          );
        }

        #app-menu-content {
          width: 100%;
          height: 100%;
          display: flex;
          flex-direction: column;
          justify-content: flex-end;
          gap: clamp(12px, 1.4vh, 18px);
        }

        #app-menu-content-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-end;
          gap: 20px;
          flex: 0 0 auto;
        }

        .app-menu-content-header-section {
          min-width: 0;
        }

        .info-bar {
          display: flex;
          align-items: flex-end;
          gap: 18px;
          flex-wrap: wrap;
        }

        .time-text {
          color: var(--text);
          font-size: clamp(3rem, 6vw, 6rem);
          line-height: 1;
          text-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
          white-space: nowrap;
        }

        .weather-snap {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          margin-bottom: 8px;
          white-space: nowrap;
        }

        .weather-icon {
          font-size: 1rem;
        }

        .weather-temp {
          color: var(--text);
          font-size: clamp(1.2rem, 2vw, 1.6rem);
        }

        .weather-unit {
          color: var(--text);
          font-size: 0.9rem;
          align-self: flex-start;
        }

        .reminder {
          display: inline-flex;
          gap: 8px;
          margin-top: 10px;
          align-items: center;
          flex-wrap: wrap;
          max-width: min(820px, 90%);
        }

        .reminder-text {
          color: rgba(255, 255, 255, 0.86);
          font-size: clamp(0.95rem, 1.5vw, 1.08rem);
        }

        .reminder-time {
          color: #1e1e1e;
          background: rgba(255, 255, 255, 0.88);
          padding: 2px 6px;
          border-radius: 999px;
          font-size: 0.8rem;
        }

        #quick-nav {
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
          align-items: center;
          flex: 0 0 auto;
        }

        .quick-nav-item {
          padding: 10px 18px;
          white-space: nowrap;
          color: var(--text);
          font-size: clamp(0.86rem, 1vw, 0.96rem);
        }

        .menu-section {
          display: flex;
          flex-direction: column;
          justify-content: flex-end;
          flex: 0 0 auto;
        }

        .weather-section-shell {
          width: min(100%, 720px);
        }

        .menu-section-title {
          display: flex;
          align-items: center;
          gap: 8px;
          color: var(--text);
          flex: 0 0 auto;
          margin-bottom: 8px;
        }

        .menu-section-title-text {
          color: var(--text-soft);
          font-size: clamp(0.96rem, 1.3vw, 1.1rem);
        }

        .weather-grid {
          display: grid;
          grid-template-columns: repeat(7, minmax(104px, 78px));
          gap: 8px;
          align-items: end;
          justify-content: start;
        }

        .day-card {
          min-width: 0;
          aspect-ratio: 1 / 1;
          border-radius: 14px;
          background:
            linear-gradient(180deg, rgba(255, 255, 255, 0.13), rgba(255, 255, 255, 0.07)),
            rgba(255, 255, 255, 0.08);
          border: 1px solid rgba(255, 255, 255, 0.12);
          box-shadow:
            0 8px 18px rgba(0, 0, 0, 0.18),
            inset 0 1px 0 rgba(255, 255, 255, 0.07);
          backdrop-filter: blur(10px);
          overflow: hidden;
        }

        .day-card-content {
          width: 100%;
          height: 100%;
          padding: 8px 6px;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: space-between;
          text-align: center;
          gap: 4px;
        }

        .day-weather-temperature,
        .day-name {
          color: var(--text);
        }

        .day-weather-temperature {
          font-size: clamp(0.82rem, 0.95vw, 0.95rem);
          font-weight: 700;
        }

        .day-weather-temperature-unit {
          font-size: 0.66em;
          margin-left: 1px;
        }

        .day-weather-icon {
          font-size: clamp(1.15rem, 1.45vw, 1.45rem);
          line-height: 1;
        }

        .day-name {
          font-size: clamp(0.62rem, 0.72vw, 0.72rem);
          font-weight: 600;
          letter-spacing: 0.04em;
        }

        .floating-settings-button {
          position: fixed;
          left: 18px;
          top: 50%;
          transform: translateY(-50%);
          z-index: 99999;
          width: 62px;
          height: 62px;
          border: 1px solid rgba(255, 255, 255, 0.16);
          border-radius: 999px;
          background: rgba(20, 20, 20, 0.65);
          backdrop-filter: blur(14px);
          color: white;
          box-shadow: 0 16px 40px rgba(0, 0, 0, 0.38);
          cursor: pointer;
          transition: transform 0.25s ease, background 0.25s ease, border-color 0.25s ease;
        }

        .floating-settings-button:hover {
          background: rgba(35, 35, 35, 0.82);
          border-color: rgba(255, 255, 255, 0.28);
          transform: translateY(-50%) scale(1.04);
        }

        .floating-settings-icon {
          display: inline-block;
          font-size: 1.7rem;
          line-height: 1;
        }

        .settings-overlay {
          position: fixed;
          inset: 0;
          z-index: 99998;
          background: rgba(0, 0, 0, 0.4);
          backdrop-filter: blur(4px);
        }

        .settings-modal {
          position: fixed;
          left: 95px;
          top: 50%;
          transform: translateY(-50%);
          z-index: 99999;
          width: min(420px, calc(100vw - 130px));
          border-radius: 22px;
          padding: 20px;
          background: rgba(18, 18, 18, 0.9);
          border: 1px solid rgba(255, 255, 255, 0.12);
          box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
          backdrop-filter: blur(18px);
          color: white;
        }

        .settings-modal-header {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          gap: 16px;
          margin-bottom: 18px;
        }

        .settings-modal-title {
          font-size: 1.2rem;
          font-weight: 600;
          color: white;
        }

        .settings-modal-subtitle {
          margin-top: 4px;
          font-size: 0.9rem;
          color: rgba(255, 255, 255, 0.72);
        }

        .settings-close-button {
          width: 38px;
          height: 38px;
          border: none;
          border-radius: 12px;
          background: rgba(255, 255, 255, 0.08);
          color: white;
          cursor: pointer;
          transition: background 0.2s ease;
        }

        .settings-close-button:hover {
          background: rgba(255, 255, 255, 0.14);
        }

        .settings-modal-content {
          display: flex;
          flex-direction: column;
          gap: 14px;
        }

        .settings-action-button {
          width: 100%;
          min-height: 52px;
          border: 1px solid rgba(255, 255, 255, 0.12);
          border-radius: 14px;
          background: rgba(255, 255, 255, 0.07);
          color: white;
          font-size: 0.98rem;
          font-weight: 500;
          text-align: left;
          padding: 0 16px;
          cursor: pointer;
          transition: background 0.2s ease, border-color 0.2s ease, transform 0.2s ease;
        }

        .settings-action-button:hover {
          background: rgba(255, 255, 255, 0.12);
          border-color: rgba(255, 255, 255, 0.22);
          transform: translateY(-1px);
        }

        .settings-field {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .settings-field-label {
          font-size: 0.95rem;
          font-weight: 500;
          color: rgba(255, 255, 255, 0.88);
        }

        .settings-select {
          width: 100%;
          min-height: 52px;
          border: 1px solid rgba(255, 255, 255, 0.12);
          border-radius: 14px;
          background: rgba(255, 255, 255, 0.07);
          color: white;
          padding: 0 14px;
          font-size: 0.96rem;
          outline: none;
        }

        .settings-select option {
          background: #1f1f1f;
          color: white;
        }

        .settings-select:focus {
          border-color: rgba(255, 255, 255, 0.35);
        }

        .tv-notification {
          position: fixed;
          top: 22px;
          right: 22px;
          z-index: 99997;
          width: min(420px, calc(100vw - 32px));
          display: flex;
          gap: 14px;
          padding: 16px;
          border-radius: 24px;
          overflow: hidden;
          background:
            linear-gradient(135deg, rgba(27, 54, 46, 0.96), rgba(12, 28, 24, 0.95)),
            rgba(20, 20, 20, 0.82);
          border: 1px solid rgba(173, 255, 225, 0.12);
          box-shadow:
            0 24px 60px rgba(0, 0, 0, 0.42),
            inset 0 1px 0 rgba(255, 255, 255, 0.05);
          backdrop-filter: blur(18px);
          transform-origin: top right;
        }

        .tv-notification--entering,
        .tv-notification--visible {
          animation: notification-in 0.78s cubic-bezier(0.22, 1, 0.36, 1) forwards;
        }

        .tv-notification--exiting {
          animation: notification-out 0.58s cubic-bezier(0.4, 0, 0.2, 1) forwards;
        }

        .tv-notification-glow {
          position: absolute;
          inset: auto auto -70px -40px;
          width: 220px;
          height: 220px;
          border-radius: 999px;
          background: radial-gradient(circle, rgba(115, 255, 208, 0.22), transparent 70%);
          pointer-events: none;
        }

        .tv-notification-icon-wrap {
          position: relative;
          z-index: 1;
          flex-shrink: 0;
          width: 58px;
          height: 58px;
          display: grid;
          place-items: center;
          border-radius: 18px;
          background: linear-gradient(135deg, rgba(125, 255, 212, 0.18), rgba(83, 208, 167, 0.06));
          border: 1px solid rgba(168, 255, 226, 0.18);
          box-shadow:
            inset 0 1px 0 rgba(255, 255, 255, 0.08),
            0 10px 24px rgba(50, 160, 125, 0.16);
        }

        .tv-notification-icon {
          font-size: 1.55rem;
          line-height: 1;
        }

        .tv-notification-content {
          position: relative;
          z-index: 1;
          min-width: 0;
          flex: 1;
        }

        .tv-notification-top-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
        }

        .tv-notification-badge {
          display: inline-flex;
          align-items: center;
          height: 28px;
          padding: 0 12px;
          border-radius: 999px;
          background: rgba(255, 255, 255, 0.07);
          border: 1px solid rgba(255, 255, 255, 0.06);
          color: rgba(236, 255, 248, 0.88);
          font-size: 0.78rem;
          font-weight: 600;
          letter-spacing: 0.04em;
          text-transform: uppercase;
        }

        .tv-notification-close,
        .tv-event-card-close,
        .tv-quote-close,
        .tv-ad-close {
          width: 34px;
          height: 34px;
          border: none;
          border-radius: 12px;
          background: rgba(255, 255, 255, 0.08);
          color: rgba(255, 255, 255, 0.9);
          cursor: pointer;
          transition: background 0.2s ease, transform 0.2s ease;
        }

        .tv-notification-close:hover,
        .tv-event-card-close:hover,
        .tv-quote-close:hover,
        .tv-ad-close:hover {
          background: rgba(255, 255, 255, 0.14);
          transform: scale(1.03);
        }

        .tv-notification-title {
          margin-top: 12px;
          color: white;
          font-size: 1.15rem;
          font-weight: 700;
          line-height: 1.25;
        }

        .tv-notification-description {
          margin-top: 8px;
          color: rgba(236, 255, 248, 0.76);
          font-size: 0.95rem;
          line-height: 1.55;
        }

        .tv-notification-progress {
          margin-top: 14px;
          width: 100%;
          height: 5px;
          border-radius: 999px;
          overflow: hidden;
          background: rgba(255, 255, 255, 0.08);
        }

        .tv-notification-progress-bar {
          height: 100%;
          width: 100%;
          transform-origin: left center;
          background: linear-gradient(90deg, #7dffd4, #c9fff0);
          animation: notification-progress 4.5s linear forwards;
        }

        .tv-event-card {
          position: fixed;
          top: 22px;
          right: 22px;
          z-index: 99996;
          width: min(560px, calc(100vw - 32px));
          min-height: 210px;
          display: flex;
          gap: 18px;
          padding: 16px;
          border-radius: 28px;
          overflow: hidden;
          background:
            linear-gradient(140deg, rgba(70, 43, 23, 0.96), rgba(34, 18, 10, 0.96)),
            rgba(20, 20, 20, 0.82);
          border: 1px solid rgba(255, 214, 176, 0.12);
          box-shadow:
            0 28px 70px rgba(0, 0, 0, 0.45),
            inset 0 1px 0 rgba(255, 255, 255, 0.05);
          backdrop-filter: blur(20px);
          transform-origin: top right;
        }

        .tv-event-card--entering,
        .tv-event-card--visible {
          animation: event-card-in 0.82s cubic-bezier(0.22, 1, 0.36, 1) forwards;
        }

        .tv-event-card--exiting {
          animation: event-card-out 0.6s cubic-bezier(0.4, 0, 0.2, 1) forwards;
        }

        .tv-event-card-glow {
          position: absolute;
          right: -40px;
          top: -50px;
          width: 230px;
          height: 230px;
          border-radius: 999px;
          background: radial-gradient(circle, rgba(255, 182, 107, 0.18), transparent 72%);
          pointer-events: none;
        }

        .tv-event-card-image {
          position: relative;
          z-index: 1;
          width: 160px;
          min-width: 160px;
          border-radius: 22px;
          background-position: center;
          background-repeat: no-repeat;
          background-size: cover;
          box-shadow:
            0 14px 28px rgba(0, 0, 0, 0.28),
            inset 0 0 0 1px rgba(255, 255, 255, 0.06);
        }

        .tv-event-card-content {
          position: relative;
          z-index: 1;
          min-width: 0;
          flex: 1;
          display: flex;
          flex-direction: column;
        }

        .tv-event-card-top-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
        }

        .tv-event-card-badge {
          display: inline-flex;
          align-items: center;
          height: 30px;
          padding: 0 12px;
          border-radius: 999px;
          background: rgba(255, 255, 255, 0.08);
          border: 1px solid rgba(255, 255, 255, 0.06);
          color: rgba(255, 240, 227, 0.9);
          font-size: 0.78rem;
          font-weight: 700;
          letter-spacing: 0.05em;
          text-transform: uppercase;
        }

        .tv-event-card-title {
          margin-top: 12px;
          color: white;
          font-size: 1.22rem;
          font-weight: 800;
          line-height: 1.25;
        }

        .tv-event-card-description {
          margin-top: 10px;
          color: rgba(255, 238, 227, 0.76);
          font-size: 0.95rem;
          line-height: 1.52;
          display: -webkit-box;
          -webkit-line-clamp: 2;
          -webkit-box-orient: vertical;
          overflow: hidden;
        }

        .tv-event-details {
          margin-top: 14px;
          display: grid;
          gap: 8px;
        }

        .tv-event-detail-row {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 10px 12px;
          border-radius: 16px;
          background: rgba(255, 255, 255, 0.06);
          border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .tv-event-detail-icon {
          width: 36px;
          height: 36px;
          display: grid;
          place-items: center;
          border-radius: 12px;
          background: rgba(255, 255, 255, 0.08);
          font-size: 1rem;
          flex-shrink: 0;
        }

        .tv-event-detail-body {
          min-width: 0;
        }

        .tv-event-detail-label {
          color: rgba(255, 238, 227, 0.58);
          font-size: 0.72rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.06em;
        }

        .tv-event-detail-value {
          margin-top: 3px;
          color: rgba(255, 249, 244, 0.94);
          font-size: 0.92rem;
          font-weight: 600;
          line-height: 1.35;
        }

        .tv-event-card-progress {
          margin-top: auto;
          padding-top: 14px;
          width: 100%;
          height: 20px;
          display: flex;
          align-items: flex-end;
        }

        .tv-event-card-progress-bar {
          width: 100%;
          height: 5px;
          border-radius: 999px;
          transform-origin: left center;
          background: linear-gradient(90deg, #ffb66b, #ffe0b8);
          animation: event-card-progress 6s linear forwards;
        }

        .tv-quote-banner {
          position: fixed;
          top: 26px;
          left: 50%;
          z-index: 99995;
          width: min(760px, calc(100vw - 40px));
          padding: 18px 22px;
          border-radius: 24px;
          background:
            linear-gradient(135deg, rgba(48, 33, 58, 0.96), rgba(22, 14, 28, 0.95)),
            rgba(20, 20, 20, 0.82);
          border: 1px solid rgba(228, 191, 255, 0.12);
          box-shadow:
            0 24px 64px rgba(0, 0, 0, 0.42),
            inset 0 1px 0 rgba(255, 255, 255, 0.05);
          backdrop-filter: blur(18px);
          transform-origin: top center;
        }

        .tv-quote-banner--entering,
        .tv-quote-banner--visible {
          animation: quote-in 0.8s cubic-bezier(0.22, 1, 0.36, 1) forwards;
        }

        .tv-quote-banner--exiting {
          animation: quote-out 0.56s cubic-bezier(0.4, 0, 0.2, 1) forwards;
        }

        .tv-quote-banner-glow {
          position: absolute;
          top: -70px;
          left: 50%;
          transform: translateX(-50%);
          width: 260px;
          height: 180px;
          border-radius: 999px;
          background: radial-gradient(circle, rgba(209, 149, 255, 0.2), transparent 72%);
          pointer-events: none;
        }

        .tv-quote-top-row {
          position: relative;
          z-index: 1;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
        }

        .tv-quote-badge {
          display: inline-flex;
          align-items: center;
          height: 28px;
          padding: 0 12px;
          border-radius: 999px;
          background: rgba(255, 255, 255, 0.08);
          border: 1px solid rgba(255, 255, 255, 0.06);
          color: rgba(248, 236, 255, 0.9);
          font-size: 0.78rem;
          font-weight: 600;
          letter-spacing: 0.04em;
          text-transform: uppercase;
        }

        .tv-quote-text {
          position: relative;
          z-index: 1;
          margin-top: 14px;
          color: white;
          font-size: clamp(1rem, 1.5vw, 1.18rem);
          line-height: 1.55;
          text-align: center;
          font-weight: 600;
        }

        .tv-quote-author {
          position: relative;
          z-index: 1;
          margin-top: 10px;
          color: rgba(248, 236, 255, 0.72);
          font-size: 0.9rem;
          text-align: center;
          letter-spacing: 0.03em;
        }

        .tv-ad-panel {
          position: fixed;
          z-index: 99994;
          overflow: hidden;
          background: #000000;
          box-shadow: 0 28px 80px rgba(0, 0, 0, 0.5);
        }

        .tv-ad-panel--full-screen {
          inset: 0;
        }

        .tv-ad-panel--horizontal {
          top: 0;
          right: 0;
          bottom: 0;
          border-top-left-radius: 28px;
          border-bottom-left-radius: 28px;
        }

        .tv-ad-panel--vertical {
          top: 0;
          left: 0;
          right: 0;
          border-bottom-left-radius: 28px;
          border-bottom-right-radius: 28px;
        }

        .tv-ad-panel--ads_1_4_h {
          width: 25vw;
          min-width: 300px;
        }

        .tv-ad-panel--ads_1_2_h {
          width: 50vw;
          min-width: 400px;
        }

        .tv-ad-panel--ads_3_4_h {
          width: 75vw;
          min-width: 500px;
        }

        .tv-ad-panel--ads_1_4_v {
          height: 25vh;
          min-height: 190px;
        }

        .tv-ad-panel--ads_1_2_v {
          height: 50vh;
          min-height: 280px;
        }

        .tv-ad-panel--ads_3_4_v {
          height: 75vh;
          min-height: 360px;
        }

        .tv-ad-panel--full-screen.tv-ad-panel--entering,
        .tv-ad-panel--full-screen.tv-ad-panel--visible {
          animation: ad-fade-in 0.9s cubic-bezier(0.22, 1, 0.36, 1) forwards;
        }

        .tv-ad-panel--full-screen.tv-ad-panel--exiting {
          animation: ad-fade-out 0.68s cubic-bezier(0.4, 0, 0.2, 1) forwards;
        }

        .tv-ad-panel--horizontal.tv-ad-panel--entering,
        .tv-ad-panel--horizontal.tv-ad-panel--visible {
          animation: ad-horizontal-in 0.95s cubic-bezier(0.22, 1, 0.36, 1) forwards;
        }

        .tv-ad-panel--horizontal.tv-ad-panel--exiting {
          animation: ad-horizontal-out 0.72s cubic-bezier(0.4, 0, 0.2, 1) forwards;
        }

        .tv-ad-panel--vertical.tv-ad-panel--entering,
        .tv-ad-panel--vertical.tv-ad-panel--visible {
          animation: ad-vertical-in 0.95s cubic-bezier(0.22, 1, 0.36, 1) forwards;
        }

        .tv-ad-panel--vertical.tv-ad-panel--exiting {
          animation: ad-vertical-out 0.72s cubic-bezier(0.4, 0, 0.2, 1) forwards;
        }

        .tv-ad-panel-video-placeholder {
          position: relative;
          width: 100%;
          height: 100%;
          background: #000000;
        }

        .tv-ad-placeholder-center {
          position: absolute;
          inset: 0;
          display: grid;
          place-items: center;
          padding: 30px;
        }

        .tv-ad-placeholder-box {
          padding: 26px 34px;
          border-radius: 24px;
          border: 1px solid rgba(255, 255, 255, 0.08);
          background: rgba(255, 255, 255, 0.03);
          text-align: center;
          backdrop-filter: blur(6px);
        }

        .tv-ad-placeholder-label {
          color: rgba(255, 255, 255, 0.46);
          font-size: 0.82rem;
          font-weight: 700;
          letter-spacing: 0.14em;
          text-transform: uppercase;
        }

        .tv-ad-placeholder-text {
          margin-top: 10px;
          color: rgba(255, 255, 255, 0.95);
          font-size: clamp(1.25rem, 2.6vw, 2.5rem);
          font-weight: 800;
          letter-spacing: 0.06em;
        }

        .tv-ad-close {
          position: absolute;
          top: 18px;
          right: 18px;
          z-index: 1;
        }

        @keyframes notification-in {
          0% {
            opacity: 0;
            transform: translate3d(54px, -18px, 0) scale(0.94);
            filter: blur(10px);
          }
          55% {
            opacity: 1;
            transform: translate3d(-3px, 2px, 0) scale(1.005);
            filter: blur(0);
          }
          100% {
            opacity: 1;
            transform: translate3d(0, 0, 0) scale(1);
            filter: blur(0);
          }
        }

        @keyframes notification-out {
          0% {
            opacity: 1;
            transform: translate3d(0, 0, 0) scale(1);
            filter: blur(0);
          }
          100% {
            opacity: 0;
            transform: translate3d(52px, -10px, 0) scale(0.96);
            filter: blur(8px);
          }
        }

        @keyframes notification-progress {
          0% {
            transform: scaleX(1);
          }
          100% {
            transform: scaleX(0);
          }
        }

        @keyframes event-card-in {
          0% {
            opacity: 0;
            transform: translate3d(62px, -18px, 0) scale(0.95);
            filter: blur(10px);
          }
          55% {
            opacity: 1;
            transform: translate3d(-3px, 2px, 0) scale(1.005);
            filter: blur(0);
          }
          100% {
            opacity: 1;
            transform: translate3d(0, 0, 0) scale(1);
            filter: blur(0);
          }
        }

        @keyframes event-card-out {
          0% {
            opacity: 1;
            transform: translate3d(0, 0, 0) scale(1);
            filter: blur(0);
          }
          100% {
            opacity: 0;
            transform: translate3d(58px, -12px, 0) scale(0.96);
            filter: blur(8px);
          }
        }

        @keyframes event-card-progress {
          0% {
            transform: scaleX(1);
          }
          100% {
            transform: scaleX(0);
          }
        }

        @keyframes quote-in {
          0% {
            opacity: 0;
            transform: translate(-50%, -24px) scale(0.95);
            filter: blur(10px);
          }
          55% {
            opacity: 1;
            transform: translate(-50%, 2px) scale(1.005);
            filter: blur(0);
          }
          100% {
            opacity: 1;
            transform: translate(-50%, 0) scale(1);
            filter: blur(0);
          }
        }

        @keyframes quote-out {
          0% {
            opacity: 1;
            transform: translate(-50%, 0) scale(1);
            filter: blur(0);
          }
          100% {
            opacity: 0;
            transform: translate(-50%, -14px) scale(0.97);
            filter: blur(8px);
          }
        }

        @keyframes ad-horizontal-in {
          0% {
            opacity: 0;
            transform: translateX(100%) scale(0.99);
            filter: blur(12px);
          }
          58% {
            opacity: 1;
            transform: translateX(-4px) scale(1);
            filter: blur(0);
          }
          100% {
            opacity: 1;
            transform: translateX(0) scale(1);
            filter: blur(0);
          }
        }

        @keyframes ad-horizontal-out {
          0% {
            opacity: 1;
            transform: translateX(0) scale(1);
            filter: blur(0);
          }
          100% {
            opacity: 0;
            transform: translateX(100%) scale(0.99);
            filter: blur(10px);
          }
        }

        @keyframes ad-vertical-in {
          0% {
            opacity: 0;
            transform: translateY(-100%) scale(0.99);
            filter: blur(12px);
          }
          58% {
            opacity: 1;
            transform: translateY(4px) scale(1);
            filter: blur(0);
          }
          100% {
            opacity: 1;
            transform: translateY(0) scale(1);
            filter: blur(0);
          }
        }

        @keyframes ad-vertical-out {
          0% {
            opacity: 1;
            transform: translateY(0) scale(1);
            filter: blur(0);
          }
          100% {
            opacity: 0;
            transform: translateY(-100%) scale(0.99);
            filter: blur(10px);
          }
        }

        @keyframes ad-fade-in {
          0% {
            opacity: 0;
            transform: scale(1.02);
            filter: blur(12px);
          }
          100% {
            opacity: 1;
            transform: scale(1);
            filter: blur(0);
          }
        }

        @keyframes ad-fade-out {
          0% {
            opacity: 1;
            transform: scale(1);
            filter: blur(0);
          }
          100% {
            opacity: 0;
            transform: scale(1.01);
            filter: blur(10px);
          }
        }

        @media (max-aspect-ratio: 16/9) {
          .weather-grid {
            grid-template-columns: repeat(7, minmax(64px, 78px));
          }
        }

        @media (max-width: 1200px) {
          #app-menu-content-wrapper {
            padding: 18px 28px;
          }

          .weather-grid {
            gap: 8px;
            grid-template-columns: repeat(7, minmax(58px, 72px));
          }

          .weather-section-shell {
            width: min(100%, 850px);
          }
        }

        @media (max-width: 900px) {
          .weather-grid {
            grid-template-columns: repeat(4, minmax(58px, 70px));
          }

          .tv-event-card {
            width: min(520px, calc(100vw - 28px));
          }

          .tv-event-card-image {
            width: 140px;
            min-width: 140px;
          }

          .tv-ad-panel--ads_1_4_h {
            min-width: 240px;
          }

          .tv-ad-panel--ads_1_2_h {
            min-width: 300px;
          }

          .tv-ad-panel--ads_3_4_h {
            min-width: 360px;
          }
        }

        @media (max-width: 700px) {
          #app-menu-content-wrapper {
            padding: 14px 16px;
          }

          .floating-settings-button {
            left: 12px;
            width: 54px;
            height: 54px;
          }

          .settings-modal {
            left: 16px;
            right: 16px;
            top: auto;
            bottom: 16px;
            transform: none;
            width: auto;
          }

          .time-text {
            font-size: 2.8rem;
          }

          .weather-grid {
            grid-template-columns: repeat(3, minmax(56px, 68px));
          }

          .tv-notification,
          .tv-event-card {
            top: 14px;
            right: 14px;
            left: 14px;
            width: auto;
          }

          .tv-event-card {
            flex-direction: column;
          }

          .tv-event-card-image {
            width: 100%;
            min-width: 100%;
            height: 150px;
          }

          .tv-quote-banner {
            top: 14px;
            width: calc(100vw - 28px);
          }

          .tv-ad-panel--ads_1_4_h,
          .tv-ad-panel--ads_1_2_h,
          .tv-ad-panel--ads_3_4_h {
            width: min(82vw, 320px);
            min-width: 0;
          }

          .tv-ad-panel--ads_1_4_v {
            height: 25vh;
            min-height: 160px;
          }

          .tv-ad-panel--ads_1_2_v {
            height: 45vh;
            min-height: 220px;
          }

          .tv-ad-panel--ads_3_4_v {
            height: 65vh;
            min-height: 300px;
          }
        }

        @media (max-width: 520px) {
          .weather-grid {
            grid-template-columns: repeat(2, minmax(54px, 66px));
          }

          .day-card-content {
            padding: 6px;
          }

          .day-weather-icon {
            font-size: 1.05rem;
          }

          .day-weather-temperature {
            font-size: 0.78rem;
          }

          .day-name {
            font-size: 0.58rem;
          }
        }
      `}</style>

      <div id="app">
        <Background visualSrc={visualSrc} visualMimeType={visualMimeType} />

        <SettingsPanel
          isOpen={isSettingsOpen}
          onOpen={() => setIsSettingsOpen(true)}
          onClose={() => setIsSettingsOpen(false)}
          adMode={adMode}
          onAdModeChange={setAdMode}
          onShowNotification={showNotification}
          onShowEvent={showEventCard}
          onShowQuote={showQuote}
          onShowAd={showAdPanel}
        />

        <NotificationToast notification={notification} onClose={hideNotification} />
        <EventCardToast event={eventCard} onClose={hideEventCard} />
        <QuoteBanner quote={quote} onClose={hideQuote} />
        <AdPanel adPanel={adPanel} onClose={hideAdPanel} />

        <div id="app-menu">
          <div id="app-menu-content-wrapper">
            <div id="app-menu-content">
              <div id="app-menu-content-header">
                <div className="app-menu-content-header-section">
                  <Info id="app-menu-info" />
                  <Reminder />
                </div>
              </div>

              <QuickNav />
              <WeatherSection />
            </div>
          </div>
        </div>

        {audioTitle && (
          <div
            style={{
              position: "fixed",
              bottom: 24,
              right: 24,
              zIndex: 100,
              background: "rgba(0,0,0,0.65)",
              backdropFilter: "blur(12px)",
              WebkitBackdropFilter: "blur(12px)",
              borderRadius: 16,
              padding: "12px 18px",
              minWidth: 220,
              maxWidth: 320,
              boxShadow: "0 8px 30px rgba(0,0,0,0.35)",
            }}
          >
            <div
              style={{
                fontSize: "0.72rem",
                color: "rgba(255,255,255,0.55)",
                marginBottom: 4,
                textTransform: "uppercase",
                letterSpacing: "0.08em",
              }}
            >
              ♪ Now playing
            </div>
            <div
              style={{
                fontSize: "0.95rem",
                fontWeight: 600,
                color: "#fff",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {audioTitle}
            </div>
            <div
              style={{
                marginTop: 8,
                height: 3,
                borderRadius: 999,
                background: "rgba(255,255,255,0.18)",
              }}
            >
              <div
                style={{
                  height: "100%",
                  width: `${Math.max(0, Math.min(100, audioProgressPercent ?? 0))}%`,
                  background: "linear-gradient(90deg,#7dffd4,#c9fff0)",
                  borderRadius: 999,
                  transition: "width 1s linear",
                }}
              />
            </div>
          </div>
        )}
      </div>
    </>
  );
}