import React, { useEffect, useMemo, useState } from "react";

type IconProps = {
  size?: number;
  strokeWidth?: number;
  color?: string;
};

type AdMode =
  | "none"
  | "full screen"
  | "1/4_H"
  | "2/4_H"
  | "3/4_H"
  | "1/4_V"
  | "2/4_V"
  | "3/4_V";

type EventItem = {
  title: string;
  description: string;
  remaining: string;
  coach: string;
  room: string;
  image: string;
  tag: string;
  accent: string;
};

type QuoteItem = {
  text: string;
  author: string;
  mood: string;
};

function Svg({
  children,
  size = 20,
  strokeWidth = 1.8,
  color = "currentColor",
  viewBox = "0 0 24 24",
}: {
  children: React.ReactNode;
  size?: number;
  strokeWidth?: number;
  color?: string;
  viewBox?: string;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox={viewBox}
      fill="none"
      stroke={color}
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

const SettingsIcon = ({ size, color }: IconProps) => (
  <Svg size={size} color={color}>
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1 1 0 0 0 .2 1.1l.1.1a2 2 0 0 1-2.8 2.8l-.1-.1a1 1 0 0 0-1.1-.2 1 1 0 0 0-.6.9V20a2 2 0 1 1-4 0v-.1a1 1 0 0 0-.6-.9 1 1 0 0 0-1.1.2l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1 1 0 0 0 .2-1.1 1 1 0 0 0-.9-.6H4a2 2 0 1 1 0-4h.1a1 1 0 0 0 .9-.6 1 1 0 0 0-.2-1.1l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1 1 0 0 0 1.1.2 1 1 0 0 0 .6-.9V4a2 2 0 1 1 4 0v.1a1 1 0 0 0 .6.9 1 1 0 0 0 1.1-.2l.1-.1a2 2 0 0 1 2.8 2.8l-.1.1a1 1 0 0 0-.2 1.1 1 1 0 0 0 .9.6H20a2 2 0 1 1 0 4h-.1a1 1 0 0 0-.9.6Z" />
  </Svg>
);

const QuoteIcon = ({ size, color }: IconProps) => (
  <Svg size={size} color={color}>
    <path d="M9 8H6a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h1v2l3-2.5V10a2 2 0 0 0-2-2Z" />
    <path d="M18 8h-3a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h1v2l3-2.5V10a2 2 0 0 0-2-2Z" />
  </Svg>
);

const PlayFilledIcon = ({ size = 18, color = "currentColor" }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill={color} aria-hidden="true">
    <path d="M8 6.5v11l9-5.5-9-5.5Z" />
  </svg>
);

const PauseFilledIcon = ({ size = 22, color = "currentColor" }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill={color} aria-hidden="true">
    <path d="M7 6h4v12H7zM13 6h4v12h-4z" />
  </svg>
);

const PrevFilledIcon = ({ size = 18, color = "currentColor" }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill={color} aria-hidden="true">
    <path d="M18 7v10h-2V7h2ZM6 12l8 5V7l-8 5Z" />
  </svg>
);

const NextFilledIcon = ({ size = 18, color = "currentColor" }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill={color} aria-hidden="true">
    <path d="M6 7v10h2V7H6Zm4 5 8 5V7l-8 5Z" />
  </svg>
);

function AdPlaceholder({
  title = "AD PLACEHOLDER",
  subtitle = "Future ad video area",
  compact = false,
}: {
  title?: string;
  subtitle?: string;
  compact?: boolean;
}) {
  return (
    <div className={`ad-placeholder ${compact ? "compact" : ""}`}>
      <div className="ad-placeholder-inner">
        <p className="ad-label">Advertisement</p>
        <h2 className="ad-title">{title}</h2>
        <p className="ad-subtitle">{subtitle}</p>
      </div>
    </div>
  );
}

function EventCarousel({
  events,
  eventIndex,
  setEventIndex,
  notificationVisible,
  compact = false,
}: {
  events: EventItem[];
  eventIndex: number;
  setEventIndex: React.Dispatch<React.SetStateAction<number>>;
  notificationVisible: boolean;
  compact?: boolean;
}) {
  const currentEvent = events[eventIndex];

  const goPrev = () => {
    setEventIndex((prev) => (prev === 0 ? events.length - 1 : prev - 1));
  };

  const goNext = () => {
    setEventIndex((prev) => (prev === events.length - 1 ? 0 : prev + 1));
  };

  return (
    <div
      className={`event-card card ${compact ? "compact" : ""}`}
      style={{ background: currentEvent.accent }}
    >
      <div className="event-card-overlay" />
      <div className="event-card-blur-a" />
      <div className="event-card-blur-b" />

      <div className="event-card-content">
        <div className="top-row">
          <div className="pill-dark">
            <span className="dot" />
            {notificationVisible ? "Notification" : "Event carousel"}
          </div>

          <div className="event-actions">
            <div className="pill-light">{notificationVisible ? "Live alert" : currentEvent.tag}</div>

            {!notificationVisible && !compact && (
              <>
                <button className="round-btn" type="button" onClick={goPrev} aria-label="Previous event">
                  <PrevFilledIcon size={18} color="#ffffff" />
                </button>
                <button className="round-btn" type="button" onClick={goNext} aria-label="Next event">
                  <NextFilledIcon size={18} color="#ffffff" />
                </button>
              </>
            )}
          </div>
        </div>

        {notificationVisible ? (
          <div className="event-notification-wrap">
            <div className="event-notification-box">
              <p className="section-kicker">Gym notification</p>
              <h2 className="notification-title">Hydration reminder</h2>
              <p className="notification-text">
                Stay hydrated, control your breathing, and prepare for the next class. This notification
                stays visible for 5 seconds, then the event carousel returns automatically.
              </p>

              <div className="chips">
                <span className="chip-primary">Visible for 5s</span>
                <span className="chip-secondary">Triggered from settings</span>
              </div>
            </div>
          </div>
        ) : (
          <div className={`event-main-grid ${compact ? "compact" : ""}`}>
            <div className="event-info-panel">
              <p className="section-kicker">Room • {currentEvent.room}</p>
              <h2 className="event-title">{currentEvent.title}</h2>
              <p className="event-description">{currentEvent.description}</p>

              <div className="chips">
                <span className="chip-primary">{currentEvent.remaining}</span>
                <span className="chip-secondary">{currentEvent.coach}</span>
                <span className="chip-secondary">Room: {currentEvent.room}</span>
              </div>
            </div>

            <div className="event-image-card">
              <img src={currentEvent.image} alt={currentEvent.title} className="event-image" />
              <div className="event-image-overlay" />
              <div className="event-image-footer">
                <p className="event-image-kicker">Event visual</p>
                <p className="event-image-title">{currentEvent.title}</p>
              </div>
            </div>
          </div>
        )}

        {!compact && (
          <div className="event-footer">
            <div>
              <p className="footer-title">{notificationVisible ? "Attention" : "Upcoming Events"}</p>
              <p className="footer-subtitle">
                {notificationVisible
                  ? "Temporary notification overlay before returning to the event carousel"
                  : "Title, image, description, time left, coach, and room"}
              </p>
            </div>

            {!notificationVisible && (
              <div className="dots-row">
                {events.map((event, index) => (
                  <button
                    key={event.title}
                    type="button"
                    onClick={() => setEventIndex(index)}
                    className={`carousel-dot ${index === eventIndex ? "active" : ""}`}
                    aria-label={`Go to ${event.title}`}
                  />
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function ModeCard() {
  return (
    <div className="mode-card card">
      <div className="mode-card-inner">
        <div className="mode-pill">
          <span className="dot" />
          Combined mode card
        </div>
        <p className="mode-text">ANOTHER ONE</p>
        <p className="mode-subtext">Merged replacement for Sport time and Monster Mode</p>
      </div>
    </div>
  );
}

function QuoteCard({ quote, compact = false }: { quote: QuoteItem; compact?: boolean }) {
  return (
    <div className={`quote-card card ${compact ? "compact" : ""}`}>
      <div className="quote-top">
        <div className="quote-badge">
          <QuoteIcon size={16} color="rgba(255,255,255,0.92)" />
          Gym quote
        </div>
        <div className="quote-meta">Auto change • 15s</div>
      </div>

      <div className="quote-body">
        <p className="quote-text">“{quote.text}”</p>
      </div>

      <div className="quote-footer">
        <p className="quote-author">{quote.author}</p>
        <div className="quote-badge">{quote.mood}</div>
      </div>
    </div>
  );
}

function VideoCard({ showAdInside = false, compact = false }: { showAdInside?: boolean; compact?: boolean }) {
  return (
    <div className={`video-card card ${compact ? "compact" : ""}`}>
      <div className="video-panel">
        <div className="video-content">
          <div className="video-top">
            <div>
              <h2 className="video-title">{showAdInside ? "Ad Player" : "Video Player"}</h2>
              <p className="video-subtitle">
                {showAdInside ? "Ad currently displayed in the video area" : "Main gym display area"}
              </p>
            </div>
            <div className="placeholder-badge">{showAdInside ? "Ad mode" : "Placeholder"}</div>
          </div>

          <div className="video-body">
            {showAdInside ? (
              <AdPlaceholder title="AD PLACEHOLDER" subtitle="Ad displayed inside video player" compact />
            ) : (
              <div className="video-dropzone">
                <div className="video-center">
                  <button className="video-play" type="button">
                    <PlayFilledIcon size={34} color="#2e2e2e" />
                  </button>
                  <h3 className="video-center-title">Video area</h3>
                  <p className="video-center-subtitle">
                    Replace this block later with a real video component, ad renderer, live stream,
                    local player, or iframe source.
                  </p>
                </div>
              </div>
            )}
          </div>

          <div className="video-bottom">
            <div>
              <p className="status-label">Status</p>
              <p className="status-text">
                {showAdInside ? "Ad placeholder is active" : "Ready for player integration"}
              </p>
            </div>

            <div className="video-actions">
              <button className="btn-ghost" type="button">
                Add source
              </button>
              <button className="btn-primary" type="button">
                Play preview
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function MediaCard({
  textOnly = false,
  compact = false,
}: {
  textOnly?: boolean;
  compact?: boolean;
}) {
  return (
    <div className={`media-card card ${textOnly ? "text-only" : ""} ${compact ? "compact" : ""}`}>
      {!textOnly && (
        <div className="media-art">
          <div className="media-tag">● Everyday Playlist</div>
        </div>
      )}

      <div className="media-player">
        <div>
          <p className="media-kicker">Now playing</p>
          <h3 className="media-title">Workout Energy Mix</h3>
          <p className="media-subtitle">Gym speakers • Cardio zone</p>

          <div className="media-progress-wrap">
            <div className="media-progress-top">
              <span>01:34</span>
              <span>03:42</span>
            </div>
            <div className="media-progress">
              <div className="media-progress-fill" />
            </div>
          </div>
        </div>

        <div className="media-controls">
          <button className="player-mini-btn" type="button">
            <PrevFilledIcon size={20} color="rgba(255,255,255,0.9)" />
          </button>

          <button className="player-main-btn" type="button">
            <PauseFilledIcon size={26} color="#2e2e2e" />
          </button>

          <button className="player-mini-btn" type="button">
            <NextFilledIcon size={20} color="rgba(255,255,255,0.9)" />
          </button>
        </div>
      </div>
    </div>
  );
}

export default function TvDashboardPage() {
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [selectedAdMode, setSelectedAdMode] = useState<AdMode>("none");
  const [activeAdMode, setActiveAdMode] = useState<AdMode>("none");
  const [eventIndex, setEventIndex] = useState(0);
  const [quoteIndex, setQuoteIndex] = useState(0);
  const [notificationNonce, setNotificationNonce] = useState(0);
  const [notificationVisible, setNotificationVisible] = useState(false);

  const events: EventItem[] = [
    {
      title: "HIIT Full Body Session",
      description:
        "An explosive full-body interval class focused on strength, cardio bursts, and fast recovery blocks.",
      remaining: "Starts in 18 min",
      coach: "Coach Yasmine",
      room: "Studio A",
      image:
        "https://images.unsplash.com/photo-1517836357463-d25dfeac3438?auto=format&fit=crop&w=1200&q=80",
      tag: "Upcoming",
      accent: "linear-gradient(135deg, #f0dfd0 0%, #d8bca7 45%, #a67858 100%)",
    },
    {
      title: "Pilates & Mobility Class",
      description:
        "Controlled movement, flexibility, and core activation to improve posture, balance, and recovery.",
      remaining: "Starts in 42 min",
      coach: "Coach Hamza",
      room: "Mind & Body Room",
      image:
        "https://images.unsplash.com/photo-1518611012118-696072aa579a?auto=format&fit=crop&w=1200&q=80",
      tag: "Today",
      accent: "linear-gradient(135deg, #dfe7e8 0%, #b7c9c9 45%, #6a7b78 100%)",
    },
    {
      title: "Strength & Conditioning",
      description:
        "A high-energy session mixing compound lifts, athletic circuits, and performance-focused conditioning.",
      remaining: "Starts in 1h 25m",
      coach: "Coach Lina",
      room: "Power Zone",
      image:
        "https://images.unsplash.com/photo-1534438327276-14e5300c3a48?auto=format&fit=crop&w=1200&q=80",
      tag: "Popular",
      accent: "linear-gradient(135deg, #e8d9cd 0%, #ba9980 45%, #65483a 100%)",
    },
  ];

  const quotes: QuoteItem[] = [
    {
      text: "Discipline is choosing between what you want now and what you want most.",
      author: "Mon Club",
      mood: "Mindset",
    },
    {
      text: "Consistency builds the body. Effort builds the identity.",
      author: "Gym Motivation",
      mood: "Focus",
    },
    {
      text: "Every rep counts, even the one you almost skipped.",
      author: "Coach Note",
      mood: "Energy",
    },
    {
      text: "Train with purpose, recover with respect, return with hunger.",
      author: "Performance",
      mood: "Growth",
    },
  ];

  useEffect(() => {
    const id = window.setInterval(() => {
      setQuoteIndex((prev) => (prev + 1) % quotes.length);
    }, 15000);

    return () => window.clearInterval(id);
  }, [quotes.length]);

  useEffect(() => {
    if (notificationNonce === 0) return;

    setNotificationVisible(true);
    const timeout = window.setTimeout(() => {
      setNotificationVisible(false);
    }, 5000);

    return () => window.clearTimeout(timeout);
  }, [notificationNonce]);

  useEffect(() => {
    if (activeAdMode === "none") return;

    const timeout = window.setTimeout(() => {
      setActiveAdMode("none");
    }, 3000);

    return () => window.clearTimeout(timeout);
  }, [activeAdMode]);

  const currentQuote = quotes[quoteIndex];

  const content = useMemo(() => {
    const eventBlock = (
      <EventCarousel
        events={events}
        eventIndex={eventIndex}
        setEventIndex={setEventIndex}
        notificationVisible={notificationVisible}
      />
    );

    const compactEventBlock = (
      <EventCarousel
        events={events}
        eventIndex={eventIndex}
        setEventIndex={setEventIndex}
        notificationVisible={notificationVisible}
        compact
      />
    );

    const modeBlock = <ModeCard />;
    const quoteBlock = <QuoteCard quote={currentQuote} />;
    const compactQuoteBlock = <QuoteCard quote={currentQuote} compact />;
    const mediaBlock = <MediaCard />;
    const textOnlyMediaBlock = <MediaCard textOnly compact />;
    const normalVideoBlock = <VideoCard showAdInside={false} />;
    const adInVideoBlock = <VideoCard showAdInside={true} />;

    if (activeAdMode === "full screen") {
      return (
        <div className="full-screen-ad-layout">
          <AdPlaceholder
            title="AD PLACEHOLDER"
            subtitle="Full screen ad mode — all other content is hidden"
          />
        </div>
      );
    }

    if (activeAdMode === "2/4_H") {
      return (
        <div className="h-half-layout">
          <div className="h-half-top">{adInVideoBlock}</div>
          <div className="h-half-bottom">{mediaBlock}</div>
        </div>
      );
    }

    if (activeAdMode === "3/4_H") {
      return (
        <div className="h-three-quarter-layout">
          <div className="h-three-quarter-ad">
            <AdPlaceholder
              title="AD PLACEHOLDER"
              subtitle="3/4 horizontal ad takeover"
            />
          </div>

          <div className="h-three-quarter-side">
            <div className="h-three-quarter-event">{compactEventBlock}</div>
            <div className="h-three-quarter-music">{textOnlyMediaBlock}</div>
          </div>
        </div>
      );
    }

    if (activeAdMode === "2/4_V") {
      return (
        <div className="v-half-layout">
          <div className="v-half-top">
            <AdPlaceholder
              title="AD PLACEHOLDER"
              subtitle="Top half ad takeover"
            />
          </div>

          <div className="v-half-bottom">
            <div className="v-half-bottom-media">{mediaBlock}</div>
            <div className="v-half-bottom-quote">{quoteBlock}</div>
          </div>
        </div>
      );
    }

    if (activeAdMode === "3/4_V") {
      return (
        <div className="v-three-quarter-layout">
          <div className="v-three-quarter-top">
            <AdPlaceholder
              title="AD PLACEHOLDER"
              subtitle="Top 3/4 ad takeover"
            />
          </div>

          <div className="v-three-quarter-bottom">
            <div className="v-three-quarter-media">{textOnlyMediaBlock}</div>
            <div className="v-three-quarter-quote">{compactQuoteBlock}</div>
          </div>
        </div>
      );
    }

    const videoBlock =
      activeAdMode === "1/4_H" || activeAdMode === "1/4_V"
        ? adInVideoBlock
        : normalVideoBlock;

    return (
      <div className="layout-grid">
        <div className="left-grid">
          {eventBlock}
          {modeBlock}
          {quoteBlock}
        </div>

        <div className="right-grid">
          {videoBlock}
          {mediaBlock}
        </div>
      </div>
    );
  }, [activeAdMode, currentQuote, eventIndex, events, notificationVisible]);

  return (
    <>
      <style>{`
        * {
          box-sizing: border-box;
        }

        html, body, #root {
          margin: 0;
          padding: 0;
          width: 100%;
          height: 100%;
          overflow: hidden;
        }

        body {
          font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: #2f2923;
          color: #ffffff;
        }

        .tv-page {
          width: 100vw;
          height: 100vh;
          overflow: hidden;
          background: #2f2923;
          padding: clamp(6px, 0.7vw, 10px);
          position: relative;
        }

        .tv-shell {
          width: 100%;
          height: 100%;
          border-radius: clamp(18px, 1.8vw, 28px);
          border: 1px solid rgba(255,255,255,0.10);
          background: rgba(96,84,74,0.58);
          backdrop-filter: blur(18px);
          -webkit-backdrop-filter: blur(18px);
          box-shadow: 0 20px 60px rgba(0,0,0,0.22);
          padding: clamp(8px, 0.8vw, 12px);
          overflow: hidden;
        }

        .layout-grid {
          width: 100%;
          height: 100%;
          display: grid;
          grid-template-columns: minmax(0, 1.02fr) minmax(0, 1.22fr);
          gap: clamp(8px, 0.8vw, 12px);
          min-height: 0;
        }

        .left-grid {
          min-width: 0;
          min-height: 0;
          display: grid;
          grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
          grid-template-rows: minmax(0, 1.52fr) minmax(0, 0.58fr) minmax(0, 0.92fr);
          gap: clamp(8px, 0.8vw, 12px);
        }

        .right-grid {
          min-width: 0;
          min-height: 0;
          display: grid;
          grid-template-rows: minmax(0, 1.52fr) minmax(0, 0.92fr);
          gap: clamp(8px, 0.8vw, 12px);
        }

        .card {
          border-radius: clamp(18px, 1.6vw, 26px);
          border: 1px solid rgba(255,255,255,0.07);
          box-shadow: 0 14px 40px rgba(0,0,0,0.14);
          overflow: hidden;
          min-height: 0;
        }

        .event-card {
          grid-column: span 2;
          position: relative;
          padding: clamp(12px, 1vw, 16px);
          overflow: hidden;
        }

        .event-card.compact {
          grid-column: span 1;
          padding: clamp(10px, 0.9vw, 14px);
        }

        .event-card-overlay {
          position: absolute;
          inset: 0;
          background:
            radial-gradient(circle at 20% 20%, rgba(255,255,255,0.22), transparent 24%),
            radial-gradient(circle at 80% 24%, rgba(255,255,255,0.12), transparent 18%),
            linear-gradient(to top, rgba(33,24,18,0.38), rgba(33,24,18,0.05), rgba(255,255,255,0.06));
          pointer-events: none;
        }

        .event-card-blur-a {
          position: absolute;
          right: -40px;
          top: 40px;
          width: 180px;
          height: 180px;
          border-radius: 999px;
          background: rgba(255,255,255,0.10);
          filter: blur(32px);
          pointer-events: none;
        }

        .event-card-blur-b {
          position: absolute;
          left: -20px;
          bottom: -40px;
          width: 180px;
          height: 180px;
          border-radius: 999px;
          background: rgba(0,0,0,0.08);
          filter: blur(32px);
          pointer-events: none;
        }

        .event-card-content {
          position: relative;
          z-index: 1;
          width: 100%;
          height: 100%;
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          gap: clamp(10px, 0.9vw, 14px);
          min-height: 0;
        }

        .top-row {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          gap: 10px;
        }

        .event-actions {
          display: flex;
          align-items: center;
          gap: 8px;
          flex-wrap: wrap;
        }

        .pill-dark {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          border-radius: 999px;
          background: rgba(0,0,0,0.14);
          color: rgba(255,255,255,0.94);
          padding: 8px 12px;
          font-size: clamp(10px, 0.75vw, 12px);
          font-weight: 600;
          backdrop-filter: blur(8px);
        }

        .pill-light {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          border-radius: 999px;
          background: #ffffff;
          color: #3c342d;
          padding: 8px 12px;
          font-size: clamp(10px, 0.75vw, 12px);
          font-weight: 700;
          box-shadow: 0 10px 24px rgba(0,0,0,0.12);
          white-space: nowrap;
        }

        .dot {
          width: 8px;
          height: 8px;
          border-radius: 999px;
          background: #d9efee;
          display: inline-block;
        }

        .round-btn {
          width: 38px;
          height: 38px;
          border-radius: 999px;
          border: 0;
          background: rgba(0,0,0,0.15);
          color: #ffffff;
          display: flex;
          align-items: center;
          justify-content: center;
          cursor: pointer;
          backdrop-filter: blur(8px);
          flex-shrink: 0;
        }

        .event-main-grid {
          flex: 1;
          min-height: 0;
          display: grid;
          grid-template-columns: minmax(0, 1.08fr) minmax(260px, 0.92fr);
          gap: clamp(10px, 0.9vw, 14px);
          align-items: center;
        }

        .event-main-grid.compact {
          grid-template-columns: 1fr;
        }

        .event-info-panel {
          border-radius: clamp(18px, 1.6vw, 24px);
          border: 1px solid rgba(255,255,255,0.10);
          background: rgba(0,0,0,0.10);
          backdrop-filter: blur(12px);
          padding: clamp(14px, 1.1vw, 20px);
          min-height: 0;
        }

        .section-kicker {
          margin: 0;
          text-transform: uppercase;
          letter-spacing: 0.18em;
          font-size: clamp(9px, 0.7vw, 11px);
          color: rgba(255,255,255,0.62);
        }

        .event-title {
          margin: 10px 0 0;
          font-size: clamp(22px, 1.9vw, 36px);
          line-height: 1.08;
          font-weight: 750;
          color: #ffffff;
          text-shadow: 0 2px 10px rgba(0,0,0,0.10);
          display: -webkit-box;
          -webkit-line-clamp: 2;
          -webkit-box-orient: vertical;
          overflow: hidden;
        }

        .event-description {
          margin: 12px 0 0;
          font-size: clamp(12px, 0.92vw, 16px);
          line-height: 1.45;
          color: rgba(255,255,255,0.90);
          max-width: 95%;
          display: -webkit-box;
          -webkit-line-clamp: 4;
          -webkit-box-orient: vertical;
          overflow: hidden;
        }

        .chips {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
          margin-top: 14px;
        }

        .chip-primary {
          border-radius: 999px;
          background: #d9efee;
          color: #2d332f;
          padding: 9px 13px;
          font-size: clamp(10px, 0.82vw, 13px);
          font-weight: 700;
          box-shadow: 0 8px 20px rgba(0,0,0,0.12);
        }

        .chip-secondary {
          border-radius: 999px;
          border: 1px solid rgba(255,255,255,0.15);
          background: rgba(255,255,255,0.10);
          color: rgba(255,255,255,0.90);
          padding: 9px 13px;
          font-size: clamp(10px, 0.82vw, 13px);
        }

        .event-image-card {
          position: relative;
          height: 100%;
          min-height: 0;
          overflow: hidden;
          border-radius: clamp(18px, 1.6vw, 24px);
          border: 1px solid rgba(255,255,255,0.10);
          background: rgba(0,0,0,0.14);
          box-shadow: 0 18px 40px rgba(0,0,0,0.18);
        }

        .event-main-grid.compact .event-image-card {
          display: none;
        }

        .event-image {
          width: 100%;
          height: 100%;
          object-fit: cover;
        }

        .event-image-overlay {
          position: absolute;
          inset: 0;
          background: linear-gradient(to top, rgba(0,0,0,0.48), rgba(0,0,0,0.08));
        }

        .event-image-footer {
          position: absolute;
          left: 0;
          right: 0;
          bottom: 0;
          padding: 14px;
        }

        .event-image-kicker {
          margin: 0;
          font-size: clamp(9px, 0.7vw, 11px);
          letter-spacing: 0.18em;
          text-transform: uppercase;
          color: rgba(255,255,255,0.62);
        }

        .event-image-title {
          margin: 8px 0 0;
          font-size: clamp(16px, 1.2vw, 22px);
          font-weight: 700;
          color: #ffffff;
        }

        .event-notification-wrap {
          flex: 1;
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 0;
        }

        .event-notification-box {
          width: 100%;
          max-width: 82%;
          border-radius: clamp(18px, 1.6vw, 24px);
          border: 1px solid rgba(255,255,255,0.10);
          background: rgba(0,0,0,0.12);
          backdrop-filter: blur(12px);
          padding: clamp(16px, 1.2vw, 22px);
        }

        .notification-title {
          margin: 10px 0 0;
          font-size: clamp(22px, 1.8vw, 34px);
          font-weight: 750;
          line-height: 1.08;
          color: #ffffff;
        }

        .notification-text {
          margin: 12px 0 0;
          font-size: clamp(12px, 0.92vw, 16px);
          line-height: 1.55;
          color: rgba(255,255,255,0.90);
        }

        .event-footer {
          display: flex;
          align-items: flex-end;
          justify-content: space-between;
          gap: 10px;
          flex-wrap: wrap;
        }

        .footer-title {
          margin: 0;
          font-size: clamp(18px, 1.25vw, 24px);
          font-weight: 700;
          color: #ffffff;
        }

        .footer-subtitle {
          margin: 5px 0 0;
          font-size: clamp(10px, 0.76vw, 13px);
          color: rgba(255,255,255,0.75);
        }

        .dots-row {
          display: flex;
          gap: 8px;
          align-items: center;
        }

        .carousel-dot {
          height: 9px;
          width: 9px;
          border-radius: 999px;
          border: 0;
          background: rgba(255,255,255,0.42);
          cursor: pointer;
          transition: all 180ms ease;
        }

        .carousel-dot.active {
          width: 34px;
          background: #ffffff;
        }

        .mode-card {
          grid-column: span 2;
          background:
            radial-gradient(circle at 18% 18%, rgba(255,255,255,0.06), transparent 22%),
            radial-gradient(circle at 82% 78%, rgba(201,235,236,0.08), transparent 24%),
            rgba(91,85,77,0.65);
          padding: clamp(14px, 1vw, 18px);
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 0;
          text-align: center;
        }

        .mode-card-inner {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 10px;
        }

        .mode-pill {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          border-radius: 999px;
          background: rgba(255,255,255,0.10);
          color: rgba(255,255,255,0.86);
          padding: 7px 12px;
          font-size: clamp(10px, 0.74vw, 12px);
          font-weight: 600;
          backdrop-filter: blur(8px);
        }

        .mode-text {
          margin: 0;
          font-size: clamp(24px, 2vw, 44px);
          line-height: 1.02;
          font-weight: 800;
          letter-spacing: 0.06em;
          color: rgba(255,255,255,0.98);
        }

        .mode-subtext {
          margin: 0;
          font-size: clamp(11px, 0.84vw, 14px);
          color: rgba(255,255,255,0.58);
        }

        .quote-card {
          grid-column: span 2;
          background:
            radial-gradient(circle at 18% 18%, rgba(255,255,255,0.06), transparent 22%),
            radial-gradient(circle at 80% 80%, rgba(201,235,236,0.08), transparent 24%),
            rgba(91,85,77,0.65);
          padding: clamp(14px, 1vw, 18px);
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          min-height: 0;
        }

        .quote-card.compact {
          padding: clamp(10px, 0.8vw, 14px);
        }

        .quote-top {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
        }

        .quote-badge {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          border-radius: 999px;
          background: rgba(255,255,255,0.10);
          color: rgba(255,255,255,0.88);
          padding: 7px 12px;
          font-size: clamp(10px, 0.74vw, 12px);
          font-weight: 600;
          backdrop-filter: blur(8px);
        }

        .quote-body {
          flex: 1;
          display: flex;
          align-items: center;
          min-height: 0;
        }

        .quote-text {
          margin: 0;
          max-width: 96%;
          font-size: clamp(18px, 1.45vw, 28px);
          line-height: 1.3;
          font-weight: 650;
          color: rgba(255,255,255,0.98);
          display: -webkit-box;
          -webkit-line-clamp: 4;
          -webkit-box-orient: vertical;
          overflow: hidden;
        }

        .quote-card.compact .quote-text {
          font-size: clamp(14px, 1vw, 20px);
          -webkit-line-clamp: 3;
        }

        .quote-footer {
          display: flex;
          align-items: flex-end;
          justify-content: space-between;
          gap: 10px;
          flex-wrap: wrap;
        }

        .quote-author {
          margin: 8px 0 0;
          font-size: clamp(11px, 0.84vw, 14px);
          color: rgba(255,255,255,0.72);
        }

        .quote-meta {
          font-size: clamp(10px, 0.76vw, 12px);
          color: rgba(255,255,255,0.52);
        }

        .video-card {
          background: rgba(91,85,77,0.65);
          padding: clamp(10px, 0.9vw, 14px);
          min-height: 0;
        }

        .video-card.compact {
          padding: clamp(8px, 0.75vw, 12px);
        }

        .video-panel {
          width: 100%;
          height: 100%;
          border-radius: clamp(18px, 1.6vw, 24px);
          overflow: hidden;
          border: 1px solid rgba(255,255,255,0.08);
          background:
            radial-gradient(circle at 30% 20%, rgba(255,255,255,0.08), transparent 28%),
            radial-gradient(circle at 75% 75%, rgba(201,235,236,0.08), transparent 26%),
            linear-gradient(145deg, #181614 0%, #2c2723 38%, #131210 100%);
          display: flex;
          flex-direction: column;
          position: relative;
        }

        .video-panel::after {
          content: "";
          position: absolute;
          inset: 0;
          background: linear-gradient(to top, rgba(0,0,0,0.42), rgba(0,0,0,0.12), rgba(0,0,0,0.22));
          pointer-events: none;
        }

        .video-content {
          position: relative;
          z-index: 1;
          width: 100%;
          height: 100%;
          display: flex;
          flex-direction: column;
          min-height: 0;
        }

        .video-top {
          padding: clamp(12px, 1vw, 18px);
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          gap: 10px;
        }

        .video-title {
          margin: 0;
          font-size: clamp(22px, 1.7vw, 34px);
          font-weight: 700;
          line-height: 1.05;
          color: rgba(255,255,255,0.97);
        }

        .video-subtitle {
          margin: 7px 0 0;
          font-size: clamp(12px, 0.88vw, 15px);
          color: rgba(255,255,255,0.58);
        }

        .placeholder-badge {
          border-radius: 999px;
          border: 1px solid rgba(255,255,255,0.10);
          background: rgba(255,255,255,0.10);
          padding: 7px 11px;
          color: rgba(255,255,255,0.76);
          font-size: clamp(10px, 0.72vw, 12px);
          white-space: nowrap;
        }

        .video-body {
          flex: 1;
          min-height: 0;
          padding: 0 clamp(12px, 1vw, 18px) clamp(12px, 1vw, 18px);
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .video-dropzone {
          width: 100%;
          height: 100%;
          min-height: 0;
          border-radius: clamp(18px, 1.6vw, 24px);
          border: 1px dashed rgba(255,255,255,0.22);
          background: rgba(0,0,0,0.20);
          backdrop-filter: blur(8px);
          display: flex;
          align-items: center;
          justify-content: center;
          position: relative;
          overflow: hidden;
        }

        .video-dropzone::before {
          content: "";
          position: absolute;
          inset: 0;
          background: linear-gradient(135deg, rgba(255,255,255,0.02), rgba(255,255,255,0.06), rgba(255,255,255,0.02));
        }

        .video-center {
          position: relative;
          z-index: 1;
          text-align: center;
          display: flex;
          flex-direction: column;
          align-items: center;
          padding: 16px;
        }

        .video-play {
          width: clamp(64px, 5vw, 84px);
          height: clamp(64px, 5vw, 84px);
          border-radius: 999px;
          border: 0;
          background: #ffffff;
          color: #2e2e2e;
          display: flex;
          align-items: center;
          justify-content: center;
          box-shadow: 0 14px 30px rgba(0,0,0,0.28);
          margin-bottom: 16px;
          cursor: pointer;
        }

        .video-center-title {
          margin: 0;
          font-size: clamp(20px, 1.45vw, 28px);
          font-weight: 700;
          color: rgba(255,255,255,0.97);
        }

        .video-center-subtitle {
          margin: 8px 0 0;
          max-width: 520px;
          font-size: clamp(11px, 0.84vw, 14px);
          color: rgba(255,255,255,0.60);
          line-height: 1.45;
        }

        .video-bottom {
          padding: 0 clamp(12px, 1vw, 18px) clamp(12px, 1vw, 18px);
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
          flex-wrap: wrap;
          position: relative;
          z-index: 1;
        }

        .status-label {
          margin: 0;
          font-size: clamp(9px, 0.68vw, 11px);
          text-transform: uppercase;
          letter-spacing: 0.18em;
          color: rgba(255,255,255,0.36);
        }

        .status-text {
          margin: 5px 0 0;
          font-size: clamp(11px, 0.84vw, 14px);
          color: rgba(255,255,255,0.76);
        }

        .video-actions {
          display: flex;
          align-items: center;
          gap: 8px;
          flex-wrap: wrap;
        }

        .btn-ghost {
          border: 0;
          border-radius: 999px;
          background: rgba(255,255,255,0.10);
          color: rgba(255,255,255,0.90);
          padding: 10px 14px;
          font-size: clamp(10px, 0.76vw, 12px);
          cursor: pointer;
          backdrop-filter: blur(8px);
        }

        .btn-primary {
          border: 0;
          border-radius: 999px;
          background: #ffffff;
          color: #2e2e2e;
          padding: 10px 14px;
          font-size: clamp(10px, 0.76vw, 12px);
          font-weight: 700;
          cursor: pointer;
        }

        .media-card {
          background: rgba(91,85,77,0.65);
          padding: clamp(10px, 0.9vw, 14px);
          display: grid;
          grid-template-columns: minmax(0, 0.88fr) minmax(0, 1.12fr);
          gap: clamp(8px, 0.8vw, 12px);
          min-height: 0;
        }

        .media-card.text-only {
          grid-template-columns: 1fr;
        }

        .media-card.compact {
          padding: clamp(8px, 0.75vw, 12px);
        }

        .media-art {
          position: relative;
          border-radius: clamp(16px, 1.4vw, 22px);
          overflow: hidden;
          min-height: 0;
          background:
            radial-gradient(circle at 45% 28%, rgba(255,187,120,0.2), transparent 26%),
            radial-gradient(circle at 58% 72%, rgba(255,80,80,0.12), transparent 22%),
            linear-gradient(145deg, #0f1416 0%, #152025 26%, #40281f 62%, #161818 100%);
        }

        .media-art::after {
          content: "";
          position: absolute;
          inset: auto 0 0 0;
          height: 90px;
          background: linear-gradient(to top, rgba(0,0,0,0.52), transparent);
        }

        .media-tag {
          position: absolute;
          top: 12px;
          left: 12px;
          z-index: 1;
          border-radius: 999px;
          background: rgba(39,66,48,0.90);
          color: #7ef79b;
          padding: 7px 11px;
          font-size: clamp(10px, 0.72vw, 12px);
          box-shadow: 0 8px 18px rgba(0,0,0,0.16);
        }

        .media-player {
          border-radius: clamp(16px, 1.4vw, 22px);
          background: rgba(0,0,0,0.10);
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          padding: clamp(14px, 1vw, 18px);
          min-height: 0;
        }

        .media-kicker {
          margin: 0;
          font-size: clamp(9px, 0.68vw, 11px);
          text-transform: uppercase;
          letter-spacing: 0.18em;
          color: rgba(255,255,255,0.34);
        }

        .media-title {
          margin: 8px 0 0;
          font-size: clamp(18px, 1.3vw, 26px);
          font-weight: 700;
          line-height: 1.08;
          color: rgba(255,255,255,0.97);
          display: -webkit-box;
          -webkit-line-clamp: 2;
          -webkit-box-orient: vertical;
          overflow: hidden;
        }

        .media-subtitle {
          margin: 6px 0 0;
          font-size: clamp(11px, 0.84vw, 14px);
          color: rgba(255,255,255,0.58);
        }

        .media-progress-wrap {
          margin-top: 14px;
        }

        .media-progress-top {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
          margin-bottom: 7px;
          font-size: clamp(10px, 0.74vw, 12px);
          color: rgba(255,255,255,0.62);
        }

        .media-progress {
          width: 100%;
          height: 7px;
          border-radius: 999px;
          background: rgba(255,255,255,0.12);
          overflow: hidden;
        }

        .media-progress-fill {
          width: 42%;
          height: 100%;
          background: #d9efee;
          border-radius: 999px;
        }

        .media-controls {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: clamp(12px, 1vw, 20px);
        }

        .player-mini-btn {
          width: clamp(40px, 2.8vw, 46px);
          height: clamp(40px, 2.8vw, 46px);
          border-radius: 999px;
          border: 0;
          background: transparent;
          color: rgba(255,255,255,0.88);
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .player-mini-btn:hover {
          background: rgba(255,255,255,0.10);
        }

        .player-main-btn {
          width: clamp(58px, 4.5vw, 74px);
          height: clamp(58px, 4.5vw, 74px);
          border-radius: 999px;
          border: 0;
          background: #ffffff;
          color: #2e2e2e;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          box-shadow: 0 14px 30px rgba(0,0,0,0.22);
        }

        .ad-placeholder {
          width: 100%;
          height: 100%;
          min-height: 0;
          background: #000000;
          border-radius: clamp(18px, 1.6vw, 24px);
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 20px;
          text-align: center;
          border: 1px solid rgba(255,255,255,0.10);
        }

        .ad-placeholder.compact {
          min-height: 0;
        }

        .ad-placeholder-inner {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 10px;
          width: 100%;
          max-width: 780px;
        }

        .ad-label {
          margin: 0;
          text-transform: uppercase;
          letter-spacing: 0.22em;
          font-size: clamp(9px, 0.68vw, 11px);
          color: rgba(255,255,255,0.40);
        }

        .ad-title {
          margin: 0;
          font-size: clamp(26px, 2.8vw, 54px);
          font-weight: 800;
          line-height: 1;
          color: #ffffff;
        }

        .ad-subtitle {
          margin: 0;
          font-size: clamp(11px, 0.9vw, 16px);
          color: rgba(255,255,255,0.62);
          max-width: 700px;
        }

        .full-screen-ad-layout,
        .h-half-layout,
        .h-three-quarter-layout,
        .v-half-layout,
        .v-three-quarter-layout {
          width: 100%;
          height: 100%;
          min-height: 0;
        }

        .full-screen-ad-layout {
          display: grid;
        }

        .h-half-layout {
          display: grid;
          grid-template-rows: minmax(0, 1.2fr) minmax(0, 0.8fr);
          gap: clamp(8px, 0.8vw, 12px);
        }

        .h-half-top,
        .h-half-bottom {
          min-height: 0;
        }

        .h-three-quarter-layout {
          display: grid;
          grid-template-columns: minmax(0, 2.8fr) minmax(260px, 1fr);
          gap: clamp(8px, 0.8vw, 12px);
          min-height: 0;
        }

        .h-three-quarter-ad,
        .h-three-quarter-side {
          min-height: 0;
        }

        .h-three-quarter-side {
          display: grid;
          grid-template-rows: minmax(0, 1.15fr) minmax(0, 0.85fr);
          gap: clamp(8px, 0.8vw, 12px);
        }

        .h-three-quarter-event,
        .h-three-quarter-music {
          min-height: 0;
        }

        .v-half-layout {
          display: grid;
          grid-template-rows: minmax(0, 1fr) minmax(0, 1fr);
          gap: clamp(8px, 0.8vw, 12px);
          min-height: 0;
        }

        .v-half-top,
        .v-half-bottom {
          min-height: 0;
        }

        .v-half-bottom {
          display: grid;
          grid-template-columns: minmax(0, 1.12fr) minmax(0, 0.88fr);
          gap: clamp(8px, 0.8vw, 12px);
        }

        .v-half-bottom-media,
        .v-half-bottom-quote {
          min-height: 0;
        }

        .v-three-quarter-layout {
          display: grid;
          grid-template-rows: minmax(0, 3fr) minmax(0, 1fr);
          gap: clamp(8px, 0.8vw, 12px);
          min-height: 0;
        }

        .v-three-quarter-top,
        .v-three-quarter-bottom {
          min-height: 0;
        }

        .v-three-quarter-bottom {
          display: grid;
          grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
          gap: clamp(8px, 0.8vw, 12px);
          align-items: stretch;
        }

        .v-three-quarter-media,
        .v-three-quarter-quote {
          min-height: 0;
        }

        .floating-settings {
          position: fixed;
          left: clamp(8px, 1vw, 14px);
          top: 50%;
          transform: translateY(-50%);
          z-index: 9999;
        }

        .floating-toggle {
          width: clamp(46px, 3.8vw, 54px);
          height: clamp(46px, 3.8vw, 54px);
          border-radius: 999px;
          border: 1px solid rgba(255,255,255,0.10);
          background: #cde7e5;
          color: #27312d;
          display: flex;
          align-items: center;
          justify-content: center;
          cursor: pointer;
          box-shadow: 0 18px 40px rgba(0,0,0,0.35);
          backdrop-filter: blur(12px);
        }

        .floating-panel {
          position: absolute;
          left: calc(100% + 10px);
          top: 50%;
          transform: translateY(-50%);
          width: min(280px, 24vw);
          min-width: 220px;
          border-radius: 20px;
          border: 1px solid rgba(255,255,255,0.10);
          background: rgba(49,43,38,0.96);
          backdrop-filter: blur(18px);
          box-shadow: 0 24px 60px rgba(0,0,0,0.42);
          padding: 12px;
        }

        .floating-head {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
          margin-bottom: 12px;
        }

        .floating-kicker {
          font-size: clamp(9px, 0.68vw, 11px);
          letter-spacing: 0.18em;
          text-transform: uppercase;
          color: rgba(255,255,255,0.35);
          margin: 0;
        }

        .floating-title {
          margin: 5px 0 0;
          font-size: clamp(16px, 1.1vw, 20px);
          font-weight: 700;
          color: rgba(255,255,255,0.96);
        }

        .close-btn {
          border: 0;
          border-radius: 999px;
          background: rgba(255,255,255,0.10);
          color: rgba(255,255,255,0.75);
          padding: 7px 11px;
          cursor: pointer;
          font-size: 11px;
        }

        .floating-actions {
          display: flex;
          flex-direction: column;
          gap: 10px;
        }

        .floating-secondary-btn {
          width: 100%;
          border: 0;
          border-radius: 16px;
          background: rgba(255,255,255,0.10);
          color: rgba(255,255,255,0.92);
          padding: 12px 14px;
          font-size: 13px;
          font-weight: 600;
          text-align: left;
          cursor: pointer;
        }

        .select-block {
          border-radius: 16px;
          background: rgba(255,255,255,0.08);
          padding: 12px;
        }

        .select-label {
          display: block;
          margin-bottom: 8px;
          font-size: 13px;
          font-weight: 600;
          color: rgba(255,255,255,0.84);
        }

        .select-input {
          width: 100%;
          border-radius: 12px;
          border: 1px solid rgba(255,255,255,0.10);
          background: #4a433d;
          color: #ffffff;
          padding: 11px 12px;
          font-size: 13px;
          outline: none;
        }

        @media (max-width: 1200px) {
          .layout-grid {
            grid-template-columns: minmax(0, 1fr) minmax(0, 1.08fr);
          }

          .event-main-grid {
            grid-template-columns: 1fr;
          }

          .event-image-card {
            min-height: 180px;
          }

          .h-three-quarter-layout {
            grid-template-columns: minmax(0, 2.2fr) minmax(220px, 1fr);
          }
        }

        @media (max-width: 920px) {
          .layout-grid,
          .h-three-quarter-layout,
          .v-half-bottom,
          .v-three-quarter-bottom {
            grid-template-columns: 1fr;
          }

          .left-grid {
            grid-template-columns: 1fr;
            grid-template-rows: minmax(0, 1.2fr) minmax(0, 0.45fr) minmax(0, 0.8fr);
          }

          .event-card,
          .mode-card,
          .quote-card {
            grid-column: span 1;
          }

          .right-grid,
          .h-three-quarter-side {
            grid-template-rows: minmax(0, 1fr) minmax(0, 0.8fr);
          }

          .floating-panel {
            width: 240px;
          }
        }
      `}</style>

      <div className="tv-page">
        <div className="floating-settings">
          <button
            type="button"
            className="floating-toggle"
            onClick={() => setSettingsOpen((v) => !v)}
            aria-label="Open TV settings"
          >
            <SettingsIcon size={22} color="#27312d" />
          </button>

          {settingsOpen && (
            <div className="floating-panel">
              <div className="floating-head">
                <div>
                  <p className="floating-kicker">TV Controls</p>
                  <p className="floating-title">Screen Settings</p>
                </div>
                <button className="close-btn" type="button" onClick={() => setSettingsOpen(false)}>
                  Close
                </button>
              </div>

              <div className="floating-actions">
                <button
                  className="floating-secondary-btn"
                  type="button"
                  onClick={() => {
                    setNotificationNonce((v) => v + 1);
                    setSettingsOpen(false);
                  }}
                >
                  Send notification
                </button>

                <div className="select-block">
                  <label className="select-label">Send ad</label>
                  <select
                    className="select-input"
                    value={selectedAdMode}
                    onChange={(e) => {
                      const nextMode = e.target.value as AdMode;
                      setSelectedAdMode(nextMode);
                      setActiveAdMode(nextMode);
                    }}
                  >
                    <option value="none">none</option>
                    <option value="full screen">full screen</option>
                    <option value="1/4_H">1/4_H</option>
                    <option value="2/4_H">2/4_H</option>
                    <option value="3/4_H">3/4_H</option>
                    <option value="1/4_V">1/4_V</option>
                    <option value="2/4_V">2/4_V</option>
                    <option value="3/4_V">3/4_V</option>
                  </select>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="tv-shell">{content}</div>
      </div>
    </>
  );
}