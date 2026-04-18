/**
 * ScanResultPage — RFID-card-style popup opened by the scan shortcut handler.
 *
 * Window: 440 × 278 px, no decorations, always-on-top, centered.
 * Reads the card number from the URL: /scan-result?card=XXXXXXXXXX
 * Auto-closes after 4 seconds.  Click anywhere to close immediately.
 */

import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

const AUTO_CLOSE_MS = 4000;

// Format a raw card number into groups of 4 for readability.
function formatCard(raw: string): string {
  if (!raw) return "—";
  const digits = raw.replace(/\s+/g, "");
  return digits.match(/.{1,4}/g)?.join("  ") ?? digits;
}

export default function ScanResultPage() {
  const [params] = useSearchParams();
  const card = params.get("card") ?? "";
  const formatted = formatCard(card);

  const [progress, setProgress] = useState(100);
  const startRef = useRef<number>(performance.now());
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    const tick = (now: number) => {
      const elapsed = now - startRef.current;
      const pct = Math.max(0, 1 - elapsed / AUTO_CLOSE_MS);
      setProgress(pct * 100);
      if (pct > 0) {
        rafRef.current = requestAnimationFrame(tick);
      } else {
        closeWindow();
      }
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => { if (rafRef.current !== null) cancelAnimationFrame(rafRef.current); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function closeWindow() {
    import("@tauri-apps/api/window")
      .then(({ getCurrentWindow }) => getCurrentWindow().close())
      .catch(() => window.close());
  }

  const fontSize = formatted.length > 23 ? 15 : formatted.length > 14 ? 18 : 22;

  return (
    <>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        html, body, #root { width: 100%; height: 100%; overflow: hidden; }

        /* Animated RFID rings */
        @keyframes ring-pulse {
          0%   { transform: translate(-50%, -50%) scale(0.6); opacity: 0.9; }
          100% { transform: translate(-50%, -50%) scale(2.2); opacity: 0;   }
        }
        .rfid-ring {
          position: absolute;
          top: 50%; left: 50%;
          border-radius: 50%;
          border: 1.5px solid rgba(74, 222, 128, 0.7);
          animation: ring-pulse 2s ease-out infinite;
          pointer-events: none;
        }
        .rfid-ring:nth-child(1) { width: 28px; height: 28px; animation-delay: 0s;    }
        .rfid-ring:nth-child(2) { width: 28px; height: 28px; animation-delay: 0.55s; }
        .rfid-ring:nth-child(3) { width: 28px; height: 28px; animation-delay: 1.1s;  }

        /* Chip glow pulse */
        @keyframes chip-glow {
          0%, 100% { box-shadow: 0 0 6px 1px rgba(251,191,36,0.5); }
          50%       { box-shadow: 0 0 14px 3px rgba(251,191,36,0.8); }
        }

        /* Holographic shimmer on card number */
        @keyframes shimmer {
          0%   { background-position: 200% center; }
          100% { background-position: -200% center; }
        }
        .shimmer-text {
          background: linear-gradient(
            90deg,
            #4ade80 0%,
            #22d3ee 25%,
            #a3e635 50%,
            #22d3ee 75%,
            #4ade80 100%
          );
          background-size: 300% auto;
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
          animation: shimmer 3s linear infinite;
        }

        /* Card entrance */
        @keyframes card-in {
          from { opacity: 0; transform: scale(0.92) translateY(8px); }
          to   { opacity: 1; transform: scale(1)    translateY(0);   }
        }
        .card-root {
          animation: card-in 0.25s cubic-bezier(0.34, 1.56, 0.64, 1) forwards;
        }

        /* Success badge pulse */
        @keyframes badge-pop {
          0%   { transform: scale(0); opacity: 0; }
          60%  { transform: scale(1.2); opacity: 1; }
          100% { transform: scale(1); opacity: 1; }
        }
        .badge { animation: badge-pop 0.4s 0.1s cubic-bezier(0.34,1.56,0.64,1) both; }

        /* Scanline overlay */
        .scanlines::after {
          content: "";
          position: absolute; inset: 0;
          background: repeating-linear-gradient(
            to bottom,
            transparent          0px,
            transparent          3px,
            rgba(0,0,0,0.07)     3px,
            rgba(0,0,0,0.07)     4px
          );
          pointer-events: none;
          border-radius: inherit;
        }
      `}</style>

      {/* Window shell — dark matte background */}
      <div
        onClick={closeWindow}
        style={{
          width: "100vw",
          height: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "radial-gradient(ellipse at 60% 40%, #0f2035 0%, #080d1a 100%)",
          cursor: "pointer",
          userSelect: "none",
          position: "relative",
          overflow: "hidden",
        }}
      >
        {/* Subtle ambient glow behind card */}
        <div style={{
          position: "absolute",
          width: 280, height: 160,
          borderRadius: "50%",
          background: "radial-gradient(ellipse, rgba(34,211,238,0.08) 0%, transparent 70%)",
          pointerEvents: "none",
        }} />

        {/* ── RFID Card ── */}
        <div
          className="card-root scanlines"
          style={{
            position: "relative",
            width: 400,
            height: 252,
            borderRadius: 16,
            /* Dark navy-to-indigo gradient like a real card */
            background: "linear-gradient(135deg, #0d1b3e 0%, #1a2357 40%, #0d2548 70%, #0a1628 100%)",
            boxShadow: [
              "0 2px 0 rgba(255,255,255,0.06) inset",   /* top edge highlight */
              "0 -1px 0 rgba(0,0,0,0.6) inset",          /* bottom inner shadow */
              "0 20px 50px rgba(0,0,0,0.7)",              /* drop shadow */
              "0 0 0 1px rgba(255,255,255,0.08)",         /* card border */
            ].join(","),
            overflow: "hidden",
            flexShrink: 0,
          }}
        >
          {/* Holographic foil gleam (top-right) */}
          <div style={{
            position: "absolute", top: -30, right: -30,
            width: 140, height: 140, borderRadius: "50%",
            background: "radial-gradient(circle, rgba(167,139,250,0.12) 0%, transparent 65%)",
            pointerEvents: "none",
          }} />

          {/* Diagonal light streak */}
          <div style={{
            position: "absolute", top: 0, left: "30%",
            width: "55%", height: "100%",
            background: "linear-gradient(105deg, transparent 45%, rgba(255,255,255,0.03) 50%, transparent 55%)",
            pointerEvents: "none",
          }} />

          {/* ── TOP ROW ── */}
          <div style={{
            display: "flex", justifyContent: "space-between", alignItems: "flex-start",
            padding: "18px 20px 0",
          }}>
            {/* Brand */}
            <div>
              <div style={{ fontSize: 9, fontWeight: 800, letterSpacing: "0.2em", color: "#60a5fa", fontFamily: "system-ui, sans-serif" }}>
                MONCLUB
              </div>
              <div style={{ fontSize: 7, letterSpacing: "0.15em", color: "#3b82f6", fontFamily: "system-ui, sans-serif", marginTop: 1 }}>
                ACCESS CONTROL
              </div>
            </div>

            {/* Success badge */}
            <div
              className="badge"
              style={{
                display: "flex", alignItems: "center", gap: 5,
                background: "rgba(74,222,128,0.12)",
                border: "1px solid rgba(74,222,128,0.35)",
                borderRadius: 20,
                padding: "4px 10px",
              }}
            >
              {/* Green dot */}
              <div style={{
                width: 6, height: 6, borderRadius: "50%",
                background: "#4ade80",
                boxShadow: "0 0 6px rgba(74,222,128,0.9)",
              }} />
              <span style={{ fontSize: 9, fontWeight: 700, color: "#4ade80", letterSpacing: "0.1em", fontFamily: "system-ui, sans-serif" }}>
                VALIDÉ
              </span>
            </div>
          </div>

          {/* ── MIDDLE ROW: chip + waves ── */}
          <div style={{
            display: "flex", alignItems: "center",
            padding: "14px 20px 0",
            gap: 18,
          }}>
            {/* Chip + RFID waves container */}
            <div style={{ position: "relative", width: 52, height: 52, flexShrink: 0 }}>
              {/* Animated rings */}
              <div className="rfid-ring" />
              <div className="rfid-ring" />
              <div className="rfid-ring" />

              {/* Gold EMV chip */}
              <div style={{
                position: "absolute", top: "50%", left: "50%",
                transform: "translate(-50%, -50%)",
                width: 32, height: 24,
                borderRadius: 4,
                background: "linear-gradient(135deg, #b45309 0%, #fbbf24 35%, #92400e 55%, #d97706 80%, #fbbf24 100%)",
                animation: "chip-glow 2.5s ease-in-out infinite",
                boxShadow: "0 0 8px rgba(251,191,36,0.5), inset 0 1px 0 rgba(255,255,255,0.3)",
                display: "grid",
                gridTemplateColumns: "repeat(3, 1fr)",
                gridTemplateRows: "repeat(3, 1fr)",
                gap: "2px",
                padding: "4px 5px",
              }}>
                {Array.from({ length: 9 }).map((_, i) => (
                  <div key={i} style={{
                    background: i === 4
                      ? "rgba(0,0,0,0.15)"          /* center contact */
                      : "rgba(0,0,0,0.28)",
                    borderRadius: 1,
                  }} />
                ))}
              </div>
            </div>

            {/* Thin divider */}
            <div style={{ width: 1, height: 36, background: "rgba(148,163,184,0.15)", flexShrink: 0 }} />

            {/* Label */}
            <div>
              <div style={{
                fontSize: 8, fontWeight: 600, letterSpacing: "0.15em",
                color: "#64748b", fontFamily: "system-ui, sans-serif", marginBottom: 4,
              }}>
                CARTE RFID SCANNÉE
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                {/* Wifi / RFID icon using CSS arcs */}
                <svg width="16" height="12" viewBox="0 0 16 12" fill="none" style={{ opacity: 0.7 }}>
                  <path d="M8 10 C8 10 8 10 8 10" stroke="#22d3ee" strokeWidth="2" strokeLinecap="round"/>
                  <path d="M5.5 8 Q8 5.5 10.5 8" stroke="#22d3ee" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
                  <path d="M3 5.5 Q8 1 13 5.5" stroke="#22d3ee" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
                  <path d="M0.5 3 Q8 -2 15.5 3" stroke="#22d3ee" strokeWidth="1.5" strokeLinecap="round" fill="none" opacity="0.5"/>
                </svg>
                <span style={{ fontSize: 10, color: "#22d3ee", fontWeight: 500, fontFamily: "system-ui, sans-serif" }}>
                  Lecture sans contact
                </span>
              </div>
            </div>
          </div>

          {/* ── CARD NUMBER ── */}
          <div style={{ padding: "12px 20px 0" }}>
            <div style={{
              fontSize: 7, letterSpacing: "0.15em", color: "#475569",
              fontFamily: "system-ui, sans-serif", marginBottom: 5,
            }}>
              NUMÉRO DE CARTE
            </div>
            <div
              className="shimmer-text"
              style={{
                fontFamily: "'Courier New', Courier, monospace",
                fontSize,
                fontWeight: 700,
                letterSpacing: "0.1em",
                lineHeight: 1.2,
              }}
            >
              {formatted}
            </div>
          </div>

          {/* ── BOTTOM ROW ── */}
          <div style={{
            position: "absolute", bottom: 14, left: 20, right: 20,
            display: "flex", justifyContent: "space-between", alignItems: "flex-end",
          }}>
            {/* Hint */}
            <span style={{
              fontSize: 7, color: "#334155", letterSpacing: "0.08em",
              fontFamily: "system-ui, sans-serif",
            }}>
              Cliquer pour fermer
            </span>

            {/* Contactless symbol (stylised) */}
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" style={{ opacity: 0.25 }}>
              <circle cx="12" cy="12" r="2" fill="white"/>
              <path d="M9 9.5 Q12 6 15 9.5" stroke="white" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
              <path d="M6.5 7 Q12 1.5 17.5 7" stroke="white" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
              <path d="M4 4.5 Q12 -3 20 4.5" stroke="white" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
            </svg>
          </div>

          {/* ── PROGRESS BAR (within card, at very bottom) ── */}
          <div style={{
            position: "absolute", bottom: 0, left: 0, right: 0,
            height: 3,
            background: "rgba(255,255,255,0.05)",
          }}>
            <div style={{
              height: "100%",
              width: `${progress}%`,
              background: "linear-gradient(90deg, #4ade80, #22d3ee)",
              transition: "width 80ms linear",
              borderRadius: "0 2px 0 0",
            }} />
          </div>
        </div>

        {/* Reflection below card */}
        <div style={{
          position: "absolute",
          width: 400,
          height: 40,
          top: "calc(50% + 126px)",
          borderRadius: "0 0 16px 16px",
          background: "linear-gradient(to bottom, rgba(13,27,62,0.25) 0%, transparent 100%)",
          transform: "scaleY(-1)",
          pointerEvents: "none",
          opacity: 0.4,
        }} />
      </div>
    </>
  );
}
