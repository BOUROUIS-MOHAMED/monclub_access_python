/**
 * ScanResultPage — RFID scan popup window.
 *
 * Lifecycle:
 *   1. Opens immediately on shortcut press in "scanning" state — shows pulsing
 *      card animation so the operator knows to place their card.
 *   2. Listens for the Tauri "scan-shortcut-result" event.
 *   3. Transitions to "result" (card number) or "error" state.
 *   4. Auto-closes 3 s after the result arrives, with a fade-out to avoid
 *      the white-panel flash.
 *
 * Window: 440 × 278 px, no decorations, always-on-top, centered.
 */

import { useEffect, useRef, useState } from "react";

type Phase = "scanning" | "result" | "error";

const RESULT_DISPLAY_MS = 3500;
const FADE_MS           = 220;

function formatCard(raw: string): string {
  const digits = raw.replace(/\s+/g, "");
  return digits.match(/.{1,4}/g)?.join("  ") ?? digits;
}

function closeWindow() {
  import("@tauri-apps/api/window")
    .then(({ getCurrentWindow }) => getCurrentWindow().close())
    .catch(() => { /* ignore */ });
}

export default function ScanResultPage() {
  const [phase, setPhase]     = useState<Phase>("scanning");
  const [card, setCard]       = useState("");
  const [errMsg, setErrMsg]   = useState("");
  const [progress, setProgress] = useState(100);   // countdown bar 100→0
  const [opacity, setOpacity] = useState(0);       // fade-in on mount, fade-out on close

  const rafRef      = useRef<number | null>(null);
  const startRef    = useRef<number>(0);
  const closing     = useRef(false);

  // ── Fade in on mount ──
  useEffect(() => {
    requestAnimationFrame(() => setOpacity(1));
  }, []);

  // ── Listen for scan result from Rust ──
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    (async () => {
      try {
        const { listen } = await import("@tauri-apps/api/event");
        unlisten = await listen<{
          ok: boolean;
          card: string;
          error?: string | null;
        }>("scan-shortcut-result", (ev) => {
          const p = ev.payload;
          if (p.ok && p.card) {
            setCard(p.card);
            setPhase("result");
          } else {
            setErrMsg(p.error ?? "Aucune carte détectée");
            setPhase("error");
          }
        });
      } catch { /* non-Tauri */ }
    })();
    return () => { if (unlisten) unlisten(); };
  }, []);

  // ── Countdown + auto-close once we have a result ──
  useEffect(() => {
    if (phase !== "result" && phase !== "error") return;
    startRef.current = performance.now();

    const tick = (now: number) => {
      const elapsed = now - startRef.current;
      const pct = Math.max(0, 1 - elapsed / RESULT_DISPLAY_MS);
      setProgress(pct * 100);
      if (pct > 0) {
        rafRef.current = requestAnimationFrame(tick);
      } else {
        triggerClose();
      }
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => { if (rafRef.current !== null) cancelAnimationFrame(rafRef.current); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase]);

  function triggerClose() {
    if (closing.current) return;
    closing.current = true;
    if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
    setOpacity(0);
    setTimeout(closeWindow, FADE_MS + 50);
  }

  const formatted  = formatCard(card);
  const numFontSize = formatted.length > 23 ? 14 : formatted.length > 14 ? 17 : 21;

  return (
    <>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        /* Dark bg on html/body prevents white flash when window closes */
        html, body, #root { width: 100%; height: 100%; overflow: hidden; background: #080d1a; }

        @keyframes ring-pulse {
          0%   { transform: translate(-50%,-50%) scale(0.5); opacity: 1; }
          100% { transform: translate(-50%,-50%) scale(2.6); opacity: 0; }
        }
        .rfid-ring {
          position: absolute; top: 50%; left: 50%;
          border-radius: 50%;
          border: 1.5px solid rgba(74,222,128,0.7);
          animation: ring-pulse 2s ease-out infinite;
          pointer-events: none;
        }
        .rfid-ring:nth-child(1) { width: 28px; height: 28px; animation-delay: 0s;    }
        .rfid-ring:nth-child(2) { width: 28px; height: 28px; animation-delay: 0.6s;  }
        .rfid-ring:nth-child(3) { width: 28px; height: 28px; animation-delay: 1.2s;  }

        @keyframes chip-glow {
          0%,100% { box-shadow: 0 0 6px 1px rgba(251,191,36,.5); }
          50%      { box-shadow: 0 0 16px 4px rgba(251,191,36,.9); }
        }
        @keyframes shimmer {
          0%   { background-position: 200% center; }
          100% { background-position:-200% center; }
        }
        .shimmer-text {
          background: linear-gradient(90deg,#4ade80 0%,#22d3ee 25%,#a3e635 50%,#22d3ee 75%,#4ade80 100%);
          background-size: 300% auto;
          -webkit-background-clip: text; -webkit-text-fill-color: transparent;
          background-clip: text;
          animation: shimmer 3s linear infinite;
        }
        @keyframes card-in {
          from { opacity:0; transform: scale(.92) translateY(8px); }
          to   { opacity:1; transform: scale(1)   translateY(0);   }
        }
        .card-root { animation: card-in .25s cubic-bezier(.34,1.56,.64,1) forwards; }

        @keyframes badge-pop {
          0%  { transform:scale(0); opacity:0; }
          60% { transform:scale(1.2); opacity:1; }
          100%{ transform:scale(1);   opacity:1; }
        }
        .badge { animation: badge-pop .4s .05s cubic-bezier(.34,1.56,.64,1) both; }

        /* Scanning state: big pulsing ripple behind card icon */
        @keyframes scan-ripple {
          0%   { transform:scale(.8); opacity:.6; }
          100% { transform:scale(2.8); opacity:0; }
        }
        .scan-ripple {
          position:absolute; inset:0; margin:auto;
          width:80px; height:80px; border-radius:50%;
          border:2px solid rgba(34,211,238,.5);
          animation: scan-ripple 1.8s ease-out infinite;
          pointer-events:none;
        }
        .scan-ripple:nth-child(2) { animation-delay:.6s; }
        .scan-ripple:nth-child(3) { animation-delay:1.2s; }

        @keyframes float-card {
          0%,100% { transform: translateY(0); }
          50%      { transform: translateY(-5px); }
        }
        .float-card { animation: float-card 2.4s ease-in-out infinite; }

        .scanlines::after {
          content:""; position:absolute; inset:0;
          background:repeating-linear-gradient(to bottom,transparent 0,transparent 3px,rgba(0,0,0,.07) 3px,rgba(0,0,0,.07) 4px);
          pointer-events:none; border-radius:inherit;
        }
      `}</style>

      {/* Root shell — fade in/out controls white-flash prevention */}
      <div
        onClick={triggerClose}
        style={{
          width:"100vw", height:"100vh",
          display:"flex", alignItems:"center", justifyContent:"center",
          background:"radial-gradient(ellipse at 60% 40%, #0f2035 0%, #080d1a 100%)",
          cursor:"pointer", userSelect:"none", position:"relative", overflow:"hidden",
          opacity, transition:`opacity ${FADE_MS}ms ease`,
        }}
      >
        {/* Ambient glow */}
        <div style={{
          position:"absolute", width:300, height:180, borderRadius:"50%",
          background:"radial-gradient(ellipse, rgba(34,211,238,.07) 0%, transparent 70%)",
          pointerEvents:"none",
        }}/>

        {/* ═══════════════ SCANNING STATE ═══════════════ */}
        {phase === "scanning" && (
          <div style={{
            display:"flex", flexDirection:"column", alignItems:"center",
            gap:18, padding:"0 24px",
          }}>
            {/* Ripples + floating card icon */}
            <div style={{ position:"relative", width:100, height:100 }}>
              <div className="scan-ripple"/>
              <div className="scan-ripple"/>
              <div className="scan-ripple"/>
              <div className="float-card" style={{
                position:"absolute", inset:0, display:"flex",
                alignItems:"center", justifyContent:"center",
                fontSize:44, lineHeight:1,
              }}>
                🪪
              </div>
            </div>

            <div style={{ textAlign:"center" }}>
              <div style={{
                fontSize:15, fontWeight:700, color:"#e2e8f0",
                fontFamily:"system-ui, sans-serif", letterSpacing:".02em",
                marginBottom:6,
              }}>
                Approchez votre carte
              </div>
              <div style={{
                fontSize:11, color:"#64748b",
                fontFamily:"system-ui, sans-serif", letterSpacing:".08em",
              }}>
                SCANNER EN ATTENTE…
              </div>
            </div>

            {/* Indeterminate scan bar */}
            <div style={{
              position:"absolute", bottom:0, left:0, right:0,
              height:3, overflow:"hidden",
              background:"rgba(255,255,255,.05)",
            }}>
              <div style={{
                height:"100%", width:"35%",
                background:"linear-gradient(90deg,transparent,#22d3ee,transparent)",
                animation:"shimmer 1.4s linear infinite",
                backgroundSize:"300% auto",
              }}/>
            </div>
          </div>
        )}

        {/* ═══════════════ RESULT STATE ═══════════════ */}
        {(phase === "result" || phase === "error") && (
          <div
            className="card-root scanlines"
            style={{
              position:"relative", width:400, height:252, borderRadius:16,
              background:"linear-gradient(135deg,#0d1b3e 0%,#1a2357 40%,#0d2548 70%,#0a1628 100%)",
              boxShadow:[
                "0 2px 0 rgba(255,255,255,.06) inset",
                "0 -1px 0 rgba(0,0,0,.6) inset",
                "0 20px 50px rgba(0,0,0,.7)",
                "0 0 0 1px rgba(255,255,255,.08)",
              ].join(","),
              overflow:"hidden", flexShrink:0,
            }}
          >
            {/* Holographic gleam */}
            <div style={{
              position:"absolute", top:-30, right:-30,
              width:140, height:140, borderRadius:"50%",
              background:"radial-gradient(circle,rgba(167,139,250,.12) 0%,transparent 65%)",
              pointerEvents:"none",
            }}/>
            <div style={{
              position:"absolute", top:0, left:"30%", width:"55%", height:"100%",
              background:"linear-gradient(105deg,transparent 45%,rgba(255,255,255,.03) 50%,transparent 55%)",
              pointerEvents:"none",
            }}/>

            {/* TOP ROW */}
            <div style={{
              display:"flex", justifyContent:"space-between", alignItems:"flex-start",
              padding:"18px 20px 0",
            }}>
              <div>
                <div style={{fontSize:9,fontWeight:800,letterSpacing:".2em",color:"#60a5fa",fontFamily:"system-ui,sans-serif"}}>
                  MONCLUB
                </div>
                <div style={{fontSize:7,letterSpacing:".15em",color:"#3b82f6",fontFamily:"system-ui,sans-serif",marginTop:1}}>
                  ACCESS CONTROL
                </div>
              </div>

              {phase === "result" ? (
                <div className="badge" style={{
                  display:"flex",alignItems:"center",gap:5,
                  background:"rgba(74,222,128,.12)",
                  border:"1px solid rgba(74,222,128,.35)",
                  borderRadius:20, padding:"4px 10px",
                }}>
                  <div style={{width:6,height:6,borderRadius:"50%",background:"#4ade80",boxShadow:"0 0 6px rgba(74,222,128,.9)"}}/>
                  <span style={{fontSize:9,fontWeight:700,color:"#4ade80",letterSpacing:".1em",fontFamily:"system-ui,sans-serif"}}>
                    VALIDÉ
                  </span>
                </div>
              ) : (
                <div className="badge" style={{
                  display:"flex",alignItems:"center",gap:5,
                  background:"rgba(248,113,113,.12)",
                  border:"1px solid rgba(248,113,113,.35)",
                  borderRadius:20, padding:"4px 10px",
                }}>
                  <div style={{width:6,height:6,borderRadius:"50%",background:"#f87171",boxShadow:"0 0 6px rgba(248,113,113,.9)"}}/>
                  <span style={{fontSize:9,fontWeight:700,color:"#f87171",letterSpacing:".1em",fontFamily:"system-ui,sans-serif"}}>
                    ERREUR
                  </span>
                </div>
              )}
            </div>

            {/* MIDDLE ROW: chip + waves */}
            <div style={{display:"flex",alignItems:"center",padding:"14px 20px 0",gap:18}}>
              <div style={{position:"relative",width:52,height:52,flexShrink:0}}>
                <div className="rfid-ring"/>
                <div className="rfid-ring"/>
                <div className="rfid-ring"/>
                <div style={{
                  position:"absolute",top:"50%",left:"50%",
                  transform:"translate(-50%,-50%)",
                  width:32,height:24,borderRadius:4,
                  background:"linear-gradient(135deg,#b45309 0%,#fbbf24 35%,#92400e 55%,#d97706 80%,#fbbf24 100%)",
                  animation:"chip-glow 2.5s ease-in-out infinite",
                  boxShadow:"0 0 8px rgba(251,191,36,.5),inset 0 1px 0 rgba(255,255,255,.3)",
                  display:"grid",gridTemplateColumns:"repeat(3,1fr)",gridTemplateRows:"repeat(3,1fr)",
                  gap:"2px",padding:"4px 5px",
                }}>
                  {Array.from({length:9}).map((_,i)=>(
                    <div key={i} style={{background:i===4?"rgba(0,0,0,.15)":"rgba(0,0,0,.28)",borderRadius:1}}/>
                  ))}
                </div>
              </div>

              <div style={{width:1,height:36,background:"rgba(148,163,184,.15)",flexShrink:0}}/>

              <div>
                <div style={{fontSize:8,fontWeight:600,letterSpacing:".15em",color:"#64748b",fontFamily:"system-ui,sans-serif",marginBottom:4}}>
                  CARTE RFID SCANNÉE
                </div>
                <div style={{display:"flex",alignItems:"center",gap:6}}>
                  <svg width="16" height="12" viewBox="0 0 16 12" fill="none" style={{opacity:.7}}>
                    <path d="M8 10 C8 10 8 10 8 10" stroke="#22d3ee" strokeWidth="2" strokeLinecap="round"/>
                    <path d="M5.5 8 Q8 5.5 10.5 8" stroke="#22d3ee" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
                    <path d="M3 5.5 Q8 1 13 5.5"   stroke="#22d3ee" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
                    <path d="M0.5 3 Q8 -2 15.5 3"  stroke="#22d3ee" strokeWidth="1.5" strokeLinecap="round" fill="none" opacity=".5"/>
                  </svg>
                  <span style={{fontSize:10,color:"#22d3ee",fontWeight:500,fontFamily:"system-ui,sans-serif"}}>
                    Lecture sans contact
                  </span>
                </div>
              </div>
            </div>

            {/* CARD NUMBER / ERROR */}
            <div style={{padding:"12px 20px 0"}}>
              <div style={{fontSize:7,letterSpacing:".15em",color:"#475569",fontFamily:"system-ui,sans-serif",marginBottom:5}}>
                {phase === "result" ? "NUMÉRO DE CARTE" : "ERREUR DE LECTURE"}
              </div>
              {phase === "result" ? (
                <div className="shimmer-text" style={{
                  fontFamily:"'Courier New',Courier,monospace",
                  fontSize:numFontSize, fontWeight:700, letterSpacing:".1em", lineHeight:1.2,
                }}>
                  {formatted}
                </div>
              ) : (
                <div style={{
                  fontFamily:"system-ui,sans-serif", fontSize:12,
                  color:"#f87171", fontWeight:500, lineHeight:1.4,
                  maxWidth:280, overflowWrap:"break-word",
                }}>
                  {errMsg}
                </div>
              )}
            </div>

            {/* BOTTOM */}
            <div style={{
              position:"absolute",bottom:14,left:20,right:20,
              display:"flex",justifyContent:"space-between",alignItems:"flex-end",
            }}>
              <span style={{fontSize:7,color:"#334155",letterSpacing:".08em",fontFamily:"system-ui,sans-serif"}}>
                Cliquer pour fermer
              </span>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" style={{opacity:.2}}>
                <circle cx="12" cy="12" r="2" fill="white"/>
                <path d="M9 9.5 Q12 6 15 9.5"   stroke="white" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
                <path d="M6.5 7 Q12 1.5 17.5 7" stroke="white" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
                <path d="M4 4.5 Q12 -3 20 4.5"  stroke="white" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
              </svg>
            </div>

            {/* PROGRESS BAR */}
            <div style={{position:"absolute",bottom:0,left:0,right:0,height:3,background:"rgba(255,255,255,.05)"}}>
              <div style={{
                height:"100%", width:`${progress}%`,
                background: phase === "result"
                  ? "linear-gradient(90deg,#4ade80,#22d3ee)"
                  : "linear-gradient(90deg,#f87171,#fb923c)",
                transition:"width 80ms linear",
                borderRadius:"0 2px 0 0",
              }}/>
            </div>
          </div>
        )}

        {/* Reflection */}
        {(phase === "result" || phase === "error") && (
          <div style={{
            position:"absolute", width:400, height:40,
            top:"calc(50% + 126px)", borderRadius:"0 0 16px 16px",
            background:"linear-gradient(to bottom,rgba(13,27,62,.25) 0%,transparent 100%)",
            transform:"scaleY(-1)", pointerEvents:"none", opacity:.4,
          }}/>
        )}
      </div>
    </>
  );
}
