import { useCallback, useEffect, useState } from "react";
import { Box, Button, Typography } from "@mui/material";
import { keyframes } from "@mui/material/styles";
import BuildIcon from "@mui/icons-material/Build";
import CardGiftcardIcon from "@mui/icons-material/CardGiftcard";
import CenterFocusStrongIcon from "@mui/icons-material/CenterFocusStrong";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import FaceIcon from "@mui/icons-material/Face";
import ReplayIcon from "@mui/icons-material/Replay";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import ShieldIcon from "@mui/icons-material/Shield";
import { shouldShowWhatsNew } from "@/lib/whatsNew";
import { ACCESS_CHANGELOG } from "@/whats-new/access-changelog";

const STORAGE_KEY = "monclub.access.whatsNew.lastShownVersion";
const DURATION_SECONDS = 20;
const ringPulse = keyframes`
  0% { transform: scale(0.7); opacity: 0.8; }
  100% { transform: scale(1.6); opacity: 0; }
`;

const CATEGORIES = {
  new: { icon: CardGiftcardIcon, tint: "rgba(142,51,255,0.2)", fg: "#C684FF" },
  perf: { icon: RocketLaunchIcon, tint: "rgba(0,184,217,0.2)", fg: "#61F3F3" },
  fix: { icon: BuildIcon, tint: "rgba(34,197,94,0.2)", fg: "#77ED8B" },
  acc: { icon: CenterFocusStrongIcon, tint: "rgba(24,119,242,0.2)", fg: "#73BAFB" },
  sec: { icon: ShieldIcon, tint: "rgba(69,79,91,0.2)", fg: "#C4CDD5" },
};

function lastShownVersion(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

// The layout keys this component by version so a version change starts a fresh card.
export default function AccessWhatsNewCard({ version }: { version: string }) {
  const [items, setItems] = useState(() => shouldShowWhatsNew(version, lastShownVersion(), ACCESS_CHANGELOG));
  const [secondsLeft, setSecondsLeft] = useState(DURATION_SECONDS);

  const close = useCallback(() => {
    setItems(null);
    try {
      localStorage.setItem(STORAGE_KEY, version);
    } catch {
      // The card still closes when storage is unavailable.
    }
  }, [version]);

  useEffect(() => {
    if (!items) return;
    const deadline = Date.now() + DURATION_SECONDS * 1000;
    const interval = window.setInterval(() => {
      setSecondsLeft(Math.max(0, Math.ceil((deadline - Date.now()) / 1000)));
    }, 1000);
    const timeout = window.setTimeout(close, DURATION_SECONDS * 1000);
    return () => {
      window.clearInterval(interval);
      window.clearTimeout(timeout);
    };
  }, [items, close]);

  if (!items) return null;

  return (
    <Box
      component="section"
      aria-labelledby="access-whats-new-title"
      sx={{
        position: "fixed", right: "24px", bottom: "24px", width: "400px",
        maxWidth: "calc(100vw - 48px)", maxHeight: "calc(100vh - 48px)", overflow: "auto",
        zIndex: 1200, borderRadius: "16px", bgcolor: "#1C252E", color: "#FFFFFF",
        border: "1px solid rgba(145,158,171,0.16)", boxShadow: "0 24px 48px rgba(0,0,0,0.5)",
        fontFamily: "'DM Sans', sans-serif",
      }}
    >
      <Box sx={{ position: "relative", height: "96px", overflow: "hidden", background: "linear-gradient(135deg, #042174 0%, #1877F2 100%)" }}>
        <Box aria-hidden="true" sx={{
          position: "absolute", inset: 0,
          backgroundImage: "radial-gradient(rgba(255,255,255,0.18) 1px, transparent 1px)",
          backgroundSize: "16px 16px",
        }} />
        <Box aria-hidden="true" sx={{ position: "absolute", right: "18px", top: 0, bottom: 0, width: "120px", display: "grid", placeItems: "center" }}>
          <svg width="75" height="75" viewBox="0 0 80 80" fill="none">
            <path d="M17 68V26a5 5 0 0 1 5-5h13a5 5 0 0 1 5 5v42M13 68h31M21 15h15" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
            <rect x="23" y="28" width="11" height="8" rx="2" fill="currentColor" />
            <circle cx="40" cy="43" r="5" fill="currentColor" />
            <path d="m40 43 24-14M40 43l24 14M40 43v24" stroke="currentColor" strokeWidth="4" strokeLinecap="round" />
          </svg>
        </Box>
        <Box aria-hidden="true" sx={{
          position: "absolute", left: "calc(50% - 31px)", top: "calc(46% - 31px)",
          width: "62px", height: "62px", borderRadius: "50%", border: "3px solid rgba(119,237,139,0.9)",
          animation: `${ringPulse} 2s ease-in-out infinite`,
          "@media (prefers-reduced-motion: reduce)": { animation: "none" },
        }} />
        <FaceIcon aria-hidden="true" sx={{ position: "absolute", left: "71%", top: "12%", fontSize: "27px" }} />
        <ReplayIcon aria-hidden="true" sx={{ position: "absolute", left: "27%", top: "16%", fontSize: "20px", opacity: 0.8 }} />
        <CheckCircleIcon aria-hidden="true" sx={{ position: "absolute", left: "67%", top: "58%", fontSize: "20px", color: "#77ED8B" }} />
        <Typography id="access-whats-new-title" component="h2" sx={{
          position: "absolute", left: "16px", right: "12px", bottom: "12px",
          fontFamily: "'Barlow', sans-serif", fontSize: "19px", fontWeight: 800, lineHeight: 1.2,
          textShadow: "0 2px 8px rgba(0,0,0,0.2)",
        }}>
          Nouveautés de MonClub Access {version}
        </Typography>
      </Box>

      <Box component="ul" sx={{ m: 0, p: "10px 14px 4px", listStyle: "none" }}>
        {items.slice(0, 4).map((item, index) => {
          const { icon: Icon, tint, fg } = CATEGORIES[item.category];
          return (
            <Box component="li" key={index} sx={{
              display: "flex", gap: "10px", alignItems: "flex-start", p: "8px 2px",
              borderTop: index ? "1px solid rgba(145,158,171,0.16)" : "none",
            }}>
              <Box sx={{ width: "28px", height: "28px", borderRadius: "8px", bgcolor: tint, color: fg, display: "grid", placeItems: "center", flexShrink: 0 }}>
                <Icon aria-hidden="true" sx={{ fontSize: "15px" }} />
              </Box>
              <Typography sx={{ flex: 1, fontFamily: "inherit", fontSize: "13.5px", fontWeight: 600, lineHeight: 1.4 }}>{item.fr}</Typography>
            </Box>
          );
        })}
      </Box>

      <Box sx={{ p: "10px 14px 14px", display: "flex", alignItems: "center", gap: "10px" }}>
        <Box aria-hidden="true" sx={{ flex: 1, height: "4px", borderRadius: "2px", bgcolor: "rgba(145,158,171,0.2)", overflow: "hidden" }}>
          <Box sx={{ width: `${(secondsLeft / DURATION_SECONDS) * 100}%`, height: "4px", bgcolor: "#73BAFB" }} />
        </Box>
        <Typography sx={{ fontFamily: "inherit", fontSize: "11.5px", color: "#919EAB", whiteSpace: "nowrap" }}>se ferme dans {secondsLeft} s</Typography>
        <Button onClick={close} disableElevation sx={{
          minWidth: 0, height: "34px", px: "16px", borderRadius: "8px", bgcolor: "#FFFFFF", color: "#1C252E",
          fontFamily: "inherit", fontSize: "14px", fontWeight: 700, textTransform: "none",
          "&:hover": { bgcolor: "#DFE3E8" }, "&.Mui-focusVisible": { outline: "3px solid #73BAFB", outlineOffset: "2px" },
        }}>Compris</Button>
      </Box>
    </Box>
  );
}
