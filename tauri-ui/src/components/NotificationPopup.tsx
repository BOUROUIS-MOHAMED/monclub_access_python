import { Box, Typography, Chip, Fade } from "@mui/material";
import PersonIcon from "@mui/icons-material/Person";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import type { PopupEvent } from "../api/types";

interface Props {
  popup: PopupEvent | null;
  onDismiss: () => void;
}

/**
 * Fallback in-window notification popup for browser dev mode.
 * In Tauri, popups open in a separate window (PopupWindow.tsx).
 * This component only shows when the Tauri window API is unavailable.
 */
export default function NotificationPopup({ popup, onDismiss }: Props) {
  if (!popup) return null;

  const allowed = popup.allowed;
  const accentColor = allowed ? "#22c55e" : "#ef4444";
  const statusLabel = allowed ? "ACCÈS AUTORISÉ" : "ACCÈS REFUSÉ";

  const imageUrl = popup.popupShowImage
    ? (popup.userImage || popup.userProfileImage || popup.imagePath || "")
    : "";

  const formatDate = (d: string) => {
    if (!d) return "—";
    try {
      const dt = new Date(d.replace("Z", "+00:00"));
      if (isNaN(dt.getTime())) return d;
      return dt.toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "numeric" });
    } catch { return d; }
  };

  return (
    <Fade in timeout={300}>
      <Box
        onClick={onDismiss}
        sx={{
          position: "fixed", inset: 0, zIndex: 9999,
          display: "grid",
          gridTemplateColumns: "1fr 1fr 1fr 1fr",
          gridTemplateRows: "auto 1fr 1fr auto",
          bgcolor: "#000", cursor: "pointer", overflow: "hidden",
        }}
      >
        {/* ROW 1: Header */}
        <Box sx={{
          gridColumn: "1 / -1",
          display: "flex", alignItems: "center", justifyContent: "space-between",
          px: 4, py: 2, bgcolor: "#111",
          borderBottom: `3px solid ${accentColor}`,
        }}>
          <Typography variant="h5" sx={{ color: "#fff", fontWeight: 700 }}>
            {popup.deviceName || `Appareil #${popup.deviceId}`}
          </Typography>
          <Chip label={statusLabel} sx={{ bgcolor: accentColor, color: "#fff", fontWeight: 700, fontSize: "1.1rem", height: 40, px: 2 }} />
        </Box>

        {/* ROW 2-3, COL 1: Info left */}
        <Box sx={{ gridColumn: "1/2", gridRow: "2/4", display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "flex-end", px: 3, py: 2, bgcolor: allowed ? "rgba(34,197,94,0.1)" : "rgba(239,68,68,0.1)" }}>
          <Typography variant="overline" sx={{ color: "#888", mb: 0.5 }}>Nom complet</Typography>
          <Typography variant="h4" sx={{ color: "#fff", fontWeight: 700, textAlign: "right", mb: 3 }}>{popup.userFullName || "—"}</Typography>
          <Typography variant="overline" sx={{ color: "#888", mb: 0.5 }}>Téléphone</Typography>
          <Typography variant="h6" sx={{ color: "#ccc", textAlign: "right" }}>{popup.userPhone || "—"}</Typography>
        </Box>

        {/* ROW 2-3, COL 2-3: Image */}
        <Box sx={{ gridColumn: "2/4", gridRow: "2/4", display: "flex", alignItems: "center", justifyContent: "center", bgcolor: "#0a0a0a", p: 2 }}>
          {imageUrl ? (
            <Box component="img" src={imageUrl} alt={popup.userFullName}
              onError={(e: React.SyntheticEvent<HTMLImageElement>) => { e.currentTarget.style.display = "none"; const ph = e.currentTarget.nextElementSibling as HTMLElement; if (ph) ph.style.display = "flex"; }}
              sx={{ maxWidth: "100%", maxHeight: "100%", objectFit: "contain", borderRadius: 2, border: `3px solid ${accentColor}` }} />
          ) : null}
          <Box sx={{ display: imageUrl ? "none" : "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", width: 280, height: 280, borderRadius: 2, border: `3px solid ${accentColor}`, bgcolor: "#1a1a1a" }}>
            <PersonIcon sx={{ fontSize: 120, color: "#555" }} />
            <Typography variant="body2" sx={{ color: "#555", mt: 1 }}>Photo non disponible</Typography>
          </Box>
        </Box>

        {/* Image flags */}
        {(popup.imageSource === 'PROFILE_BORROWED' || popup.userImageStatus === 'REQUIRED_CHANGE') && (
          <Box sx={{ gridColumn: "2/4", display: "flex", flexWrap: "wrap", gap: 1, px: 2, pb: 1 }}>
            {popup.imageSource === 'PROFILE_BORROWED' && (
              <Chip
                size="small"
                icon={<PersonIcon />}
                label="Profile photo — no gym image set"
              />
            )}
            {popup.userImageStatus === 'REQUIRED_CHANGE' && (
              <Chip
                size="small"
                color="warning"
                icon={<WarningAmberIcon />}
                label="Image change required"
              />
            )}
          </Box>
        )}

        {/* ROW 2-3, COL 4: Info right */}
        <Box sx={{ gridColumn: "4/5", gridRow: "2/4", display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "flex-start", px: 3, py: 2, bgcolor: allowed ? "rgba(34,197,94,0.1)" : "rgba(239,68,68,0.1)" }}>
          <Typography variant="overline" sx={{ color: "#888", mb: 0.5 }}>Abonnement</Typography>
          <Typography variant="h5" sx={{ color: "#fff", fontWeight: 600, mb: 3 }}>{popup.userMembershipId ?? "—"}</Typography>
          <Typography variant="overline" sx={{ color: "#888", mb: 0.5 }}>Valide du</Typography>
          <Typography variant="h6" sx={{ color: "#ccc", mb: 2 }}>{formatDate(popup.userValidFrom)}</Typography>
          <Typography variant="overline" sx={{ color: "#888", mb: 0.5 }}>Valide jusqu'au</Typography>
          <Typography variant="h6" sx={{ color: "#ccc" }}>{formatDate(popup.userValidTo)}</Typography>
        </Box>

        {/* ROW 4: Footer */}
        <Box sx={{ gridColumn: "1/-1", display: "flex", alignItems: "center", justifyContent: "space-between", px: 4, py: 2, bgcolor: "#111", borderTop: `3px solid ${accentColor}` }}>
          <Typography variant="body1" sx={{ color: "#999" }}>
            {popup.scanMode && <Chip label={popup.scanMode} size="small" variant="outlined" sx={{ color: "#ccc", borderColor: "#555", mr: 1 }} />}
            {popup.reason && !popup.reason.startsWith("ALLOW") && <Chip label={popup.reason} size="small" variant="outlined" sx={{ color: accentColor, borderColor: accentColor }} />}
          </Typography>
          <Typography variant="body2" sx={{ color: "#666" }}>
            {popup.eventId ? `Event: ${popup.eventId.slice(0, 12)}…` : ""}
            {popup.receivedAt ? ` • ${new Date(popup.receivedAt).toLocaleTimeString("fr-FR")}` : ""}
          </Typography>
        </Box>
      </Box>
    </Fade>
  );
}
