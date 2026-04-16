import {
  Drawer, Box, Typography, Stack, IconButton, Chip, List, ListItem,
  ListItemAvatar, ListItemText, Avatar, Divider, Button,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import DeleteSweepIcon from "@mui/icons-material/DeleteSweep";
import PersonIcon from "@mui/icons-material/Person";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import CancelIcon from "@mui/icons-material/Cancel";
import type { PopupEvent } from "../api/types";

interface Props {
  open: boolean;
  onClose: () => void;
  history: PopupEvent[];
  onClear: () => void;
}

export default function NotificationDrawer({ open, onClose, history, onClear }: Props) {
  const formatTime = (ts?: number) => {
    if (!ts) return "";
    return new Date(ts).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  return (
    <Drawer anchor="right" open={open} onClose={onClose}
      slotProps={{ paper: { sx: { width: 420, maxWidth: "90vw", bgcolor: "background.paper" } } }}>
      <Box sx={{ p: 2 }}>
        <Stack direction="row" alignItems="center" sx={{ mb: 2 }}>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>Notifications</Typography>
          {history.length > 0 && (
            <Button size="small" startIcon={<DeleteSweepIcon />} onClick={onClear} color="warning">
              Effacer
            </Button>
          )}
          <IconButton onClick={onClose} size="small" sx={{ ml: 1 }}>
            <CloseIcon />
          </IconButton>
        </Stack>

        {history.length === 0 ? (
          <Typography variant="body2" color="text.secondary" sx={{ textAlign: "center", py: 4 }}>
            Aucune notification récente
          </Typography>
        ) : (
          <List disablePadding>
            {history.map((evt, idx) => (
              <Box key={evt.eventId || idx}>
                {idx > 0 && <Divider />}
                <ListItem alignItems="flex-start" sx={{ px: 0, py: 1.5 }}>
                  <ListItemAvatar>
                    <Avatar
                      src={evt.popupShowImage ? (evt.userImage || evt.userProfileImage || evt.imagePath || undefined) : undefined}
                      sx={{
                        bgcolor: evt.allowed ? "success.main" : "error.main",
                        width: 48, height: 48,
                      }}
                    >
                      <PersonIcon />
                    </Avatar>
                  </ListItemAvatar>
                  <ListItemText
                    primary={
                      <Stack direction="row" alignItems="center" spacing={1}>
                        {evt.allowed ? (
                          <CheckCircleIcon color="success" sx={{ fontSize: 18 }} />
                        ) : (
                          <CancelIcon color="error" sx={{ fontSize: 18 }} />
                        )}
                        <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                          {evt.userFullName || "Inconnu"}
                        </Typography>
                        <Chip label={evt.deviceName || `#${evt.deviceId}`}
                          size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                      </Stack>
                    }
                    secondary={
                      <Box component="span" sx={{ display: "block" }}>
                        <Typography variant="caption" color="text.secondary" component="span">
                          {formatTime(evt.receivedAt)}
                          {evt.scanMode && ` • ${evt.scanMode}`}
                          {evt.reason && ` • ${evt.reason}`}
                        </Typography>
                        {evt.userMembershipId != null && (
                          <Typography variant="caption" color="text.secondary" component="span" sx={{ display: "block" }}>
                            Abonnement #{evt.userMembershipId}
                          </Typography>
                        )}
                      </Box>
                    }
                  />
                </ListItem>
              </Box>
            ))}
          </List>
        )}
      </Box>
    </Drawer>
  );
}

