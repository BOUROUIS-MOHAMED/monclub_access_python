import { Card, CardContent, CardActions, Typography, Box, Stack, Button, Chip } from "@mui/material";
import RouterIcon from "@mui/icons-material/Router";
import LockOpenIcon from "@mui/icons-material/LockOpen";
import InfoIcon from "@mui/icons-material/Info";
import StatusChip from "./StatusChip";

interface DeviceProps {
  device: {
    id?: number;
    name?: string;
    deviceName?: string;
    ipAddress?: string;
    ip_address?: string;
    portNumber?: string | number;
    port_number?: string | number;
    accessDataMode?: string;
    access_data_mode?: string;
    platform?: string;
    active?: boolean;
    [key: string]: unknown;
  };
  connected?: boolean;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onDoorOpen?: () => void;
  onInfo?: () => void;
}

export default function DeviceCard({ device, connected = false, onConnect, onDisconnect, onDoorOpen, onInfo }: DeviceProps) {
  const name = device.name || device.deviceName || "Device";
  const ip = device.ipAddress || device.ip_address || "—";
  const port = device.portNumber || device.port_number || "";
  const mode = (device.accessDataMode || device.access_data_mode || "UNKNOWN").toUpperCase();
  const platform = device.platform || "";

  return (
    <Card sx={{ height: "100%", display: "flex", flexDirection: "column" }}>
      <CardContent sx={{ flexGrow: 1 }}>
        <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
          <RouterIcon color="primary" />
          <Typography variant="h6" sx={{ flexGrow: 1 }}>{name}</Typography>
          <StatusChip variant={connected ? "online" : "offline"} label={connected ? "Connected" : "Offline"} />
        </Stack>

        <Box sx={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: 0.5, fontSize: "0.85rem" }}>
          <Typography variant="body2" color="text.secondary">IP:</Typography>
          <Typography variant="body2">{ip}{port ? `:${port}` : ""}</Typography>

          <Typography variant="body2" color="text.secondary">Mode:</Typography>
          <Box>
            <Chip label={mode} size="small" color={mode === "AGENT" ? "info" : mode === "DEVICE" ? "success" : "default"} variant="outlined" />
          </Box>

          {platform && (
            <>
              <Typography variant="body2" color="text.secondary">Platform:</Typography>
              <Typography variant="body2">{platform}</Typography>
            </>
          )}
        </Box>
      </CardContent>

      <CardActions sx={{ px: 2, pb: 2 }}>
        {!connected ? (
          <Button size="small" variant="contained" onClick={onConnect}>Connect</Button>
        ) : (
          <Button size="small" variant="outlined" color="warning" onClick={onDisconnect}>Disconnect</Button>
        )}
        <Button size="small" variant="outlined" startIcon={<LockOpenIcon />} onClick={onDoorOpen} disabled={!connected && mode !== "AGENT"}>
          Open Door
        </Button>
        <Button size="small" variant="text" startIcon={<InfoIcon />} onClick={onInfo}>
          Info
        </Button>
      </CardActions>
    </Card>
  );
}

