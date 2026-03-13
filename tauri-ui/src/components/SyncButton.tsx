import { Button, CircularProgress } from "@mui/material";
import SyncIcon from "@mui/icons-material/Sync";

interface Props {
  loading: boolean;
  onClick: () => void;
  label?: string;
}

export default function SyncButton({ loading, onClick, label = "Sync Now" }: Props) {
  return (
    <Button
      variant="outlined"
      size="small"
      startIcon={loading ? <CircularProgress size={16} /> : <SyncIcon />}
      disabled={loading}
      onClick={onClick}
    >
      {loading ? "Syncing…" : label}
    </Button>
  );
}

