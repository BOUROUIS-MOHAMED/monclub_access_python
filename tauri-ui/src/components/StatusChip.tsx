import { Chip, type ChipProps } from "@mui/material";

type Variant = "online" | "offline" | "warning" | "syncing" | "error" | "idle";

const colorMap: Record<Variant, ChipProps["color"]> = {
  online: "success",
  offline: "default",
  warning: "warning",
  syncing: "info",
  error: "error",
  idle: "default",
};

interface Props {
  variant: Variant;
  label?: string;
  size?: "small" | "medium";
}

export default function StatusChip({ variant, label, size = "small" }: Props) {
  return (
    <Chip
      label={label ?? variant}
      color={colorMap[variant] ?? "default"}
      size={size}
      variant="filled"
      sx={{ textTransform: "capitalize" }}
    />
  );
}

