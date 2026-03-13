import { useEffect, useRef } from "react";
import { Box, Typography, Chip, Stack } from "@mui/material";
import type { LogLine } from "../api/types";

const levelColor: Record<string, string> = {
  DEBUG: "#8b949e",
  INFO: "#58a6ff",
  WARNING: "#d29922",
  ERROR: "#f85149",
  CRITICAL: "#ff7b72",
};

interface Props {
  lines: LogLine[];
  maxHeight?: number | string;
  filter?: string;
  showToolbar?: boolean;
  onClear?: () => void;
}

export default function LogViewer({ lines, maxHeight = 400, filter = "ALL", showToolbar = false, onClear }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);

  const filtered = filter === "ALL"
    ? lines
    : lines.filter((l) => l.level?.toUpperCase() === filter);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [filtered.length]);

  return (
    <Box>
      {showToolbar && (
        <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
          <Chip label={`${filtered.length} lines`} size="small" />
          {onClear && (
            <Chip label="Clear" size="small" onClick={onClear} onDelete={onClear} />
          )}
        </Stack>
      )}
      <Box
        sx={{
          maxHeight,
          overflow: "auto",
          bgcolor: "#0d1117",
          border: "1px solid #1e2a3a",
          borderRadius: 1,
          p: 1,
          fontFamily: '"JetBrains Mono","Fira Code","Consolas",monospace',
          fontSize: "0.78rem",
          lineHeight: 1.6,
        }}
      >
        {filtered.length === 0 ? (
          <Typography variant="body2" color="text.secondary" sx={{ fontStyle: "italic" }}>
            No log entries yet…
          </Typography>
        ) : (
          filtered.map((l, i) => (
            <Box key={i} sx={{ color: levelColor[l.level?.toUpperCase()] || "#e6edf3", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {l.text}
            </Box>
          ))
        )}
        <div ref={bottomRef} />
      </Box>
    </Box>
  );
}

