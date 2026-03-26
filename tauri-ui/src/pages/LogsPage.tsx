import { useCallback } from "react";

import type { LogLine } from "@/api/types";
import { get, openSSE } from "@/api/client";
import LiveLogWorkbench from "@/components/LiveLogWorkbench";

export default function LogsPage() {
  const loadRecent = useCallback((limit: number) => get<{ ok?: boolean; lines: LogLine[]; total: number }>(
    "/logs/recent",
    { limit: String(limit) },
  ), []);

  const openStream = useCallback(
    (onEvent: (type: string, data: unknown) => void, onError?: (event: Event) => void) =>
      openSSE("/logs/stream", onEvent, onError),
    [],
  );

  const openFolder = useCallback(() => get<{ ok: boolean; path: string }>("/logs/open-dir"), []);

  return (
    <LiveLogWorkbench
      eyebrow="Access runtime log stream"
      title="MonClub Access logs"
      description="Watch local API, device, agent, and access decision logs in one duplicate-aware console with clickable filters."
      exportPrefix="monclub-access-logs"
      emptyText="No Access logs have been captured yet."
      accentClassName="border-sky-500/20 bg-sky-500/10 text-sky-300"
      loadRecent={loadRecent}
      openStream={openStream}
      openFolder={openFolder}
    />
  );
}
