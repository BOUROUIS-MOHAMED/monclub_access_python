import { useCallback } from "react";

import LiveLogWorkbench from "@/components/LiveLogWorkbench";
import { getTvRecentLogs, openTvLogsStream } from "@/tv/api";

export default function TvLogsPage() {
  const loadRecent = useCallback((limit: number) => getTvRecentLogs({ limit }), []);
  const openStream = useCallback(
    (onEvent: (type: string, data: unknown) => void, onError?: (event: Event) => void) =>
      openTvLogsStream(onEvent, { onError }),
    [],
  );

  return (
    <LiveLogWorkbench
      eyebrow="TV runtime log stream"
      title="MonClub TV logs"
      description="Track player lifecycle, binding orchestration, downloads, and recovery events in the same duplicate-aware console."
      exportPrefix="monclub-tv-logs"
      emptyText="No TV logs have been captured yet."
      accentClassName="border-emerald-500/20 bg-emerald-500/10 text-emerald-300"
      loadRecent={loadRecent}
      openStream={openStream}
    />
  );
}
