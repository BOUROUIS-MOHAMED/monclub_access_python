// The AGENT realtime engine (app/core/realtime_agent.py) only drives turnstiles whose
// accessDataMode is AGENT, and Access stops it whenever the gym has none. Gyms run
// ULTRA, so its status ("Agent arrêté"), its page and its Start button would only
// ever report a stopped engine that has nothing to do. Show them only when there is
// at least one AGENT device. The /agent/events stream itself stays: the popup reads
// ULTRA events from it.
export function hasAgentDevices(status: { mode?: { AGENT?: number } | null } | null | undefined): boolean {
  return (status?.mode?.AGENT ?? 0) > 0;
}
