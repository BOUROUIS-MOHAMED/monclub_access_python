// A mock of the watchdog card (src/components/WatchdogCard.tsx) for screenshots and the BLUE v5
// redesign: the real card over a SIMULATED GET/POST /api/v2/watchdog -- no Python app, no task.
// Served by the Vite dev server only (watchdog-mock.html). ?state=on|off|missing|error|stood|dev
// picks the starting status; ?lang=en starts in English. The switch works (in memory).
import ReactDOM from "react-dom/client";
import WatchdogCard from "@/components/WatchdogCard";
import { installSemanticTokenStyles } from "@/theme/colors";
import { saveLang, type WatchdogStatus } from "@/lib/watchdogStatus";
import "@/index.css";

installSemanticTokenStyles();

const now = Date.now();
const iso = (msAgo: number) => new Date(now - msAgo).toISOString().replace(/\.\d{3}Z$/, "Z");

// Illustrative values only (a mock): no real task was read.
const base: WatchdogStatus = {
  taskName: "MonClub Access Watchdog", registered: true, enabled: true, state: "Ready",
  lastRunAt: iso(40_000), lastResult: "ok", lastResultCode: 0, nextRunAt: iso(-80_000),
  intervalMinutes: 2, restartsLastHour: 0, stoodDown: false, stoodDownReason: null,
  scriptPath: "C:\Users\gym\AppData\Local\MonClubAccess\watchdog\monclub_access_watchdog.ps1",
  lastLogEntry: { at: iso(26 * 3600_000), rawAt: "", level: "INFO", message: "restart issued", fromLastCheck: false },
  lastError: null, available: true, installRoot: "C:\Users\gym\AppData\Local\MonClubAccess", checkedAt: iso(0),
};

const STATES: Record<string, Partial<WatchdogStatus>> = {
  on: {},
  off: { enabled: false, state: "Disabled" },
  missing: { registered: false, enabled: false, state: null, lastRunAt: null, lastResult: null, lastResultCode: null,
             nextRunAt: null, intervalMinutes: null, scriptPath: null, lastLogEntry: null },
  error: { registered: null, enabled: null, state: null, lastRunAt: null, lastResult: null,
           lastError: "reading the scheduled task timed out after 20 s" },
  stood: { restartsLastHour: 5, stoodDown: true, stoodDownReason: "Access was restarted 5 times in the last 60 min",
           lastLogEntry: { at: iso(30_000), rawAt: "", level: "INFO", message: "restart issued", fromLastCheck: true } },
  dev: { available: false, installRoot: null },
};

const params = new URLSearchParams(window.location.search);
saveLang(params.get("lang") === "en" ? "en" : "fr");
let current: WatchdogStatus = { ...base, ...(STATES[params.get("state") || "on"] || {}) };

const realFetch = window.fetch.bind(window);
window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input instanceof Request ? input.url : input);
  if (!url.includes("/api/v2/watchdog")) return realFetch(input, init);
  await new Promise((r) => setTimeout(r, 400));
  if ((init?.method || "GET") === "POST") {
    const { enabled } = JSON.parse(String(init?.body || "{}"));
    current = { ...current, registered: true, enabled, state: enabled ? "Ready" : "Disabled", lastError: null,
                intervalMinutes: current.intervalMinutes ?? 2 };
  }
  return new Response(JSON.stringify({ ok: true, watchdog: current }), {
    status: 200, headers: { "Content-Type": "application/json" },
  });
};

ReactDOM.createRoot(document.getElementById("root")!).render(
  <div className="min-h-screen bg-background p-6 text-foreground"><div className="mx-auto max-w-3xl"><WatchdogCard /></div></div>,
);
