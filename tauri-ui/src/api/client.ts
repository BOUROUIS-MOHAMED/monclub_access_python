// Fetch wrapper for localhost Python API - all endpoints under /api/v2/

import {
  LOCAL_API_BASE_URL_ACCESS,
  LOCAL_API_PREFIX,
} from "@/config/appConst";

let _baseUrl = LOCAL_API_BASE_URL_ACCESS;
const PFX = LOCAL_API_PREFIX;

let _token: string | null = null;
export const setAuthToken = (t: string) => { _token = t; };
export const getAuthToken = () => _token;

export const configureApiBaseUrl = (baseUrl: string) => {
  const trimmed = String(baseUrl || "").trim();
  if (trimmed) _baseUrl = trimmed.replace(/\/+$/, "");
};

export const configureApiPort = (port: number) => {
  if (!Number.isFinite(port) || port <= 0) return;
  _baseUrl = `http://127.0.0.1:${Math.trunc(port)}`;
};

export const getApiBaseUrl = () => _baseUrl;

export class ApiError extends Error {
  status: number;
  constructor(msg: string, status: number) {
    super(msg);
    this.name = "ApiError";
    this.status = status;
  }
}

function hdrs(includeJsonBody = false): Record<string, string> {
  const h: Record<string, string> = { Accept: "application/json" };
  if (includeJsonBody) h["Content-Type"] = "application/json";
  if (_token) h["X-Local-Token"] = _token;
  return h;
}

async function parse<T>(res: Response): Promise<T> {
  const txt = await res.text();
  let json: any;
  try { json = JSON.parse(txt); } catch { throw new ApiError(txt || `HTTP ${res.status}`, res.status); }
  if (!res.ok && json.ok === false) throw new ApiError(json.error || `HTTP ${res.status}`, res.status);
  if (!res.ok) throw new ApiError(json.error || txt, res.status);
  return json as T;
}

export async function get<T>(path: string, params?: Record<string, string>): Promise<T> {
  let url = `${_baseUrl}${PFX}${path}`;
  if (params) { const q = new URLSearchParams(params).toString(); if (q) url += `?${q}`; }
  return parse<T>(await fetch(url, { headers: hdrs(false) }));
}

export async function post<T>(path: string, body?: unknown): Promise<T> {
  return parse<T>(await fetch(`${_baseUrl}${PFX}${path}`, {
    method: "POST", headers: hdrs(true),
    body: body != null ? JSON.stringify(body) : undefined,
  }));
}

export async function patch<T>(path: string, body: unknown): Promise<T> {
  return parse<T>(await fetch(`${_baseUrl}${PFX}${path}`, {
    method: "PATCH", headers: hdrs(true), body: JSON.stringify(body),
  }));
}

export async function del<T>(path: string): Promise<T> {
  return parse<T>(await fetch(`${_baseUrl}${PFX}${path}`, { method: "DELETE", headers: hdrs(false) }));
}

// SSE helper
export function openSSE(
  path: string,
  onEvent: (type: string, data: any) => void,
  optionsOrOnError?: ((e: Event) => void) | { onError?: (e: Event) => void; onReconnect?: () => void },
): EventSource {
  // Backward compat: third arg can be a plain onError callback or an options object
  const opts = typeof optionsOrOnError === "function"
    ? { onError: optionsOrOnError }
    : optionsOrOnError;
  let url = `${_baseUrl}${PFX}${path}`;
  // SECURITY NOTE (CRITICAL-4): EventSource cannot send custom headers, so the
  // auth token must be passed as a query-string parameter here. This makes it
  // visible in server access logs and browser DevTools network history.
  // Mitigation: the server listens only on 127.0.0.1 (loopback), limiting
  // exposure to local processes. A proper fix requires a one-time SSE ticket:
  //   POST /api/v2/sse-ticket (authenticated) → { ticket, expiresIn: 30 }
  // The SSE handler would accept ?ticket= (single-use, 30s TTL) instead of
  // ?token=. TODO: implement when a loopback log-forwarding risk is confirmed.
  if (_token) url += `${url.includes("?") ? "&" : "?"}token=${encodeURIComponent(_token)}`;
  const es = new EventSource(url);
  let wasOpen = false;
  es.onopen = () => {
    if (wasOpen && opts?.onReconnect) opts.onReconnect();
    wasOpen = true;
  };
  es.onmessage = (e) => { try { onEvent("message", JSON.parse(e.data)); } catch { onEvent("message", e.data); } };
  for (const t of ["log","step","progress","result","success","failed","error","cancelled","status","device_status","popup","ping","enroll_started","phase"]) {
    es.addEventListener(t, ((e: MessageEvent) => {
      try { onEvent(t, JSON.parse(e.data)); } catch { onEvent(t, e.data); }
    }) as EventListener);
  }
  if (opts?.onError) es.onerror = opts.onError;
  return es;
}


