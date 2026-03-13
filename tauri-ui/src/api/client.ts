// Fetch wrapper for localhost Python API â€” all endpoints under /api/v2/

const BASE = "http://127.0.0.1:8788";
const PFX = "/api/v2";

let _token: string | null = null;
export const setAuthToken = (t: string) => { _token = t; };
export const getAuthToken = () => _token;

export class ApiError extends Error {
  status: number;
  constructor(msg: string, status: number) {
    super(msg);
    this.name = "ApiError";
    this.status = status;
  }
}

function hdrs(): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json", Accept: "application/json" };
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
  let url = `${BASE}${PFX}${path}`;
  if (params) { const q = new URLSearchParams(params).toString(); if (q) url += `?${q}`; }
  return parse<T>(await fetch(url, { headers: hdrs() }));
}

export async function post<T>(path: string, body?: unknown): Promise<T> {
  return parse<T>(await fetch(`${BASE}${PFX}${path}`, {
    method: "POST", headers: hdrs(),
    body: body != null ? JSON.stringify(body) : undefined,
  }));
}

export async function patch<T>(path: string, body: unknown): Promise<T> {
  return parse<T>(await fetch(`${BASE}${PFX}${path}`, {
    method: "PATCH", headers: hdrs(), body: JSON.stringify(body),
  }));
}

export async function del<T>(path: string): Promise<T> {
  return parse<T>(await fetch(`${BASE}${PFX}${path}`, { method: "DELETE", headers: hdrs() }));
}

// SSE helper
export function openSSE(
  path: string,
  onEvent: (type: string, data: any) => void,
  onError?: (e: Event) => void,
): EventSource {
  let url = `${BASE}${PFX}${path}`;
  if (_token) url += `${url.includes("?") ? "&" : "?"}token=${encodeURIComponent(_token)}`;
  const es = new EventSource(url);
  es.onmessage = (e) => { try { onEvent("message", JSON.parse(e.data)); } catch { onEvent("message", e.data); } };
  for (const t of ["log","step","progress","result","success","failed","error","cancelled","status","device_status","popup","ping"]) {
    es.addEventListener(t, ((e: MessageEvent) => {
      try { onEvent(t, JSON.parse(e.data)); } catch { onEvent(t, e.data); }
    }) as EventListener);
  }
  if (onError) es.onerror = onError;
  return es;
}


