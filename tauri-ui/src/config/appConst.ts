/**
 * Application constants for MonClub Access / TV desktop client.
 *
 * This file centralizes all local API connection settings for the frontend.
 *
 * NOTE: The remote backend URL (https://monclubwigo.tn) is managed exclusively
 * in the Python layer — see app/core/app_const.py.
 * It is NOT accessible or editable from the UI.
 */

// ── Local Python API server ───────────────────────────────────────────────────

/** Loopback host for the local Python API server. */
export const LOCAL_API_HOST = "127.0.0.1";

/** Default port for the MonClub Access local API server. */
export const LOCAL_API_PORT_ACCESS = 8788;

/** Default port for the MonClub TV local API server. */
export const LOCAL_API_PORT_TV = 8789;

/** API version prefix used by all local API routes. */
export const LOCAL_API_PREFIX = "/api/v2";

/** Full default base URL for the local Access API. */
export const LOCAL_API_BASE_URL_ACCESS =
  `http://${LOCAL_API_HOST}:${LOCAL_API_PORT_ACCESS}`;

/** Full default base URL for the local TV API. */
export const LOCAL_API_BASE_URL_TV =
  `http://${LOCAL_API_HOST}:${LOCAL_API_PORT_TV}`;
