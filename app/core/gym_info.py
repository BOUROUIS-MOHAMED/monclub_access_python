"""Profil's gym name and account holder's name (Card P2): ``GET /manager/access/v1/gym/me``
(``name``, ``account_name``), cached in ``auth_state``.

Display only. The answer's ``enabled`` flag is NOT read: the backend sets it false for every
non-GYM account (an ADMIN login), and nothing here may gate access, restrict the app or log
anyone out -- a refused call (401 included) is logged and retried later, nothing else.

It rides the sync worker: ``maybe_refresh`` is called after a sync that reached the backend
and starts at most one daemon thread at a time, so the sync never waits on it. No new poll
loop. Throttle: once per ``SUCCESS_INTERVAL_SEC`` after any backend answer (an HTTP refusal
included), ``RETRY_INTERVAL_SEC`` after a transport failure, and at once after an Access login
or logout (``reset``) or when the login e-mail changes (the TV login mirror).
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional

# The name the backend answers for an account with no gym (GymAccessController).
NO_GYM_NAME = "N/A"
SUCCESS_INTERVAL_SEC = 3600.0
RETRY_INTERVAL_SEC = 300.0
REQUEST_TIMEOUT_SEC = 10


def gym_name_from_answer(body: Any) -> str:
    """The gym name of a ``gym/me`` answer, or "" when it carries none (blank, not a
    string, or the backend's ``"N/A"`` for an account without a gym)."""
    name = body.get("name") if isinstance(body, dict) else None
    if not isinstance(name, str):
        return ""
    name = name.strip()
    return "" if name == NO_GYM_NAME else name


def account_name_from_answer(body: Any) -> str:
    """The account holder's name of a ``gym/me`` answer (``account_name``, backend Card P2), or ""
    when it carries none: an older backend without the key, an unset name, or not a string."""
    name = body.get("account_name") if isinstance(body, dict) else None
    return name.strip() if isinstance(name, str) else ""


class GymNameRefresher:
    def __init__(
        self,
        *,
        api_factory: Callable[[], Any],
        logger: Any,
        clock: Callable[[], float] = time.monotonic,
        start_thread: Optional[Callable[[Callable[[], None]], None]] = None,
    ) -> None:
        self._api_factory = api_factory
        self._logger = logger
        self._clock = clock
        self._start_thread = start_thread or self._daemon_thread
        self._lock = threading.Lock()
        self._inflight = False
        self._next_due = 0.0
        self._last_email = ""
        self._generation = 0

    def reset(self) -> None:
        """Make the next online sync fetch: called on a successful login and on logout. Logout
        deletes the cached name with the auth_state row, so logging back in with the SAME
        e-mail would otherwise wait out the throttle with no name. A fetch still in flight
        finishes but no longer sets the throttle."""
        with self._lock:
            self._generation += 1
            self._next_due = 0.0
            self._last_email = ""

    @staticmethod
    def _daemon_thread(fn: Callable[[], None]) -> None:
        threading.Thread(target=fn, name="gym-me", daemon=True).start()

    def maybe_refresh(self) -> bool:
        """Start a background fetch when one is due. True when one was started."""
        from app.core.db import load_auth_token

        auth = load_auth_token()
        if not auth or not auth.token or not (auth.email or "").strip():
            return False
        email = auth.email.strip()
        with self._lock:
            if self._inflight:
                return False
            new_login = email.lower() != self._last_email.lower()
            if not new_login and self._clock() < self._next_due:
                return False
            self._inflight = True
            self._last_email = email
            generation = self._generation
        try:
            self._start_thread(lambda: self._fetch(email, auth.token, generation))
        except Exception:
            with self._lock:
                self._inflight = False
            self._logger.warning("[GYM-ME] could not start the gym name fetch", exc_info=True)
            return False
        return True

    def _fetch(self, email: str, token: str, generation: int) -> None:
        from app.core.db import save_gym_name

        interval = RETRY_INTERVAL_SEC
        try:
            body = self._api_factory().get_gym_me(token=token, timeout=REQUEST_TIMEOUT_SEC)
            # An answer with no gym clears the cached name: the account has none now.
            save_gym_name(email=email, gym_name=gym_name_from_answer(body),
                          account_name=account_name_from_answer(body))
            interval = SUCCESS_INTERVAL_SEC
        except Exception as exc:
            self._logger.info("[GYM-ME] gym name not refreshed: %s", exc)
            if getattr(exc, "status_code", None) is not None:
                # The backend answered (refused, or a route it does not have): asking again
                # in 5 minutes would get the same answer.
                interval = SUCCESS_INTERVAL_SEC
        finally:
            with self._lock:
                if generation == self._generation:
                    self._next_due = self._clock() + interval
                self._inflight = False
