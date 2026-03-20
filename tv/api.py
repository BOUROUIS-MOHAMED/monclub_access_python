"""TV-owned API boundary over the legacy TV implementation module."""

from __future__ import annotations

from app.core.tv_local_cache import *  # noqa: F401,F403
from tv.local_api_routes import (
    TV_LOCAL_ROUTE_SPECS,
    get_tv_local_api_route_specs,
    register_tv_local_api_routes,
)
from tv.runtime import (
    attach_combined_tv_runtime,
    attach_tv_runtime,
    get_combined_tv_runtime_state,
    get_tv_runtime_state,
    schedule_tv_shell_startup,
    start_combined_tv_runtime,
    start_tv_runtime,
)


class LocalTvApiServerV2:
    """TV-owned wrapper over the shared local HTTP shell."""

    def __init__(self, *, app, host: str = "127.0.0.1", port: int = 8789):
        from app.api.local_access_api_v2 import LocalApiServerV2

        self._server = LocalApiServerV2(
            app=app,
            host=host,
            port=port,
            route_scope="tv",
            server_name="LocalTvApiServerV2",
        )

    @property
    def app(self):
        return self._server.app

    @property
    def host(self) -> str:
        return self._server.host

    @property
    def port(self) -> int:
        return self._server.port

    def start(self) -> None:
        self._server.start()

    def stop(self) -> None:
        self._server.stop()


__all__ = [
    "LocalTvApiServerV2",
    "TV_LOCAL_ROUTE_SPECS",
    "attach_combined_tv_runtime",
    "attach_tv_runtime",
    "get_combined_tv_runtime_state",
    "get_tv_local_api_route_specs",
    "get_tv_runtime_state",
    "register_tv_local_api_routes",
    "schedule_tv_shell_startup",
    "start_combined_tv_runtime",
    "start_tv_runtime",
]
