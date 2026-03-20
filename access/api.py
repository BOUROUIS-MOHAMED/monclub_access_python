"""Access-owned API boundary for the current combined desktop runtime."""

from access.local_api_routes import (
    ACCESS_LOCAL_ROUTE_SPECS,
    get_access_local_api_route_specs,
    register_access_local_api_routes,
)
from app.api.local_access_api_v2 import (
    LocalAccessApiServerV2,
    _enroll_add_log,
    _enroll_reset,
    _enroll_set_result,
    _enroll_set_step,
)

__all__ = [
    "ACCESS_LOCAL_ROUTE_SPECS",
    "LocalAccessApiServerV2",
    "_enroll_add_log",
    "_enroll_reset",
    "_enroll_set_result",
    "_enroll_set_step",
    "get_access_local_api_route_specs",
    "register_access_local_api_routes",
]
