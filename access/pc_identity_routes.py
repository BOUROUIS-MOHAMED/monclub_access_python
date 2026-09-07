"""Loopback API handlers for the Access PC identity setup UI."""

from __future__ import annotations

from typing import Any, Mapping

from access.pc_identity import (
    PcIdentityApiError,
    get_pc_identity_service,
    wake_pc_identity_runtime,
)


def _service(ctx):
    return get_pc_identity_service(ctx.app)


def _public_registration_result(payload: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result.pop("pcSecret", None)
    result["ok"] = True
    return result


def _send_error(ctx, exc: Exception) -> None:
    if isinstance(exc, PcIdentityApiError):
        payload: dict[str, Any] = {
            "ok": False,
            "error": str(exc),
            "code": exc.code,
            "details": dict(exc.details),
        }
        if exc.code == "ACCESS_PC_CAP_REACHED":
            payload.update(
                {
                    "cap": exc.details.get("cap"),
                    "activeCount": exc.details.get("activeCount"),
                    "takeoverRequired": True,
                }
            )
        ctx.send_json(exc.status_code, payload)
        return
    if isinstance(exc, (TypeError, ValueError)):
        ctx.send_json(400, {"ok": False, "error": str(exc), "code": "INVALID_REQUEST"})
        return
    try:
        ctx.app.logger.warning("PC identity local route failed: %s", exc)
    except Exception:
        pass
    ctx.send_json(
        500,
        {
            "ok": False,
            "error": "Impossible de configurer l’identité de ce PC pour le moment.",
            "code": "PC_IDENTITY_LOCAL_ERROR",
        },
    )


def _handle_pc_identity_status(ctx) -> None:
    try:
        ctx.send_json(200, {"ok": True, **_service(ctx).status()})
    except Exception as exc:
        _send_error(ctx, exc)


def _handle_pc_identity_list(ctx) -> None:
    try:
        ctx.send_json(200, {"ok": True, **_service(ctx).list_pcs()})
    except Exception as exc:
        _send_error(ctx, exc)


def _handle_pc_identity_register(ctx) -> None:
    try:
        name = str(ctx.body().get("name") or "").strip()
        if not name:
            raise ValueError("Le nom du PC est obligatoire.")
        result = _service(ctx).register(name=name)
        wake_pc_identity_runtime(ctx.app)
        ctx.send_json(201, _public_registration_result(result))
    except Exception as exc:
        _send_error(ctx, exc)


def _handle_pc_identity_adopt(ctx) -> None:
    try:
        pc_id = ctx.param_int("pcId", 0)
        if pc_id <= 0:
            raise ValueError("Le PC à remplacer est invalide.")
        result = _service(ctx).adopt(pc_id=pc_id)
        wake_pc_identity_runtime(ctx.app)
        ctx.send_json(200, _public_registration_result(result))
    except Exception as exc:
        _send_error(ctx, exc)


__all__ = [
    "_handle_pc_identity_adopt",
    "_handle_pc_identity_list",
    "_handle_pc_identity_register",
    "_handle_pc_identity_status",
]
