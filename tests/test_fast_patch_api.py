from __future__ import annotations

from types import SimpleNamespace


def test_sync_fast_patch_bundle_calls_app_apply():
    from app.api import local_access_api_v2 as api_module

    sent: list[tuple[int, dict]] = []
    called: list[dict] = []
    ctx = SimpleNamespace(
        body=lambda: {"bundleId": "bundle-1", "generatedAt": "2026-04-12T12:00:00Z", "items": []},
        app=SimpleNamespace(apply_fast_patch_bundle=lambda bundle: called.append(bundle) or {"ok": True}),
        send_json=lambda status, payload: sent.append((status, payload)),
    )

    api_module._handle_sync_fast_patch_bundle(ctx)

    assert called == [{"bundleId": "bundle-1", "generatedAt": "2026-04-12T12:00:00Z", "items": []}]
    assert sent == [(200, {"ok": True})]
