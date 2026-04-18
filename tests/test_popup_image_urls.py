from __future__ import annotations

from app.api import local_access_api_v2


def test_normalize_image_url_maps_legacy_avatar_asset_path_to_dashboard_avatar() -> None:
    assert local_access_api_v2._normalize_image_url("assets/avatars/avatar-8.png") == (
        "https://monclubwigo.tn/assets/images/avatar/avatar-8.webp"
    )


def test_normalize_image_url_maps_legacy_avatar_asset_path_with_leading_slash() -> None:
    assert local_access_api_v2._normalize_image_url("/assets/avatars/avatar-12.png") == (
        "https://monclubwigo.tn/assets/images/avatar/avatar-12.webp"
    )


def test_normalize_image_url_keeps_existing_dashboard_avatar_path() -> None:
    assert local_access_api_v2._normalize_image_url("assets/images/avatar/avatar-7.webp") == (
        "https://monclubwigo.tn/assets/images/avatar/avatar-7.webp"
    )
