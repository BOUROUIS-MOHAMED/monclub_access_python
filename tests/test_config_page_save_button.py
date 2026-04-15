from pathlib import Path


def test_config_page_save_button_not_advanced_gated() -> None:
    content = Path("tauri-ui/src/pages/ConfigPage.tsx").read_text(encoding="utf-8")
    assert "advancedUnlocked && dirty" not in content
