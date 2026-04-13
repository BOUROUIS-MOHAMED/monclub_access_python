import importlib.util
import json
import re
import shutil
import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SYNC_SCRIPT = REPO_ROOT / "packaging" / "sync_tauri_version_files.py"


def _load_sync_module():
    spec = importlib.util.spec_from_file_location("sync_tauri_version_files", SYNC_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _copy_tree(src_root: Path, dest_root: Path) -> None:
    files = [
        "update.json",
        "tauri-ui/package.json",
        "tauri-ui/package-lock.json",
        "tauri-ui/src-tauri/tauri.conf.json",
        "tauri-ui/src-tauri/Cargo.toml",
        "tauri-ui/src-tauri/Cargo.lock",
    ]
    for rel_path in files:
        src = src_root / rel_path
        dest = dest_root / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)


def _overwrite_version_files(repo_root: Path, version: str) -> None:
    package_json_path = repo_root / "tauri-ui" / "package.json"
    package_json = json.loads(package_json_path.read_text(encoding="utf-8"))
    package_json["version"] = version
    package_json_path.write_text(json.dumps(package_json, indent=2) + "\n", encoding="utf-8")

    package_lock_path = repo_root / "tauri-ui" / "package-lock.json"
    package_lock = json.loads(package_lock_path.read_text(encoding="utf-8"))
    package_lock["version"] = version
    package_lock["packages"][""]["version"] = version
    package_lock_path.write_text(json.dumps(package_lock, indent=2) + "\n", encoding="utf-8")

    tauri_conf_path = repo_root / "tauri-ui" / "src-tauri" / "tauri.conf.json"
    tauri_conf = json.loads(tauri_conf_path.read_text(encoding="utf-8"))
    tauri_conf["version"] = version
    tauri_conf_path.write_text(json.dumps(tauri_conf, indent=2) + "\n", encoding="utf-8")

    cargo_toml_path = repo_root / "tauri-ui" / "src-tauri" / "Cargo.toml"
    cargo_toml = cargo_toml_path.read_text(encoding="utf-8")
    cargo_toml = re.sub(r'(?m)^version\s*=\s*"[^"]+"', f'version = "{version}"', cargo_toml, count=1)
    cargo_toml_path.write_text(cargo_toml, encoding="utf-8")

    cargo_lock_path = repo_root / "tauri-ui" / "src-tauri" / "Cargo.lock"
    cargo_lock = cargo_lock_path.read_text(encoding="utf-8")
    cargo_lock = re.sub(
        r'(?ms)(^name = "monclub-access-ui"\r?\nversion = ")([^"]+)(")',
        rf'\g<1>{version}\3',
        cargo_lock,
        count=1,
    )
    cargo_lock_path.write_text(cargo_lock, encoding="utf-8")


def _component_version(repo_root: Path, component: str) -> str:
    update_data = json.loads((repo_root / "update.json").read_text(encoding="utf-8"))
    return str(update_data[component]["version"])


def _read_versions(repo_root: Path) -> dict:
    package_json = json.loads((repo_root / "tauri-ui" / "package.json").read_text(encoding="utf-8"))
    package_lock = json.loads((repo_root / "tauri-ui" / "package-lock.json").read_text(encoding="utf-8"))
    tauri_conf = json.loads((repo_root / "tauri-ui" / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8"))
    cargo_toml = tomllib.loads((repo_root / "tauri-ui" / "src-tauri" / "Cargo.toml").read_text(encoding="utf-8"))
    cargo_lock = (repo_root / "tauri-ui" / "src-tauri" / "Cargo.lock").read_text(encoding="utf-8")
    cargo_lock_match = re.search(
        r'name = "monclub-access-ui"\r?\nversion = "([^"]+)"',
        cargo_lock,
    )
    assert cargo_lock_match is not None
    return {
        "package_json": package_json["version"],
        "package_lock": package_lock["version"],
        "package_lock_root": package_lock["packages"][""]["version"],
        "tauri_conf": tauri_conf["version"],
        "cargo_toml": cargo_toml["package"]["version"],
        "cargo_lock": cargo_lock_match.group(1),
    }


def test_sync_tauri_version_files_uses_access_component_version(tmp_path: Path) -> None:
    worktree = tmp_path / "repo"
    _copy_tree(REPO_ROOT, worktree)
    _overwrite_version_files(worktree, "0.1.0")
    expected_version = _component_version(worktree, "access")

    sync_module = _load_sync_module()
    version, changed = sync_module.sync_tauri_version_files(worktree, "access")

    assert version == expected_version
    assert changed
    assert all(value == expected_version for value in _read_versions(worktree).values())


def test_sync_tauri_version_files_uses_tv_component_version(tmp_path: Path) -> None:
    worktree = tmp_path / "repo"
    _copy_tree(REPO_ROOT, worktree)
    _overwrite_version_files(worktree, "9.9.9")
    expected_version = _component_version(worktree, "tv")

    sync_module = _load_sync_module()
    version, changed = sync_module.sync_tauri_version_files(worktree, "tv")

    assert version == expected_version
    assert changed
    assert all(value == expected_version for value in _read_versions(worktree).values())
