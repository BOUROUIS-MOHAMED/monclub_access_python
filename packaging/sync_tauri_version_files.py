from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


CARGO_TOML_VERSION_RE = re.compile(
    r'(?ms)(^\[package\]\s.*?^version\s*=\s*")([^"]+)(")'
)
CARGO_LOCK_VERSION_RE = re.compile(
    r'(?ms)(^name = "monclub-access-ui"\r?\nversion = ")([^"]+)(")'
)


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _replace_first(path: Path, pattern: re.Pattern[str], replacement: str) -> bool:
    content = path.read_text(encoding="utf-8")
    updated, count = pattern.subn(replacement, content, count=1)
    if count != 1:
        raise ValueError(f"Could not update version in {path}")
    if updated != content:
        path.write_text(updated, encoding="utf-8")
        return True
    return False


def _component_version(repo_root: Path, component: str) -> str:
    update_data = _read_json(repo_root / "update.json")
    try:
        value = str(update_data[component]["version"]).strip()
    except KeyError as exc:
        raise KeyError(f"Component '{component}' not found in update.json") from exc
    if not value:
        raise ValueError(f"Component '{component}' is missing a version in update.json")
    return value


def sync_tauri_version_files(repo_root: Path, component: str) -> tuple[str, list[str]]:
    version = _component_version(repo_root, component)
    changed: list[str] = []

    package_json_path = repo_root / "tauri-ui" / "package.json"
    package_json = _read_json(package_json_path)
    if package_json.get("version") != version:
        package_json["version"] = version
        _write_json(package_json_path, package_json)
        changed.append(str(package_json_path))

    package_lock_path = repo_root / "tauri-ui" / "package-lock.json"
    if package_lock_path.exists():
        package_lock = _read_json(package_lock_path)
        root_package = package_lock.setdefault("packages", {}).setdefault("", {})
        package_lock_changed = False
        if package_lock.get("version") != version:
            package_lock["version"] = version
            package_lock_changed = True
        if root_package.get("version") != version:
            root_package["version"] = version
            package_lock_changed = True
        if package_lock_changed:
            _write_json(package_lock_path, package_lock)
            changed.append(str(package_lock_path))

    tauri_conf_path = repo_root / "tauri-ui" / "src-tauri" / "tauri.conf.json"
    tauri_conf = _read_json(tauri_conf_path)
    if tauri_conf.get("version") != version:
        tauri_conf["version"] = version
        _write_json(tauri_conf_path, tauri_conf)
        changed.append(str(tauri_conf_path))

    cargo_toml_path = repo_root / "tauri-ui" / "src-tauri" / "Cargo.toml"
    if _replace_first(cargo_toml_path, CARGO_TOML_VERSION_RE, rf'\g<1>{version}\3'):
        changed.append(str(cargo_toml_path))

    cargo_lock_path = repo_root / "tauri-ui" / "src-tauri" / "Cargo.lock"
    if cargo_lock_path.exists():
        if _replace_first(cargo_lock_path, CARGO_LOCK_VERSION_RE, rf'\g<1>{version}\3'):
            changed.append(str(cargo_lock_path))

    return version, changed


def main() -> int:
    parser = argparse.ArgumentParser(description="Synchronize shared Tauri version files from update.json.")
    parser.add_argument("--repo-root", default=".", help="Repository root path.")
    parser.add_argument("--component", required=True, choices=("access", "tv"))
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    version, changed = sync_tauri_version_files(repo_root, args.component)

    print(f"Synchronized Tauri version files for {args.component}: {version}")
    if changed:
        for path in changed:
            print(f" - {path}")
    else:
        print(" - no changes needed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
