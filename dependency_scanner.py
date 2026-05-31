from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterable

from scanner import VulnerabilityScanner

DEFAULT_IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
MAX_FILE_SIZE = 1024 * 1024

PACKAGE_JSON = "package.json"
LOCK_FILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pnpm-lock.yml",
}


def _iter_dependency_files(root_path: Path, max_depth: int | None = None) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root_path):
        current_depth = len(Path(dirpath).relative_to(root_path).parts)
        if max_depth is not None and current_depth > max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [name for name in dirnames if name not in DEFAULT_IGNORED_DIRS]
        current_dir = Path(dirpath)
        for filename in filenames:
            if filename == PACKAGE_JSON or filename in LOCK_FILES:
                file_path = current_dir / filename
                try:
                    if file_path.stat().st_size > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                yield file_path


def _read_text(file_path: Path) -> str | None:
    try:
        return file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return file_path.read_text(encoding="cp1251")
        except Exception:
            return None
    except OSError:
        return None


def _find_line_with_key(text: str, needle: str) -> str | None:
    for line in text.splitlines():
        if needle in line:
            return line.strip()
    return None


def _short_words(text: str, max_words: int = 10) -> str:
    words = re.findall(r"\S+", text)
    return " ".join(words[:max_words])


def _format_code_snippet(file_path: Path, line: str | None, fallback: str) -> str:
    if line:
        return _short_words(line)
    return _short_words(fallback)


def _extract_semver(value: str) -> str | None:
    if not value:
        return None
    match = re.search(r"\d+\.\d+\.\d+", value)
    return match.group(0) if match else None


def _parse_package_json(file_path: Path) -> list[tuple[str, str, Path, str]]:
    text = _read_text(file_path)
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    dependencies: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(section)
        if isinstance(deps, dict):
            dependencies.update({str(k): str(v) for k, v in deps.items()})

    results: list[tuple[str, str, Path, str]] = []
    for name, spec in dependencies.items():
        version = _extract_semver(spec)
        if version:
            line = _find_line_with_key(text, f'"{name}"')
            code_snippet = _format_code_snippet(file_path, line, f"{name}@{version}")
            results.append((name, version, file_path, code_snippet))
    return results


def _parse_package_lock_json(file_path: Path) -> list[tuple[str, str, Path, str]]:
    text = _read_text(file_path)
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    results: list[tuple[str, str, Path, str]] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for package_path, meta in packages.items():
            if not package_path or package_path == "":
                continue
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not version:
                continue
            normalized_path = str(package_path).replace("\\", "/")
            if "node_modules/" not in normalized_path:
                continue
            name = normalized_path.split("node_modules/")[-1]
            if name:
                code_snippet = _format_code_snippet(file_path, None, f"{name}@{version}")
                results.append((name, str(version), file_path, code_snippet))

    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        for name, meta in dependencies.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if version:
                code_snippet = _format_code_snippet(file_path, None, f"{name}@{version}")
                results.append((str(name), str(version), file_path, code_snippet))

    return results


def _parse_yarn_lock(file_path: Path) -> list[tuple[str, str, Path, str]]:
    text = _read_text(file_path)
    if not text:
        return []
    results: list[tuple[str, str, Path, str]] = []
    current_packages: list[str] = []
    current_header_line = ""
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line.startswith(" "):
            key = line.strip().rstrip(":").strip('"')
            if key.startswith("#"):
                continue
            current_header_line = line.strip()
            current_packages = []
            for entry in key.split(","):
                entry = entry.strip().strip('"')
                if not entry:
                    continue
                if entry.startswith("@"):
                    split_index = entry.rfind("@")
                    pkg_name = entry[:split_index] if split_index > 0 else entry
                else:
                    split_index = entry.find("@")
                    pkg_name = entry[:split_index] if split_index > 0 else entry
                if pkg_name:
                    current_packages.append(pkg_name)
            continue
        if line.strip().startswith("version") and current_packages:
            match = re.search(r'version\s+"?([0-9]+\.[0-9]+\.[0-9][^"]*)"?', line)
            if match:
                version = match.group(1)
                for pkg in current_packages:
                    code_snippet = _format_code_snippet(file_path, current_header_line, f"{pkg}@{version}")
                    results.append((pkg, version, file_path, code_snippet))
            current_packages = []
    return results


def _parse_pnpm_lock(file_path: Path) -> list[tuple[str, str, Path, str]]:
    text = _read_text(file_path)
    if not text:
        return []
    results: list[tuple[str, str, Path, str]] = []
    pattern = re.compile(r"^\s*/(?P<name>@?[^@/]+(?:/[^@/]+)?)@(?P<version>[^:]+):\s*$")
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        name = match.group("name").strip()
        raw_version = match.group("version").strip()
        version = raw_version.split("(", 1)[0].strip()
        if name and version:
            code_snippet = _format_code_snippet(file_path, line.strip(), f"{name}@{version}")
            results.append((name, version, file_path, code_snippet))
    return results


def collect_dependency_vulnerabilities(
    root_path: str,
    osv_scanner: VulnerabilityScanner,
    max_depth: int | None = None,
    enabled_rules: set[str] | None = None,
) -> list[dict]:
    if enabled_rules is not None and "Уязвимые зависимости" not in enabled_rules:
        return []

    root = Path(root_path)
    if not root.exists() or not root.is_dir():
        return []

    dependencies: list[tuple[str, str, Path, str]] = []
    for file_path in _iter_dependency_files(root, max_depth=max_depth):
        if file_path.name == PACKAGE_JSON:
            dependencies.extend(_parse_package_json(file_path))
        elif file_path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
            dependencies.extend(_parse_package_lock_json(file_path))
        elif file_path.name == "yarn.lock":
            dependencies.extend(_parse_yarn_lock(file_path))
        elif file_path.name in {"pnpm-lock.yaml", "pnpm-lock.yml"}:
            dependencies.extend(_parse_pnpm_lock(file_path))

    seen: set[tuple[str, str]] = set()
    vulnerabilities: list[dict] = []
    for name, version, file_path, code_snippet in dependencies:
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        cves = osv_scanner.search_by_product_version(name, version)
        for cve in cves:
            cve["name"] = f"{name} {version} — {cve.get('id', 'OSV')}"
            cve["description"] = f"{cve.get('description', '')} Источник: {file_path.as_posix()}"
            cve["rule"] = "Уязвимые зависимости"
            cve["code_snippet"] = code_snippet
            vulnerabilities.append(cve)

    return vulnerabilities
