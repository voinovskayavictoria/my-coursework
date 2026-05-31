from pathlib import Path
import zipfile
from fastapi import HTTPException

from dependency_scanner import collect_dependency_vulnerabilities
from security_scanner import scan_project_security_configuration
from source_scanner import scan_source_tree
from webapp.config import MAX_ARCHIVE_MEMBERS, MAX_ARCHIVE_SIZE_BYTES
from webapp.scans.html import collect_html_vulnerabilities
from webapp.scans.storage import normalize_vulnerability
from webapp.state import scanner


def is_within_directory(base_path: Path, target_path: Path) -> bool:
    try:
        target_path.resolve().relative_to(base_path.resolve())
        return True
    except ValueError:
        return False


def safe_extract_zip(archive_path: Path, extract_to: Path) -> None:
    with zipfile.ZipFile(archive_path) as zf:
        members = zf.infolist()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise HTTPException(400, "Слишком много файлов в архиве")

        total_size = 0
        for member in members:
            total_size += member.file_size
            if total_size > MAX_ARCHIVE_SIZE_BYTES:
                raise HTTPException(400, "Архив слишком большой")

            destination = extract_to / member.filename
            if not is_within_directory(extract_to, destination):
                raise HTTPException(400, "Архив содержит опасные пути")

        zf.extractall(extract_to)


def scan_extracted_project(project_root: Path, max_depth: int | None = None, enabled_rules: set[str] | None = None) -> list[dict]:
    vulnerabilities: list[dict] = []
    source_findings = scan_source_tree(str(project_root), max_depth=max_depth, enabled_rules=enabled_rules)
    config_findings = scan_project_security_configuration(str(project_root), max_depth=max_depth, enabled_rules=enabled_rules)
    for idx, vuln in enumerate(source_findings + config_findings, start=1):
        vulnerabilities.append(normalize_vulnerability(vuln, "SOURCE", idx))

    dependency_findings = collect_dependency_vulnerabilities(str(project_root), scanner, max_depth=max_depth, enabled_rules=enabled_rules)
    for idx, vuln in enumerate(dependency_findings, start=1):
        vulnerabilities.append(normalize_vulnerability(vuln, "DEP", idx))

    for html_file in project_root.rglob("*.html"):
        try:
            html_code = html_file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                html_code = html_file.read_text(encoding="cp1251")
            except Exception:
                continue
        except OSError:
            continue

        for idx, vuln in enumerate(collect_html_vulnerabilities(html_code, enabled_rules), start=1):
            normalized = normalize_vulnerability(vuln, "HTML", idx)
            normalized["description"] = f"{normalized.get('description', '')} Файл: {html_file.as_posix()}"
            vulnerabilities.append(normalized)

    return vulnerabilities
