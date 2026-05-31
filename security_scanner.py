from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable, Mapping


DEFAULT_IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
DEFAULT_IGNORED_FILES = {"source_scanner.py", "static_checks.py", "scanner.py", "security_scanner.py"}
DEFAULT_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".htm", ".css", ".json", ".yml", ".yaml", ".conf", ".ini", ".txt"}
MAX_FILE_SIZE = 1024 * 1024

MANDATORY_RESPONSE_HEADERS = {
    "content-security-policy": (
        "Отсутствует Content-Security-Policy",
        "high",
        "На странице не найден заголовок CSP, поэтому защита от XSS и загрузки опасных ресурсов ослаблена.",
        "Добавьте Content-Security-Policy с ограничением script-src, object-src и default-src.",
    ),
    "x-frame-options": (
        "Отсутствует X-Frame-Options",
        "medium",
        "Нет защиты от clickjacking через встраивание страницы во фрейм.",
        "Установите X-Frame-Options: DENY или SAMEORIGIN.",
    ),
    "x-content-type-options": (
        "Отсутствует X-Content-Type-Options",
        "medium",
        "Браузер может пытаться интерпретировать тип контента иначе, чем ожидается.",
        "Установите X-Content-Type-Options: nosniff.",
    ),
    "referrer-policy": (
        "Отсутствует Referrer-Policy",
        "low",
        "Политика передачи Referer не задана явно.",
        "Установите Referrer-Policy, например strict-origin-when-cross-origin.",
    ),
    "permissions-policy": (
        "Отсутствует Permissions-Policy",
        "low",
        "Не задана политика доступа к чувствительным browser API.",
        "Ограничьте ненужные возможности через Permissions-Policy.",
    ),
}

PROJECT_RULES: tuple[tuple[str, re.Pattern[str], str, str, str], ...] = (
    (
        "Потенциально небезопасный CORS",
        re.compile(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]|Access-Control-Allow-Origin\s*:\s*\*", re.IGNORECASE),
        "high",
        "В проекте найден слишком открытый CORS, который может разрешать запросы с любых источников.",
        "Укажите список доверенных origin вместо wildcard.",
    ),
    (
        "Слабый CSP",
        re.compile(r"Content-Security-Policy|default-src[^\n]{0,120}\*|script-src[^\n]{0,120}('unsafe-inline'|'unsafe-eval')", re.IGNORECASE),
        "high",
        "Найдена CSP-конфигурация с опасными директивами или слишком широкими источниками.",
        "Уберите unsafe-inline/unsafe-eval и ограничьте источники по минимуму.",
    ),
    (
        "Cookie без флагов безопасности",
        re.compile(r"set_cookie\s*\(.*(secure\s*=\s*False|httponly\s*=\s*False|samesite\s*=\s*None)", re.IGNORECASE),
        "high",
        "Найдено создание cookie без базовых защитных флагов.",
        "Включите Secure, HttpOnly и подходящий SameSite.",
    ),
    (
        "Отключение проверки SSL",
        re.compile(r"verify\s*=\s*False|ssl\.CERT_NONE", re.IGNORECASE),
        "high",
        "В конфигурации найдено отключение проверки TLS/SSL.",
        "Включите проверку сертификатов и используйте доверенные CA.",
    ),
    (
        "Включенный debug",
        re.compile(r"debug\s*=\s*True|FLASK_DEBUG\s*=\s*1|uvicorn\.(?:run|Config)\(.*reload\s*=\s*True", re.IGNORECASE),
        "medium",
        "Найден включенный debug или режим разработки в конфигурации запуска.",
        "Отключите debug/reload в боевом окружении.",
    ),
)


def _severity_for_header(header_name: str) -> str:
    return MANDATORY_RESPONSE_HEADERS[header_name][1]


def _get_header_value(headers: Mapping[str, str], key: str) -> str:
    for header_name, header_value in headers.items():
        if header_name.lower() == key:
            return str(header_value)
    return ""


def _get_header_list(headers: object, key: str) -> list[str]:
    if hasattr(headers, "get_list"):
        values = headers.get_list(key)
        return [str(value) for value in values]
    value = _get_header_value(headers, key) if isinstance(headers, Mapping) else ""
    return [value] if value else []


def analyze_response_security_headers(headers: object, scheme: str = "http") -> list[dict]:
    findings: list[dict] = []

    for header_name, (title, severity, description, recommendation) in MANDATORY_RESPONSE_HEADERS.items():
        if header_name == "content-security-policy":
            header_value = _get_header_value(headers, header_name)
            if not header_value:
                findings.append({
                    "name": title,
                    "description": description,
                    "severity": severity,
                    "recommendation": recommendation,
                    "code_snippet": _short_words("Content-Security-Policy отсутствует"),
                })
                continue
            lowered = header_value.lower()
            if "unsafe-inline" in lowered or "unsafe-eval" in lowered or "default-src *" in lowered or "script-src *" in lowered:
                findings.append({
                    "name": "Слабый Content-Security-Policy",
                    "description": "CSP присутствует, но содержит опасные директивы, которые снижают защиту от XSS.",
                    "severity": "high",
                    "recommendation": "Уберите unsafe-inline/unsafe-eval и wildcard-источники, затем разрешайте только нужные домены.",
                    "code_snippet": _short_words(f"Content-Security-Policy {header_value}"),
                })
            continue

        if header_name == "permissions-policy":
            if not _get_header_value(headers, header_name):
                findings.append({
                    "name": title,
                    "description": description,
                    "severity": severity,
                    "recommendation": recommendation,
                    "code_snippet": _short_words("Permissions-Policy отсутствует"),
                })
            continue

        if header_name == "referrer-policy" and not _get_header_value(headers, header_name):
            findings.append({
                "name": title,
                "description": description,
                "severity": severity,
                "recommendation": recommendation,
                "code_snippet": _short_words("Referrer-Policy отсутствует"),
            })
            continue

        if header_name == "x-content-type-options" and not _get_header_value(headers, header_name):
            findings.append({
                "name": title,
                "description": description,
                "severity": severity,
                "recommendation": recommendation,
                "code_snippet": _short_words("X-Content-Type-Options отсутствует"),
            })
            continue

        if header_name == "x-frame-options" and not _get_header_value(headers, header_name):
            findings.append({
                "name": title,
                "description": description,
                "severity": severity,
                "recommendation": recommendation,
                "code_snippet": _short_words("X-Frame-Options отсутствует"),
            })
            continue

    if scheme.lower() == "https" and not _get_header_value(headers, "strict-transport-security"):
        findings.append({
            "name": "Отсутствует Strict-Transport-Security",
            "description": "Для HTTPS-страницы не задан HSTS, поэтому браузер может перейти на незащищённый HTTP.",
            "severity": "medium",
            "recommendation": "Установите Strict-Transport-Security с подходящим max-age.",
            "code_snippet": _short_words("Strict-Transport-Security отсутствует"),
        })

    cors_origin = _get_header_value(headers, "access-control-allow-origin")
    cors_credentials = _get_header_value(headers, "access-control-allow-credentials")
    if cors_origin == "*":
        findings.append({
            "name": "Слишком открытый CORS",
            "description": "Ответ разрешает запросы с любого origin через wildcard.",
            "severity": "high",
            "recommendation": "Смените wildcard на список доверенных origin.",
            "code_snippet": _short_words("Access-Control-Allow-Origin *"),
        })
    if cors_credentials.lower() == "true" and cors_origin == "*":
        findings.append({
            "name": "Опасная комбинация CORS и credentials",
            "description": "Разрешены credentials вместе с wildcard-origin, что небезопасно.",
            "severity": "critical",
            "recommendation": "Отключите wildcard-origin и оставьте только доверенные origin.",
            "code_snippet": _short_words("Access-Control-Allow-Origin * Access-Control-Allow-Credentials true"),
        })

    cookie_issues: dict[tuple[str, ...], dict[str, object]] = {}
    for cookie_value in _get_header_list(headers, "set-cookie"):
        lowered = cookie_value.lower()
        missing_flags = []
        if "secure" not in lowered:
            missing_flags.append("Secure")
        if "httponly" not in lowered:
            missing_flags.append("HttpOnly")
        if "samesite" not in lowered:
            missing_flags.append("SameSite")
        if missing_flags:
            key = tuple(missing_flags)
            if key not in cookie_issues:
                cookie_issues[key] = {"count": 0, "sample": cookie_value}
            cookie_issues[key]["count"] = int(cookie_issues[key]["count"]) + 1

    for missing_flags, info in cookie_issues.items():
        count = int(info.get("count", 0))
        sample = info.get("sample")
        code_snippet = _short_words(f"Set-Cookie {sample}") if sample else _short_words("Set-Cookie отсутствует")
        findings.append({
            "name": "Cookie без защитных флагов",
            "description": (
                f"Cookie не содержит флаги: {', '.join(missing_flags)}. "
                f"Количество: {count}."
            ),
            "severity": "high" if len(missing_flags) >= 2 else "medium",
            "recommendation": "Добавьте Secure, HttpOnly и SameSite для чувствительных cookie.",
            "code_snippet": code_snippet,
        })

    return findings


def _iter_config_files(root_path: Path, max_depth: int | None = None) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root_path):
        current_depth = len(Path(dirpath).relative_to(root_path).parts)
        if max_depth is not None and current_depth > max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [name for name in dirnames if name not in DEFAULT_IGNORED_DIRS]
        current_dir = Path(dirpath)
        for filename in filenames:
            file_path = current_dir / filename
            if file_path.name in DEFAULT_IGNORED_FILES:
                continue
            if file_path.suffix.lower() not in DEFAULT_EXTENSIONS and file_path.name not in {"Dockerfile", "nginx.conf", ".env"}:
                continue
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


def _word_snippet(content: str, match_start: int, max_words: int = 10) -> str:
    line_start = content.rfind("\n", 0, match_start) + 1
    line_end = content.find("\n", match_start)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if not line:
        return ""
    words = [(m.group(0), m.start(), m.end()) for m in re.finditer(r"\S+", line)]
    if not words:
        return ""
    char_in_line = match_start - line_start
    word_index = next((i for i, w in enumerate(words) if w[1] <= char_in_line < w[2]), None)
    if word_index is None:
        word_index = min(range(len(words)), key=lambda i: abs(words[i][1] - char_in_line))
    start = max(0, word_index - max_words // 2)
    end = min(len(words), start + max_words)
    if end - start < max_words:
        start = max(0, end - max_words)
    return " ".join(w[0] for w in words[start:end])


def _short_words(text: str, max_words: int = 10) -> str:
    words = re.findall(r"\S+", text)
    return " ".join(words[:max_words])


def scan_project_security_configuration(root_path: str, max_depth: int | None = None, enabled_rules: set[str] | None = None) -> list[dict]:
    root = Path(root_path)
    if not root.exists() or not root.is_dir():
        return []

    findings: list[dict] = []
    selected_rules = enabled_rules or {name for name, *_rest in PROJECT_RULES}
    for file_path in _iter_config_files(root, max_depth=max_depth):
        content = _read_text(file_path)
        if not content:
            continue

        for name, pattern, severity, description, recommendation in PROJECT_RULES:
            if name not in selected_rules:
                continue
            match = pattern.search(content)
            if match:
                code_snippet = _word_snippet(content, match.start())
                findings.append({
                    "name": name,
                    "description": f"{description} Файл: {file_path.as_posix()}",
                    "severity": severity,
                    "recommendation": recommendation,
                    "code_snippet": code_snippet,
                })

    return findings
