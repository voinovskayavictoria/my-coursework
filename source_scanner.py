from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class SourceFindingRule:
    name: str
    pattern: re.Pattern[str]
    severity: str
    description: str
    recommendation: str


SOURCE_RULES: tuple[SourceFindingRule, ...] = (
    SourceFindingRule(
        name="Использование eval",
        pattern=re.compile(r"\beval\s*\(", re.IGNORECASE),
        severity="critical",
        description="Найден вызов eval(), который может привести к выполнению произвольного кода.",
        recommendation="Замените eval() на безопасный разбор данных или явную логику обработки.",
    ),
    SourceFindingRule(
        name="Использование document.write",
        pattern=re.compile(r"\bdocument\.write\s*\(", re.IGNORECASE),
        severity="high",
        description="Обнаружен document.write(), который может создавать риск XSS и ломать разметку.",
        recommendation="Используйте textContent, appendChild или безопасный шаблонизатор.",
    ),
    SourceFindingRule(
        name="Прямое присваивание innerHTML",
        pattern=re.compile(r"\.innerHTML\s*=", re.IGNORECASE),
        severity="high",
        description="Найдено прямое присваивание innerHTML, что опасно при использовании пользовательского ввода.",
        recommendation="Используйте textContent или предварительную санацию HTML перед вставкой.",
    ),
    SourceFindingRule(
        name="Уязвимый DOM API",
        pattern=re.compile(r"dangerouslySetInnerHTML|insertAdjacentHTML", re.IGNORECASE),
        severity="high",
        description="Найден потенциально опасный DOM-паттерн, который может привести к XSS.",
        recommendation="Проверьте источник данных и по возможности замените на безопасный рендеринг.",
    ),
    SourceFindingRule(
        name="Опасное выполнение команд",
        pattern=re.compile(r"\b(os\.system|subprocess\.(?:Popen|run|call|check_output)|exec\s*\()", re.IGNORECASE),
        severity="critical",
        description="Обнаружен опасный вызов для выполнения команд или кода.",
        recommendation="Избегайте выполнения команд из пользовательского ввода и используйте безопасные API.",
    ),
    SourceFindingRule(
        name="shell=True",
        pattern=re.compile(r"shell\s*=\s*True", re.IGNORECASE),
        severity="high",
        description="Найден subprocess с shell=True, что повышает риск инъекций команд.",
        recommendation="Уберите shell=True и передавайте аргументы списком.",
    ),
    SourceFindingRule(
        name="Секрет в исходниках",
        pattern=re.compile(r"(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][^\"'\n]{8,}[\"']", re.IGNORECASE),
        severity="high",
        description="Похоже, в коде найдено значение, похожее на ключ, токен или пароль.",
        recommendation="Вынесите секреты в переменные окружения или защищённое хранилище.",
    ),
)

DEFAULT_IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
DEFAULT_IGNORED_FILES = {"source_scanner.py", "static_checks.py", "scanner.py"}
DEFAULT_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".htm", ".css", ".json", ".yml", ".yaml", ".env"}
MAX_FILE_SIZE = 1024 * 1024


def _iter_source_files(root_path: Path, max_depth: int | None = None) -> Iterable[Path]:
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
            if file_path.suffix.lower() not in DEFAULT_EXTENSIONS and file_path.name != ".env":
                continue
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            yield file_path


def _find_line_number(content: str, match_start: int) -> int:
    return content.count("\n", 0, match_start) + 1


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


def scan_source_tree(root_path: str, max_depth: int | None = None, enabled_rules: set[str] | None = None) -> list[dict]:
    root = Path(root_path)
    if not root.exists() or not root.is_dir():
        return []

    findings: list[dict] = []
    selected_rules = enabled_rules or {rule.name for rule in SOURCE_RULES}
    for file_path in _iter_source_files(root, max_depth=max_depth):
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                content = file_path.read_text(encoding="cp1251")
            except Exception:
                continue
        except OSError:
            continue

        lines = content.splitlines()
        for rule in SOURCE_RULES:
            if rule.name not in selected_rules:
                continue
            for match in rule.pattern.finditer(content):
                line_number = _find_line_number(content, match.start())
                snippet = lines[line_number - 1].strip() if 0 < line_number <= len(lines) else ""
                findings.append({
                    "name": rule.name,
                    "description": f"{rule.description} Файл: {file_path.as_posix()}\nСтрока {line_number}: {snippet}",
                    "severity": rule.severity,
                    "recommendation": rule.recommendation,
                    "code_snippet": _word_snippet(content, match.start()),
                })
                break

    return findings
