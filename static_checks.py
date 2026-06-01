# Модуль для статического анализа HTML/JS (inline-уязвимости)
import re


def _word_snippet(text: str, match_start: int, max_words: int = 10) -> str:
    line_start = text.rfind("\n", 0, match_start) + 1
    line_end = text.find("\n", match_start)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end].strip()
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


def _snippet_for_regex(text: str, pattern: re.Pattern[str]) -> str:
    match = pattern.search(text)
    return _word_snippet(text, match.start()) if match else ""


def _snippet_for_substring(text: str, needle: str) -> str:
    idx = text.find(needle)
    return _word_snippet(text, idx) if idx >= 0 else ""

def find_inline_vulnerabilities(html_code: str) -> list:
    """
    Принимает HTML/JS код, возвращает список найденных статических уязвимостей.
    Каждая уязвимость — словарь с полями:
        name, description, severity, recommendation.
    """
    vulnerabilities = []

    # 1. Инлайн-скрипты (<script>...</script> без src)
    script_pattern = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.IGNORECASE)
    if script_pattern.search(html_code):
        snippet = _snippet_for_regex(html_code, script_pattern) or _snippet_for_substring(html_code, "<script")
        vulnerabilities.append({
            'name': 'Inline script',
            'rule': 'Inline script',
            'description': 'Inline script detected (<script>...</script> without a src attribute). This can be an XSS vector.',
            'severity': 'medium',
            'recommendation': 'Move JavaScript to external files and configure Content-Security-Policy.',
            'code_snippet': snippet,
        })

    # 2. Обработчики событий (onclick, onload, onerror и т.д.)
    handlers_pattern = re.compile(r'\bon\w+\s*=', re.IGNORECASE)
    if handlers_pattern.search(html_code):
        snippet = _snippet_for_regex(html_code, handlers_pattern)
        vulnerabilities.append({
            'name': 'Inline event handlers',
            'rule': 'Inline event handlers',
            'description': 'Inline event handlers detected (onclick, onload, etc.). They increase XSS risk.',
            'severity': 'medium',
            'recommendation': 'Use addEventListener in JavaScript instead of inline attributes.',
            'code_snippet': snippet,
        })

    # 3. JavaScript URI в href
    js_uri_pattern = re.compile(r'href\s*=\s*[\'"]javascript:', re.IGNORECASE)
    if js_uri_pattern.search(html_code):
        snippet = _snippet_for_regex(html_code, js_uri_pattern)
        vulnerabilities.append({
            'name': 'JavaScript URI в ссылке',
            'rule': 'JavaScript URI в ссылке',
            'description': 'Обнаружен href="javascript:...", что может привести к XSS при клике.',
            'severity': 'high',
            'recommendation': 'Не используйте javascript: в href. Замените на обработчик события.',
            'code_snippet': snippet,
        })

    # 4. Использование eval()
    eval_pattern = re.compile(r'\beval\s*\(', re.IGNORECASE)
    if eval_pattern.search(html_code):
        snippet = _snippet_for_regex(html_code, eval_pattern)
        vulnerabilities.append({
            'name': 'Использование eval()',
            'rule': 'Использование eval()',
            'description': 'Функция eval() может выполнить произвольный код и является опасной.',
            'severity': 'critical',
            'recommendation': 'Избегайте eval. Используйте безопасные альтернативы.',
            'code_snippet': snippet,
        })

    # 5. Использование document.write()
    write_pattern = re.compile(r'document\.write\s*\(', re.IGNORECASE)
    if write_pattern.search(html_code):
        snippet = _snippet_for_regex(html_code, write_pattern)
        vulnerabilities.append({
            'name': 'Использование document.write()',
            'rule': 'Использование document.write()',
            'description': 'document.write() может быть использован для динамической вставки кода, что опасно.',
            'severity': 'high',
            'recommendation': 'Используйте textContent или createElement вместо document.write.',
            'code_snippet': snippet,
        })

    # 6. Смешанный контент (HTTP ресурсы на HTTPS странице) – простая проверка
    mixed_pattern = re.compile(r'(?:src|href)\s*=\s*[\'"]http://', re.IGNORECASE)
    if mixed_pattern.search(html_code):
        snippet = _snippet_for_regex(html_code, mixed_pattern)
        vulnerabilities.append({
            'name': 'Смешанный контент',
            'rule': 'Смешанный контент',
            'description': 'Обнаружены ресурсы, загружаемые по HTTP. На HTTPS странице это небезопасно.',
            'severity': 'high',
            'recommendation': 'Замените http:// на https:// или используйте относительные пути.',
            'code_snippet': snippet,
        })

    # 7. Прямое присваивание innerHTML
    inner_html_pattern = re.compile(r"\.innerHTML\s*=", re.IGNORECASE)
    if inner_html_pattern.search(html_code):
        snippet = _snippet_for_regex(html_code, inner_html_pattern)
        vulnerabilities.append({
            'name': 'Прямое присваивание innerHTML',
            'rule': 'Прямое присваивание innerHTML',
            'description': 'Найдено прямое присваивание innerHTML, что опасно при вставке пользовательских данных.',
            'severity': 'high',
            'recommendation': 'Используйте textContent или предварительную санацию HTML перед вставкой.',
            'code_snippet': snippet,
        })

    # 8. Уязвимый DOM API
    dom_api_pattern = re.compile(r"dangerouslySetInnerHTML|insertAdjacentHTML", re.IGNORECASE)
    if dom_api_pattern.search(html_code):
        snippet = _snippet_for_regex(html_code, dom_api_pattern)
        vulnerabilities.append({
            'name': 'Уязвимый DOM API',
            'rule': 'Уязвимый DOM API',
            'description': 'Найден потенциально опасный DOM-паттерн, который может привести к XSS.',
            'severity': 'high',
            'recommendation': 'Проверьте источник данных и по возможности замените на безопасный рендеринг.',
            'code_snippet': snippet,
        })

    # 9. Секреты в HTML/JS
    secret_pattern = re.compile(r"(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'`][^\"'`\n]{8,}[\"'`]", re.IGNORECASE)
    if secret_pattern.search(html_code):
        snippet = _snippet_for_regex(html_code, secret_pattern)
        vulnerabilities.append({
            'name': 'Секрет в HTML/JS',
            'rule': 'Секрет в HTML/JS',
            'description': 'Похоже, найдено значение, похожее на ключ, токен или пароль в HTML/JS-коде.',
            'severity': 'high',
            'recommendation': 'Вынесите секреты в переменные окружения или защищённое хранилище.',
            'code_snippet': snippet,
        })

    return vulnerabilities
