from urllib.parse import urlparse
import httpx
from bs4 import BeautifulSoup
from fastapi import HTTPException

from scanner import extract_lib_and_version
from static_checks import find_inline_vulnerabilities
from webapp.config import MAX_HTML_SIZE_BYTES
from webapp.scans.storage import apply_rule_filter, normalize_vulnerability
from webapp.state import scanner


def validate_html_size(html_code: str) -> None:
    if len(html_code.encode("utf-8")) > MAX_HTML_SIZE_BYTES:
        raise HTTPException(413, f"HTML-код превышает лимит {MAX_HTML_SIZE_BYTES // 1024} KB")


def normalize_target_url(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(400, "URL должен начинаться с http:// или https://")
    return target


async def fetch_limited_html(target: str) -> tuple[str, httpx.Headers, httpx.URL]:
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(connect=10.0, read=15.0, write=10.0, pool=10.0),
        follow_redirects=True,
    ) as client:
        async with client.stream("GET", target) as resp:
            resp.raise_for_status()
            chunks = []
            total = 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_HTML_SIZE_BYTES:
                    raise HTTPException(413, f"Ответ превышает лимит {MAX_HTML_SIZE_BYTES // 1024} KB")
                chunks.append(chunk)
            html = b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace")
            return html, resp.headers, resp.url


def collect_html_vulnerabilities(html_code: str, enabled_rules: set[str] | None = None) -> list[dict]:
    vulnerabilities = []
    static_vulns = find_inline_vulnerabilities(html_code)
    for idx, vuln in enumerate(static_vulns, start=1):
        vulnerabilities.append(normalize_vulnerability(vuln, "STATIC", idx))

    soup = BeautifulSoup(html_code, "html.parser")
    for script in soup.find_all("script", src=True):
        src = script.get("src", "")
        lib_name, version = extract_lib_and_version(src)
        if lib_name and version:
            print(f"Найдена библиотека: {lib_name}, версия: {version}")
            cves = scanner.search_by_product_version(lib_name, version)
            for idx, cve in enumerate(cves, start=1):
                cve["name"] = f"{lib_name} {version} — {cve['id']}"
                cve["rule"] = "Уязвимые зависимости"
                vulnerabilities.append(normalize_vulnerability(cve, "CVE", idx))

    return apply_rule_filter(vulnerabilities, enabled_rules)
