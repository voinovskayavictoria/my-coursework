# Модуль интеграции с локальной LLM (Ollama) для генерации человекочитаемых пояснений и рекомендаций к найденным уязвимостям.
from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx


DEFAULT_LLM_URL = os.getenv("LOCAL_LLM_URL", "http://127.0.0.1:11434/api/generate")
DEFAULT_LLM_MODEL = os.getenv("LOCAL_LLM_MODEL", "llama3.1:8b")


def _fallback_explanation(finding: dict) -> dict[str, str]:
    name = finding.get("name", "Проблема безопасности")
    description = finding.get("description", "Выявлен потенциально опасный паттерн.")
    recommendation = str(finding.get("recommendation") or "").strip()
    if not recommendation:
        recommendation = "Рекомендация недоступна."
    return {
        "description": f"{description} Это требует проверки и исправления в коде. LLM недоступна: запустите Ollama, чтобы получить рекомендацию.",
        "recommendation": recommendation,
    }


def _build_prompt(finding: dict) -> str:
    return (
        "Ты помощник по безопасной разработке. Переформулируй находку простым языком для отчета. "
        "Пиши ответ на русском. Верни только JSON с ключами description и recommendation. "
        f"Название: {finding.get('name', '')}\n"
        f"Техническое описание: {finding.get('description', '')}\n"
        f"Серьезность: {finding.get('severity', '')}\n"
        "Сформируй рекомендацию самостоятельно. "
        "Описание должно быть кратким, а recommendation - конкретным и практичным, на русском языке."
    )


def generate_human_explanation(finding: dict) -> dict[str, str]:
    payload: dict[str, Any] = {
        "model": DEFAULT_LLM_MODEL,
        "prompt": _build_prompt(finding),
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.2,
        },
    }

    try:
        response = httpx.post(DEFAULT_LLM_URL, json=payload, timeout=300)
        response.raise_for_status()
        data = response.json()
        raw_text = str(data.get("response") or "").strip()

        parsed = None
        if raw_text:
            try:
                parsed = json.loads(raw_text)
            except Exception:
                match = re.search(r"\{.*\}", raw_text, re.DOTALL)
                if match:
                    try:
                        parsed = json.loads(match.group(0))
                    except Exception:
                        parsed = None

        if isinstance(parsed, dict):
            description = str(parsed.get("description") or "").strip()
            recommendation = str(parsed.get("recommendation") or "").strip()
            if description and recommendation:
                return {
                    "description": description,
                    "recommendation": recommendation,
                }

        if raw_text:
            fallback = _fallback_explanation(finding)
            return {
                "description": fallback["description"],
                "recommendation": raw_text,
            }
    except Exception:
        pass

    return _fallback_explanation(finding)


def enrich_findings_with_llm(findings: list[dict]) -> list[dict]:
    enriched: list[dict] = []
    for finding in findings:
        updated = dict(finding)
        human_text = generate_human_explanation(finding)
        updated["description"] = human_text["description"]
        updated["recommendation"] = human_text["recommendation"]
        enriched.append(updated)
    return enriched
