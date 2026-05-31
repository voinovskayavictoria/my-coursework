from __future__ import annotations

import json
import os
from typing import Any

import httpx


DEFAULT_LLM_URL = os.getenv("LOCAL_LLM_URL", "http://127.0.0.1:11434/api/generate")
DEFAULT_LLM_MODEL = os.getenv("LOCAL_LLM_MODEL", "llama3.1:8b-instruct")


def _fallback_explanation(finding: dict) -> dict[str, str]:
    name = finding.get("name", "Проблема безопасности")
    description = finding.get("description", "Выявлен потенциально опасный паттерн.")
    recommendation = finding.get("recommendation", "Исправьте найденный паттерн и ограничьте источник данных.")
    return {
        "description": f"{description} Это требует проверки и исправления в коде.",
        "recommendation": recommendation,
    }


def _build_prompt(finding: dict) -> str:
    return (
        "Ты помощник по безопасной разработке. Переформулируй находку простым языком для отчета. "
        "Верни только JSON с ключами description и recommendation. "
        f"Название: {finding.get('name', '')}\n"
        f"Техническое описание: {finding.get('description', '')}\n"
        f"Серьезность: {finding.get('severity', '')}\n"
        f"Текущая рекомендация: {finding.get('recommendation', '')}\n"
        "Описание должно быть кратким, а recommendation - конкретным и практичным."
    )


def generate_human_explanation(finding: dict) -> dict[str, str]:
    payload: dict[str, Any] = {
        "model": DEFAULT_LLM_MODEL,
        "prompt": _build_prompt(finding),
        "stream": False,
        "options": {
            "temperature": 0.2,
        },
    }

    try:
        response = httpx.post(DEFAULT_LLM_URL, json=payload, timeout=20)
        response.raise_for_status()
        data = response.json()
        raw_text = data.get("response", "")
        parsed = json.loads(raw_text)
        if isinstance(parsed, dict):
            description = str(parsed.get("description") or "").strip()
            recommendation = str(parsed.get("recommendation") or "").strip()
            if description and recommendation:
                return {
                    "description": description,
                    "recommendation": recommendation,
                }
    except Exception:
        pass

    return _fallback_explanation(finding)


def enrich_findings_with_llm(findings: list[dict]) -> list[dict]:
    enriched: list[dict] = []
    for finding in findings:
        human_text = generate_human_explanation(finding)
        updated = dict(finding)
        updated["description"] = human_text["description"]
        updated["recommendation"] = human_text["recommendation"]
        enriched.append(updated)
    return enriched