from __future__ import annotations

"""FastAPI-приложение для анализа логов через LM Studio."""

import json
from typing import Any
import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import uvicorn

app = FastAPI()

# Конфигурация для локального LM Studio.
# Убедитесь, что адрес совпадает с настройками вашего сервера.
LLM_URL = "http://127.0.0.1:1234/v1/chat/completions"

# Если нужно конкретно указать модель, задайте здесь её имя.
# Иначе будет использована текущая модель на сервере.
MODEL_NAME: str | None = None

# --- МОДЕЛИ ДАННЫХ ---
class AnalyzeRequest(BaseModel):
    id: str
    timestamp: str
    source: str
    source_ip: str | None = None
    event_type: str
    raw_line: str
    normalized_fields: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

class AnalyzeResponse(BaseModel):
    score: float
    severity: str
    category: str
    explanation: str
    recommended_action: str

# --- ЭНДПОИНТЫ ---
@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(event: AnalyzeRequest) -> AnalyzeResponse:
    # Встроенный системный запрос для модели.
    # Принцип: четко задать формат вывода и допустимые поля.
    system_prompt = (
        "You are a cybersecurity log analysis assistant. "
        "Analyze the provided normalized log event and return ONLY valid JSON. "
        "The JSON must contain exactly these keys: "
        "score, severity, category, explanation, recommended_action. "
        "Rules: "
        "score must be a float from 0.0 to 1.0; "
        "severity must be one of low, medium, high, critical; "
        "category should be one of web, auth, system, access, unknown; "
        "explanation must be short and useful; "
        "recommended_action should be one of monitor, investigate, block, ignore."
    )

    # Собираем данные события в одну структуру
    user_payload = {
        "id": event.id,
        "timestamp": event.timestamp,
        "source": event.source,
        "source_ip": event.source_ip,
        "event_type": event.event_type,
        "raw_line": event.raw_line,
        "normalized_fields": event.normalized_fields,
        "metadata": event.metadata,
    }

    # Формируем запрос для LM Studio.
    llm_request: dict[str, Any] = {
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    "Analyze this normalized log event and decide if it is suspicious. "
                    "Return JSON only.\n\n"
                    + json.dumps(user_payload, ensure_ascii=False)
                ),
            },
        ],
        "temperature": 0.1,
    }

    if MODEL_NAME:
        llm_request["model"] = MODEL_NAME

    # Отправляем POST-запрос к LM Studio и проверяем ответ.
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(LLM_URL, json=llm_request)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LLM request failed: {exc}")

    # Извлекаем текстовый ответ модели из стандартного формата OpenAI-подобных API.
    try:
        content = data["choices"][0]["message"]["content"]
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Bad LLM response shape: {exc}")

    parsed = _parse_json_response(content)

    return AnalyzeResponse(
        score=_normalize_score(parsed.get("score", 0.5)),
        severity=_normalize_severity(parsed.get("severity", "medium")),
        category=_normalize_category(parsed.get("category", "unknown")),
        explanation=str(parsed.get("explanation", "No explanation provided.")).strip(),
        recommended_action=_normalize_action(parsed.get("recommended_action", "investigate")),
    )

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def _parse_json_response(content: str) -> dict[str, Any]:
    """Пытаемся извлечь словарь из ответа модели.

    Сначала пробуем распарсить весь текст как JSON.
    Если ответ обернут в markdown-кодовую секцию, ищем JSON внутри.
    """
    text = content.strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    if "```" in text:
        text = text.replace("```json", "```" ).replace("```JSON", "```")
        parts = text.split("```")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            try:
                parsed = json.loads(part)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                continue

    return {
        "score": 0.5,
        "severity": "medium",
        "category": "unknown",
        "explanation": "Model returned invalid JSON; adapter fallback was used.",
        "recommended_action": "investigate",
    }


def _normalize_score(value: Any) -> float:
    """Приводит значение score к диапазону [0.0, 1.0]."""
    try:
        return max(0.0, min(1.0, float(value)))
    except Exception:
        return 0.5


def _normalize_severity(value: Any) -> str:
    """Проверяет, что severity входит в список допустимых значений."""
    allowed = {"low", "medium", "high", "critical"}
    text = str(value).strip().lower()
    return text if text in allowed else "medium"


def _normalize_category(value: Any) -> str:
    """Проверяет, что category входит в список допустимых значений."""
    allowed = {"web", "auth", "system", "access", "unknown"}
    text = str(value).strip().lower()
    return text if text in allowed else "unknown"


def _normalize_action(value: Any) -> str:
    """Проверяет, что recommended_action входит в список допустимых значений."""
    allowed = {"monitor", "investigate", "block", "ignore"}
    text = str(value).strip().lower()
    return text if text in allowed else "investigate"

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)