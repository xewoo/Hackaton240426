from __future__ import annotations

"""FastAPI application for log analysis via LM Studio."""

import json
from typing import Any
import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import uvicorn

app = FastAPI()

# Configuration for local LM Studio.
# Ensure the address matches your server settings.
LLM_URL = "http://127.0.0.1:1234/v1/chat/completions"

# If you need to specify a model explicitly, set its name here.
# Otherwise the server's current model will be used.
MODEL_NAME: str | None = None

# --- DATA MODELS ---
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

# --- ENDPOINTS ---
@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(event: AnalyzeRequest) -> AnalyzeResponse:
    # Collect event data into one structure
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

    # Build request for LM Studio.
    # All LLM settings (for example, system prompt and temperature) are configured in LM Studio.
    llm_request: dict[str, Any] = {
        "messages": [
            {
                "role": "user",
                "content": json.dumps(user_payload, ensure_ascii=False),
            },
        ],
    }

    if MODEL_NAME:
        llm_request["model"] = MODEL_NAME

    # Send POST request to LM Studio and verify the response.
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(LLM_URL, json=llm_request)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LLM request failed: {exc}")

    # Extract the model's text response from the standard OpenAI-like API format.
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

# --- HELPER FUNCTIONS ---
def _parse_json_response(content: str) -> dict[str, Any]:
    """Try to parse a dictionary from the model response.

    First attempt to parse the entire text as JSON.
    If the response is wrapped in a markdown code block, search for JSON inside.
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
    """Normalize score value to the [0.0, 1.0] range."""
    try:
        return max(0.0, min(1.0, float(value)))
    except Exception:
        return 0.5


def _normalize_severity(value: Any) -> str:
    """Ensure severity is one of the allowed values."""
    allowed = {"low", "medium", "high", "critical"}
    text = str(value).strip().lower()
    return text if text in allowed else "medium"


def _normalize_category(value: Any) -> str:
    """Ensure category is one of the allowed values."""
    allowed = {"web", "auth", "system", "access", "unknown"}
    text = str(value).strip().lower()
    return text if text in allowed else "unknown"


def _normalize_action(value: Any) -> str:
    """Ensure recommended_action is one of the allowed values."""
    allowed = {"monitor", "investigate", "block", "ignore"}
    text = str(value).strip().lower()
    return text if text in allowed else "investigate"

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)