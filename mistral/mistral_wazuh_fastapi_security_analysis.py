"""
Mistral + Wazuh integration + SOC prompt templates
Single-file FastAPI app: receives Wazuh alerts (webhook), accepts ad-hoc log text,
calls local Ollama Mistral or Mixtral models, returns structured analysis.

How to use:
  1. Fill .env values (OLLAMA_HOST, OLLAMA_PORT, MODEL)
  2. pip install -r requirements.txt
  3. python mistral_wazuh_fastapi_security_analysis.py

Endpoints:
  POST /analyze      -> body: {"logs": "..."} returns JSON analysis
  POST /webhook/wazuh -> receives Wazuh webhook payload, extracts relevant logs, analyzes

Security: run Ollama locally (recommended). Avoid sending full sensitive logs to external APIs.

Requires: fastapi, uvicorn, pydantic, requests, python-dotenv
"""

from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import os
import requests
import time
from dotenv import load_dotenv

load_dotenv()

# Configuration (via .env)
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost")
OLLAMA_PORT = os.getenv("OLLAMA_PORT", "11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")  # or "mixtral" etc.
OLLAMA_API = f"{OLLAMA_HOST}:{OLLAMA_PORT}/api/chat"  # Ollama chat endpoint

# Basic rate-limiting / cooldown to avoid overloading Mistral
MIN_SECONDS_BETWEEN_CALLS = float(os.getenv("MIN_SECONDS_BETWEEN_CALLS", "0.5"))
_last_call_time = 0.0

app = FastAPI(title="Mistral Security Log Analyzer")


class AnalyzeRequest(BaseModel):
    logs: str
    context: Optional[str] = None
    max_tokens: Optional[int] = 1024


class AnalyzeResponse(BaseModel):
    summary: str
    iocs: List[str]
    severity: int
    mitre_techniques: List[str]
    recommendations: List[str]
    raw_model_output: Optional[str]


# -------------------- Helper functions --------------------

def _ollama_chat(messages: List[Dict[str, str]], model: str = OLLAMA_MODEL, max_tokens: int = 1024) -> str:
    """Call local Ollama chat API. This small wrapper assumes Ollama is running locally.
    If you use a different inference backend, replace this function accordingly.
    """
    global _last_call_time
    now = time.time()
    elapsed = now - _last_call_time
    if elapsed < MIN_SECONDS_BETWEEN_CALLS:
        time.sleep(MIN_SECONDS_BETWEEN_CALLS - elapsed)

    payload = {
        "model": model,
        "messages": messages,
        # optionally include other fields Ollama supports
    }

    try:
        resp = requests.post(OLLAMA_API, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        # Ollama response schema: {"id":..., "message": {"role":"assistant","content":"..."}, ...}
        _last_call_time = time.time()
        return data.get("message", {}).get("content", "")
    except Exception as e:
        raise RuntimeError(f"Ollama API error: {e}")


# -------------------- Prompt templates --------------------

SOC_PROMPT_TEMPLATE = """
You are a senior SOC analyst. Analyze the provided logs and produce JSON with the following fields:
- summary: a short summary (two sentences)
- iocs: a deduplicated list of Indicators of Compromise (IP addresses, file hashes, URLs, user accounts)
- severity: integer 1-10 (1 low, 10 critical) with short rationale
- mitre_techniques: list of possible MITRE ATT&CK technique IDs or names
- recommendations: concise remediation steps (3-6 items)
- timeline: concise timeline of relevant events (if available)
- matches: list of suspicious log lines (exact text excerpts)

Return ONLY valid JSON. Do not add any extra commentary. If uncertain, mark fields conservatively.

LOGS:
{logs}
"""

IOC_EXTRACTION_PROMPT = """
Extract all IOCs from the logs. Return a JSON array of strings (ip/hash/url/user).
LOGS:
{logs}
"""

MITRE_MAPPING_PROMPT = """
Given this short summary of suspicious behavior: '{summary}', return a JSON array of likely MITRE ATT&CK technique IDs or names (maximum 6).
"""


# -------------------- Analysis pipeline --------------------

def analyze_logs_pipeline(logs: str, context: Optional[str] = None, model: str = OLLAMA_MODEL) -> AnalyzeResponse:
    # 1) Main SOC analysis with structured JSON output request
    prompt = SOC_PROMPT_TEMPLATE.format(logs=logs)

    assistant_output = _ollama_chat([{"role": "user", "content": prompt}], model=model)

    # Try to parse assistant_output as JSON. If the model returns text + JSON, attempt extraction.
    import json
    def extract_json(text: str) -> Optional[Dict[str, Any]]:
        # find first '{' and last '}' and parse
        try:
            start = text.index('{')
            end = text.rindex('}')
            jtext = text[start:end+1]
            return json.loads(jtext)
        except Exception:
            try:
                # fallback: try JSON in whole text
                return json.loads(text)
            except Exception:
                return None

    parsed = extract_json(assistant_output)

    if not parsed:
        # If parsing fails, fall back to lighter extraction using separate prompts
        iocs_text = _ollama_chat([{"role": "user", "content": IOC_EXTRACTION_PROMPT.format(logs=logs)}], model=model)
        # naive parse
        try:
            iocs = json.loads(iocs_text)
        except Exception:
            # split heuristically
            iocs = [x.strip() for x in iocs_text.split('\n') if x.strip()]

        # summary fallback
        summary = assistant_output.strip().split('\n')[0][:512]
        severity = 5
        mitre_techniques = []
        recommendations = ["Review logs manually", "Isolate affected hosts"]

        return AnalyzeResponse(
            summary=summary,
            iocs=iocs,
            severity=severity,
            mitre_techniques=mitre_techniques,
            recommendations=recommendations,
            raw_model_output=assistant_output
        )

    # build response from parsed JSON (with safe defaults)
    summary = parsed.get('summary', '')
    iocs = parsed.get('iocs', []) or []
    severity = int(parsed.get('severity', 5)) if parsed.get('severity') is not None else 5
    mitre_techniques = parsed.get('mitre_techniques', []) or []
    recommendations = parsed.get('recommendations', []) or []

    return AnalyzeResponse(
        summary=summary,
        iocs=iocs,
        severity=severity,
        mitre_techniques=mitre_techniques,
        recommendations=recommendations,
        raw_model_output=assistant_output
    )


# -------------------- FastAPI endpoints --------------------

@app.post('/analyze', response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    try:
        result = analyze_logs_pipeline(req.logs, req.context, OLLAMA_MODEL)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Wazuh webhook: Wazuh can be configured to call an HTTP webhook when an alert triggers.
# This endpoint is purposely forgiving: it accepts full webhook JSON and tries to extract useful fields.

@app.post('/webhook/wazuh')
async def wazuh_webhook(request: Request, background: BackgroundTasks):
    payload = await request.json()

    # Typical Wazuh alert structure contains 'rule' and 'full_log' or 'data' fields depending on config.
    # We attempt to extract the most relevant text for analysis.
    # Example Wazuh webhook: {"agent": {...}, "rule": {...}, "full_log": "..."}

    candidate_logs = []
    if isinstance(payload, dict):
        # extract some candidate fields
        for key in ("full_log", "full_log_text", "message", "log", "syslog"):
            if key in payload and payload[key]:
                candidate_logs.append(str(payload[key]))

        # nested keys
        if 'data' in payload:
            data = payload['data']
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, str) and len(v) > 20:
                        candidate_logs.append(v)

        # if nothing found, stringify payload (cautious)
        if not candidate_logs:
            candidate_logs.append(str(payload))

    logs_text = "\n".join(candidate_logs)[:5000]  # limit length to avoid huge prompts

    # run analysis in background to return quickly to Wazuh
    def bg_task(logs):
        try:
            analysis = analyze_logs_pipeline(logs, model=OLLAMA_MODEL)
            # Here you can push the analysis into Elastic, Slack, or other alerting system
            print("Wazuh alert analysis:", analysis.json())
        except Exception as e:
            print("Background analysis error:", e)

    background.add_task(bg_task, logs_text)

    return {"status": "accepted"}


# -------------------- Example utility: CLI analyze --------------------

if __name__ == '__main__':
    import uvicorn
    print("Starting Mistral Security Log Analyzer on http://0.0.0.0:8000")
    uvicorn.run(app, host='0.0.0.0', port=8000)
