#!/usr/bin/env python3
"""
Run: pip install fastapi uvicorn requests --break-system-packages
Start: python server.py
Serves chat.html + /chat API on http://localhost:8000
"""

import re, json, base64, datetime, logging
import requests
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

LOG_FILE = "/var/log/prompt_injection_alerts.log"
try:
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(message)s")
except PermissionError:
    logging.basicConfig(filename="alerts.log", level=logging.INFO, format="%(message)s")

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

PATTERNS = {
    "instruction_override": r"(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+instructions",
    "system_prompt_leak": r"(reveal|print|show|leak).{0,20}(system prompt|instructions)",
    "jailbreak_dan": r"(DAN|developer mode|do anything now|no restrictions|jailbroken)",
    "role_override": r"you are (now|the) (system|admin|root|unrestricted)",
    "rce_attempt": r"(os\.popen|os\.system|subprocess|eval\(|exec\(|__import__)",
    "network_exfil": r"(curl|wget|requests\.get)\s*\(?.*(http|ftp)",
    "reverse_shell": r"(bash -i|nc -e|/dev/tcp/)",
    "sql_injection": r"(\bOR\b\s+1=1|--|xp_cmdshell)",
    "xss_payload": r"(<script>|onerror=|onload=)",
    "data_exfil_request": r"(credit card|password|api key|ssn|environment variables?)",
    "prompt_flood": r"(.)\1{200,}",
}
COMPILED = {k: re.compile(v, re.IGNORECASE) for k, v in PATTERNS.items()}


def is_base64_suspicious(text):
    for t in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            d = base64.b64decode(t + "==").decode("utf-8", "ignore")
            if re.search(r"(echo|bash|rm -rf|curl|passwd)", d, re.IGNORECASE):
                return True
        except Exception:
            pass
    return False


def scan(text):
    hits = [n for n, p in COMPILED.items() if p.search(text)]
    if is_base64_suspicious(text):
        hits.append("base64_payload")
    return hits


def log_alert(prompt, hits):
    alert = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "source": "chat_defense",
        "detections": hits,
        "severity": "high" if len(hits) > 2 else "medium",
        "prompt_snippet": prompt[:200],
    }
    logging.info(json.dumps(alert))
    return alert


def forward_to_ai(api_key, prompt):
    # Real AI call voided — this is a firewall demo, not a live LLM proxy.
    return "[PASSED] Prompt clean. Would be forwarded to AI server (call skipped)."


class ChatRequest(BaseModel):
    api_key: str
    prompt: str


@app.get("/")
def root():
    return FileResponse("chat.html")


@app.post("/chat")
def chat(req: ChatRequest):
    hits = scan(req.prompt)
    if hits:
        alert = log_alert(req.prompt, hits)
        return JSONResponse({"blocked": True, "detections": hits, "alert": alert})
    reply = forward_to_ai(req.api_key, req.prompt)
    return JSONResponse({"blocked": False, "reply": reply})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
