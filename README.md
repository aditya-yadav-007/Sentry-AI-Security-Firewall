# Sentry - AI Security Firewall

A lightweight detection layer that intercepts chatbot input, screens it against known LLM attack patterns, and routes malicious traffic to a SIEM before it reaches the model.

## Problem

LLM-integrated applications inherit a structural weakness: there is no reliable boundary between "instructions" and "data" in the input stream. This enables prompt injection, jailbreaking, and downstream exploitation (RCE via generated code, XSS via unsanitized output, credential/data exfiltration). OWASP formalizes these under LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure), LLM05 (Improper Output Handling), and LLM06 (Excessive Agency).

## Architecture

```
Client (chat.html)
      |
      v
FastAPI backend (server.py)
      |
      v
Detection engine (regex + base64 decode heuristics)
      |
      +--> Match found  --> Alert logged --> Wazuh SIEM (localfile ingestion)
      |
      +--> No match      --> Request cleared for downstream processing
```

## Detection Coverage

| Category | Technique | OWASP Mapping |
|---|---|---|
| Instruction override | "ignore previous instructions" patterns | LLM01 |
| System prompt leakage | extraction phrasing | LLM01 / LLM07 |
| Jailbreak framing | DAN-style, role override | LLM01 |
| Code execution attempts | `os.system`, `eval`, `subprocess` | LLM06 |
| Network exfiltration | `curl`, `wget`, outbound requests | LLM06 |
| Reverse shell payloads | `/dev/tcp/`, `nc -e` | LLM06 |
| Injection payloads | SQLi, XSS markers | LLM05 |
| Sensitive data requests | credentials, keys, PII | LLM02 |
| Obfuscation | Base64-encoded payloads, decoded and re-scanned | LLM01 |
| Resource abuse | repeated-character flooding | LLM10 |

## Components

- `chat.html` — self-contained frontend (HTML/CSS/JS), no external dependencies
- `server.py` — FastAPI backend running the detection engine and serving the frontend
- Detected events are written as structured JSON to a local log file, consumable by a Wazuh agent via `localfile` monitoring in `ossec.conf`

## Design Notes

- Detection is signature-based (regex), not model-based. This trades recall for speed, transparency, and zero inference cost — appropriate for a firewall layer that must not itself become an attack surface.
- Base64 payloads are decoded and re-scanned rather than treated as opaque strings, closing a common obfuscation bypass.
- No live model endpoint is called. Cleared requests return a stub response; this project scopes to detection and alerting, not LLM proxying.

## Running

```
pip install fastapi uvicorn --break-system-packages
python server.py
```

Serves on `http://localhost:8000`.

## Limitations

Signature-based detection does not generalize to novel phrasing or semantic-level attacks (e.g. paraphrased injections, multi-turn context poisoning). A production system would layer this with an embedding-similarity or classifier-based second stage.