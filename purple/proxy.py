"""mitmproxy addon that captures LLM API traffic.

Run as:

    mitmdump -s purple/proxy.py --set capture_path=runs/proxy/captures.jsonl

Then point a target product (Cursor, Cline, Claude Desktop, Continue.dev,
or any litellm-using script) at the proxy via:

    HTTPS_PROXY=http://127.0.0.1:8080
    HTTP_PROXY=http://127.0.0.1:8080

… and trust mitmproxy's CA (one-time setup; see
https://docs.mitmproxy.org/stable/concepts/certificates/).

The addon intercepts POSTs to the well-known LLM API hosts and writes
one JSONL record per (request, response) tuple. API keys are redacted
from the captured headers before write.

The output schema is intentionally close to garak's `attempt` record
shape so that downstream tooling (`scripts/run_custom_probes.py`,
`scripts/garak_to_card.py`, the existing `custom_probes` detectors)
can consume captures with minimal adaptation.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from mitmproxy import ctx, http


# ─── Configuration ─────────────────────────────────────────────────


# Hosts whose POST traffic we record. Anything else passes through
# untouched. Add new hosts here when adding support for more
# providers.
INTERESTING_HOSTS: set[str] = {
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "api.x.ai",
}

# Headers that may carry API keys. Always redacted before capture.
SENSITIVE_HEADERS: set[str] = {
    "authorization",
    "x-api-key",
    "anthropic-api-key",
    "x-goog-api-key",
}

# Anthropic & OpenAI key regex (rough — used for body-side redaction
# in case a key shows up inside a request body, which would be
# unusual but possible).
KEY_PATTERN = re.compile(
    r"(sk-[A-Za-z0-9_\-]{20,}|sk-ant-[A-Za-z0-9_\-]{20,}|AIza[A-Za-z0-9_\-]{20,})"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            out[k] = "***REDACTED***"
        else:
            out[k] = v
    return out


def _redact_body(text: str) -> str:
    return KEY_PATTERN.sub("***REDACTED***", text)


# ─── Body parsing per provider ─────────────────────────────────────


def _summarize_anthropic_request(body: dict[str, Any]) -> dict[str, Any]:
    """Extract the parts of an Anthropic /v1/messages request that
    matter for prompt-injection analysis: model, system prompt, full
    message history, and tool definitions."""
    return {
        "provider": "anthropic",
        "model": body.get("model"),
        "system": body.get("system"),
        "messages": body.get("messages", []),
        "tools": body.get("tools", []),
        "max_tokens": body.get("max_tokens"),
    }


def _summarize_anthropic_response(body: dict[str, Any]) -> dict[str, Any]:
    """Extract content blocks + tool_use blocks from an Anthropic
    /v1/messages response."""
    content = body.get("content", []) or []
    text_blocks = [b.get("text", "") for b in content if b.get("type") == "text"]
    tool_uses = [
        {
            "name": b.get("name"),
            "input": b.get("input"),
            "id": b.get("id"),
        }
        for b in content
        if b.get("type") == "tool_use"
    ]
    return {
        "stop_reason": body.get("stop_reason"),
        "text": "\n".join(text_blocks),
        "tool_uses": tool_uses,
        "usage": body.get("usage"),
    }


def _summarize_openai_request(body: dict[str, Any]) -> dict[str, Any]:
    """OpenAI /v1/chat/completions request shape."""
    return {
        "provider": "openai",
        "model": body.get("model"),
        "system": None,  # OpenAI puts system in messages[0]
        "messages": body.get("messages", []),
        "tools": body.get("tools", []),
        "max_tokens": body.get("max_tokens") or body.get("max_completion_tokens"),
    }


def _summarize_openai_response(body: dict[str, Any]) -> dict[str, Any]:
    """OpenAI /v1/chat/completions response shape."""
    choices = body.get("choices", []) or []
    if not choices:
        return {"text": "", "tool_uses": [], "stop_reason": None, "usage": body.get("usage")}
    msg = choices[0].get("message", {}) or {}
    tool_calls = msg.get("tool_calls", []) or []
    tool_uses = [
        {
            "name": (tc.get("function") or {}).get("name"),
            "input": _maybe_json_loads((tc.get("function") or {}).get("arguments")),
            "id": tc.get("id"),
        }
        for tc in tool_calls
    ]
    return {
        "stop_reason": choices[0].get("finish_reason"),
        "text": msg.get("content") or "",
        "tool_uses": tool_uses,
        "usage": body.get("usage"),
    }


def _summarize_gemini_request(body: dict[str, Any]) -> dict[str, Any]:
    """Gemini generateContent request shape (very rough — Gemini's
    schema differs more from the others; this captures the essentials
    for analysis)."""
    return {
        "provider": "gemini",
        "model": None,  # Gemini puts model in URL path
        "system": (body.get("systemInstruction") or {}).get("parts"),
        "messages": body.get("contents", []),
        "tools": body.get("tools", []),
        "max_tokens": (body.get("generationConfig") or {}).get("maxOutputTokens"),
    }


def _summarize_gemini_response(body: dict[str, Any]) -> dict[str, Any]:
    candidates = body.get("candidates", []) or []
    if not candidates:
        return {"text": "", "tool_uses": [], "stop_reason": None, "usage": None}
    content = (candidates[0].get("content") or {}).get("parts", []) or []
    text_blocks = [p.get("text", "") for p in content if "text" in p]
    tool_uses = [
        {
            "name": (p.get("functionCall") or {}).get("name"),
            "input": (p.get("functionCall") or {}).get("args"),
            "id": None,
        }
        for p in content
        if "functionCall" in p
    ]
    return {
        "stop_reason": candidates[0].get("finishReason"),
        "text": "\n".join(text_blocks),
        "tool_uses": tool_uses,
        "usage": body.get("usageMetadata"),
    }


def _summarize_xai_request(body: dict[str, Any]) -> dict[str, Any]:
    """xAI uses OpenAI-compatible chat completions."""
    out = _summarize_openai_request(body)
    out["provider"] = "xai"
    return out


def _summarize_xai_response(body: dict[str, Any]) -> dict[str, Any]:
    return _summarize_openai_response(body)


# ─── Dispatch ──────────────────────────────────────────────────────


def _maybe_json_loads(s: Any) -> Any:
    if isinstance(s, str):
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return s
    return s


def _summarize_request(host: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
    if host == "api.anthropic.com":
        return _summarize_anthropic_request(body)
    if host == "api.openai.com":
        return _summarize_openai_request(body)
    if host == "api.x.ai":
        return _summarize_xai_request(body)
    if host == "generativelanguage.googleapis.com":
        return _summarize_gemini_request(body)
    return {"provider": "unknown", "raw_body_keys": list(body.keys())}


def _summarize_response(host: str, body: dict[str, Any]) -> dict[str, Any]:
    if host == "api.anthropic.com":
        return _summarize_anthropic_response(body)
    if host == "api.openai.com":
        return _summarize_openai_response(body)
    if host == "api.x.ai":
        return _summarize_xai_response(body)
    if host == "generativelanguage.googleapis.com":
        return _summarize_gemini_response(body)
    return {"raw_body_keys": list(body.keys())}


# ─── The addon ─────────────────────────────────────────────────────


class CaptureAddon:
    """mitmproxy addon: writes one JSONL line per intercepted LLM API
    request/response pair.

    Plain class (not @dataclass) — mitmproxy's script loader doesn't
    register the module in sys.modules in a way @dataclass expects on
    Python 3.14, so dataclass introspection fails at class-creation
    time. Plain __init__ avoids that path entirely.
    """

    def __init__(self) -> None:
        self.capture_path: Path = Path("runs/proxy/captures.jsonl")
        self._file: Any = None  # opened lazily in `running()`
        self._capture_count: int = 0

    def load(self, loader) -> None:  # mitmproxy addon hook
        loader.add_option(
            name="capture_path",
            typespec=str,
            default="runs/proxy/captures.jsonl",
            help="Path to the JSONL file the proxy writes captures to",
        )

    def running(self) -> None:  # mitmproxy addon hook
        self.capture_path = Path(ctx.options.capture_path)
        self.capture_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.capture_path.open("a", encoding="utf-8")
        ctx.log.info(f"[purple.proxy] capturing to {self.capture_path}")

    def done(self) -> None:  # mitmproxy addon hook
        if self._file is not None:
            self._file.close()
            ctx.log.info(
                f"[purple.proxy] wrote {self._capture_count} captures to {self.capture_path}"
            )

    def response(self, flow: http.HTTPFlow) -> None:
        """Hook called after a full request+response is available."""
        host = flow.request.pretty_host
        if host not in INTERESTING_HOSTS:
            return
        if flow.request.method != "POST":
            return

        try:
            request_body = self._parse_body(flow.request.get_text() or "{}")
        except Exception as exc:
            ctx.log.warn(f"[purple.proxy] request body parse failed: {exc}")
            return
        try:
            response_body = self._parse_body(flow.response.get_text() or "{}")
        except Exception as exc:
            ctx.log.warn(f"[purple.proxy] response body parse failed: {exc}")
            return

        record = {
            "entry_type": "proxy_capture",
            "uuid": uuid4().hex,
            "timestamp": _now(),
            "host": host,
            "method": flow.request.method,
            "path": flow.request.path,
            "status_code": flow.response.status_code,
            "request_headers": _redact_headers(dict(flow.request.headers)),
            "request": _summarize_request(host, flow.request.path, request_body),
            "response": _summarize_response(host, response_body),
        }

        # Final pass: redact any key that snuck into a stringifiable
        # field (defence in depth).
        line = _redact_body(json.dumps(record, ensure_ascii=False))
        self._file.write(line + "\n")
        self._file.flush()
        self._capture_count += 1

    @staticmethod
    def _parse_body(text: str) -> dict[str, Any]:
        if not text.strip():
            return {}
        return json.loads(text)


# mitmproxy looks for a module-level `addons` list.
addons = [CaptureAddon()]
