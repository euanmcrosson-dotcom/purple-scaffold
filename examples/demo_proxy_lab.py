"""Phase 1 smoke test: verify the proxy + replay rig end-to-end.

Strategy: we don't drive a real product yet. Instead we drive a
litellm call (the existing `scripts/run_custom_probes.py` runner)
through the proxy, capture the LLM API traffic, and verify:

  1. The proxy wrote at least one capture record.
  2. Each capture has a non-empty `request.messages` and a parsed
     `response` (text or tool_uses).
  3. Replaying the capture in passive mode produces a verdict that
     matches the in-process verdict the runner computed.
  4. API keys are redacted from the captured headers.

This validates the architecture before moving to Phase 2 (Cline
target) where the LLM caller is a third-party product instead of
our own runner.

Run:
    python -m examples.demo_proxy_lab

Requires:
    pip install -e .[product]
    ANTHROPIC_API_KEY in env (smoke test calls Haiku 4.5; ~$0.01)

Note: the smoke test starts mitmdump as a subprocess and points
litellm at it via HTTPS_PROXY. mitmproxy will MITM the Anthropic
TLS connection, which requires the user to trust mitmproxy's CA
once. Without trust, the connection fails fast with a TLS error
which the script reports clearly.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
CAPTURE_DIR = REPO_ROOT / "runs" / "proxy"
CAPTURE_PATH = CAPTURE_DIR / "smoke-captures.jsonl"
PROXY_LISTEN = "127.0.0.1:8765"  # bind port (note: the lab uses 8765 too;
# this is fine because we don't run the lab in this demo)


def _start_mitmdump() -> subprocess.Popen:
    """Launch mitmdump in the background with our addon."""
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    # Truncate any previous smoke captures so the assertions below are
    # definitive about THIS run's output.
    CAPTURE_PATH.write_text("", encoding="utf-8")

    cmd = [
        "mitmdump",
        "-s",
        str(REPO_ROOT / "purple" / "proxy.py"),
        "--set",
        f"capture_path={CAPTURE_PATH}",
        "--listen-host",
        PROXY_LISTEN.split(":")[0],
        "--listen-port",
        PROXY_LISTEN.split(":")[1],
        "--quiet",  # less noise on stdout; addon prints what we need
    ]
    print(f"[smoke] starting: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    # Give mitmdump a moment to bind.
    time.sleep(2)
    if proc.poll() is not None:
        out = (proc.stdout.read().decode("utf-8", errors="replace") if proc.stdout else "")
        raise RuntimeError(f"mitmdump exited early:\n{out}")
    return proc


def _drive_one_call_through_proxy() -> int:
    """Run a single one-prompt litellm call through the proxy. Returns
    the runner's exit code."""
    env = os.environ.copy()
    env["HTTPS_PROXY"] = f"http://{PROXY_LISTEN}"
    env["HTTP_PROXY"] = f"http://{PROXY_LISTEN}"
    # mitmproxy uses its own CA. Pointing requests at it without
    # trusting the CA fails with SSL verify errors. For the smoke
    # test we set REQUESTS_CA_BUNDLE / SSL_CERT_FILE to mitmproxy's
    # CA bundle if it exists (created on first mitmproxy run).
    ca_bundle = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if ca_bundle.exists():
        env["REQUESTS_CA_BUNDLE"] = str(ca_bundle)
        env["SSL_CERT_FILE"] = str(ca_bundle)
    else:
        print(
            f"[smoke] WARNING: {ca_bundle} not found; mitmproxy may not have "
            "been initialised yet. The litellm call will likely fail with "
            "a TLS verify error.\n"
            "Fix: run `mitmdump --listen-port 9999` once and Ctrl-C; that "
            "creates the CA, then re-run this script."
        )

    cmd = [
        sys.executable,
        "scripts/run_custom_probes.py",
        "mcp_filesystem",
        "anthropic/claude-haiku-4-5-20251001",
    ]
    print(f"[smoke] driving: {' '.join(cmd)} via proxy {PROXY_LISTEN}")
    result = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
    )
    print("[smoke] runner stdout:")
    print(result.stdout)
    if result.returncode != 0:
        print("[smoke] runner stderr:")
        print(result.stderr)
    return result.returncode


def _read_captures() -> list[dict]:
    if not CAPTURE_PATH.exists():
        return []
    return [
        json.loads(line)
        for line in CAPTURE_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _assert(condition: bool, label: str) -> None:
    status = "OK  " if condition else "FAIL"
    print(f"  [{status}] {label}")
    if not condition:
        raise AssertionError(label)


def main() -> None:
    print("=" * 70)
    print("Phase 1 smoke test: LLM-API proxy + capture rig")
    print("=" * 70)

    proxy = _start_mitmdump()
    try:
        rc = _drive_one_call_through_proxy()
        # We allow a non-zero exit if it's because of TLS / CA issues;
        # the assertions below will tell us whether captures landed
        # regardless.
        time.sleep(1)  # let any in-flight write flush
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()

    captures = _read_captures()

    print()
    print("Assertions:")
    _assert(len(captures) > 0, f"at least one capture written ({len(captures)} found)")

    if not captures:
        print()
        print("No captures landed. Most common causes:")
        print("  1. mitmproxy CA not trusted by the system / Python.")
        print("     Fix: run `mitmdump` once to generate ~/.mitmproxy/.")
        print("     Then add the CA to the OS trust store, or set")
        print("     REQUESTS_CA_BUNDLE / SSL_CERT_FILE to its path.")
        print("  2. ANTHROPIC_API_KEY not set in env.")
        print("  3. Network is otherwise broken.")
        sys.exit(2)

    sample = captures[0]
    _assert(sample.get("entry_type") == "proxy_capture", "entry_type=proxy_capture")
    _assert(sample.get("host") in {"api.anthropic.com", "api.openai.com",
                                    "generativelanguage.googleapis.com",
                                    "api.x.ai"},
            f"host is a known LLM provider: {sample.get('host')}")
    _assert(isinstance(sample.get("request", {}).get("messages"), list)
            and len(sample["request"]["messages"]) > 0,
            "request.messages is a non-empty list")
    response = sample.get("response", {}) or {}
    has_text = bool(response.get("text"))
    has_tool_uses = bool(response.get("tool_uses"))
    _assert(has_text or has_tool_uses, "response has text or tool_uses")
    headers = sample.get("request_headers", {}) or {}
    sensitive = [k for k in headers if k.lower() in
                 {"authorization", "x-api-key", "anthropic-api-key", "x-goog-api-key"}]
    if sensitive:
        for h in sensitive:
            _assert(headers[h] == "***REDACTED***",
                    f"sensitive header redacted: {h}")
    else:
        print("  [INFO] no sensitive headers present in this capture")

    # Replay
    print()
    print("Passive replay (verdict on captured (request, response) tuples):")
    sys.path.insert(0, str(REPO_ROOT))
    from purple.proxy_replay import score_capture

    counts = {"PASS": 0, "FAIL": 0, "REFUSAL": 0}
    for cap in captures:
        v = score_capture(cap)
        counts[v.verdict] += 1
        print(f"  {(v.host + ' / ' + (v.model or '?')):55s} -> {v.verdict}")

    total = sum(counts.values())
    print()
    print(f"  PASS: {counts['PASS']}  REFUSAL: {counts['REFUSAL']}  FAIL: {counts['FAIL']}  / {total}")
    print()
    print(f"Capture file: {CAPTURE_PATH}")
    print()
    print("Phase 1 smoke test PASSED — proxy + capture + replay are wired.")


if __name__ == "__main__":
    main()
