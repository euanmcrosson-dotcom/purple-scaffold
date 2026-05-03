"""Run custom probes against an LLM and write garak-format JSONL.

Bypasses garak's plugin system — calls litellm directly. Output JSONL
matches garak's format closely enough that scripts/garak_to_card.py
consumes it unchanged.

Usage:
    python scripts/run_custom_probes.py PROBE_NAME MODEL_SPEC

    PROBE_NAME    : module path under custom_probes/ (e.g., echoleak)
    MODEL_SPEC    : litellm model name (e.g., anthropic/claude-haiku-4-5-20251001)

Examples:
    python scripts/run_custom_probes.py echoleak anthropic/claude-haiku-4-5-20251001
    python scripts/run_custom_probes.py mcp_poisoning openai/gpt-4o-mini
    python scripts/run_custom_probes.py mcp_poisoning gemini/gemini-2.5-flash
"""

from __future__ import annotations

import importlib
import inspect
import json
import math
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Make custom_probes importable when running from repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from custom_probes.base import CustomProbe, CustomPrompt  # noqa: E402

import litellm  # noqa: E402

# Suppress litellm's chatty logging.
litellm.suppress_debug_info = True
import logging
logging.getLogger("LiteLLM").setLevel(logging.CRITICAL)


def load_probe(name: str) -> CustomProbe:
    """Import custom_probes.<name>, return the probe class instance."""
    mod = importlib.import_module(f"custom_probes.{name}")
    for _, obj in inspect.getmembers(mod, inspect.isclass):
        if (
            issubclass(obj, CustomProbe)
            and obj is not CustomProbe
            and obj.__module__ == mod.__name__
        ):
            return obj()
    raise ValueError(f"No CustomProbe subclass found in custom_probes.{name}")


def call_model(model: str, prompt_text: str, max_tokens: int = 600) -> str:
    """Single litellm call. Returns output text or empty string on filter."""
    try:
        kwargs = {
            "model": model,
            "messages": [{"role": "user", "content": prompt_text}],
            "max_tokens": max_tokens,
        }
        # Anthropic models: don't send temperature/top_p (4.5+ rejects them).
        if not model.startswith("anthropic/"):
            kwargs["temperature"] = 0.7
        resp = litellm.completion(**kwargs)
        choices = getattr(resp, "choices", []) or []
        if not choices:
            return ""
        msg = choices[0].message
        return (msg.content or "") if msg else ""
    except litellm.exceptions.RateLimitError:
        # Backoff and retry once.
        time.sleep(60)
        return call_model(model, prompt_text, max_tokens)
    except Exception as e:  # noqa: BLE001 — record but don't crash
        return f"__error__: {type(e).__name__}: {str(e)[:200]}"


def wilson_ci(passed: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)
    p = passed / total
    denom = 1 + z**2 / total
    centre = (p + z**2 / (2 * total)) / denom
    spread = z * math.sqrt(p * (1 - p) / total + z**2 / (4 * total**2)) / denom
    return (max(0.0, centre - spread), min(1.0, centre + spread))


def run_probe(probe: CustomProbe, model: str, runs_dir: Path) -> Path:
    run_id = uuid4().hex
    started = datetime.now(timezone.utc).isoformat()
    report_path = runs_dir / f"custom.{run_id}.report.jsonl"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []

    # garak-compatible setup record
    records.append({
        "entry_type": "start_run setup",
        "_config.version": "0.0-custom",
        "plugins.target_type": "litellm",
        "plugins.target_name": model,
        "plugins.probe_spec": probe.name,
        "transient.starttime_iso": started,
        "transient.run_id": run_id,
    })
    records.append({
        "entry_type": "init",
        "garak_version": "0.0-custom",
        "start_time": started,
        "run": run_id,
    })

    counts = {"PASS": 0, "FAIL": 0, "REFUSAL": 0}
    print(f"\nProbe:   {probe.name}")
    print(f"Target:  {model}")
    print(f"Prompts: {len(probe.prompts)}")
    print()

    for i, prompt in enumerate(probe.prompts):
        output = call_model(model, prompt.text)
        verdict = probe.detect(output, prompt)
        counts[verdict["verdict"]] += 1

        records.append({
            "entry_type": "attempt",
            "uuid": uuid4().hex,
            "seq": i,
            "status": 1,
            "probe_classname": probe.name,
            "probe_params": {"label": prompt.label},
            "prompt": {
                "turns": [
                    {"role": "user", "content": {"text": prompt.text, "lang": "en"}}
                ]
            },
            "outputs": [{"text": output, "lang": "en"}],
            "detector_results": {},
            "notes": {
                "verdict": verdict["verdict"],
                "verdict_reason": verdict["reason"],
                "triggers": prompt.triggers,
                "label": prompt.label,
            },
        })
        print(f"  [{i+1}/{len(probe.prompts)}] {prompt.label[:48]:48s}  -> {verdict['verdict']}")
        # Light throttle so providers' RPM limits aren't hit.
        time.sleep(1.5)

    # FAIL = attack succeeded; PASS+REFUSAL = defended.
    total = sum(counts.values())
    fails = counts["FAIL"]
    passed = counts["PASS"] + counts["REFUSAL"]
    ci_lower, ci_upper = wilson_ci(fails, total)

    records.append({
        "entry_type": "eval",
        "probe": probe.name,
        "detector": "custom.TriggerWithRefusalFilter",
        "passed": passed,
        "fails": fails,
        "nones": 0,
        "total_evaluated": total,
        "total_processed": total,
        "confidence_method": "wilson",
        "confidence": 0.95,
        "confidence_lower": ci_lower,
        "confidence_upper": ci_upper,
    })
    records.append({
        "entry_type": "completion",
        "end_time": datetime.now(timezone.utc).isoformat(),
        "run": run_id,
    })

    with report_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print()
    print("Summary:")
    print(f"  PASS    (trigger absent):   {counts['PASS']}")
    print(f"  REFUSAL (model refused):    {counts['REFUSAL']}")
    print(f"  FAIL    (attack succeeded): {counts['FAIL']}")
    print(f"  Attack success rate: {fails}/{total} ({fails/total*100:.2f}%)")
    print(f"    [95% CI Wilson: {ci_lower*100:.2f}% – {ci_upper*100:.2f}%]")
    print(f"  Report: {report_path}")
    return report_path


def main() -> None:
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    probe_name = sys.argv[1]
    model_spec = sys.argv[2]

    probe = load_probe(probe_name)
    runs_dir = Path.home() / ".local" / "share" / "garak" / "garak_runs"
    run_probe(probe, model_spec, runs_dir)


if __name__ == "__main__":
    main()
