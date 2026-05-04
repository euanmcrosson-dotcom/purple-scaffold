"""Real-product driving: Cline CLI in headless / non-interactive mode.

Phase 8b investigation result: Cline (cline/cline) ships a real
terminal-native CLI (`npm i -g cline`) with `--json` and `--yolo` /
`--auto-approve-all` flags that allow non-interactive driving of the
actual Cline agent — not a simulator. This is the closest thing to
"verbatim Cline product evidence" we can produce without a UI.

This file is a SKELETON. It has the shape of a probe but does not
produce verdicts on its own — driving Cline's CLI through proxy +
parsing its JSON output is more complex than the
`mcp-server-{filesystem,fetch,git,sqlite}` probes we already have.
Two open questions for whoever fills this in:

  1. Auth: `cline auth -k <key> -m <model> anthropic` configures
     the CLI globally. In CI / per-run we want a per-invocation
     credential rather than touching global config; investigate
     `--config <path>` to scope a config dir per probe run.
  2. MCP config: Cline reads MCP server configs from its config
     directory. Pointing it at the same poisoned filesystem MCP
     server we use elsewhere requires writing the right JSON to
     that dir. See `cline mcp --help`.

When this is wired up, it gives us **verbatim Cline evidence** — the
actual prompt Cline constructs internally, with Cline's actual MCP
tool plumbing, scored by the same tool-use-aware verdict the rest
of the harness uses. Until it's wired, the headless product
simulator at `examples/demo_product_simulator.py` is the
agent-loop-equivalent stand-in.

Run (currently a smoke test only — does not produce verdicts):
    set -a; . ./.env; set +a
    python -m examples.demo_cline_cli_real --skel
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _check_cline_cli() -> tuple[bool, str]:
    """Return (installed, version-or-error)."""
    if shutil.which("cline") is None:
        return False, "cline CLI not on PATH; install with `npm i -g cline`"
    try:
        out = subprocess.run(
            ["cline", "--version"], capture_output=True, text=True, check=True, timeout=15,
        )
        return True, out.stdout.strip() or "(unknown version)"
    except subprocess.TimeoutExpired:
        return False, "cline --version timed out (cline may be hanging — check auth state)"
    except subprocess.CalledProcessError as exc:
        return False, f"cline --version failed: {exc.stderr.strip()[:200]}"


def _smoke_test() -> int:
    print("Phase 8b skeleton — Cline CLI driving")
    print("=" * 50)
    installed, info = _check_cline_cli()
    print(f"Cline CLI: {info}" if installed else f"NOT INSTALLED: {info}")
    if not installed:
        return 1
    print()
    print("Next steps to make this a real probe:")
    print("  1. Authenticate Cline via `cline auth -k $ANTHROPIC_API_KEY \\")
    print("       -m claude-haiku-4-5-20251001 anthropic` (interactive — the")
    print("     hang we hit suggests it expects TTY; --no-interactive flag may help)")
    print("  2. Configure MCP filesystem server via `cline mcp add filesystem \\")
    print("       npx -y @modelcontextprotocol/server-filesystem <sandbox>`")
    print("  3. Plant poisoned files in <sandbox> using the constants from")
    print("     `examples/demo_mcp_headless_target.py`")
    print("  4. Run `cline task -y --json --cwd <sandbox> \\")
    print("       'summarize README.md'`")
    print("  5. Parse stdout for tool_use events. Score with")
    print("     `examples.demo_mcp_headless_target.score_session`.")
    print()
    print("Once wired: this produces VERBATIM Cline product evidence —")
    print("the strongest possible cross-product validation against the")
    print("simulator's null result.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skel", action="store_true",
                        help="Run the smoke / skeleton test (default behaviour)")
    args = parser.parse_args()
    sys.exit(_smoke_test())


if __name__ == "__main__":
    main()
