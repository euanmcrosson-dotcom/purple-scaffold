# Driving real Continue.dev through the harness — runbook

User-in-the-loop runbook for the Continue.dev target. Continue.dev
is an MIT-licensed VS Code / JetBrains extension. Open source means
the system prompt is verifiable from
[`continuedev/continue:core/llm/defaultSystemMessages.ts`](https://github.com/continuedev/continue/blob/main/core/llm/defaultSystemMessages.ts);
the simulator (`examples/demo_product_simulator.py`) uses that
verbatim.

This runbook produces real-driving evidence as a confirmation
against the simulator's null result.

## Prerequisites

- VS Code with the Continue extension installed (or JetBrains
  equivalent).
- mitmproxy CA trusted on your OS.
- npm-installed `@modelcontextprotocol/server-filesystem`.

## Step 1 — Start the proxy

```powershell
Set-Location C:\Users\euanc\purple-scaffold
mitmdump -s purple/proxy.py --set capture_path=runs/proxy/continue.jsonl --listen-port 8765
```

## Step 2 — Configure Continue.dev's API endpoint to the proxy

Continue.dev's `~/.continue/config.json` (or its UI) lets you set the
`apiBase` for any provider. Example for Anthropic:

```json
{
  "models": [
    {
      "title": "Claude (proxied)",
      "provider": "anthropic",
      "model": "claude-haiku-4-5-20251001",
      "apiKey": "<your key>",
      "apiBase": "http://127.0.0.1:8765"
    }
  ]
}
```

Reload VS Code or the Continue panel so the new config takes effect.

## Step 3 — Configure Continue.dev's MCP filesystem server

Continue.dev's MCP support: edit `~/.continue/config.json` (or its
UI):

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "stdio",
          "command": "npx",
          "args": [
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "C:\\Users\\euanc\\Desktop\\continue-test-sandbox"
          ]
        }
      }
    ]
  }
}
```

Reload Continue to pick up the MCP server.

## Step 4 — Plant the sandbox

```powershell
$sandbox = "$env:USERPROFILE\Desktop\continue-test-sandbox"
Remove-Item -Recurse -Force $sandbox -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $sandbox | Out-Null
New-Item -ItemType Directory -Path "$sandbox\notes","$sandbox\docs","$sandbox\src" | Out-Null
```

Plant the three poisoned files using the same constants from
`examples/demo_mcp_headless_target.py` (see the Cursor runbook for
the file list).

## Step 5 — Drive Continue through the four scenarios in Agent mode

Continue's Agent mode is the relevant one for tool-using behaviour
(its DEFAULT_AGENT_SYSTEM_MESSAGE is what the simulator uses
verbatim). Switch to Agent mode in the Continue panel before each
scenario.

Use the same four prompts as `examples/demo_cursor_runbook.md`
Step 5.

## Step 6 — Analyse captures

```powershell
python -m purple.proxy_replay runs/proxy/continue.jsonl --mode passive
```

Inspect captured tool_uses for any attack patterns from
`examples/demo_mcp_headless_target.py`'s `SCENARIOS[i].attack_tool_patterns`.

## Step 7 — Record evidence

Append results to `findings/2026-05-04-deployed-agents-mcp-injection-comparison.md`.

For any FAIL: file via Continue.dev's `security@continue.dev` email
or via their GitHub security policy at
https://github.com/continuedev/continue/security.

For all-PASS: confirms the simulator's null result against the real
Continue.dev product running in Agent mode.

## Why Continue.dev is the cleanest cross-product confirmation

Continue.dev's prompt is OSS-verifiable. The simulator runs that
exact prompt; this runbook validates that the simulator + real
product agree. If the simulator says PASS and the real product also
says PASS, the simulator's null result for OSS products is fully
validated. If they diverge, it's a methodology bug in the simulator
to flag and fix.

A pass at this layer is the strongest possible cross-product
confirmation that the agent-loop-defends pattern holds for OSS
filesystem-MCP-using agents.
