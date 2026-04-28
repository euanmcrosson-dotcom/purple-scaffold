# 30-day plan — exact steps

A linear, actionable list. Items marked **[manual]** require something only
you can do (signups, identity verification, downloads from gated sources).
Everything else can be scripted.

---

## Week 1 — local lab + atomic tests

### A. Local Python workspace (done already)

- [x] `purple-scaffold/` exists at `C:\Users\euanc\purple-scaffold`
- [x] `python -m examples.demo` and `python -m examples.demo_atlas` both run
- [x] `python -m pytest tests/` — all tests green

### B. Install AI red-team tooling

```bash
# From inside purple-scaffold/
pip install garak           # AI red-team probe library
pip install promptfoo       # AI eval / red-team CLI (optional, JS-based)
```

If `pip install garak` fails on Python 3.14 (very new), create a 3.11
venv:

```bash
py -3.11 -m venv .venv311
.venv311\Scripts\activate    # Windows
pip install garak pydantic pytest
```

### C. Local vulnerable target — no API key required

The lab target at `lab/vulnerable_agent.py` (created in this session) is
a deterministic stand-in for a tool-using AI agent with a known
prompt-injection weakness. Run it with:

```bash
python lab/vulnerable_agent.py     # listens on http://127.0.0.1:8765
```

Then in another terminal:

```bash
python -m examples.demo_atlas_live # probes the running target
```

This produces a real card with real findings — not a mock.

### D. **[manual]** Detection Lab (Windows VM, ATT&CK side)

The ATT&CK demo is currently mocked. To make it real you need a
Windows lab with Sysmon + a SIEM. Three options, easiest first:

1. **Single VM + Wazuh** (lightest)
   - Install VirtualBox: https://www.virtualbox.org/wiki/Downloads
   - Download Windows 11 dev VM (free, 90-day):
     https://developer.microsoft.com/windows/downloads/virtual-machines
   - Install Sysmon with SwiftOnSecurity config:
     https://github.com/SwiftOnSecurity/sysmon-config
   - Install Wazuh agent on the VM, Wazuh manager on host (or use a
     hosted trial: https://wazuh.com)
   - Time: 2-4 hours

2. **Detection Lab** (Chris Long, multi-VM)
   - https://github.com/clong/DetectionLab
   - Vagrant + VirtualBox/VMware
   - Builds DC + WEC + Splunk + Velociraptor on 4 VMs
   - Time: 1 day, lots of disk

3. **Atomic test runner online** (Splunk Attack Range)
   - https://github.com/splunk/attack_range
   - AWS-hosted, costs ~$5/day to run
   - Good if you don't have local resources

Once a lab is up, install Atomic Red Team **inside the VM**:

```powershell
# From inside the lab VM, NOT your host
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

⚠ **Never run atomic-red-team on your host machine.** Many atomics
modify the registry, drop files, or trigger AV.

### E. Wire scaffold to the lab

Replace `AttackerAgent.handle()` in `purple/agents.py` with a subprocess
call that invokes `Invoke-AtomicTest` over WinRM/SSH against the lab VM.
Same for `AnalystAgent.handle()` — replace with a Wazuh / Splunk API
query.

---

## Week 2 — AI agent attack surface

### F. **[manual]** Pick a target agent product

Choose ONE to go deep on (don't fan out):

- **Cursor** — coding agent, large bug bounty scope
- **Continue.dev** — open source coding agent, MIT licensed
- **Open WebUI** — self-hosted LLM UI, lots of attack surface
- **AnythingLLM** — self-hosted RAG agent
- **A specific MCP server** from https://github.com/modelcontextprotocol/servers

For first-time research, **Continue.dev** or an MCP server is best:
open source, no bounty rules to navigate, you can read the code.

### G. Run garak against your chosen target

Two paths:

1. **Against an OpenAI/Anthropic model directly** (needs API key):
   ```bash
   garak --model_type openai --model_name gpt-4o-mini --probes promptinject
   garak --model_type anthropic --model_name claude-haiku-4-5 --probes promptinject
   ```

2. **Against a local model via ollama** (no API key, free):
   - Install ollama: https://ollama.com/download
   - `ollama pull llama3.2:3b`
   - `garak --model_type ollama --model_name llama3.2:3b --probes promptinject`

Save the garak report. Cards from `purple-scaffold` should reference
the garak report as their atomic source.

### H. **[manual]** Set up an MCP test environment

```bash
# Install the official MCP servers locally
npm install -g @modelcontextprotocol/server-filesystem
npm install -g @modelcontextprotocol/server-fetch
```

Connect them to Claude Desktop or Continue.dev. Configure a sandbox
directory. Then run `examples/demo_atlas_live.py` against the agent
that uses them.

---

## Week 3 — find a real finding

### I. Pick a low-stakes target first

For your first responsible-disclosure submission, pick a project that
welcomes security reports and has a clear contact:

- **GitHub: huggingface/transformers** — security@huggingface.co
- **GitHub: langchain-ai/langchain** — security@langchain.dev
- **GitHub: modelcontextprotocol/servers** — file an issue, follow
  https://github.com/modelcontextprotocol/.github/blob/main/SECURITY.md
- **Open WebUI** — security@openwebui.com

Run your harness against the project. If you find something:

1. Reproduce twice, independently
2. Write up using the `purple-scaffold` card format as your evidence
3. Email security@<project> — give 90 days before publishing
4. Track in your repo under `findings/<id>.md`

### J. **[manual]** Sign up for AI bug bounties

Do these in one sitting (1-2 hours total). Each requires identity
verification:

| Program | Platform | URL |
|---|---|---|
| Anthropic | HackerOne | https://hackerone.com/anthropic |
| OpenAI | Bugcrowd | https://bugcrowd.com/openai |
| GitHub | HackerOne | https://hackerone.com/github |
| Microsoft AI | MSRC | https://www.microsoft.com/msrc/bounty-ai |
| Hugging Face | (program varies, check site) | https://huggingface.co/security |
| Replit | HackerOne | https://hackerone.com/replit |

You'll need:
- Government ID (some programs require)
- Tax info (if you want to be paid)
- A reachable email
- A pen-test account / sandbox if the program offers one

---

## Week 4 — community + visibility

### K. **[manual]** Communities to join

Sign up to all of these, lurk for a week before posting:

- **DEF CON AI Village Discord** — https://aivillage.org/ → Discord link
- **MLSecOps Community** — https://mlsecops.com/community
- **Embrace The Red blog** — https://embracethered.com/blog/ (Johann
  Rehberger, the indie standard for AI red team)
- **r/LLMSecurity** subreddit
- **HackerOne / Bugcrowd public reports** — read disclosed reports in
  your category for ~30 minutes daily for two weeks; this is
  the fastest way to learn what good submissions look like

### L. **[manual]** Twitter/X follow list

Open Twitter, follow:

- @simonw (Simon Willison — best AI security commentator)
- @wunderwuzzi23 (Johann Rehberger — practitioner)
- @rez0__ (Joseph Thacker — bounty hunter, AI focus)
- @LeapLabsAI
- @aivillage_dc
- @HiddenLayerSec
- @lakeraai

### M. Publish your repo

Put `capnagent` (or `purple-scaffold` renamed) on your GitHub:

- README explaining the architecture (you have this)
- A `findings/` directory you'll add to as you work
- A `CONTRIBUTING.md` if you want others to add atomics/tests
- Tag it: `ai-security`, `red-team`, `purple-team`, `mcp`, `atlas`

Pin it to your profile. This is the credential you'll point at when
applying for AI security work.

---

## After 30 days — what to do with what you have

If you have:
- ✅ Working local lab (week 1)
- ✅ One real probe of a real agent product (week 2)
- ✅ One disclosed finding (week 3)
- ✅ Public repo + community presence (week 4)

…you're at the bar to start applying for:

1. **Anthropic bug bounty** — submit higher-value findings
2. **AI security startups** — HiddenLayer, Lakera, Protect AI, Calypso AI
3. **Pentesting firms with AI offerings** — NCC Group, Bishop Fox, Trail of Bits
4. **Frontier lab safety / red team contractor roles** — Anthropic, OpenAI,
   GDM, Apollo, METR (these usually want demonstrated public work)

Don't apply to those before you have those four checkmarks. Cold outreach
without artifacts is a waste of attention; with artifacts it's straightforward.

---

## What can't be automated

These steps require you specifically:

- Account creation and identity verification (HackerOne, Bugcrowd, etc.)
- Signing legal docs (some programs have NDAs / safe-harbor agreements)
- Setting up a hypervisor + downloading multi-GB Windows VM images
- Exercising judgment on what to disclose, when, and to whom
- Building reputation in communities — only your own posts count

Everything else is in this repo or in the commands above.
