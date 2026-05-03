# What's next: second target + outreach

Notes for the post-publish phase. Items 4 and 5 from the post-launch
checklist. These are choices the human has to make — this doc lays out
the options cleanly so the choice is fast.

---

## Item 4 — Run the harness against a real product

The two existing findings are *single-prompt model behaviour*. A
finding with *product-level impact* (data leaves the system, file gets
read, email gets sent in a deployed agent product) is what bug bounties
actually pay for and what most security writeups cite. This is the
inflection from "research artifact" to "vulnerability disclosure."

### Target options, ranked

**1. An MCP server from `modelcontextprotocol/servers` (recommended first target)**

- Pros: open-source, MIT-licensed, you can read the code, no bounty
  rules to navigate, the disclosure path is `SECURITY.md` in the
  `.github` repo. Lowest friction, highest ratio of work-to-finding.
- Cons: not a "deployed product" — finding has to be framed around the
  reference implementation. Some servers in this list are toy / demo
  quality and don't represent production exposure.
- Best candidates inside this repo: `server-filesystem`,
  `server-fetch`, `server-postgres`, `server-git`. Each takes
  attacker-controllable input that downstream agents act on.
- How to point the harness at it: install the MCP server locally,
  point Claude Desktop / Cursor / Continue.dev at it, then drive
  the agent with prompts containing your existing injection patterns.
- Writeup format: same as `findings/2026-04-28-mcp-tool-description-poisoning-openai.md`
  but with a *deployed-tool* angle.

**2. Continue.dev**

- Pros: open-source (Apache 2.0), VS Code coding agent, security
  contact is `security@continue.dev`. Real users. Has tool-using
  flows where exfiltration would have product impact.
- Cons: much larger surface than an MCP server; longer time to a
  finding. May be already-hardened against the obvious patterns.
- Best attack class: indirect injection via repository content the
  agent ingests — README, docstrings, code comments containing
  injection.

**3. Open WebUI**

- Pros: self-hosted LLM UI, large surface, security contact at
  `security@openwebui.com`, plenty of disclosed CVEs already so the
  process is well-trodden.
- Cons: largest of the three; finding novelty is harder.

**4. A specific commercial product (Cursor, Cline, Claude Desktop, etc.)**

- Pros: highest impact if landed; bounty-eligible.
- Cons: you must follow their bug-bounty scope rules exactly. Most
  programs require pen-test accounts / sandbox setups before any
  probe activity. Significantly higher friction. Save this for after
  you've published one open-source finding.

### Recommended first move

Pick `server-filesystem` from the modelcontextprotocol/servers repo.

Why: smallest surface, attack class is exactly what your existing
custom probes already fire (`mcp_poisoning.py` + `echoleak.py`), the
disclosure path is documented, no bounty paperwork. Two days of work
to a finding, three to a writeup. Then move up the list.

Concrete steps:

1. `git clone https://github.com/modelcontextprotocol/servers`
2. Install `@modelcontextprotocol/server-filesystem` locally
3. Wire it to Claude Desktop with a sandbox dir
4. Adapt `examples/demo_atlas_live.py` — change `_post_chat()` to
   send prompts to an agent connected to the MCP server
5. Drive the harness; it should produce a card per probe in
   `examples/cards/`
6. If you find something, write up using the existing finding format
7. File following https://github.com/modelcontextprotocol/.github/blob/main/SECURITY.md

---

## Item 5 — Cold outreach

Once repo + writeup + (eventually) a product-level finding exist, the
bar is met to apply for AI red-team / safety contractor work. Order
matters: aim → tactic → message.

### Aim: what you're applying for

| Path | Compensation | Time to first opportunity | Why this path |
|------|--------------|---------------------------|---------------|
| Frontier-lab safety / red-team contractor (Anthropic, OpenAI, GDM, Apollo, METR) | High; bar is "demonstrated public work" | 3-12 months from first artifact | Best long-term fit if you want to do this full-time at a frontier lab |
| AI security startup full-time (HiddenLayer, Lakera, Protect AI, CalypsoAI) | Medium-high; bar is "can ship" | 1-3 months | Faster, more product-focused, broader attack-class exposure |
| Pentest firms with AI offerings (NCC Group, Bishop Fox, Trail of Bits) | Medium; bar is "competent generalist + AI portfolio" | 1-2 months | Broadest, highest-volume work; useful as a stepping stone |
| Bug-bounty income (Anthropic, OpenAI, GitHub, Microsoft AI) | Variable; bar is "valid finding" | Weeks per finding | Not a primary income path; useful as proof for above three |

### Where to be visible (do these in week 1 post-publish)

These are sign-up / lurk-for-a-week steps, not active posting:

- DEF CON AI Village Discord — https://aivillage.org/ → Discord link
- MLSecOps Community — https://mlsecops.com/community
- Embrace The Red blog (Johann Rehberger) — https://embracethered.com/blog/
- r/LLMSecurity subreddit
- HackerOne / Bugcrowd public reports (in your category) — read 30 min/day for two weeks

X follow list (already in `CHECKLIST.md`):

- @simonw — Simon Willison (best AI security commentator)
- @wunderwuzzi23 — Johann Rehberger (practitioner, Embrace The Red)
- @rez0__ — Joseph Thacker (bounty hunter, AI focus)
- @LeapLabsAI, @aivillage_dc, @HiddenLayerSec, @lakeraai

### Outreach message template

For cold outreach to a specific person at a frontier lab / AI security
startup. Adapt — generic "I want to work in AI security" gets ignored.

```
Subject: AI red-team work — public artifact

Hi [name],

I'm an independent AI security researcher. Over the past month I've
shipped:

- A purple-team harness for AI agents
  (github.com/euanmcrosson-dotcom/purple-scaffold) — deterministic
  orchestrator + 5 specialist agents, ATLAS-aware, with a self-
  contained vulnerable-agent target. The Engineer agent generates
  real tool-call policies from analysis gaps and backtests them
  against a fixture corpus.

- Two reproducible findings against GPT-4o
  - 67% silent compliance on EchoLeak-style email injection
  - Verbatim SSH-key exfil plans from MCP tool-description poisoning

- An upstream PR for garak (NVIDIA's red-team library) fixing
  86–100% false-positive rates on three default detectors against
  modern frontier models.

Public writeup: [link to blog / X thread]

I'd like to talk about [specific role / contract type / specific
project at their org]. Available for [contract / part-time /
freelance].

Best,
Euan
```

Key points for the message:

- Lead with the artifacts (links). Skip the cover-letter intro.
- Three concrete deliverables, each with a link.
- One specific ask at the end. Don't say "any role." Say which.
- Keep it under 150 words.

### Who to send it to (in order)

1. **Anthropic safety / red-team team** — apply through
   https://www.anthropic.com/jobs and reference the public artifacts.
   For contract / consulting, message via the relationship-manager
   listed on the bug-bounty disclosure email if you have one.
2. **METR** (https://metr.org) — small org, runs frontier-model
   evaluations. Reach `careers@metr.org` or via their blog comments.
3. **Apollo Research** (https://www.apolloresearch.ai/) — same
   profile as METR; smaller, hire on demonstrated work.
4. **HiddenLayer / Lakera / Protect AI** — apply normally; the public
   artifact is the differentiator. LinkedIn message a senior engineer
   at the org with a one-line "I shipped X — would value a 15-min
   chat" rather than a full cover letter.
5. **NCC Group AI practice / Bishop Fox / Trail of Bits** — these
   firms post named contractor roles regularly. Apply there directly.

### Bug-bounty submissions — what to do with the existing two findings

The findings in `findings/` are written as defensive-research artifacts
and disclose what is/isn't novel. For each:

- `2026-04-28-echoleak-style-injection-openai.md` — submit to OpenAI's
  bounty (https://bugcrowd.com/openai). The phrasing pattern + the
  empirical compliance rate may be in scope; the attack class itself
  is public. Frame: "specific phrasing patterns produce silent
  compliance with cross-tool exfiltration plans, vs Anthropic models
  refusing the same prompts."
- `2026-04-28-mcp-tool-description-poisoning-openai.md` — same
  submission path. Both findings can be one bundle.

If accepted: take the bounty, leave the finding public.
If declined as out-of-scope: leave the finding public anyway. The
artifact is the credential, not the bounty.

---

## Tracking

Add to a personal tracking doc (not in this repo):

```
- 2026-05-04 published purple-scaffold
- 2026-05-?? blog post live
- 2026-05-?? OpenAI bounty submitted (echoleak + MCP)
- 2026-05-?? garak upstream PR opened (#?)
- 2026-05-?? first finding against an MCP server
- 2026-05-?? first cold-outreach message sent
```

The dates create their own pressure to ship. Aim for one row per week.
