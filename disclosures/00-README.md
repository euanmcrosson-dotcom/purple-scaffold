# Disclosure submissions for 2026-05-04 server-filesystem finding

Four drafted submissions, one per provider. Copy-paste the body of
each into the corresponding bounty / safety channel; do not modify
the verbatim quoted output sections (they're the citable evidence).

| File | Recipient | Submission channel |
|------|-----------|-------------------|
| `openai-gpt4o-mcp-filesystem.md` | OpenAI | [Bugcrowd OpenAI](https://bugcrowd.com/openai) |
| `google-gemini-mcp-filesystem.md` | Google | [Google AI VRP](https://bughunters.google.com/about/rules/google-friends/5238615256793088/abuse-vulnerability-reward-program-rules) |
| `xai-grok-mcp-filesystem.md` | xAI | `security@x.ai` (verify before sending) |
| `anthropic-haiku-disguise-gap.md` | Anthropic | [HackerOne Anthropic](https://hackerone.com/anthropic) |

## Suggested submission order

1. **OpenAI first** — the SSH-key exfil chain is the most concrete
   "would clearly fail in a deployed product" demonstration in the
   panel. Easiest to argue scope-eligibility on.
2. **Google second** — same compliance pattern, different provider.
   Submitting both lets the receiving teams see the cross-provider
   pattern (it's not just an OpenAI thing).
3. **xAI third** — the "without disclosing… to the user" reasoning
   trace is qualitatively distinct and worth flagging. xAI doesn't
   have a published public bounty as of the writing of this
   submission; `security@x.ai` is the customary destination but
   verify on https://x.ai/legal/responsible-disclosure or current
   public docs before sending.
4. **Anthropic last (and as safety telemetry, not a bounty
   submission)** — the Haiku disguise-recognition gap is a single
   scenario, not a product-impact-grade finding. Most useful as a
   datapoint for the safety team's evaluation suite. Frame as
   "evaluation telemetry" not "vulnerability."

## What to include in EACH submission

Each drafted body has these sections — keep them; reviewers expect
this shape:

- One-paragraph summary
- Severity / scope framing (per program rules)
- Reproduction steps (short — point at the public repo)
- Verbatim model output proving the compliance behaviour
- What the impact is in deployed products
- Suggested mitigations
- Pointer to the full finding for context

## After you submit

Track each submission with:

```
- 2026-05-?? OpenAI:   submitted, ref #_____
- 2026-05-?? Google:   submitted, ref #_____
- 2026-05-?? xAI:      sent to security@x.ai
- 2026-05-?? Anthropic: filed via HackerOne, ref #_____
```

For any finding accepted into a bounty: the public repo and verbatim
text in this directory remain useful even if the bounty programme
treats the submission as confidential. Disclosure status for *this
research* is "publicly available defensive-research artifact"; the
bounty programs are about whether the receiving organisation pays for
the work, not whether the public artifact is allowed to exist. The
public artifact already exists at the public repo.

If a programme requests a hold on public discussion: pause new
public posts about the specific finding for the duration of the
embargo. The findings/ directory is already public — leaving it up
during an embargo is fine; *new* social-media posts or blog posts
about the same finding should pause until the window closes.
