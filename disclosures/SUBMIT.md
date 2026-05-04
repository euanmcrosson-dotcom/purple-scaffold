# Submission helper — 5-minute click-through

Pre-filled URLs, copy-paste blocks, and exact form-field guidance
for each of the four disclosures. Each submission is 60-90s once
the corresponding portal is open.

**Why this exists rather than auto-submission:** the four submission
channels (HackerOne, Bugcrowd, Google's bughunters portal, and an
email to `security@x.ai`) all require credentialed login (or in xAI's
case, an authenticated email client). The repo's automation has
neither HackerOne / Bugcrowd / Google API tokens nor an SMTP relay,
so the submission step has to happen from your account. The bodies
are 100% drafted; you click through.

**Order matters:** OpenAI → Google → xAI → Anthropic. Reasoning in
[`00-README.md`](00-README.md). Don't reorder unless you have a
specific reason.

---

## 1. OpenAI (Bugcrowd)

**File:** [`openai-gpt4o-mcp-filesystem.md`](openai-gpt4o-mcp-filesystem.md)

**URL to open:** https://bugcrowd.com/openai/submissions/new

**Form fields:**

| Field | Value |
|---|---|
| Title | `GPT-4o + GPT-4o-mini comply with filesystem-MCP indirect prompt injection — SSH-key exfiltration chain executed end-to-end` |
| Severity (CVSS) | Submitter to set; we suggest P3 (Medium) — single-prompt model behaviour with documented product-impact path. Bugcrowd may reclassify. |
| Target | "OpenAI Models — GPT-4o family" (or whichever target row matches in their dropdown) |
| Description | Paste the full body of `openai-gpt4o-mcp-filesystem.md` |
| Reproduction | "See section 'Reproducer' in the description" |
| Attachments | None — repo URL in the description is the canonical reproducer |

**Open the body for copy-paste:**

```powershell
notepad disclosures\openai-gpt4o-mcp-filesystem.md
# or
code disclosures\openai-gpt4o-mcp-filesystem.md
```

**After submission:** record the Bugcrowd reference number in
[`00-README.md`](00-README.md) under the tracking section. If
Bugcrowd marks it Out of Scope, the artifact stays public — that's
fine, the value is the published research, not the bounty.

---

## 2. Google (AI Vulnerability Reward Program)

**File:** [`google-gemini-mcp-filesystem.md`](google-gemini-mcp-filesystem.md)

**URL to open:** https://bughunters.google.com/report

(VRP main page: https://bughunters.google.com/about/rules/google-friends/5238615256793088/abuse-vulnerability-reward-program-rules)

**Form fields:**

| Field | Value |
|---|---|
| Product affected | "Gemini API" or "Generative Language API" — pick whichever matches Google's current taxonomy |
| Title | `Gemini 2.5 Flash silently complies with filesystem-MCP indirect prompt injection — reads ~/.ssh/id_rsa and ./.env from injection content` |
| Description | Paste full body of `google-gemini-mcp-filesystem.md` |
| Severity | Submitter to set; we suggest "Medium" |

**After submission:** if Google's portal returns a tracking ID,
record it in `00-README.md`.

---

## 3. xAI (email to `security@x.ai`)

**File:** [`xai-grok-mcp-filesystem.md`](xai-grok-mcp-filesystem.md)

**Pre-flight check:** verify the contact address against
https://x.ai/legal/responsible-disclosure (or current xAI public
docs) before sending. xAI's published security contact may have
moved; `security@x.ai` is the customary destination but not
guaranteed current.

**Compose:**

| Field | Value |
|---|---|
| To | `security@x.ai` (verify per pre-flight) |
| Subject | `Indirect prompt injection: Grok 4.1 Fast Reasoning explicitly notes "without disclosing… to the user" while planning .env exfil` |
| Body | Full content of `xai-grok-mcp-filesystem.md` |
| Format | Plain text or Markdown — both readable |
| Reply-to | `euanmcrosson@gmail.com` |

If you prefer to send from PowerShell with `Send-MailMessage`:

```powershell
$cred = Get-Credential                # use your SMTP credentials
$body = Get-Content -Raw disclosures\xai-grok-mcp-filesystem.md
Send-MailMessage `
  -From "euanmcrosson@gmail.com" `
  -To "security@x.ai" `
  -Subject "Indirect prompt injection: Grok 4.1 Fast Reasoning ..." `
  -Body $body `
  -SmtpServer "smtp.gmail.com" `       # adjust per your provider
  -Port 587 `
  -UseSsl `
  -Credential $cred
```

(`Send-MailMessage` is deprecated in newer PowerShell but still
works. Or just send from your normal mail client.)

**After sending:** record the date sent in `00-README.md`. xAI may
or may not reply — if no response within 30 days, follow up once,
then leave the artifact public.

---

## 4. Anthropic (HackerOne)

**File:** [`anthropic-haiku-disguise-gap.md`](anthropic-haiku-disguise-gap.md)

**URL to open:** https://hackerone.com/anthropic/reports/new

**Form fields:**

| Field | Value |
|---|---|
| Title | `Safety telemetry: Haiku 4.5 misses HTML-comment-disguised filesystem-MCP injection that Opus 4.7 catches` |
| Severity | "Informational" (this is evaluation telemetry, not a vulnerability) |
| Target | "Anthropic Models — Claude" |
| Description | Paste full body of `anthropic-haiku-disguise-gap.md` |
| Notes | The methodology caveat at the top is important — it tells the safety team that the prompt-only number is a model-disposition signal, not a product-impact claim |

**After submission:** record the HackerOne report number in
`00-README.md`.

---

## Tracking template

Append to `00-README.md` after each submission:

```
### Submission tracking — 2026-05-XX

| Recipient | Date sent | Channel | Reference | Status |
|---|---|---|---|---|
| OpenAI    | 2026-05-?? | Bugcrowd  | #_____  | Submitted |
| Google    | 2026-05-?? | bughunters | #_____ | Submitted |
| xAI       | 2026-05-?? | email     | n/a     | Sent |
| Anthropic | 2026-05-?? | HackerOne | #_____  | Submitted |
```

If any programme requests an embargo: **leave the existing public
artifact in place** (the public repo, the findings/, the
disclosures/), but pause new public posts about the specific finding
during the embargo window. The README's "Findings" table stays as-is.

---

## What this helper file is NOT

This is not a programme-policy document. The actual rules-of-
engagement / scope / payouts are at each programme's own URL. The
helper just removes the friction from "I have four polished
disclosures, where do I paste them?"
